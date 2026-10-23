import fs from 'fs';
import path from 'path';
import fg from 'fast-glob';
import { TreeSitterEngine } from '../parser/tree-sitter-engine.js';
import { ASTCallGraphAnalyzer } from '../parser/call-graph.js';
import { scanHardcodedSecretsAndProviders } from '../parser/hardcoded-secrets.js';
import { RuleRegistry } from '../rules/registry.js';
import { QuantumScoringEngine } from './qvi.js';
import { CnsaEvaluator } from './cnsa.js';
import { CryptoFinding, ScanOptions, ScanResult, Severity } from '../types/index.js';

const SEVERITY_LEVELS: Record<Severity, number> = {
  info: 0,
  low: 1,
  medium: 2,
  high: 3,
  critical: 4,
};

export class PQCScanner {
  private registry: RuleRegistry;

  constructor(registry?: RuleRegistry) {
    this.registry = registry || RuleRegistry.createDefault();
  }

  public async scan(options: ScanOptions): Promise<ScanResult> {
    const startTime = Date.now();
    const targetDir = path.resolve(options.targetDir || '.');

    // 1. Discover target source files
    const defaultIgnores = [
      '**/node_modules/**',
      '**/.git/**',
      '**/dist/**',
      '**/build/**',
      '**/vendor/**',
      '**/__pycache__/**',
      '**/.venv/**',
      '**/venv/**',
      '**/target/**',
      '**/*.min.js',
      '**/*.d.ts',
      '**/*.d.ts.map',
    ];

    const ignorePatterns = options.ignorePatterns
      ? [...defaultIgnores, ...options.ignorePatterns]
      : defaultIgnores;

    const fileEntries = await fg(
      ['**/*.py', '**/*.js', '**/*.mjs', '**/*.cjs', '**/*.jsx', '**/*.ts', '**/*.mts', '**/*.cts', '**/*.tsx', '**/*.go', '**/*.java'],
      {
        cwd: targetDir,
        ignore: ignorePatterns,
        absolute: true,
        onlyFiles: true,
      }
    );

    const treeEngine = await TreeSitterEngine.getInstance();
    let allFindings: CryptoFinding[] = [];
    let filesScanned = 0;

    for (const absolutePath of fileEntries) {
      const relPath = path.relative(targetDir, absolutePath);
      const detectedLang = treeEngine.detectLanguageFromPath(absolutePath);
      if (!detectedLang) continue;

      filesScanned++;

      let content: string;
      try {
        content = fs.readFileSync(absolutePath, 'utf-8');
      } catch {
        continue;
      }

      // 1. Scan for hardcoded keys, PEM blocks, and legacy providers
      const secretFindings = scanHardcodedSecretsAndProviders(content, relPath);
      for (const sf of secretFindings) {
        sf.language = treeEngine.normalizeLanguage(detectedLang);
      }
      allFindings.push(...secretFindings);

      // 2. Parse with Tree-sitter for AST queries & call graphs
      try {
        const parser = await treeEngine.createParser(detectedLang);
        const tree = parser.parse(content);
        const normalizedLang = treeEngine.normalizeLanguage(detectedLang);
        const rules = this.registry.getRulesForLanguage(normalizedLang);

        const ctx = ASTCallGraphAnalyzer.extractContext(
          tree.rootNode,
          relPath,
          content,
          normalizedLang
        );

        const astFindings = ASTCallGraphAnalyzer.analyzeNode(tree.rootNode, ctx, rules);
        allFindings.push(...astFindings);
      } catch {
        // Continue if single file parse fails
      }
    }

    // Apply CNSA Mode if enabled
    if (options.cnsaMode) {
      allFindings = CnsaEvaluator.applyCnsaMode(allFindings);
    }

    // Filter by minSeverity
    if (options.minSeverity) {
      const minThreshold = SEVERITY_LEVELS[options.minSeverity];
      allFindings = allFindings.filter((f) => SEVERITY_LEVELS[f.severity] >= minThreshold);
    }

    const durationMs = Date.now() - startTime;
    const summary = QuantumScoringEngine.generateSummary(
      targetDir,
      filesScanned,
      allFindings,
      durationMs
    );

    return {
      summary,
      findings: allFindings,
    };
  }
}

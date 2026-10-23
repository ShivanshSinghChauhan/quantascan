import Parser from 'web-tree-sitter';
import { ASTContext, Rule } from '../rules/registry.js';
import { CryptoFinding, Language } from '../types/index.js';

export class ASTCallGraphAnalyzer {
  public static extractContext(
    rootNode: Parser.SyntaxNode,
    filePath: string,
    sourceCode: string,
    _lang: Language
  ): ASTContext {
    const lines = sourceCode.split('\n');
    const imports = new Set<string>();
    const aliases = new Map<string, string>();
    const varTypes = new Map<string, string>();

    // Initial pass to collect imports and declarations
    function walkCollect(node: Parser.SyntaxNode) {
      // Python imports: import foo as bar, from foo import bar
      if (node.type === 'import_statement' || node.type === 'import_from_statement') {
        imports.add(node.text);
      }
      // JS imports: import ... from '...', const ... = require('...')
      else if (node.type === 'import_statement' || node.type === 'lexical_declaration') {
        if (node.text.includes('require(') || node.text.includes('from ')) {
          imports.add(node.text);
        }
      }
      // Go imports: import "crypto/rsa", import ( ... )
      else if (node.type === 'import_declaration') {
        imports.add(node.text);
      }
      // Java imports: import java.security.*;
      else if (node.type === 'import_declaration') {
        imports.add(node.text);
      }

      for (let i = 0; i < node.childCount; i++) {
        const child = node.child(i);
        if (child) walkCollect(child);
      }
    }

    walkCollect(rootNode);

    return {
      filePath,
      sourceCode,
      lines,
      imports,
      aliases,
      varTypes,
    };
  }

  public static analyzeNode(
    rootNode: Parser.SyntaxNode,
    ctx: ASTContext,
    rules: Rule[]
  ): CryptoFinding[] {
    const findings: CryptoFinding[] = [];
    const seenLocations = new Set<string>();

    function walk(node: Parser.SyntaxNode) {
      for (const rule of rules) {
        try {
          const finding = rule.check(node, ctx);
          if (finding) {
            const locKey = `${finding.file}:${finding.location.startLine}:${finding.location.startColumn}:${finding.algorithm}`;
            if (!seenLocations.has(locKey)) {
              seenLocations.add(locKey);
              findings.push(finding);
            }
          }
        } catch {
          // Keep scanner resilient across unexpected AST variations
        }
      }

      for (let i = 0; i < node.childCount; i++) {
        const child = node.child(i);
        if (child) walk(child);
      }
    }

    walk(rootNode);
    return findings;
  }
}

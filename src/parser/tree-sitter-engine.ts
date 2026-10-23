import path from 'path';
import fs from 'fs';
import { createRequire } from 'module';
import Parser from 'web-tree-sitter';
import { Language } from '../types/index.js';

const require = createRequire(import.meta.url);

export class TreeSitterEngine {
  private static instance: TreeSitterEngine | null = null;
  private initialized = false;
  private languages: Map<string, Parser.Language> = new Map();
  private wasmDir: string = '';

  private constructor() {}

  public static async getInstance(): Promise<TreeSitterEngine> {
    if (!TreeSitterEngine.instance) {
      TreeSitterEngine.instance = new TreeSitterEngine();
      await TreeSitterEngine.instance.init();
    }
    return TreeSitterEngine.instance;
  }

  private async init(): Promise<void> {
    if (this.initialized) return;

    await Parser.init();

    // Locate tree-sitter-wasms directory
    const wasmPkgPath = require.resolve('tree-sitter-wasms/package.json');
    this.wasmDir = path.join(path.dirname(wasmPkgPath), 'out');

    if (!fs.existsSync(this.wasmDir)) {
      throw new Error(`Tree-sitter WASM directory not found at ${this.wasmDir}`);
    }

    this.initialized = true;
  }

  public async getLanguage(lang: Language | 'tsx'): Promise<Parser.Language> {
    if (this.languages.has(lang)) {
      return this.languages.get(lang)!;
    }

    const wasmFileName = `tree-sitter-${lang}.wasm`;
    const wasmFilePath = path.join(this.wasmDir, wasmFileName);

    if (!fs.existsSync(wasmFilePath)) {
      throw new Error(`WASM file not found for language ${lang}: ${wasmFilePath}`);
    }

    const loadedLang = await Parser.Language.load(wasmFilePath);
    this.languages.set(lang, loadedLang);
    return loadedLang;
  }

  public async createParser(lang: Language | 'tsx'): Promise<Parser> {
    const language = await this.getLanguage(lang);
    const parser = new Parser();
    parser.setLanguage(language);
    return parser;
  }

  public detectLanguageFromPath(filePath: string): Language | 'tsx' | null {
    const ext = path.extname(filePath).toLowerCase();
    switch (ext) {
      case '.py':
      case '.pyw':
        return 'python';
      case '.js':
      case '.mjs':
      case '.cjs':
      case '.jsx':
        return 'javascript';
      case '.ts':
      case '.mts':
      case '.cts':
        return 'typescript';
      case '.tsx':
        return 'tsx';
      case '.go':
        return 'go';
      case '.java':
        return 'java';
      default:
        return null;
    }
  }

  public normalizeLanguage(lang: Language | 'tsx'): Language {
    if (lang === 'tsx') return 'typescript';
    return lang;
  }
}

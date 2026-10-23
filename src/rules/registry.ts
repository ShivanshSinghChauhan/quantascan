import Parser from 'web-tree-sitter';
import { CryptoFinding, Language, CryptoCategory, CryptoPrimitive, Severity } from '../types/index.js';
import { pythonRules } from './python-rules.js';
import { javascriptRules } from './javascript-rules.js';
import { goRules } from './go-rules.js';
import { javaRules } from './java-rules.js';

export interface ASTContext {
  filePath: string;
  sourceCode: string;
  lines: string[];
  imports: Set<string>;
  aliases: Map<string, string>; // alias -> full module name
  varTypes: Map<string, string>; // variable name -> instantiated type/algorithm
}

export interface Rule {
  id: string;
  languages: Language[];
  name: string;
  category: CryptoCategory;
  primitive: CryptoPrimitive;
  defaultSeverity: Severity;
  check: (node: Parser.SyntaxNode, ctx: ASTContext) => CryptoFinding | null;
}

export class RuleRegistry {
  private rules: Rule[] = [];

  public register(rule: Rule): void {
    this.rules.push(rule);
  }

  public getRulesForLanguage(lang: Language): Rule[] {
    return this.rules.filter((r) => r.languages.includes(lang));
  }

  public getAllRules(): Rule[] {
    return this.rules;
  }

  public static createDefault(): RuleRegistry {
    const registry = new RuleRegistry();
    for (const r of pythonRules) registry.register(r);
    for (const r of javascriptRules) registry.register(r);
    for (const r of goRules) registry.register(r);
    for (const r of javaRules) registry.register(r);
    return registry;
  }
}

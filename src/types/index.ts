export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info';

export type Language = 'python' | 'javascript' | 'typescript' | 'go' | 'java';

export type CryptoCategory =
  | 'asymmetric-kem'
  | 'digital-signature'
  | 'symmetric-crypto'
  | 'hash-function'
  | 'hardcoded-secret'
  | 'legacy-provider';

export type CryptoPrimitive =
  | 'kem'
  | 'signature'
  | 'key-exchange'
  | 'block-cipher'
  | 'hash'
  | 'mac'
  | 'pke'
  | 'stream-cipher';

export type AssetType = 'algorithm' | 'certificate' | 'key' | 'protocol';

export type CryptoContext =
  | 'key-exchange'
  | 'signature-verify'
  | 'signature-sign'
  | 'data-at-rest'
  | 'data-in-transit'
  | 'digest'
  | 'unknown';

export interface LocationRange {
  startLine: number;
  startColumn: number;
  endLine: number;
  endColumn: number;
}

export interface RemediationAdvisory {
  nistStandard: 'FIPS 203' | 'FIPS 204' | 'FIPS 205' | 'SP 800-208' | 'CNSA 2.0' | 'NIST General';
  replacement: string;
  advisory: string;
  codeSnippet?: string;
}

export interface CnsaStatus {
  compliant: boolean;
  requirement: string;
  deadline: string;
}

export interface CryptoFinding {
  id: string;
  ruleId: string;
  file: string;
  location: LocationRange;
  language: Language;
  category: CryptoCategory;
  assetType: AssetType;
  algorithm: string;
  primitive: CryptoPrimitive;
  parameterSet?: string;
  curve?: string;
  keyLength?: number;
  context: CryptoContext;
  severity: Severity;
  classicalSecurityLevel?: number;
  nistQuantumSecurityLevel: 0 | 1 | 2 | 3 | 4 | 5;
  title: string;
  description: string;
  codeSnippet: string;
  remediation: RemediationAdvisory;
  cnsa: CnsaStatus;
}

export interface ScanOptions {
  targetDir: string;
  format?: 'cli-table' | 'json' | 'cyclonedx-cbom' | 'html';
  minSeverity?: Severity;
  cnsaMode?: boolean;
  output?: string;
  failOn?: Severity;
  ignorePatterns?: string[];
  maxFiles?: number;
}

export interface ScanSummary {
  targetDir: string;
  totalFilesScanned: number;
  totalCryptoAssets: number;
  findingsCount: number;
  bySeverity: Record<Severity, number>;
  byCategory: Record<CryptoCategory, number>;
  byLanguage: Record<Language, number>;
  quantumVulnerabilityIndex: number; // 0 - 100
  postQuantumReadiness: number; // 0 - 100%
  cnsaCompliant: boolean;
  cnsaViolationsCount: number;
  criticalDeprecations: string[];
  scanDurationMs: number;
  timestamp: string;
}

export interface ScanResult {
  summary: ScanSummary;
  findings: CryptoFinding[];
}

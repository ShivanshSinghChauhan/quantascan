import { CryptoFinding, Severity, ScanSummary, Language, CryptoCategory } from '../types/index.js';

const SEVERITY_WEIGHTS: Record<Severity, number> = {
  critical: 25,
  high: 15,
  medium: 8,
  low: 3,
  info: 0,
};

export class QuantumScoringEngine {
  /**
   * Calculates the Quantum Vulnerability Index (QVI) on a scale of 0 to 100.
   * 0 = Fully Post-Quantum Resilient (No quantum-vulnerable primitives found)
   * 100 = Fully Vulnerable / Critical Quantum Exposure
   */
  public static calculateQVI(findings: CryptoFinding[]): number {
    if (findings.length === 0) {
      return 0;
    }

    let rawScore = 0;
    for (const f of findings) {
      rawScore += SEVERITY_WEIGHTS[f.severity] || 0;
    }

    // Dampened exponential scaling to normalize to 0 - 100
    const normalized = Math.min(100, Math.round(100 * (1 - Math.exp(-rawScore / 45))));
    return Math.max(0, normalized);
  }

  /**
   * Calculates Post-Quantum Readiness Percentage (0% - 100%)
   */
  public static calculateReadiness(qvi: number): number {
    return Math.max(0, 100 - qvi);
  }

  /**
   * Generates comprehensive scan summary
   */
  public static generateSummary(
    targetDir: string,
    totalFiles: number,
    findings: CryptoFinding[],
    durationMs: number
  ): ScanSummary {
    const bySeverity: Record<Severity, number> = {
      critical: 0,
      high: 0,
      medium: 0,
      low: 0,
      info: 0,
    };

    const byCategory: Record<CryptoCategory, number> = {
      'asymmetric-kem': 0,
      'digital-signature': 0,
      'symmetric-crypto': 0,
      'hash-function': 0,
      'hardcoded-secret': 0,
      'legacy-provider': 0,
    };

    const byLanguage: Record<Language, number> = {
      python: 0,
      javascript: 0,
      typescript: 0,
      go: 0,
      java: 0,
    };

    const criticalDeprecationsSet = new Set<string>();
    let cnsaViolationsCount = 0;

    for (const f of findings) {
      bySeverity[f.severity]++;
      byCategory[f.category]++;
      byLanguage[f.language]++;

      if (f.severity === 'critical' || f.severity === 'high') {
        criticalDeprecationsSet.add(`${f.algorithm} (${f.remediation.nistStandard} replacement: ${f.remediation.replacement})`);
      }

      if (!f.cnsa.compliant) {
        cnsaViolationsCount++;
      }
    }

    const qvi = this.calculateQVI(findings);
    const postQuantumReadiness = this.calculateReadiness(qvi);

    return {
      targetDir,
      totalFilesScanned: totalFiles,
      totalCryptoAssets: findings.length,
      findingsCount: findings.length,
      bySeverity,
      byCategory,
      byLanguage,
      quantumVulnerabilityIndex: qvi,
      postQuantumReadiness,
      cnsaCompliant: cnsaViolationsCount === 0,
      cnsaViolationsCount,
      criticalDeprecations: Array.from(criticalDeprecationsSet),
      scanDurationMs: durationMs,
      timestamp: new Date().toISOString(),
    };
  }
}

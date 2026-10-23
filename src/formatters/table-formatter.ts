import pc from 'picocolors';
import { ScanResult, CryptoFinding, Severity, CryptoCategory } from '../types/index.js';

function colorSeverity(sev: Severity): string {
  switch (sev) {
    case 'critical':
      return pc.bgRed(pc.white(pc.bold(' CRITICAL ')));
    case 'high':
      return pc.red(pc.bold(' HIGH '));
    case 'medium':
      return pc.yellow(pc.bold(' MEDIUM '));
    case 'low':
      return pc.cyan(' LOW ');
    default:
      return pc.gray(' INFO ');
  }
}

function categoryHeading(category: CryptoCategory): string {
  switch (category) {
    case 'asymmetric-kem':
      return pc.magenta(pc.bold('▼ ASYMMETRIC KEY EXCHANGE / KEM (FIPS 203 ML-KEM Candidates)'));
    case 'digital-signature':
      return pc.cyan(pc.bold('▼ DIGITAL SIGNATURES (FIPS 204 ML-DSA / FIPS 205 SLH-DSA Candidates)'));
    case 'symmetric-crypto':
      return pc.yellow(pc.bold('▼ SYMMETRIC CIPHERS (Grover’s Algorithm & AES-128 Longevity Risk)'));
    case 'hash-function':
      return pc.blue(pc.bold('▼ HASH FUNCTIONS (CNSA 2.0 & Grover/BHT Sub-Threshold Checks)'));
    case 'hardcoded-secret':
      return pc.red(pc.bold('▼ HARDCODED CRYPTOGRAPHIC SECRETS & PEM BLOCKS (Critical Exposure)'));
    case 'legacy-provider':
      return pc.red(pc.bold('▼ LEGACY CRYPTO PROVIDERS & BROKEN CIPHERS (Immediate Deprecation)'));
  }
}

export class TableFormatter {
  public static render(result: ScanResult): string {
    const { summary, findings } = result;
    const output: string[] = [];

    // Header Banner
    output.push('');
    output.push(pc.bold(pc.cyan('╔════════════════════════════════════════════════════════════════════════════╗')));
    output.push(pc.bold(pc.cyan('║')) + pc.bold(pc.white('   QUANTASCAN: Post-Quantum Cryptography (PQC) Static Analysis CLI   ')) + pc.bold(pc.cyan('║')));
    output.push(pc.bold(pc.cyan('║')) + pc.gray('   NIST FIPS 203 ML-KEM | FIPS 204 ML-DSA | FIPS 205 SLH-DSA | CNSA 2.0      ') + pc.bold(pc.cyan('║')));
    output.push(pc.bold(pc.cyan('╚════════════════════════════════════════════════════════════════════════════╝')));
    output.push('');

    // Summary Scorecard
    const readinessColor =
      summary.postQuantumReadiness >= 80
        ? pc.green
        : summary.postQuantumReadiness >= 50
        ? pc.yellow
        : pc.red;

    const qviColor =
      summary.quantumVulnerabilityIndex <= 25
        ? pc.green
        : summary.quantumVulnerabilityIndex <= 60
        ? pc.yellow
        : pc.red;

    output.push(pc.bold(pc.underline('SCAN EXECUTIVE SUMMARY:')));
    output.push(
      `  Files Scanned:            ${pc.bold(summary.totalFilesScanned.toString())} files in ${summary.scanDurationMs}ms`
    );
    output.push(
      `  Total Crypto Assets:      ${pc.bold(summary.totalCryptoAssets.toString())} assets identified`
    );
    output.push(
      `  Quantum Vulnerability (QVI): ${qviColor(pc.bold(`${summary.quantumVulnerabilityIndex} / 100`))} ${pc.gray('(0 = safe, 100 = broken)')}`
    );
    output.push(
      `  Post-Quantum Readiness:   ${readinessColor(pc.bold(`${summary.postQuantumReadiness}%`))}`
    );
    output.push(
      `  CNSA 2.0 Status:          ${
        summary.cnsaCompliant
          ? pc.green(pc.bold('✔ COMPLIANT'))
          : pc.red(pc.bold(`✖ NON-COMPLIANT (${summary.cnsaViolationsCount} violations)`))
      }`
    );
    output.push(
      `  Severity Breakdown:       ${pc.red(`Critical: ${summary.bySeverity.critical}`)} | ${pc.magenta(`High: ${summary.bySeverity.high}`)} | ${pc.yellow(`Medium: ${summary.bySeverity.medium}`)} | ${pc.cyan(`Low: ${summary.bySeverity.low}`)}`
    );
    output.push('');

    if (findings.length === 0) {
      output.push(
        pc.green(pc.bold('✔ ZERO legacy or quantum-vulnerable cryptographic primitives detected!'))
      );
      output.push(
        pc.green('  All scanned code conforms to Post-Quantum Cryptography standards.')
      );
      output.push('');
      return output.join('\n');
    }

    // Group findings by category
    const categories: CryptoCategory[] = [
      'asymmetric-kem',
      'digital-signature',
      'symmetric-crypto',
      'hash-function',
      'hardcoded-secret',
      'legacy-provider',
    ];

    for (const cat of categories) {
      const catFindings = findings.filter((f) => f.category === cat);
      if (catFindings.length === 0) continue;

      output.push(categoryHeading(cat));
      output.push(pc.gray('─'.repeat(78)));

      for (const f of catFindings) {
        output.push(
          `  ${colorSeverity(f.severity)} ${pc.bold(pc.white(f.title))} [${pc.gray(f.language)}]`
        );
        output.push(
          `    ${pc.gray('Location:')} ${pc.underline(`${f.file}:${f.location.startLine}:${f.location.startColumn}`)}`
        );
        output.push(
          `    ${pc.gray('Algorithm:')} ${pc.bold(f.algorithm)} ${f.curve ? `(${f.curve})` : ''} ${f.parameterSet ? `[${f.parameterSet}]` : ''}`
        );
        output.push(
          `    ${pc.gray('Code:')}      ${pc.italic(f.codeSnippet)}`
        );
        output.push(
          `    ${pc.green('➡ NIST Replacement:')} ${pc.bold(f.remediation.replacement)} (${f.remediation.nistStandard})`
        );
        output.push(
          `    ${pc.yellow('⚠ Remediation:')}      ${f.remediation.advisory}`
        );
        if (f.remediation.codeSnippet) {
          output.push(pc.gray('    Suggested Refactor:'));
          for (const sLine of f.remediation.codeSnippet.split('\n')) {
            output.push(pc.gray(`      ${sLine}`));
          }
        }
        output.push('');
      }
    }

    // Critical Deprecations Section
    if (summary.criticalDeprecations.length > 0) {
      output.push(pc.bold(pc.red('CRITICAL DEPRECATIONS & IMMEDIATE ACTION ITEMS:')));
      for (const item of summary.criticalDeprecations) {
        output.push(`  ${pc.red('✖')} ${item}`);
      }
      output.push('');
    }

    return output.join('\n');
  }
}

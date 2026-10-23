import crypto from 'crypto';
import { CycloneDXCBOM, CBOMComponent, CBOMVulnerability } from '../types/cyclonedx.js';
import { ScanResult, CryptoFinding } from '../types/index.js';

export class CBOMGenerator {
  public static generate(result: ScanResult): CycloneDXCBOM {
    const { summary, findings } = result;

    const serialUuid = crypto.randomUUID();
    const serialNumber = `urn:uuid:${serialUuid}`;
    const timestamp = summary.timestamp;

    const components: CBOMComponent[] = [];
    const vulnerabilities: CBOMVulnerability[] = [];

    // Map each finding to a CycloneDX 1.6 cryptographic component
    findings.forEach((f, idx) => {
      const bomRef = `crypto-asset-${idx + 1}-${f.ruleId}`;
      const vulnRef = `quantum-vuln-${idx + 1}-${f.ruleId}`;

      const cryptoFunctions: Array<
        'key-agree' | 'sign' | 'verify' | 'encrypt' | 'decrypt' | 'digest' | 'generate' | 'derive'
      > = [];

      if (f.primitive === 'key-exchange' || f.primitive === 'kem') {
        cryptoFunctions.push('key-agree', 'generate');
      } else if (f.primitive === 'signature') {
        if (f.context === 'signature-verify') cryptoFunctions.push('verify');
        else cryptoFunctions.push('sign');
      } else if (f.primitive === 'block-cipher' || f.primitive === 'pke') {
        cryptoFunctions.push('encrypt', 'decrypt');
      } else if (f.primitive === 'hash') {
        cryptoFunctions.push('digest');
      }

      const component: CBOMComponent = {
        type: 'cryptographic-asset',
        'bom-ref': bomRef,
        name: f.algorithm,
        description: f.title,
        cryptoProperties: {
          assetType: f.assetType,
          algorithmProperties: {
            primitive: f.primitive === 'pke' ? 'kem' : (f.primitive as any),
            parameterSetIdentifier: f.parameterSet || (f.keyLength ? `${f.keyLength}-bit` : undefined),
            curve: f.curve,
            executionEnvironment: 'software-plain',
            implementationPlatform: 'generic',
            certificationLevel: f.cnsa.compliant ? 'cnsa-2.0' : 'none',
            cryptoFunctions,
            classicalSecurityLevel: f.classicalSecurityLevel,
            nistQuantumSecurityLevel: f.nistQuantumSecurityLevel,
          },
        },
        evidence: {
          occurrences: [
            {
              location: f.file,
              line: f.location.startLine,
              offset: f.location.startColumn,
              symbol: f.algorithm,
              additionalContext: f.codeSnippet,
            },
          ],
        },
        properties: [
          { name: 'pqc:replacement', value: f.remediation.replacement },
          { name: 'pqc:nistStandard', value: f.remediation.nistStandard },
          { name: 'pqc:cnsaCompliant', value: String(f.cnsa.compliant) },
          { name: 'pqc:category', value: f.category },
        ],
      };

      components.push(component);

      // Create linked vulnerability entry for quantum risk
      const vuln: CBOMVulnerability = {
        'bom-ref': vulnRef,
        id: `PQC-VULN-${f.ruleId.toUpperCase()}`,
        source: {
          name: 'NIST Post-Quantum Cryptography & CNSA 2.0 Advisory',
          url: 'https://csrc.nist.gov/projects/post-quantum-cryptography',
        },
        description: f.title,
        detail: `${f.description}\n\nRecommended NIST Replacement: ${f.remediation.replacement} (${f.remediation.nistStandard}).\nAdvisory: ${f.remediation.advisory}`,
        recommendation: `Migrate to ${f.remediation.replacement}. ${f.remediation.advisory}`,
        ratings: [
          {
            source: { name: 'QuantaScan QVI Engine' },
            severity: f.severity,
            score: f.severity === 'critical' ? 9.8 : f.severity === 'high' ? 7.5 : f.severity === 'medium' ? 5.3 : 2.5,
            method: 'CVSSv31',
          },
        ],
        affects: [
          {
            ref: bomRef,
          },
        ],
      };

      vulnerabilities.push(vuln);
    });

    const cbom: CycloneDXCBOM = {
      bomFormat: 'CycloneDX',
      specVersion: '1.6',
      serialNumber,
      version: 1,
      metadata: {
        timestamp,
        tools: {
          components: [
            {
              type: 'application',
              author: 'QuantaScan Engineering',
              name: 'quantascan',
              version: '1.0.0',
              description: 'Automated Post-Quantum Cryptography Static Analysis & CycloneDX v1.6 CBOM Generator',
            },
          ],
        },
        component: {
          type: 'application',
          name: summary.targetDir.split('/').pop() || 'target-project',
        },
        properties: [
          { name: 'pqc:qvi', value: String(summary.quantumVulnerabilityIndex) },
          { name: 'pqc:readinessScore', value: `${summary.postQuantumReadiness}%` },
          { name: 'pqc:cnsaCompliant', value: String(summary.cnsaCompliant) },
        ],
      },
      components,
      vulnerabilities,
    };

    return cbom;
  }
}

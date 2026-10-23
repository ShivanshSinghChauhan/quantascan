import { CryptoFinding } from '../types/index.js';

export interface CnsaTimelineRule {
  domain: string;
  preferenceYear: number;
  mandatoryYear: number;
  approvedAlgorithms: string[];
}

export const CNSA_2_0_TIMELINES: CnsaTimelineRule[] = [
  {
    domain: 'Software & Firmware Signing',
    preferenceYear: 2025,
    mandatoryYear: 2030,
    approvedAlgorithms: ['ML-DSA-87', 'SLH-DSA-SHAKE-256s', 'LMS', 'XMSS'],
  },
  {
    domain: 'Web Browsers, Servers & Cloud Services',
    preferenceYear: 2025,
    mandatoryYear: 2033,
    approvedAlgorithms: ['ML-KEM-1024', 'ML-DSA-87'],
  },
  {
    domain: 'Traditional Networking Equipment (Routers, Switches, VPNs)',
    preferenceYear: 2026,
    mandatoryYear: 2030,
    approvedAlgorithms: ['ML-KEM-1024', 'ML-DSA-87'],
  },
  {
    domain: 'Custom Systems & Legacy Hardware Equipment',
    preferenceYear: 2030,
    mandatoryYear: 2033,
    approvedAlgorithms: ['ML-KEM-1024', 'ML-DSA-87', 'AES-256', 'SHA-384', 'SHA-512'],
  },
];

export class CnsaEvaluator {
  /**
   * Applies CNSA 2.0 strict mode adjustments:
   * Upgrades SHA-256 and AES-128 finding severities to High/Critical
   * because CNSA 2.0 completely outlaws AES-128 and SHA-256 for National Security Systems.
   */
  public static applyCnsaMode(findings: CryptoFinding[]): CryptoFinding[] {
    return findings.map((finding) => {
      const copy = { ...finding };

      if (copy.category === 'hash-function' && copy.algorithm.includes('256')) {
        copy.severity = 'high';
        copy.title = `[CNSA 2.0 VIOLATION] ${copy.title}`;
        copy.description = `CNSA 2.0 strictly bans SHA-256. All message digests must use SHA-384 or SHA-512. Current usage creates a compliance failure under NSA advisory.`;
        copy.cnsa = {
          compliant: false,
          requirement: 'CNSA 2.0 mandates SHA-384 or SHA-512',
          deadline: 'Mandatory by 2025/2030',
        };
      } else if (copy.category === 'symmetric-crypto' && (copy.algorithm.includes('128') || copy.keyLength === 128)) {
        copy.severity = 'critical';
        copy.title = `[CNSA 2.0 VIOLATION] ${copy.title}`;
        copy.description = `CNSA 2.0 strictly prohibits AES-128. Symmetric encryption must use AES-256 exclusively to guarantee minimum 128-bit quantum security against Grover search.`;
        copy.cnsa = {
          compliant: false,
          requirement: 'CNSA 2.0 mandates AES-256 (AES-128 not approved)',
          deadline: 'Mandatory by 2025/2030',
        };
      }

      return copy;
    });
  }
}

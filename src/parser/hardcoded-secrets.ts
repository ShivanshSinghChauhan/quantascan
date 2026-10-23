import { CryptoFinding, LocationRange } from '../types/index.js';

interface SecretPattern {
  name: string;
  regex: RegExp;
  category: 'hardcoded-secret' | 'legacy-provider';
  primitive: 'key-exchange' | 'signature' | 'pke' | 'block-cipher' | 'hash';
  algorithm: string;
  severity: 'critical' | 'high' | 'medium';
  title: string;
  description: string;
  replacement: string;
  nistStandard: 'FIPS 203' | 'FIPS 204' | 'FIPS 205' | 'CNSA 2.0' | 'NIST General';
  advisory: string;
}

const SECRET_PATTERNS: SecretPattern[] = [
  {
    name: 'Hardcoded RSA Private Key (PKCS#1)',
    regex: /-----BEGIN RSA PRIVATE KEY-----[\s\S]*?-----END RSA PRIVATE KEY-----/g,
    category: 'hardcoded-secret',
    primitive: 'signature',
    algorithm: 'RSA Private Key (PEM)',
    severity: 'critical',
    title: 'Hardcoded Pre-Quantum RSA Private Key Detected',
    description:
      'Hardcoded RSA private key found in source code. Classical asymmetric private keys are vulnerable to full key recovery via Shor’s algorithm on cryptanalytically relevant quantum computers (CRQC), and hardcoding credentials violates secret hygiene.',
    replacement: 'ML-DSA-65 or ML-DSA-87 Private Key in HSM/Vault',
    nistStandard: 'FIPS 204',
    advisory:
      'Immediately remove hardcoded private keys from source code. Rotate to a post-quantum digital signature algorithm (FIPS 204 ML-DSA-65 / ML-DSA-87) managed through a secure KMS or HSM.',
  },
  {
    name: 'Hardcoded EC Private Key (SEC1)',
    regex: /-----BEGIN EC PRIVATE KEY-----[\s\S]*?-----END EC PRIVATE KEY-----/g,
    category: 'hardcoded-secret',
    primitive: 'key-exchange',
    algorithm: 'Elliptic Curve Private Key (PEM)',
    severity: 'critical',
    title: 'Hardcoded Pre-Quantum Elliptic Curve Private Key Detected',
    description:
      'Hardcoded Elliptic Curve (ECC) private key found. All standard curves (NIST P-curves, secp256k1, Curve25519) are susceptible to Shor’s discrete logarithm algorithm.',
    replacement: 'FIPS 203 ML-KEM-768 or FIPS 204 ML-DSA-65',
    nistStandard: 'FIPS 203',
    advisory:
      'Remove embedded private key. For key establishment, transition to FIPS 203 ML-KEM-768 or hybrid X25519+ML-KEM-768. For signatures, transition to FIPS 204 ML-DSA.',
  },
  {
    name: 'Hardcoded PKCS#8 Private Key',
    regex: /-----BEGIN (?:ENCRYPTED )?PRIVATE KEY-----[\s\S]*?-----END (?:ENCRYPTED )?PRIVATE KEY-----/g,
    category: 'hardcoded-secret',
    primitive: 'key-exchange',
    algorithm: 'PKCS#8 Private Key (PEM)',
    severity: 'critical',
    title: 'Hardcoded PKCS#8 Private Key Detected',
    description:
      'Source file embeds a raw PKCS#8 private key structure. In addition to hardcoded credential leakage, classical asymmetric keys must be migrated to quantum-resistant primitives.',
    replacement: 'FIPS 203 ML-KEM or FIPS 204 ML-DSA via Secrets Manager',
    nistStandard: 'FIPS 203',
    advisory:
      'Extract private keys to environment variables or secret vaults (AWS Secrets Manager, HashiCorp Vault, GCP Secret Manager). Prepare architecture for larger PQC key sizes (e.g. ML-KEM-768 public key: 1184 bytes, private key: 2400 bytes).',
  },
  {
    name: 'Hardcoded X.509 Certificate',
    regex: /-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----/g,
    category: 'hardcoded-secret',
    primitive: 'signature',
    algorithm: 'X.509 Certificate (PEM)',
    severity: 'medium',
    title: 'Hardcoded Classical X.509 Certificate',
    description:
      'Hardcoded X.509 certificate detected. Classical public key certificates relying on RSA/ECDSA signatures will fail post-quantum trust chain verification once quantum adversaries can forge signatures.',
    replacement: 'Hybrid or PQC X.509 Certificate (FIPS 204 ML-DSA)',
    nistStandard: 'FIPS 204',
    advisory:
      'Plan migration to Composite / Hybrid Certificates (IETF draft-ietf-lamps-cert-binding-for-multi-auth) or native ML-DSA certificates according to CNSA 2.0 / NIST timelines.',
  },
  {
    name: 'Hardcoded PGP/OpenPGP Private Key',
    regex: /-----BEGIN PGP PRIVATE KEY BLOCK-----[\s\S]*?-----END PGP PRIVATE KEY BLOCK-----/g,
    category: 'hardcoded-secret',
    primitive: 'pke',
    algorithm: 'PGP/GPG Private Key Block',
    severity: 'critical',
    title: 'Hardcoded OpenPGP Classical Private Key',
    description:
      'Hardcoded OpenPGP private key block. Pre-quantum OpenPGP keys (RSA, ElGamal, Ed25519) are vulnerable to decryption ("Harvest Now, Decrypt Later") and signature forgery.',
    replacement: 'Post-Quantum OpenPGP (IETF draft-ietf-openpgp-pqc: ML-KEM + ML-DSA)',
    nistStandard: 'FIPS 203',
    advisory:
      'Adopt modern PQC OpenPGP drafts implementing ML-KEM for encryption subkeys and ML-DSA / SLH-DSA for primary signing keys.',
  },
  {
    name: 'Deprecated PyCrypto Library Import',
    regex: /(?:from\s+Crypto\.(?:Cipher|PublicKey|Signature|Hash)\s+import|import\s+Crypto\b)/g,
    category: 'legacy-provider',
    primitive: 'block-cipher',
    algorithm: 'PyCrypto (Deprecated)',
    severity: 'high',
    title: 'Deprecated PyCrypto Provider Detected',
    description:
      'The PyCrypto library has been unmaintained since 2013 and contains multiple unpatched CVEs in addition to lacking post-quantum cryptographic primitives.',
    replacement: 'pycryptodome >= 3.20.0 or standard cryptography >= 42.0.0 with PQC/liboqs',
    nistStandard: 'NIST General',
    advisory:
      'Replace pycrypto with pycryptodome or python-cryptography, and integrate PQClean/liboqs-python bindings for ML-KEM and ML-DSA support.',
  },
  {
    name: 'Deprecated Node crypto.createCipher',
    regex: /\bcrypto\s*\.\s*createCipher\s*\(/g,
    category: 'legacy-provider',
    primitive: 'block-cipher',
    algorithm: 'crypto.createCipher (Insecure KDF)',
    severity: 'high',
    title: 'Deprecated Node.js crypto.createCipher() Usage',
    description:
      'crypto.createCipher() uses an insecure, unstandardized MD5-based key derivation function and has no IV, making it vulnerable to classical attacks and providing 0 post-quantum protection.',
    replacement: 'crypto.createCipheriv("aes-256-gcm", key, iv)',
    nistStandard: 'CNSA 2.0',
    advisory:
      'Migrate to crypto.createCipheriv with AES-256-GCM. AES-256 retains 128-bit security against Grover quantum search, whereas MD5 and weak KDFs are broken.',
  },
  {
    name: 'Legacy DES / 3DES Cipher Reference',
    regex: /["'](?:DES|DES-EDE|DES-EDE3|DES3|3DES|Blowfish|RC4|ARCFOUR|CAST5)["']/gi,
    category: 'legacy-provider',
    primitive: 'block-cipher',
    algorithm: 'Legacy Broken Cipher (DES/3DES/RC4/Blowfish)',
    severity: 'critical',
    title: 'Legacy Broken Cipher In Use',
    description:
      '64-bit block ciphers (DES, 3DES, Blowfish) and stream ciphers (RC4) are fundamentally broken classically (Sweet32 attack, biassed keystreams) and collapse completely in quantum environments.',
    replacement: 'AES-256-GCM (NIST SP 800-38D / CNSA 2.0)',
    nistStandard: 'CNSA 2.0',
    advisory:
      'Immediately deprecate legacy ciphers. Standardize on AES-256 in GCM or ChaCha20-Poly1305 authenticated modes.',
  },
  {
    name: 'Legacy MD5 / SHA-1 Hash Reference',
    regex: /["'](?:MD5|MD4|SHA-?1|RIPEMD-?160)["']/gi,
    category: 'legacy-provider',
    primitive: 'hash',
    algorithm: 'Collision-Broken Hash (MD5 / SHA-1)',
    severity: 'high',
    title: 'Legacy Cryptographically Broken Hash Algorithm',
    description:
      'MD5 and SHA-1 have practical classical collision attacks (SHAttered, Flame) and provide trivial security margins against quantum BHT collision search.',
    replacement: 'SHA-384 or SHA-512 (FIPS 180-4 / CNSA 2.0)',
    nistStandard: 'CNSA 2.0',
    advisory:
      'Replace with SHA-384 or SHA-512. For CNSA 2.0 compliance, SHA-256 is not approved for national security systems.',
  },
];

export function scanHardcodedSecretsAndProviders(
  content: string,
  filePath: string
): CryptoFinding[] {
  const findings: CryptoFinding[] = [];
  const lines = content.split('\n');

  // Compute character offset to line/column index
  const lineOffsets: number[] = [0];
  for (let i = 0; i < lines.length; i++) {
    lineOffsets.push(lineOffsets[i] + lines[i].length + 1);
  }

  function getLineCol(index: number): { line: number; column: number } {
    let low = 0;
    let high = lineOffsets.length - 1;
    while (low <= high) {
      const mid = Math.floor((low + high) / 2);
      if (lineOffsets[mid] <= index) {
        if (mid === lineOffsets.length - 1 || lineOffsets[mid + 1] > index) {
          return {
            line: mid + 1,
            column: index - lineOffsets[mid] + 1,
          };
        }
        low = mid + 1;
      } else {
        high = mid - 1;
      }
    }
    return { line: 1, column: 1 };
  }

  for (const pattern of SECRET_PATTERNS) {
    // Reset regex state
    pattern.regex.lastIndex = 0;
    let match: RegExpExecArray | null;
    while ((match = pattern.regex.exec(content)) !== null) {
      const startIndex = match.index;
      const endIndex = startIndex + match[0].length;
      const startLoc = getLineCol(startIndex);
      const endLoc = getLineCol(endIndex);

      const snippetLine = lines[startLoc.line - 1] || '';
      const displaySnippet =
        match[0].length > 100
          ? `${match[0].slice(0, 70)}...[TRUNCATED ${match[0].length} bytes]...${match[0].slice(-25)}`
          : snippetLine.trim();

      const findingId = `SECRET-${Buffer.from(`${filePath}:${startLoc.line}:${pattern.algorithm}`).toString('base64url').slice(0, 16)}`;

      findings.push({
        id: findingId,
        ruleId: `hardcoded-${pattern.category}-${pattern.algorithm.toLowerCase().replace(/[^a-z0-9]+/g, '-')}`,
        file: filePath,
        location: {
          startLine: startLoc.line,
          startColumn: startLoc.column,
          endLine: endLoc.line,
          endColumn: endLoc.column,
        },
        language: 'python', // generic or detected
        category: pattern.category,
        assetType: pattern.category === 'hardcoded-secret' ? 'key' : 'algorithm',
        algorithm: pattern.algorithm,
        primitive: pattern.primitive,
        context: pattern.category === 'hardcoded-secret' ? 'key-exchange' : 'data-at-rest',
        severity: pattern.severity,
        classicalSecurityLevel: pattern.algorithm.includes('DES') ? 56 : 112,
        nistQuantumSecurityLevel: 0,
        title: pattern.title,
        description: pattern.description,
        codeSnippet: displaySnippet,
        remediation: {
          nistStandard: pattern.nistStandard,
          replacement: pattern.replacement,
          advisory: pattern.advisory,
        },
        cnsa: {
          compliant: false,
          requirement: 'CNSA 2.0 strictly bans hardcoded credentials and legacy algorithms',
          deadline: 'Immediate (2025/2030)',
        },
      });

      // Avoid infinite loop on zero-width match
      if (match.index === pattern.regex.lastIndex) {
        pattern.regex.lastIndex++;
      }
    }
  }

  return findings;
}

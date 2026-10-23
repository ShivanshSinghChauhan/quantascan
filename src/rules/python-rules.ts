import Parser from 'web-tree-sitter';
import { Rule, ASTContext } from './registry.js';
import { CryptoFinding, LocationRange } from '../types/index.js';
import { MIGRATION_GUIDES } from '../advisories/migration-guides.js';

function createRange(node: Parser.SyntaxNode): LocationRange {
  return {
    startLine: node.startPosition.row + 1,
    startColumn: node.startPosition.column + 1,
    endLine: node.endPosition.row + 1,
    endColumn: node.endPosition.column + 1,
  };
}

function getNodeSnippet(node: Parser.SyntaxNode, lines: string[]): string {
  const line = lines[node.startPosition.row];
  return line ? line.trim() : node.text;
}

export const pythonRules: Rule[] = [
  // 1. Python RSA Generation
  {
    id: 'py-rsa-generate',
    languages: ['python'],
    name: 'Python RSA Key Generation',
    category: 'asymmetric-kem',
    primitive: 'key-exchange',
    defaultSeverity: 'critical',
    check(node: Parser.SyntaxNode, ctx: ASTContext): CryptoFinding | null {
      if (node.type !== 'call') return null;
      const funcText = node.child(0)?.text || '';

      if (
        funcText.endsWith('generate_private_key') ||
        funcText.endsWith('RSA.generate') ||
        funcText === 'RSA.generate'
      ) {
        const fullCallText = node.text;
        if (!fullCallText.includes('rsa') && !fullCallText.includes('RSA')) {
          return null;
        }

        let keySize = 2048;
        const match = fullCallText.match(/key_size\s*=\s*(\d+)/) || fullCallText.match(/RSA\.generate\s*\(\s*(\d+)/);
        if (match) {
          keySize = parseInt(match[1], 10);
        }

        const guide = MIGRATION_GUIDES['rsa-key-exchange'];
        const loc = createRange(node);
        return {
          id: `PY-RSA-${ctx.filePath}:${loc.startLine}`,
          ruleId: 'py-rsa-generate',
          file: ctx.filePath,
          location: loc,
          language: 'python',
          category: 'asymmetric-kem',
          assetType: 'algorithm',
          algorithm: `RSA-${keySize}`,
          primitive: 'key-exchange',
          parameterSet: `${keySize}-bit`,
          keyLength: keySize,
          context: 'key-exchange',
          severity: 'critical',
          classicalSecurityLevel: keySize >= 2048 ? 112 : 80,
          nistQuantumSecurityLevel: 0,
          title: `Classical RSA-${keySize} Key Generation (Vulnerable to Shor's Algorithm)`,
          description: `RSA-${keySize} relies on integer factorization hardness. Shor’s algorithm on a quantum computer factors RSA keys in polynomial time, completely destroying security.`,
          codeSnippet: getNodeSnippet(node, ctx.lines),
          remediation: {
            nistStandard: guide.nistStandard,
            replacement: guide.replacement,
            advisory: guide.advisory,
            codeSnippet: guide.snippets.python,
          },
          cnsa: guide.cnsa,
        };
      }
      return null;
    },
  },

  // 2. Python ECC / ECDH / ECDSA Generation
  {
    id: 'py-ec-generate',
    languages: ['python'],
    name: 'Python Elliptic Curve Key Generation',
    category: 'asymmetric-kem',
    primitive: 'key-exchange',
    defaultSeverity: 'critical',
    check(node: Parser.SyntaxNode, ctx: ASTContext): CryptoFinding | null {
      if (node.type !== 'call') return null;
      const funcText = node.child(0)?.text || '';
      const fullCallText = node.text;

      const isEcGenerate =
        (funcText.endsWith('generate_private_key') && (fullCallText.includes('ec.') || fullCallText.includes('curve'))) ||
        funcText.endsWith('ECC.generate') ||
        funcText.endsWith('X25519PrivateKey.generate') ||
        funcText.endsWith('Ed25519PrivateKey.generate');

      if (!isEcGenerate) return null;

      let curve = 'P-256 (secp256r1)';
      if (fullCallText.includes('SECP384R1') || fullCallText.includes('P-384')) curve = 'secp384r1';
      else if (fullCallText.includes('SECP521R1') || fullCallText.includes('P-521')) curve = 'secp521r1';
      else if (fullCallText.includes('SECP256K1') || fullCallText.includes('secp256k1')) curve = 'secp256k1';
      else if (fullCallText.includes('X25519') || fullCallText.includes('x25519')) curve = 'X25519';
      else if (fullCallText.includes('Ed25519') || fullCallText.includes('ed25519')) curve = 'Ed25519';

      const isSignature = curve === 'Ed25519' || fullCallText.includes('ecdsa') || fullCallText.includes('ECDSA');
      const category = isSignature ? 'digital-signature' : 'asymmetric-kem';
      const primitive = isSignature ? 'signature' : 'key-exchange';
      const guideKey = isSignature ? 'classical-signature-ecdsa' : 'ecdh-key-exchange';
      const guide = MIGRATION_GUIDES[guideKey];

      const loc = createRange(node);
      return {
        id: `PY-EC-${ctx.filePath}:${loc.startLine}`,
        ruleId: 'py-ec-generate',
        file: ctx.filePath,
        location: loc,
        language: 'python',
        category,
        assetType: 'algorithm',
        algorithm: `ECDH/ECDSA (${curve})`,
        primitive,
        curve,
        context: isSignature ? 'signature-sign' : 'key-exchange',
        severity: 'critical',
        classicalSecurityLevel: 128,
        nistQuantumSecurityLevel: 0,
        title: `Pre-Quantum Elliptic Curve (${curve}) Vulnerable to Shor’s Algorithm`,
        description: `Elliptic curve cryptography over ${curve} is vulnerable to discrete logarithm resolution via Shor's algorithm. All encrypted traffic is exposed to "Harvest Now, Decrypt Later".`,
        codeSnippet: getNodeSnippet(node, ctx.lines),
        remediation: {
          nistStandard: guide.nistStandard,
          replacement: guide.replacement,
          advisory: guide.advisory,
          codeSnippet: guide.snippets.python,
        },
        cnsa: guide.cnsa,
      };
    },
  },

  // 3. Python ECDH Key Agreement Call
  {
    id: 'py-ecdh-exchange',
    languages: ['python'],
    name: 'Python ECDH Key Agreement',
    category: 'asymmetric-kem',
    primitive: 'key-exchange',
    defaultSeverity: 'critical',
    check(node: Parser.SyntaxNode, ctx: ASTContext): CryptoFinding | null {
      if (node.type !== 'call') return null;
      const text = node.text;

      if (text.includes('ec.ECDH()') || (text.includes('.exchange(') && text.includes('ec.'))) {
        const guide = MIGRATION_GUIDES['ecdh-key-exchange'];
        const loc = createRange(node);
        return {
          id: `PY-ECDH-AGREE-${ctx.filePath}:${loc.startLine}`,
          ruleId: 'py-ecdh-exchange',
          file: ctx.filePath,
          location: loc,
          language: 'python',
          category: 'asymmetric-kem',
          assetType: 'algorithm',
          algorithm: 'ECDH Key Agreement',
          primitive: 'key-exchange',
          context: 'key-exchange',
          severity: 'critical',
          classicalSecurityLevel: 128,
          nistQuantumSecurityLevel: 0,
          title: 'ECDH Key Exchange Vulnerable to Harvest Now, Decrypt Later',
          description: 'Active ECDH key exchange call creates ephemeral symmetric session keys using pre-quantum elliptic curves.',
          codeSnippet: getNodeSnippet(node, ctx.lines),
          remediation: {
            nistStandard: 'FIPS 203',
            replacement: 'FIPS 203 ML-KEM-768 or Hybrid X25519+ML-KEM-768',
            advisory: guide.advisory,
            codeSnippet: guide.snippets.python,
          },
          cnsa: guide.cnsa,
        };
      }
      return null;
    },
  },

  // 4. Python AES-128 Grover Check
  {
    id: 'py-aes-128-grover',
    languages: ['python'],
    name: 'Python AES-128 Grover Key Longevity',
    category: 'symmetric-crypto',
    primitive: 'block-cipher',
    defaultSeverity: 'medium',
    check(node: Parser.SyntaxNode, ctx: ASTContext): CryptoFinding | null {
      if (node.type !== 'call') return null;
      const text = node.text;

      if (
        (text.includes('algorithms.AES') || text.includes('AES.new')) &&
        (text.includes('128') || text.includes('bit_length=128') || text.includes('len(key) == 16'))
      ) {
        const guide = MIGRATION_GUIDES['symmetric-aes-128'];
        const loc = createRange(node);
        return {
          id: `PY-AES128-${ctx.filePath}:${loc.startLine}`,
          ruleId: 'py-aes-128-grover',
          file: ctx.filePath,
          location: loc,
          language: 'python',
          category: 'symmetric-crypto',
          assetType: 'algorithm',
          algorithm: 'AES-128',
          primitive: 'block-cipher',
          parameterSet: '128-bit key',
          keyLength: 128,
          context: 'data-at-rest',
          severity: 'medium',
          classicalSecurityLevel: 128,
          nistQuantumSecurityLevel: 1,
          title: 'AES-128 Security Degradation from Grover’s Algorithm',
          description: 'AES with 128-bit key is reduced to 64 bits of security against Grover quantum search. Upgrade to AES-256 for 128-bit quantum security and CNSA 2.0 compliance.',
          codeSnippet: getNodeSnippet(node, ctx.lines),
          remediation: {
            nistStandard: 'CNSA 2.0',
            replacement: guide.replacement,
            advisory: guide.advisory,
            codeSnippet: guide.snippets.python,
          },
          cnsa: guide.cnsa,
        };
      }
      return null;
    },
  },

  // 5. Python SHA-256 CNSA 2.0 Check
  {
    id: 'py-sha256-cnsa',
    languages: ['python'],
    name: 'Python SHA-256 CNSA 2.0 Sub-Threshold',
    category: 'hash-function',
    primitive: 'hash',
    defaultSeverity: 'low',
    check(node: Parser.SyntaxNode, ctx: ASTContext): CryptoFinding | null {
      if (node.type !== 'call') return null;
      const text = node.text;

      if (text.includes('hashlib.sha256') || text.includes('hashes.SHA256()') || text.includes('SHA256.new()')) {
        const guide = MIGRATION_GUIDES['hash-sha256-cnsa'];
        const loc = createRange(node);
        return {
          id: `PY-SHA256-${ctx.filePath}:${loc.startLine}`,
          ruleId: 'py-sha256-cnsa',
          file: ctx.filePath,
          location: loc,
          language: 'python',
          category: 'hash-function',
          assetType: 'algorithm',
          algorithm: 'SHA-256',
          primitive: 'hash',
          parameterSet: '256-bit digest',
          context: 'digest',
          severity: 'low',
          classicalSecurityLevel: 128,
          nistQuantumSecurityLevel: 1,
          title: 'SHA-256 Sub-Threshold Hash (CNSA 2.0 Flag)',
          description: 'SHA-256 is acceptable for standard NIST workloads, but CNSA 2.0 mandates SHA-384 or SHA-512 for quantum-resistant message integrity.',
          codeSnippet: getNodeSnippet(node, ctx.lines),
          remediation: {
            nistStandard: 'CNSA 2.0',
            replacement: guide.replacement,
            advisory: guide.advisory,
            codeSnippet: guide.snippets.python,
          },
          cnsa: guide.cnsa,
        };
      }
      return null;
    },
  },
];

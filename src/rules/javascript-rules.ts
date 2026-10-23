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

export const javascriptRules: Rule[] = [
  // 1. JS/TS createECDH / createDiffieHellman
  {
    id: 'js-ecdh-create',
    languages: ['javascript', 'typescript'],
    name: 'Node.js ECDH / Diffie-Hellman Key Exchange',
    category: 'asymmetric-kem',
    primitive: 'key-exchange',
    defaultSeverity: 'critical',
    check(node: Parser.SyntaxNode, ctx: ASTContext): CryptoFinding | null {
      if (node.type !== 'call_expression') return null;
      const text = node.text;

      if (text.includes('createECDH') || text.includes('createDiffieHellman')) {
        let curve = 'secp256k1 / prime256v1';
        if (text.includes('prime256v1') || text.includes('secp256r1')) curve = 'secp256r1 (P-256)';
        else if (text.includes('secp256k1')) curve = 'secp256k1';

        const guide = MIGRATION_GUIDES['ecdh-key-exchange'];
        const loc = createRange(node);
        return {
          id: `JS-ECDH-${ctx.filePath}:${loc.startLine}`,
          ruleId: 'js-ecdh-create',
          file: ctx.filePath,
          location: loc,
          language: ctx.filePath.endsWith('.ts') || ctx.filePath.endsWith('.tsx') ? 'typescript' : 'javascript',
          category: 'asymmetric-kem',
          assetType: 'algorithm',
          algorithm: `ECDH (${curve})`,
          primitive: 'key-exchange',
          curve,
          context: 'key-exchange',
          severity: 'critical',
          classicalSecurityLevel: 128,
          nistQuantumSecurityLevel: 0,
          title: `Pre-Quantum ECDH (${curve}) Key Agreement`,
          description: 'Node.js crypto.createECDH produces shared secrets via classical curves vulnerable to Shor’s algorithm and Harvest Now Decrypt Later.',
          codeSnippet: getNodeSnippet(node, ctx.lines),
          remediation: {
            nistStandard: guide.nistStandard,
            replacement: guide.replacement,
            advisory: guide.advisory,
            codeSnippet: guide.snippets.typescript,
          },
          cnsa: guide.cnsa,
        };
      }
      return null;
    },
  },

  // 2. JS/TS RSA Key Generation & Encryption
  {
    id: 'js-rsa-generate',
    languages: ['javascript', 'typescript'],
    name: 'Node.js RSA Key Generation / Operations',
    category: 'asymmetric-kem',
    primitive: 'key-exchange',
    defaultSeverity: 'critical',
    check(node: Parser.SyntaxNode, ctx: ASTContext): CryptoFinding | null {
      if (node.type !== 'call_expression' && node.type !== 'new_expression') return null;
      const text = node.text;

      const isRsa =
        (text.includes('generateKeyPair') && text.includes("'rsa'")) ||
        (text.includes('generateKeyPair') && text.includes('"rsa"')) ||
        text.includes('NodeRSA') ||
        text.includes('publicEncrypt') ||
        text.includes('privateDecrypt');

      if (!isRsa) return null;

      let keySize = 2048;
      const modulusMatch = text.match(/modulusLength:\s*(\d+)/);
      if (modulusMatch) keySize = parseInt(modulusMatch[1], 10);

      const guide = MIGRATION_GUIDES['rsa-key-exchange'];
      const loc = createRange(node);
      return {
        id: `JS-RSA-${ctx.filePath}:${loc.startLine}`,
        ruleId: 'js-rsa-generate',
        file: ctx.filePath,
        location: loc,
        language: ctx.filePath.endsWith('.ts') || ctx.filePath.endsWith('.tsx') ? 'typescript' : 'javascript',
        category: 'asymmetric-kem',
        assetType: 'algorithm',
        algorithm: `RSA-${keySize}`,
        primitive: 'kem',
        parameterSet: `${keySize}-bit`,
        keyLength: keySize,
        context: text.includes('Encrypt') || text.includes('Decrypt') ? 'data-at-rest' : 'key-exchange',
        severity: 'critical',
        classicalSecurityLevel: keySize >= 2048 ? 112 : 80,
        nistQuantumSecurityLevel: 0,
        title: `Pre-Quantum RSA-${keySize} Cryptographic Primitive`,
        description: 'RSA primitives are susceptible to Shor’s polynomial-time factoring attack on quantum computers.',
        codeSnippet: getNodeSnippet(node, ctx.lines),
        remediation: {
          nistStandard: guide.nistStandard,
          replacement: guide.replacement,
          advisory: guide.advisory,
          codeSnippet: guide.snippets.typescript,
        },
        cnsa: guide.cnsa,
      };
    },
  },

  // 3. JS/TS Sign & Verify (RSA-SHA256, ECDSA, Ed25519)
  {
    id: 'js-signature-sign-verify',
    languages: ['javascript', 'typescript'],
    name: 'Node.js Signature Sign/Verify (RSA/ECDSA/Ed25519)',
    category: 'digital-signature',
    primitive: 'signature',
    defaultSeverity: 'critical',
    check(node: Parser.SyntaxNode, ctx: ASTContext): CryptoFinding | null {
      if (node.type !== 'call_expression') return null;
      const text = node.text;

      const isSignOrVerify =
        text.includes('createSign') ||
        text.includes('createVerify') ||
        (text.includes('crypto.sign') && !text.includes('crypto.signKey')) ||
        (text.includes('crypto.verify') && !text.includes('crypto.verifyKey')) ||
        text.includes('nacl.sign') ||
        text.includes('mldsa') === false && (text.includes('.sign(') && (text.includes('ec') || text.includes('rsa') || text.includes('noble')));

      if (!isSignOrVerify) return null;

      let algo = 'RSA / ECDSA / Ed25519 Signature';
      if (text.includes('RSA') || text.includes('rsa')) algo = 'RSA Signature (PKCS1/PSS)';
      else if (text.includes('ed25519') || text.includes('Ed25519')) algo = 'Ed25519 Signature';
      else if (text.includes('ecdsa') || text.includes('ECDSA') || text.includes('secp256k1') || text.includes('p256')) algo = 'ECDSA Signature';

      const isVerify = text.includes('Verify') || text.includes('verify');
      const guide = MIGRATION_GUIDES['classical-signature-rsa'];
      const loc = createRange(node);
      return {
        id: `JS-SIG-${ctx.filePath}:${loc.startLine}`,
        ruleId: 'js-signature-sign-verify',
        file: ctx.filePath,
        location: loc,
        language: ctx.filePath.endsWith('.ts') || ctx.filePath.endsWith('.tsx') ? 'typescript' : 'javascript',
        category: 'digital-signature',
        assetType: 'algorithm',
        algorithm: algo,
        primitive: 'signature',
        context: isVerify ? 'signature-verify' : 'signature-sign',
        severity: 'critical',
        classicalSecurityLevel: 128,
        nistQuantumSecurityLevel: 0,
        title: `Pre-Quantum Signature Scheme: ${algo}`,
        description: 'Classical digital signature schemes can be forged by a quantum attacker calculating the private signing key via Shor’s algorithm.',
        codeSnippet: getNodeSnippet(node, ctx.lines),
        remediation: {
          nistStandard: 'FIPS 204',
          replacement: 'ML-DSA-65 (FIPS 204) or SLH-DSA (FIPS 205)',
          advisory: guide.advisory,
          codeSnippet: guide.snippets.typescript,
        },
        cnsa: guide.cnsa,
      };
    },
  },

  // 4. JS/TS Third-party Elliptic / TweetNaCl / @noble/curves
  {
    id: 'js-ecc-libraries',
    languages: ['javascript', 'typescript'],
    name: 'Elliptic / TweetNaCl / Noble Curves Usage',
    category: 'asymmetric-kem',
    primitive: 'key-exchange',
    defaultSeverity: 'critical',
    check(node: Parser.SyntaxNode, ctx: ASTContext): CryptoFinding | null {
      if (node.type !== 'call_expression' && node.type !== 'new_expression') return null;
      const text = node.text;

      const isEcLib =
        (text.includes('elliptic.ec') || text.includes('new ec(')) ||
        text.includes('nacl.box') ||
        (text.includes('@noble/curves') && (text.includes('secp256k1') || text.includes('p256') || text.includes('ed25519')));

      if (!isEcLib) return null;

      const guide = MIGRATION_GUIDES['ecdh-key-exchange'];
      const loc = createRange(node);
      return {
        id: `JS-ECLIB-${ctx.filePath}:${loc.startLine}`,
        ruleId: 'js-ecc-libraries',
        file: ctx.filePath,
        location: loc,
        language: ctx.filePath.endsWith('.ts') || ctx.filePath.endsWith('.tsx') ? 'typescript' : 'javascript',
        category: 'asymmetric-kem',
        assetType: 'algorithm',
        algorithm: 'Elliptic Curve (secp256k1 / ed25519 / p256)',
        primitive: 'key-exchange',
        context: 'key-exchange',
        severity: 'critical',
        classicalSecurityLevel: 128,
        nistQuantumSecurityLevel: 0,
        title: 'Classical Elliptic Curve Library Invocation',
        description: 'Direct use of elliptic, tweetnacl, or legacy @noble/curves without post-quantum encapsulation exposes operations to Shor’s algorithm.',
        codeSnippet: getNodeSnippet(node, ctx.lines),
        remediation: {
          nistStandard: 'FIPS 203',
          replacement: 'FIPS 203 ML-KEM-768 (@noble/post-quantum)',
          advisory: guide.advisory,
          codeSnippet: guide.snippets.typescript,
        },
        cnsa: guide.cnsa,
      };
    },
  },

  // 5. JS/TS AES-128 Grover Check
  {
    id: 'js-aes-128-grover',
    languages: ['javascript', 'typescript'],
    name: 'Node.js AES-128 Cipher Grover Check',
    category: 'symmetric-crypto',
    primitive: 'block-cipher',
    defaultSeverity: 'medium',
    check(node: Parser.SyntaxNode, ctx: ASTContext): CryptoFinding | null {
      if (node.type !== 'call_expression') return null;
      const text = node.text;

      if (
        (text.includes('createCipheriv') || text.includes('createDecipheriv')) &&
        (text.includes('aes-128') || text.includes('aes128'))
      ) {
        const guide = MIGRATION_GUIDES['symmetric-aes-128'];
        const loc = createRange(node);
        return {
          id: `JS-AES128-${ctx.filePath}:${loc.startLine}`,
          ruleId: 'js-aes-128-grover',
          file: ctx.filePath,
          location: loc,
          language: ctx.filePath.endsWith('.ts') || ctx.filePath.endsWith('.tsx') ? 'typescript' : 'javascript',
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
          title: 'AES-128 Security Degradation via Grover’s Search',
          description: 'AES-128 effective quantum security is reduced to 64 bits by Grover’s algorithm. Upgrade to AES-256 for 128-bit quantum security and CNSA 2.0 readiness.',
          codeSnippet: getNodeSnippet(node, ctx.lines),
          remediation: {
            nistStandard: 'CNSA 2.0',
            replacement: guide.replacement,
            advisory: guide.advisory,
            codeSnippet: guide.snippets.typescript,
          },
          cnsa: guide.cnsa,
        };
      }
      return null;
    },
  },

  // 6. JS/TS SHA-256 Hash CNSA Check
  {
    id: 'js-sha256-cnsa',
    languages: ['javascript', 'typescript'],
    name: 'Node.js SHA-256 Hash CNSA Check',
    category: 'hash-function',
    primitive: 'hash',
    defaultSeverity: 'low',
    check(node: Parser.SyntaxNode, ctx: ASTContext): CryptoFinding | null {
      if (node.type !== 'call_expression') return null;
      const text = node.text;

      if (text.includes('createHash') && (text.includes("'sha256'") || text.includes('"sha256"'))) {
        const guide = MIGRATION_GUIDES['hash-sha256-cnsa'];
        const loc = createRange(node);
        return {
          id: `JS-SHA256-${ctx.filePath}:${loc.startLine}`,
          ruleId: 'js-sha256-cnsa',
          file: ctx.filePath,
          location: loc,
          language: ctx.filePath.endsWith('.ts') || ctx.filePath.endsWith('.tsx') ? 'typescript' : 'javascript',
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
          description: 'SHA-256 message digests do not meet CNSA 2.0 post-quantum requirements (which require SHA-384 or SHA-512).',
          codeSnippet: getNodeSnippet(node, ctx.lines),
          remediation: {
            nistStandard: 'CNSA 2.0',
            replacement: guide.replacement,
            advisory: guide.advisory,
            codeSnippet: guide.snippets.typescript,
          },
          cnsa: guide.cnsa,
        };
      }
      return null;
    },
  },
];

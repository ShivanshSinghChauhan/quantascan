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

export const goRules: Rule[] = [
  // 1. Go RSA Key Generation & Crypto Operations
  {
    id: 'go-rsa-operations',
    languages: ['go'],
    name: 'Go RSA Key Generation & Encryption / Signatures',
    category: 'asymmetric-kem',
    primitive: 'key-exchange',
    defaultSeverity: 'critical',
    check(node: Parser.SyntaxNode, ctx: ASTContext): CryptoFinding | null {
      if (node.type !== 'call_expression') return null;
      const text = node.text;

      const isRsa =
        text.includes('rsa.GenerateKey') ||
        text.includes('rsa.EncryptOAEP') ||
        text.includes('rsa.DecryptOAEP') ||
        text.includes('rsa.EncryptPKCS1v15') ||
        text.includes('rsa.SignPKCS1v15') ||
        text.includes('rsa.SignPSS') ||
        text.includes('rsa.VerifyPKCS1v15') ||
        text.includes('rsa.VerifyPSS');

      if (!isRsa) return null;

      let keySize = 2048;
      const match = text.match(/GenerateKey\([^,]+,\s*(\d+)\)/);
      if (match) keySize = parseInt(match[1], 10);

      const isSignature = text.includes('Sign') || text.includes('Verify');
      const category = isSignature ? 'digital-signature' : 'asymmetric-kem';
      const primitive = isSignature ? 'signature' : 'kem';
      const guideKey = isSignature ? 'classical-signature-rsa' : 'rsa-key-exchange';
      const guide = MIGRATION_GUIDES[guideKey];

      const loc = createRange(node);
      return {
        id: `GO-RSA-${ctx.filePath}:${loc.startLine}`,
        ruleId: 'go-rsa-operations',
        file: ctx.filePath,
        location: loc,
        language: 'go',
        category,
        assetType: 'algorithm',
        algorithm: `crypto/rsa (${keySize}-bit)`,
        primitive,
        parameterSet: `${keySize}-bit`,
        keyLength: keySize,
        context: isSignature ? (text.includes('Sign') ? 'signature-sign' : 'signature-verify') : 'key-exchange',
        severity: 'critical',
        classicalSecurityLevel: keySize >= 2048 ? 112 : 80,
        nistQuantumSecurityLevel: 0,
        title: `Pre-Quantum Go RSA Primitive (${text.split('(')[0]})`,
        description: 'RSA operations in Go standard library are vulnerable to Shor’s algorithm factorization attacks on a quantum computer.',
        codeSnippet: getNodeSnippet(node, ctx.lines),
        remediation: {
          nistStandard: guide.nistStandard,
          replacement: guide.replacement,
          advisory: guide.advisory,
          codeSnippet: guide.snippets.go,
        },
        cnsa: guide.cnsa,
      };
    },
  },

  // 2. Go ECDSA / ECDH / Elliptic Curve Operations
  {
    id: 'go-ecdsa-ecdh-operations',
    languages: ['go'],
    name: 'Go ECDSA / ECDH Elliptic Curve Primitives',
    category: 'asymmetric-kem',
    primitive: 'key-exchange',
    defaultSeverity: 'critical',
    check(node: Parser.SyntaxNode, ctx: ASTContext): CryptoFinding | null {
      if (node.type !== 'call_expression') return null;
      const text = node.text;

      const isEc =
        text.includes('ecdsa.GenerateKey') ||
        text.includes('ecdsa.Sign') ||
        text.includes('ecdsa.Verify') ||
        text.includes('ecdh.P256') ||
        text.includes('ecdh.X25519') ||
        text.includes('elliptic.P256') ||
        text.includes('elliptic.P384') ||
        text.includes('elliptic.P521') ||
        text.includes('ed25519.GenerateKey') ||
        text.includes('ed25519.Sign') ||
        text.includes('ed25519.Verify') ||
        text.includes('curve25519.X25519');

      if (!isEc) return null;

      let curve = 'P-256';
      if (text.includes('P384')) curve = 'P-384';
      else if (text.includes('P521')) curve = 'P-521';
      else if (text.includes('X25519') || text.includes('curve25519')) curve = 'X25519';
      else if (text.includes('ed25519') || text.includes('Ed25519')) curve = 'Ed25519';

      const isSignature =
        text.includes('ecdsa.Sign') ||
        text.includes('ecdsa.Verify') ||
        text.includes('ed25519.Sign') ||
        text.includes('ed25519.Verify') ||
        text.includes('ed25519.GenerateKey');

      const category = isSignature ? 'digital-signature' : 'asymmetric-kem';
      const primitive = isSignature ? 'signature' : 'key-exchange';
      const guideKey = isSignature ? 'classical-signature-ecdsa' : 'ecdh-key-exchange';
      const guide = MIGRATION_GUIDES[guideKey];

      const loc = createRange(node);
      return {
        id: `GO-EC-${ctx.filePath}:${loc.startLine}`,
        ruleId: 'go-ecdsa-ecdh-operations',
        file: ctx.filePath,
        location: loc,
        language: 'go',
        category,
        assetType: 'algorithm',
        algorithm: `crypto/${isSignature ? 'ecdsa' : 'ecdh'} (${curve})`,
        primitive,
        curve,
        context: isSignature ? (text.includes('Sign') ? 'signature-sign' : 'signature-verify') : 'key-exchange',
        severity: 'critical',
        classicalSecurityLevel: 128,
        nistQuantumSecurityLevel: 0,
        title: `Pre-Quantum Elliptic Curve (${curve}) in Go`,
        description: 'Go crypto/ecdsa and crypto/ecdh use pre-quantum elliptic curves that can be cracked in polynomial time by Shor’s algorithm.',
        codeSnippet: getNodeSnippet(node, ctx.lines),
        remediation: {
          nistStandard: guide.nistStandard,
          replacement: guide.replacement,
          advisory: guide.advisory,
          codeSnippet: guide.snippets.go,
        },
        cnsa: guide.cnsa,
      };
    },
  },

  // 3. Go AES-128 Grover Check
  {
    id: 'go-aes-128-grover',
    languages: ['go'],
    name: 'Go AES-128 Grover Cipher Check',
    category: 'symmetric-crypto',
    primitive: 'block-cipher',
    defaultSeverity: 'medium',
    check(node: Parser.SyntaxNode, ctx: ASTContext): CryptoFinding | null {
      if (node.type !== 'call_expression') return null;
      const text = node.text;

      if (text.includes('aes.NewCipher') && (text.includes('16') || text.includes('make([]byte, 16)'))) {
        const guide = MIGRATION_GUIDES['symmetric-aes-128'];
        const loc = createRange(node);
        return {
          id: `GO-AES128-${ctx.filePath}:${loc.startLine}`,
          ruleId: 'go-aes-128-grover',
          file: ctx.filePath,
          location: loc,
          language: 'go',
          category: 'symmetric-crypto',
          assetType: 'algorithm',
          algorithm: 'crypto/aes (128-bit key)',
          primitive: 'block-cipher',
          parameterSet: '128-bit key',
          keyLength: 128,
          context: 'data-at-rest',
          severity: 'medium',
          classicalSecurityLevel: 128,
          nistQuantumSecurityLevel: 1,
          title: 'Go AES-128 Vulnerable to Grover Quadratic Search Speedup',
          description: 'AES-128 offers only 64 bits of quantum security margin. Upgrade to 256-bit keys (32 bytes) in aes.NewCipher.',
          codeSnippet: getNodeSnippet(node, ctx.lines),
          remediation: {
            nistStandard: 'CNSA 2.0',
            replacement: guide.replacement,
            advisory: guide.advisory,
            codeSnippet: guide.snippets.go,
          },
          cnsa: guide.cnsa,
        };
      }
      return null;
    },
  },

  // 4. Go SHA-256 CNSA 2.0 Check
  {
    id: 'go-sha256-cnsa',
    languages: ['go'],
    name: 'Go SHA-256 Hash CNSA 2.0 Check',
    category: 'hash-function',
    primitive: 'hash',
    defaultSeverity: 'low',
    check(node: Parser.SyntaxNode, ctx: ASTContext): CryptoFinding | null {
      if (node.type !== 'call_expression') return null;
      const text = node.text;

      if (text.includes('sha256.New') || text.includes('sha256.Sum256')) {
        const guide = MIGRATION_GUIDES['hash-sha256-cnsa'];
        const loc = createRange(node);
        return {
          id: `GO-SHA256-${ctx.filePath}:${loc.startLine}`,
          ruleId: 'go-sha256-cnsa',
          file: ctx.filePath,
          location: loc,
          language: 'go',
          category: 'hash-function',
          assetType: 'algorithm',
          algorithm: 'crypto/sha256',
          primitive: 'hash',
          parameterSet: '256-bit digest',
          context: 'digest',
          severity: 'low',
          classicalSecurityLevel: 128,
          nistQuantumSecurityLevel: 1,
          title: 'Go SHA-256 Digest (CNSA 2.0 Threshold Check)',
          description: 'SHA-256 does not meet CNSA 2.0 quantum resistance standards (which mandate SHA-384 or SHA-512).',
          codeSnippet: getNodeSnippet(node, ctx.lines),
          remediation: {
            nistStandard: 'CNSA 2.0',
            replacement: guide.replacement,
            advisory: guide.advisory,
            codeSnippet: guide.snippets.go,
          },
          cnsa: guide.cnsa,
        };
      }
      return null;
    },
  },
];

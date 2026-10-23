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

export const javaRules: Rule[] = [
  // 1. Java KeyPairGenerator / KeyAgreement (RSA, EC, DH)
  {
    id: 'java-asymmetric-keypair-gen',
    languages: ['java'],
    name: 'Java KeyPairGenerator (RSA / EC / DiffieHellman)',
    category: 'asymmetric-kem',
    primitive: 'key-exchange',
    defaultSeverity: 'critical',
    check(node: Parser.SyntaxNode, ctx: ASTContext): CryptoFinding | null {
      if (node.type !== 'method_invocation') return null;
      const text = node.text;

      const isKpg =
        text.includes('KeyPairGenerator.getInstance') ||
        text.includes('KeyAgreement.getInstance');

      if (!isKpg) return null;

      let algo = 'RSA';
      if (text.includes('"EC"') || text.includes('"ECDH"') || text.includes('EC256')) algo = 'Elliptic Curve (EC/ECDH)';
      else if (text.includes('"DH"') || text.includes('"DiffieHellman"')) algo = 'Diffie-Hellman';
      else if (text.includes('"DSA"')) algo = 'DSA';

      const isEc = algo.includes('EC') || algo.includes('Diffie');
      const guideKey = isEc ? 'ecdh-key-exchange' : 'rsa-key-exchange';
      const guide = MIGRATION_GUIDES[guideKey];

      const loc = createRange(node);
      return {
        id: `JAVA-KPG-${ctx.filePath}:${loc.startLine}`,
        ruleId: 'java-asymmetric-keypair-gen',
        file: ctx.filePath,
        location: loc,
        language: 'java',
        category: 'asymmetric-kem',
        assetType: 'algorithm',
        algorithm: `Java JCA ${algo}`,
        primitive: 'key-exchange',
        context: 'key-exchange',
        severity: 'critical',
        classicalSecurityLevel: 112,
        nistQuantumSecurityLevel: 0,
        title: `Java Pre-Quantum KeyPairGenerator / KeyAgreement (${algo})`,
        description: `Java JCA ${algo} is vulnerable to Shor’s algorithm on cryptanalytically relevant quantum computers. Replace with BCPQC ML-KEM.`,
        codeSnippet: getNodeSnippet(node, ctx.lines),
        remediation: {
          nistStandard: guide.nistStandard,
          replacement: guide.replacement,
          advisory: guide.advisory,
          codeSnippet: guide.snippets.java,
        },
        cnsa: guide.cnsa,
      };
    },
  },

  // 2. Java Signature (SHA256withRSA, SHA256withECDSA, Ed25519)
  {
    id: 'java-signature-instance',
    languages: ['java'],
    name: 'Java Signature.getInstance (RSA/ECDSA/EdDSA)',
    category: 'digital-signature',
    primitive: 'signature',
    defaultSeverity: 'critical',
    check(node: Parser.SyntaxNode, ctx: ASTContext): CryptoFinding | null {
      if (node.type !== 'method_invocation') return null;
      const text = node.text;

      if (!text.includes('Signature.getInstance')) return null;

      let algo = 'RSA / ECDSA Signature';
      if (text.includes('withRSA') || text.includes('RSA')) algo = 'RSA Signature (PKCS1/PSS)';
      else if (text.includes('withECDSA') || text.includes('ECDSA')) algo = 'ECDSA Signature';
      else if (text.includes('Ed25519') || text.includes('EdDSA')) algo = 'Ed25519 Signature';

      const guide = MIGRATION_GUIDES['classical-signature-rsa'];
      const loc = createRange(node);
      return {
        id: `JAVA-SIG-${ctx.filePath}:${loc.startLine}`,
        ruleId: 'java-signature-instance',
        file: ctx.filePath,
        location: loc,
        language: 'java',
        category: 'digital-signature',
        assetType: 'algorithm',
        algorithm: algo,
        primitive: 'signature',
        context: 'signature-sign',
        severity: 'critical',
        classicalSecurityLevel: 128,
        nistQuantumSecurityLevel: 0,
        title: `Pre-Quantum Java Signature Engine (${algo})`,
        description: 'Java Signature.getInstance with classical asymmetric primitives can be forged by quantum adversaries solving discrete logs or integer factorizations.',
        codeSnippet: getNodeSnippet(node, ctx.lines),
        remediation: {
          nistStandard: 'FIPS 204',
          replacement: 'ML-DSA-65 (FIPS 204) or SLH-DSA (FIPS 205) via BCPQC',
          advisory: guide.advisory,
          codeSnippet: guide.snippets.java,
        },
        cnsa: guide.cnsa,
      };
    },
  },

  // 3. Java Cipher (RSA Encryption / Legacy Ciphers)
  {
    id: 'java-cipher-instance',
    languages: ['java'],
    name: 'Java Cipher.getInstance (RSA / DES / AES-128)',
    category: 'asymmetric-kem',
    primitive: 'kem',
    defaultSeverity: 'critical',
    check(node: Parser.SyntaxNode, ctx: ASTContext): CryptoFinding | null {
      if (node.type !== 'method_invocation') return null;
      const text = node.text;

      if (!text.includes('Cipher.getInstance')) return null;

      if (text.includes('RSA')) {
        const guide = MIGRATION_GUIDES['rsa-key-exchange'];
        const loc = createRange(node);
        return {
          id: `JAVA-CIPHER-RSA-${ctx.filePath}:${loc.startLine}`,
          ruleId: 'java-cipher-instance',
          file: ctx.filePath,
          location: loc,
          language: 'java',
          category: 'asymmetric-kem',
          assetType: 'algorithm',
          algorithm: 'RSA Cipher (OAEP / PKCS1Padding)',
          primitive: 'kem',
          context: 'data-at-rest',
          severity: 'critical',
          classicalSecurityLevel: 112,
          nistQuantumSecurityLevel: 0,
          title: 'Java RSA Cipher Usage (Harvest Now Decrypt Later Risk)',
          description: 'Direct RSA cipher encryption / key wrapping is vulnerable to quantum factoring attacks.',
          codeSnippet: getNodeSnippet(node, ctx.lines),
          remediation: {
            nistStandard: 'FIPS 203',
            replacement: guide.replacement,
            advisory: guide.advisory,
            codeSnippet: guide.snippets.java,
          },
          cnsa: guide.cnsa,
        };
      }

      if (text.includes('DES') || text.includes('DESede') || text.includes('Blowfish')) {
        const loc = createRange(node);
        return {
          id: `JAVA-CIPHER-LEGACY-${ctx.filePath}:${loc.startLine}`,
          ruleId: 'java-cipher-instance',
          file: ctx.filePath,
          location: loc,
          language: 'java',
          category: 'legacy-provider',
          assetType: 'algorithm',
          algorithm: 'Legacy Broken Cipher (DES/3DES/Blowfish)',
          primitive: 'block-cipher',
          context: 'data-at-rest',
          severity: 'critical',
          classicalSecurityLevel: 56,
          nistQuantumSecurityLevel: 0,
          title: 'Broken Legacy Cipher in Java Cipher.getInstance',
          description: 'DES and 3DES have short 64-bit blocks vulnerable to Sweet32 and are obsolete both classically and quantumly.',
          codeSnippet: getNodeSnippet(node, ctx.lines),
          remediation: {
            nistStandard: 'CNSA 2.0',
            replacement: 'AES-256-GCM',
            advisory: 'Upgrade to AES-256-GCM in Cipher.getInstance("AES/GCM/NoPadding").',
            codeSnippet: guideSnippetsJavaAES256,
          },
          cnsa: {
            compliant: false,
            requirement: 'CNSA 2.0 bans DES/3DES',
            deadline: 'Immediate',
          },
        };
      }

      return null;
    },
  },

  // 4. Java MessageDigest (SHA-256 CNSA check)
  {
    id: 'java-digest-sha256',
    languages: ['java'],
    name: 'Java MessageDigest SHA-256 CNSA Check',
    category: 'hash-function',
    primitive: 'hash',
    defaultSeverity: 'low',
    check(node: Parser.SyntaxNode, ctx: ASTContext): CryptoFinding | null {
      if (node.type !== 'method_invocation') return null;
      const text = node.text;

      if (text.includes('MessageDigest.getInstance') && (text.includes('"SHA-256"') || text.includes('"SHA256"'))) {
        const guide = MIGRATION_GUIDES['hash-sha256-cnsa'];
        const loc = createRange(node);
        return {
          id: `JAVA-SHA256-${ctx.filePath}:${loc.startLine}`,
          ruleId: 'java-digest-sha256',
          file: ctx.filePath,
          location: loc,
          language: 'java',
          category: 'hash-function',
          assetType: 'algorithm',
          algorithm: 'MessageDigest SHA-256',
          primitive: 'hash',
          parameterSet: '256-bit digest',
          context: 'digest',
          severity: 'low',
          classicalSecurityLevel: 128,
          nistQuantumSecurityLevel: 1,
          title: 'Java SHA-256 Digest (CNSA 2.0 Sub-Threshold)',
          description: 'SHA-256 is acceptable for standard NIST workloads, but CNSA 2.0 mandates SHA-384 or SHA-512 for quantum-resistant message integrity.',
          codeSnippet: getNodeSnippet(node, ctx.lines),
          remediation: {
            nistStandard: 'CNSA 2.0',
            replacement: guide.replacement,
            advisory: guide.advisory,
            codeSnippet: guide.snippets.java,
          },
          cnsa: guide.cnsa,
        };
      }
      return null;
    },
  },
];

const guideSnippetsJavaAES256 = `KeyGenerator kg = KeyGenerator.getInstance("AES");
kg.init(256);
SecretKey key = kg.generateKey();
Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");`;

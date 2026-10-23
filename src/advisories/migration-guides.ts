import { Language, RemediationAdvisory, CnsaStatus } from '../types/index.js';

export interface RuleAdvisoryMetadata {
  title: string;
  category:
    | 'asymmetric-kem'
    | 'digital-signature'
    | 'symmetric-crypto'
    | 'hash-function'
    | 'hardcoded-secret'
    | 'legacy-provider';
  primitive:
    | 'kem'
    | 'signature'
    | 'key-exchange'
    | 'block-cipher'
    | 'hash'
    | 'mac'
    | 'pke'
    | 'stream-cipher';
  severity: 'critical' | 'high' | 'medium' | 'low';
  nistStandard: 'FIPS 203' | 'FIPS 204' | 'FIPS 205' | 'SP 800-208' | 'CNSA 2.0' | 'NIST General';
  replacement: string;
  advisory: string;
  cnsa: CnsaStatus;
  snippets: Record<Language, string>;
}

export const MIGRATION_GUIDES: Record<string, RuleAdvisoryMetadata> = {
  // 1. Asymmetric Key Exchange (FIPS 203 ML-KEM)
  'ecdh-key-exchange': {
    title: 'Pre-Quantum ECDH Key Exchange (Shor’s Algorithm Vulnerability)',
    category: 'asymmetric-kem',
    primitive: 'key-exchange',
    severity: 'critical',
    nistStandard: 'FIPS 203',
    replacement: 'ML-KEM-768 or Hybrid X25519+ML-KEM-768',
    advisory:
      'Elliptic Curve Diffie-Hellman (ECDH) on classical curves (secp256r1, secp256k1, X25519) is completely broken by polynomial-time Shor’s algorithm on a quantum computer. All past session keys are susceptible to "Harvest Now, Decrypt Later" (HNDL) attacks. Migrate immediately to FIPS 203 ML-KEM-768 (Category 3) or hybrid X25519+ML-KEM-768 (IETF draft-ietf-tls-hybrid-design).',
    cnsa: {
      compliant: false,
      requirement: 'CNSA 2.0 mandates ML-KEM-1024 for all national security systems key establishment',
      deadline: 'Transition beginning 2025; mandatory by 2030-2033',
    },
    snippets: {
      python: `# Python: Migrate from ECDH to ML-KEM-768 via liboqs-python / PQClean
# Legacy: ecdh = ec.generate_private_key(ec.SECP256R1())
from oqs import KeyEncapsulation

with KeyEncapsulation("ML-KEM-768") as client:
    public_key = client.generate_keypair()
    # Or for CNSA 2.0 strict mode:
    # client = KeyEncapsulation("ML-KEM-1024")`,
      javascript: `// TypeScript/Node.js: Migrate to Hybrid X25519+ML-KEM-768
// Legacy: const ecdh = crypto.createECDH('prime256v1');
import { mlkem768 } from '@noble/post-quantum/ml-kem';

// Sender creates shared secret and ciphertext encapsulation
const [ciphertext, sharedSecretSender] = mlkem768.encapsulate(recipientPublicKey);
// Recipient decapsulates
const sharedSecretRecipient = mlkem768.decapsulate(ciphertext, recipientSecretKey);`,
      typescript: `// TypeScript: Modern Post-Quantum KEM implementation
import { mlkem768 } from '@noble/post-quantum/ml-kem';

const keys = mlkem768.keygen();
const { cipherText, sharedSecret } = mlkem768.encapsulate(keys.publicKey);`,
      go: `// Go: Migrate to ML-KEM-768 (Kyber768)
// Legacy: priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
import "github.com/cloudflare/circl/kem/kyber/kyber768"

scheme := kyber768.Scheme()
pubKey, privKey, err := scheme.GenerateKeyPair()
ct := make([]byte, scheme.CiphertextSize())
ssSender := make([]byte, scheme.SharedKeySize())
err = scheme.EncapsulateTo(ct, ssSender, pubKey)`,
      java: `// Java: BouncyCastle 1.78+ ML-KEM (Kyber)
// Legacy: KeyPairGenerator.getInstance("EC")
import org.bouncycastle.pqc.jcajce.provider.BouncyCastlePQCProvider;
import java.security.KeyPairGenerator;

Security.addProvider(new BouncyCastlePQCProvider());
KeyPairGenerator kpg = KeyPairGenerator.getInstance("ML-KEM-768", "BCPQC");
// For CNSA 2.0: KeyPairGenerator.getInstance("ML-KEM-1024", "BCPQC");
KeyPair kp = kpg.generateKeyPair();`,
    },
  },

  'rsa-key-exchange': {
    title: 'RSA Key Encapsulation / Exchange (Shor’s Algorithm Vulnerability)',
    category: 'asymmetric-kem',
    primitive: 'kem',
    severity: 'critical',
    nistStandard: 'FIPS 203',
    replacement: 'ML-KEM-768 or ML-KEM-1024',
    advisory:
      'RSA encryption / OAEP key wrapping relies on integer factorization. Shor’s algorithm factors arbitrary RSA integers in $\\mathcal{O}((\\log N)^3)$ quantum steps. Replace RSA key exchange with FIPS 203 ML-KEM.',
    cnsa: {
      compliant: false,
      requirement: 'CNSA 2.0 bans RSA key establishment entirely in favor of ML-KEM-1024',
      deadline: 'Transition beginning 2025; mandatory by 2030',
    },
    snippets: {
      python: `# Python: Replace RSA-OAEP Key Wrapping with ML-KEM-768
from oqs import KeyEncapsulation
kem = KeyEncapsulation("ML-KEM-768")
pubkey = kem.generate_keypair()
ciphertext, shared_secret = kem.encap_secret(pubkey)`,
      javascript: `// Node.js/TS: Replace RSA Key Wrapping with ML-KEM
import { mlkem768 } from '@noble/post-quantum/ml-kem';
const [ciphertext, sharedSecret] = mlkem768.encapsulate(recipientPublicKey);`,
      typescript: `// TypeScript: Replace RSA Key Wrapping with ML-KEM
import { mlkem768 } from '@noble/post-quantum/ml-kem';
const [ciphertext, sharedSecret] = mlkem768.encapsulate(recipientPublicKey);`,
      go: `// Go: Replace RSA Key Wrapping with circl/kem/kyber
import "github.com/cloudflare/circl/kem/kyber/kyber768"
scheme := kyber768.Scheme()
pubKey, privKey, _ := scheme.GenerateKeyPair()`,
      java: `// Java: BouncyCastle ML-KEM
KeyPairGenerator kpg = KeyPairGenerator.getInstance("ML-KEM-768", "BCPQC");
KeyPair kp = kpg.generateKeyPair();`,
    },
  },

  // 2. Digital Signatures (FIPS 204 ML-DSA / FIPS 205 SLH-DSA)
  'classical-signature-rsa': {
    title: 'Pre-Quantum RSA Digital Signature (Shor’s Forgery Vulnerability)',
    category: 'digital-signature',
    primitive: 'signature',
    severity: 'critical',
    nistStandard: 'FIPS 204',
    replacement: 'ML-DSA-65 (FIPS 204) or SLH-DSA-SHA2-128s (FIPS 205)',
    advisory:
      'RSA digital signatures (PKCS#1 v1.5 or PSS) can be forged by a quantum adversary calculating private exponents via Shor’s algorithm. Replace with FIPS 204 ML-DSA-65 (primary general purpose lattice signature) or FIPS 205 SLH-DSA for stateless hash-based signatures.',
    cnsa: {
      compliant: false,
      requirement: 'CNSA 2.0 mandates ML-DSA-87 or SLH-DSA-SHAKE-256s for digital signatures',
      deadline: 'Firmware/software signing transition by 2025; full enforcement by 2030',
    },
    snippets: {
      python: `# Python: Migrate RSA signing to ML-DSA-65
from oqs import Signature
with Signature("ML-DSA-65") as signer:
    signer_pub = signer.generate_keypair()
    signature = signer.sign(message)
    is_valid = signer.verify(message, signature, signer_pub)`,
      javascript: `// TypeScript/Node.js: ML-DSA-65 Signing
import { mldsa65 } from '@noble/post-quantum/ml-dsa';
const keys = mldsa65.keygen();
const signature = mldsa65.sign(keys.secretKey, message);
const isValid = mldsa65.verify(keys.publicKey, message, signature);`,
      typescript: `// TypeScript: ML-DSA-65 Signing
import { mldsa65 } from '@noble/post-quantum/ml-dsa';
const keys = mldsa65.keygen();
const signature = mldsa65.sign(keys.secretKey, message);
const isValid = mldsa65.verify(keys.publicKey, message, signature);`,
      go: `// Go: ML-DSA-65 (Dilithium3)
import "github.com/cloudflare/circl/sign/dilithium/mode3"
pubKey, privKey, err := mode3.GenerateKey(rand.Reader)
signature := make([]byte, mode3.SignatureSize)
mode3.SignTo(privKey, message, signature)`,
      java: `// Java: BouncyCastle ML-DSA
KeyPairGenerator kpg = KeyPairGenerator.getInstance("ML-DSA-65", "BCPQC");
KeyPair kp = kpg.generateKeyPair();
Signature sig = Signature.getInstance("ML-DSA-65", "BCPQC");
sig.initSign(kp.getPrivate());
sig.update(data);
byte[] signature = sig.sign();`,
    },
  },

  'classical-signature-ecdsa': {
    title: 'Pre-Quantum ECDSA / Ed25519 Signature (Shor’s Forgery Vulnerability)',
    category: 'digital-signature',
    primitive: 'signature',
    severity: 'critical',
    nistStandard: 'FIPS 204',
    replacement: 'ML-DSA-65 (FIPS 204) or SLH-DSA-128s (FIPS 205)',
    advisory:
      'ECDSA (P-256, P-384, secp256k1) and Ed25519 signatures can be broken and forged by solving discrete logs using Shor’s algorithm on a quantum computer. Migrate to FIPS 204 ML-DSA-65 or hybrid dual-signing schemes.',
    cnsa: {
      compliant: false,
      requirement: 'CNSA 2.0 mandates ML-DSA-87 for all digital signatures and authentication',
      deadline: 'Mandatory transition: 2025 - 2030',
    },
    snippets: {
      python: `# Python: Migrate ECDSA/Ed25519 to ML-DSA-65
from oqs import Signature
with Signature("ML-DSA-65") as signer:
    pubkey = signer.generate_keypair()
    sig = signer.sign(message)`,
      javascript: `// TypeScript/Node.js: ML-DSA-65 Signature
import { mldsa65 } from '@noble/post-quantum/ml-dsa';
const keys = mldsa65.keygen();
const signature = mldsa65.sign(keys.secretKey, message);`,
      typescript: `// TypeScript/Node.js: ML-DSA-65 Signature
import { mldsa65 } from '@noble/post-quantum/ml-dsa';
const keys = mldsa65.keygen();
const signature = mldsa65.sign(keys.secretKey, message);`,
      go: `// Go: ML-DSA-65 (Dilithium)
import "github.com/cloudflare/circl/sign/dilithium/mode3"
pubKey, privKey, _ := mode3.GenerateKey(rand.Reader)
sig := make([]byte, mode3.SignatureSize)
mode3.SignTo(privKey, message, sig)`,
      java: `// Java: BouncyCastle ML-DSA-65
Signature sig = Signature.getInstance("ML-DSA-65", "BCPQC");
sig.initSign(privateKey);
sig.update(message);
byte[] signature = sig.sign();`,
    },
  },

  // 3. Symmetric & Hash Longevity Check (Grover's Algorithm Risk)
  'symmetric-aes-128': {
    title: 'AES-128 Grover’s Algorithm Quantum Security Margin Degradation',
    category: 'symmetric-crypto',
    primitive: 'block-cipher',
    severity: 'medium',
    nistStandard: 'CNSA 2.0',
    replacement: 'AES-256-GCM (NIST SP 800-38D / CNSA 2.0)',
    advisory:
      'Grover’s quantum algorithm provides a quadratic speedup for brute-force symmetric key search. A 128-bit key is reduced to an effective quantum security strength of 64 bits, which is below the safe 112/128-bit quantum security threshold. Upgrade to AES-256 to guarantee at least 128 bits of post-quantum security.',
    cnsa: {
      compliant: false,
      requirement: 'CNSA 2.0 mandates AES-256 for symmetric encryption (AES-128 is not permitted)',
      deadline: 'Active requirement',
    },
    snippets: {
      python: `# Python: Upgrade AES-128 to AES-256-GCM
import os
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
key = AESGCM.generate_key(bit_length=256) # 256 bits
aesgcm = AESGCM(key)
nonce = os.urandom(12)
ciphertext = aesgcm.encrypt(nonce, b"quantum safe payload", None)`,
      javascript: `// Node.js/TS: Upgrade to AES-256-GCM
import crypto from 'crypto';
const key = crypto.randomBytes(32); // 256 bits
const iv = crypto.randomBytes(12);
const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);`,
      typescript: `// TypeScript: Upgrade to AES-256-GCM
import crypto from 'crypto';
const key = crypto.randomBytes(32); // 256-bit key
const iv = crypto.randomBytes(12);
const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);`,
      go: `// Go: Upgrade to AES-256-GCM
key := make([]byte, 32) // 32 bytes = 256 bits
rand.Read(key)
block, err := aes.NewCipher(key)
gcm, err := cipher.NewGCM(block)`,
      java: `// Java: Upgrade to AES-256
KeyGenerator kg = KeyGenerator.getInstance("AES");
kg.init(256); // 256-bit key for Grover quantum protection
SecretKey key = kg.generateKey();
Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");`,
    },
  },

  'hash-sha256-cnsa': {
    title: 'SHA-256 Sub-Threshold Hash (CNSA 2.0 Compliance Flag)',
    category: 'hash-function',
    primitive: 'hash',
    severity: 'low',
    nistStandard: 'CNSA 2.0',
    replacement: 'SHA-384 or SHA-512 (FIPS 180-4 / CNSA 2.0)',
    advisory:
      'While SHA-256 retains 128-bit collision resistance and is acceptable under general NIST guidelines, CNSA 2.0 strictly requires SHA-384 or SHA-512 for all government, defense, and critical infrastructure systems to guard against quantum collision searches (BHT algorithm).',
    cnsa: {
      compliant: false,
      requirement: 'CNSA 2.0 requires SHA-384 or SHA-512 for message digests',
      deadline: 'Transition in progress (2025/2030)',
    },
    snippets: {
      python: `# Python: Migrate SHA-256 to SHA-384 or SHA-512
import hashlib
digest = hashlib.sha384(b"data").hexdigest()`,
      javascript: `// Node.js/TS: Migrate SHA-256 to SHA-384/512
import crypto from 'crypto';
const hash = crypto.createHash('sha384').update(data).digest('hex');`,
      typescript: `// TypeScript: Migrate SHA-256 to SHA-384/512
import crypto from 'crypto';
const hash = crypto.createHash('sha384').update(data).digest('hex');`,
      go: `// Go: Migrate SHA-256 to SHA-384
import "crypto/sha512"
h := sha512.New384()
h.Write(data)`,
      java: `// Java: Migrate to SHA-384 / SHA-512
MessageDigest md = MessageDigest.getInstance("SHA-384");
byte[] digest = md.digest(data);`,
    },
  },
};

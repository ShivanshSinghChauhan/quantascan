# QuantaScan: Comprehensive User Guide & Technical Manual
**Post-Quantum Cryptography (PQC) Static Analysis Engine & Automated CycloneDX v1.6 CBOM Generator**

---

## 1. Executive Summary & Quantum Threat Model

### The Quantum Cryptanalysis Horizon
Modern cybersecurity architectures rely fundamentally on mathematical problems that are intractable for classical computing systems:
1. **Integer Factorization:** Underlying RSA signatures and encryption ($N = p \cdot q$).
2. **Discrete Logarithms & Elliptic Curve Discrete Logarithms (ECDLP):** Underlying Diffie-Hellman (DH), DSA, ECDH (P-256, secp256k1, X25519), and ECDSA.

On a **Cryptanalytically Relevant Quantum Computer (CRQC)**, Peter Shor’s algorithm solves integer factorization and discrete logarithms in polynomial time:
$$\mathcal{O}((\log N)^3)$$
Consequently, **all classical asymmetric cryptography is completely broken by CRQC.**

Furthermore, Lov Grover’s quantum search algorithm provides a quadratic speedup ($\mathcal{O}(\sqrt{N})$) for unstructured search. This halves the effective symmetric key length and collision security:
- **AES-128:** Halved to $2^{64}$ quantum operations $\to$ **vulnerable to large-scale quantum brute-force**.
- **AES-256:** Halved to $2^{128}$ quantum operations $\to$ **remains quantum-safe**.
- **SHA-256:** Pre-image and collision resistance margins are reduced, triggering strict mandates under NSA CNSA 2.0 to upgrade to **SHA-384 or SHA-512**.

### "Harvest Now, Decrypt Later" (HNDL)
Adversaries are actively exfiltrating and storing encrypted network traffic and proprietary assets today. When CRQCs emerge, stored ciphertext will be decrypted retroactively. Transitioning to Post-Quantum Cryptography (PQC) cannot wait for quantum hardware deployment.

---

## 2. Standards & Regulatory Compliance Framework

### NIST Post-Quantum Standards (August 2024 Finalized)
1. **FIPS 203 (ML-KEM):** Module-Lattice-Based Key-Encapsulation Mechanism Standard (derived from CRYSTALS-Kyber).
   - Parameter sets: `ML-KEM-512` (Category 1), `ML-KEM-768` (Category 3), `ML-KEM-1024` (Category 5).
2. **FIPS 204 (ML-DSA):** Module-Lattice-Based Digital Signature Standard (derived from CRYSTALS-Dilithium).
   - Parameter sets: `ML-DSA-44` (Category 2), `ML-DSA-65` (Category 3), `ML-DSA-87` (Category 5).
3. **FIPS 205 (SLH-DSA):** Stateless Hash-Based Digital Signature Standard (derived from SPHINCS+).
   - Provides an independent mathematical foundation (hash functions) as a hedge against lattice cryptanalysis.

### NSA CNSA 2.0 Timelines & Mandates
The **Commercial National Security Algorithm Suite 2.0 (CNSA 2.0)** mandates quantum-resistant algorithms for National Security Systems:
- **Software/Firmware Signing:** Transition begins immediately; mandatory by **2030** (`ML-DSA-87`, `SLH-DSA-SHAKE-256s`, `LMS`, `XMSS`).
- **Web Browsers, Servers & Cloud:** Preference by **2025**; mandatory by **2033** (`ML-KEM-1024`, `ML-DSA-87`).
- **Traditional Networking Equipment:** Preference by **2026**; mandatory by **2030**.
- **Symmetric Ciphers:** **AES-256 only** (AES-128 is strictly prohibited).
- **Hash Functions:** **SHA-384 or SHA-512 only** (SHA-256 is strictly prohibited).

---

## 3. Architecture & Static Analysis Engine

QuantaScan inspects source code without execution using AST grammars compiled to WebAssembly via `web-tree-sitter`.

### Supported Languages & Target Libraries
| Language | Analyzed Libraries & Providers |
| :--- | :--- |
| **Python** | `cryptography` (hazmat), `pycryptodome`, `hashlib`, `ssl`, legacy `Crypto` |
| **JavaScript / TypeScript** | Native `crypto`, `node-rsa`, `elliptic`, `tweetnacl`, `@noble/curves` |
| **Go** | `crypto/rsa`, `crypto/ecdsa`, `crypto/elliptic`, `crypto/ecdh`, `crypto/aes`, `crypto/sha256`, `golang.org/x/crypto` |
| **Java** | `java.security.*` (`KeyPairGenerator`, `Signature`, `MessageDigest`), `javax.crypto.*` (`Cipher`, `KeyGenerator`), `org.bouncycastle.*` |

---

## 4. Quantum Vulnerability Index (QVI) Mathematical Model

QuantaScan computes the **Quantum Vulnerability Index (QVI)** on a scale of $0$ to $100$:

$$\text{RawScore} = \sum_{i=1}^{N} w(finding_i)$$

Where severity weights $w$ are:
- $\text{Critical} = 25$ (Shor's algorithm breaks RSA/ECC/DH/DSA; hardcoded private keys)
- $\text{High} = 15$ (Deprecated providers: PyCrypto, broken ciphers: DES/3DES/MD5, insecure Node `createCipher`)
- $\text{Medium} = 8$ (AES-128 Grover key halving)
- $\text{Low} = 3$ (SHA-256 sub-threshold under CNSA 2.0)

To prevent linear saturation while providing smooth differentiation across codebases of various sizes, QuantaScan applies an asymptotic exponential dampening function:

$$\text{QVI} = \min\left(100, \text{round}\left(100 \times \left(1 - e^{-\text{RawScore} / 45}\right)\right)\right)$$

### Post-Quantum Readiness Score:
$$\text{Readiness} = \max(0, 100 - \text{QVI})\%$$

---

## 5. CycloneDX v1.6 CBOM Specification

QuantaScan generates Cryptographic Bill of Materials (CBOM) compliant with the **CycloneDX v1.6 (ECMA-424)** standard.

### Component Structure (`type: "cryptographic-asset"`)
Each cryptographic asset is cataloged with:
- `bom-ref`: Deterministic identifier.
- `cryptoProperties.assetType`: `"algorithm" | "certificate" | "key" | "protocol"`.
- `cryptoProperties.algorithmProperties`:
  - `primitive`: `"kem" | "signature" | "block-cipher" | "hash"`.
  - `parameterSetIdentifier`: e.g. `"2048-bit"`, `"secp256r1"`.
  - `cryptoFunctions`: `["key-agree"]`, `["sign", "verify"]`, `["encrypt", "decrypt"]`.
  - `classicalSecurityLevel`: e.g. `112`, `128`.
  - `nistQuantumSecurityLevel`: `0` for classical broken primitives; `1`, `3`, or `5` for PQC.
- `evidence.occurrences`: Exact file path, 1-based line and column offsets, and code snippet.
- `vulnerabilities`: Linked vulnerability records detailing quantum impact and FIPS remediation.

---

## 6. CLI Command & Flag Reference

Binary name: `pqc-scan`

```bash
pqc-scan [target-dir] [options]
```

### Available Options
| Option | Description | Default |
| :--- | :--- | :--- |
| `-f, --format <format>` | Output format: `cli-table`, `json`, `cyclonedx-cbom`, `html` | `cli-table` |
| `-s, --min-severity <level>` | Minimum severity threshold: `low`, `medium`, `high`, `critical` | `low` |
| `--cnsa-mode` | Strict enforcement of CNSA 2.0 algorithm mandates and timelines | `false` |
| `-o, --output <path>` | Write scan output or CBOM to file | `stdout` |
| `--fail-on <level>` | Exit with code 1 if findings meet or exceed severity: `low`, `medium`, `high`, `critical` | `none` |
| `--serve` | Start local interactive testing web portal | `false` |
| `-p, --port <port>` | Port for local testing web portal | `3333` |
| `-h, --help` | Display command help | |

---

## 7. Migration Blueprints & Code Refactors

### 1. Key Encapsulation (Migrating from ECDH / RSA-OAEP to ML-KEM)

#### Python:
```python
# Legacy ECDH
from cryptography.hazmat.primitives.asymmetric import ec
priv = ec.generate_private_key(ec.SECP256R1())
secret = priv.exchange(ec.ECDH(), peer_pub)

# Post-Quantum FIPS 203 ML-KEM-768
from oqs import KeyEncapsulation
with KeyEncapsulation("ML-KEM-768") as client:
    pub = client.generate_keypair()
    ciphertext, shared_secret = client.encap_secret(peer_pub)
```

#### TypeScript / Node.js:
```typescript
// Legacy Node.js ECDH
import crypto from 'crypto';
const ecdh = crypto.createECDH('prime256v1');
ecdh.generateKeys();

// Post-Quantum ML-KEM-768
import { mlkem768 } from '@noble/post-quantum/ml-kem';
const keys = mlkem768.keygen();
const [ciphertext, sharedSecret] = mlkem768.encapsulate(peerPubKey);
```

#### Go:
```go
// Legacy ECDSA/ECDH
import "crypto/ecdsa"; "crypto/elliptic"
priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

// Post-Quantum ML-KEM-768 (Cloudflare CIRCL)
import "github.com/cloudflare/circl/kem/kyber/kyber768"
scheme := kyber768.Scheme()
pubKey, privKey, _ := scheme.GenerateKeyPair()
```

#### Java:
```java
// Legacy JCA RSA/EC
KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC");

// Post-Quantum ML-KEM (BouncyCastle 1.78+)
import org.bouncycastle.pqc.jcajce.provider.BouncyCastlePQCProvider;
Security.addProvider(new BouncyCastlePQCProvider());
KeyPairGenerator kpg = KeyPairGenerator.getInstance("ML-KEM-768", "BCPQC");
KeyPair kp = kpg.generateKeyPair();
```

---

## 8. Local Testing Web Portal Guide

QuantaScan includes an interactive testing server:

### Starting the Server
```bash
# In the quantascan repository:
npm run serve
# Or via CLI directly:
pqc-scan --serve --port=3333
```

### Endpoints
- **Live Interactive Dashboard:** `http://localhost:3333/`
  - Change target directories on the fly.
  - Toggle strict CNSA 2.0 mode with one click.
  - Filter findings by severity and cryptographic category.
- **CycloneDX v1.6 CBOM API:** `http://localhost:3333/api/cbom`
- **JSON Findings API:** `http://localhost:3333/api/scan`
- **Standalone HTML Report:** `http://localhost:3333/report`

---

## 9. CI/CD Integration & GitHub Actions

QuantaScan provides a native GitHub Action (`action.yml`):

```yaml
name: Post-Quantum Cryptography Audit
on: [push, pull_request]

jobs:
  pqc-audit:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Run QuantaScan CBOM & Vulnerability Check
        uses: ./action.yml
        with:
          target-dir: '.'
          format: 'cyclonedx-cbom'
          output: 'target/cbom.json'
          fail-on: 'critical'
          cnsa-mode: 'true'
      - name: Upload CBOM Artifact
        uses: actions/upload-artifact@v4
        with:
          name: cryptographic-bill-of-materials
          path: target/cbom.json
```

---

## 10. Pushing QuantaScan to GitHub

To push this repository to your GitHub account:

### Step 1: Authenticate with GitHub CLI
```bash
gh auth login
```
Follow the interactive prompt to authenticate via web browser or personal access token.

### Step 2: Create Remote Repository & Push
```bash
cd /Users/shivanshsinghchauhan/.gemini/antigravity/scratch/quantascan

# Option A: Automatic via GitHub CLI
gh repo create quantascan --public --source=. --remote=origin --push

# Option B: Manual via Git Remote URL
git remote add origin https://github.com/<YOUR_USERNAME>/quantascan.git
git branch -M main
git push -u origin main
```

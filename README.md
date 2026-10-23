# QuantaScan ⚡
### Developer-First Post-Quantum Cryptography (PQC) Static Analysis CLI & Automated CycloneDX v1.6 CBOM Generator

[![NIST FIPS 203](https://img.shields.io/badge/NIST-FIPS%20203%20ML--KEM-blue.svg)](https://csrc.nist.gov/pubs/fips/203/final)
[![NIST FIPS 204](https://img.shields.io/badge/NIST-FIPS%20204%20ML--DSA-blue.svg)](https://csrc.nist.gov/pubs/fips/204/final)
[![NIST FIPS 205](https://img.shields.io/badge/NIST-FIPS%20205%20SLH--DSA-blue.svg)](https://csrc.nist.gov/pubs/fips/205/final)
[![CNSA 2.0](https://img.shields.io/badge/NSA-CNSA%202.0%20Compliant-red.svg)](https://media.defense.gov/2022/Sep/07/2003071876/-1/-1/0/CSA_CNSA_2.0_ALGORITHMS_.PDF)
[![CycloneDX v1.6](https://img.shields.io/badge/CycloneDX-v1.6%20CBOM-brightgreen.svg)](https://cyclonedx.org/)

**QuantaScan** is a high-performance static analysis CLI that detects pre-quantum and deprecated cryptographic algorithms across **Python, JavaScript/TypeScript, Go, and Java** codebases without executing code. Using AST queries and static call graphs, QuantaScan maps legacy primitives to NIST-standardized Post-Quantum replacements (FIPS 203 ML-KEM, FIPS 204 ML-DSA, FIPS 205 SLH-DSA, and CNSA 2.0 mandates), calculates a **Quantum Vulnerability Index (QVI)**, and exports standard-compliant **CycloneDX v1.6 Cryptographic Bill of Materials (CBOM)**.

---

## 🚀 Key Features

- **Multi-Language AST Analysis:** Scans Python (`cryptography`, `pycryptodome`, `hashlib`, `ssl`), JavaScript/TypeScript (`crypto`, `node-rsa`, `elliptic`, `tweetnacl`, `@noble/curves`), Go (`crypto/rsa`, `crypto/ecdsa`, `crypto/elliptic`, `crypto/ecdh`, `golang.org/x/crypto`), and Java (`java.security.*`, `javax.crypto.*`, `org.bouncycastle.*`).
- **Context-Aware Call Graph Matchers:** Accurately distinguishes between ephemeral key exchanges, digital signatures (sign vs verify), and data-at-rest encryption.
- **Automated CycloneDX v1.6 CBOM Generation:** Outputs machine-readable CBOM JSON complete with `type: "cryptographic-asset"`, `cryptoProperties` (asset type, primitives, curve parameters, classical & quantum security categories), occurrence evidence, and linked quantum risk vulnerabilities.
- **Quantum Vulnerability Index (QVI):** Normalized 0–100 quantum threat score and Post-Quantum Readiness Score (%).
- **CNSA 2.0 Strict Mode:** Validates strict compliance against NSA Commercial National Security Algorithm Suite 2.0 timelines (flags SHA-256 and AES-128 as violations).
- **Hardcoded Secret & Key Extraction:** Pinpoints embedded PEM private keys (RSA, EC, PKCS#8), X.509 certificates, and legacy broken ciphers (DES, 3DES, RC4, MD5).
- **Concrete Migration Advisories:** Delivers code snippets and migration guides for Python, TypeScript, Go, and Java.
- **Zero-Exit CI/CD Integration:** Supports `--fail-on=[low|medium|high|critical]` for gating pull requests, accompanied by a native GitHub Action (`action.yml`).

---

## 📦 Installation & Quick Start

### Global Installation
```bash
npm install -g quantascan
```

### Local / Project Installation
```bash
npm install --save-dev quantascan
```

### Direct Execution with npx
```bash
npx quantascan .
```

---

## 🛠️ CLI Usage & Flags

```bash
pqc-scan [target-dir] [options]
```

### Options

| Flag | Description | Default |
| :--- | :--- | :--- |
| `-f, --format <format>` | Output format: `cli-table`, `json`, `cyclonedx-cbom`, `html` | `cli-table` |
| `-s, --min-severity <level>` | Minimum severity threshold: `low`, `medium`, `high`, `critical` | `low` |
| `--cnsa-mode` | Strict enforcement of CNSA 2.0 timelines and algorithm mandates | `false` |
| `-o, --output <filepath>` | Save assessment or CBOM output to specified file path | `stdout` |
| `--fail-on <level>` | Exit with code 1 if findings meet or exceed severity: `low`, `medium`, `high`, `critical` | `none` |
| `-h, --help` | Display command help | |

### Examples

#### 1. Colorized Terminal Audit
```bash
pqc-scan ./src
```

#### 2. Generate CycloneDX 1.6 CBOM
```bash
pqc-scan ./src --format=cyclonedx-cbom --output=cbom.json
```

#### 3. Strict CNSA 2.0 Mode
```bash
pqc-scan ./src --cnsa-mode
```

#### 4. Generate Interactive HTML Report
```bash
pqc-scan ./src --format=html --output=pqc-report.html
```

#### 5. CI/CD Gate (Fail build on any critical finding)
```bash
pqc-scan ./src --fail-on=critical
```

---

## 🔬 Cryptographic Replacement Matrix

| Legacy Primitive | Quantum Vulnerability | Standard Replacement | NIST Standard |
| :--- | :--- | :--- | :--- |
| **RSA Key Encapsulation (OAEP)** | Shor's Algorithm ($\mathcal{O}((\log N)^3)$) | **ML-KEM-768** / **ML-KEM-1024** | **FIPS 203** |
| **ECDH (P-256, secp256k1, X25519)** | Shor's Algorithm (Discrete Log) | **ML-KEM-768** or **Hybrid X25519+ML-KEM-768** | **FIPS 203** |
| **RSA Signatures (PKCS#1 v1.5 / PSS)** | Shor's Forgery Attack | **ML-DSA-65** / **SLH-DSA-128s** | **FIPS 204 / 205** |
| **ECDSA (P-256, P-384) & Ed25519** | Shor's Forgery Attack | **ML-DSA-65** / **ML-DSA-87** | **FIPS 204** |
| **AES-128** | Grover's Algorithm ($\sqrt{N}$ speedup $\to$ 64-bit security) | **AES-256-GCM** | **CNSA 2.0 / SP 800-38D** |
| **SHA-256** | BHT Collision Search / CNSA 2.0 Sub-Threshold | **SHA-384** or **SHA-512** | **FIPS 180-4 / CNSA 2.0** |
| **DES / 3DES / RC4** | Broken Classical & Quantum Weaknesses | **AES-256-GCM** | **CNSA 2.0** |

---

## 📜 CycloneDX v1.6 CBOM Specification

QuantaScan produces CycloneDX v1.6 CBOM files adhering to the ECMA-424 standard. Each discovered cryptographic asset includes:

```json
{
  "type": "cryptographic-asset",
  "bom-ref": "crypto-asset-3-py-rsa-generate",
  "name": "RSA-2048",
  "description": "Classical RSA-2048 Key Generation (Vulnerable to Shor's Algorithm)",
  "cryptoProperties": {
    "assetType": "algorithm",
    "algorithmProperties": {
      "primitive": "key-exchange",
      "parameterSetIdentifier": "2048-bit",
      "executionEnvironment": "software-plain",
      "implementationPlatform": "generic",
      "certificationLevel": "none",
      "cryptoFunctions": ["key-agree", "generate"],
      "classicalSecurityLevel": 112,
      "nistQuantumSecurityLevel": 0
    }
  },
  "evidence": {
    "occurrences": [
      {
        "location": "src/auth/keys.py",
        "line": 42,
        "offset": 19,
        "symbol": "RSA-2048",
        "additionalContext": "private_key = rsa.generate_private_key(65537, 2048)"
      }
    ]
  },
  "properties": [
    { "name": "pqc:replacement", "value": "ML-KEM-768 or ML-KEM-1024" },
    { "name": "pqc:nistStandard", "value": "FIPS 203" },
    { "name": "pqc:cnsaCompliant", "value": "false" }
  ]
}
```

---

## 🤖 GitHub Action Workflow Integration

Add the following step to your `.github/workflows/security.yml`:

```yaml
name: Post-Quantum Cryptography Audit
on: [push, pull_request]

jobs:
  pqc-scan:
    runs-on: ubuntu-latest
    steps:
      - name: Checkout Repository
        uses: actions/checkout@v4

      - name: Run QuantaScan CBOM & Vulnerability Check
        uses: ./action.yml # Or quantascan/quantascan@v1
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

## 🧪 Testing & Verification

QuantaScan includes test suites covering all AST parser grammars, CBOM schema generation, and QVI scoring logic:

```bash
# Run unit and integration tests
npm test

# Build TypeScript to dist
npm run build
```

---

## 📄 License

Apache-2.0 License.

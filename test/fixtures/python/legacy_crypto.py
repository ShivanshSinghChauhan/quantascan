"""
Legacy Cryptographic Test Fixture (Python)
Intentional pre-quantum primitives for QuantaScan verification:
- RSA-2048 key generation
- ECDH secp256r1 key exchange
- X25519 & Ed25519
- AES-128 Grover key longevity risk
- SHA-256 CNSA 2.0 sub-threshold hash
- Deprecated PyCrypto and hardcoded RSA private key
"""

import hashlib
import os
from cryptography.hazmat.primitives.asymmetric import rsa, ec, x25519, ed25519
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from Crypto.Cipher import AES  # Legacy PyCrypto import

# 1. Hardcoded Pre-Quantum RSA Private Key
MOCK_RSA_KEY = """
-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEAzpQeF5vK7M811y9b5F6o7iZ9jV9v21sL8P9Zq4W8sX...
[MOCK RSA 2048 BIT KEY DATA FOR SCANNER TEST]
-----END RSA PRIVATE KEY-----
"""

def generate_legacy_rsa():
    # RSA Key Generation
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    return private_key

def establish_ecdh():
    # Pre-quantum ECDH on NIST P-256
    server_key = ec.generate_private_key(ec.SECP256R1())
    client_key = ec.generate_private_key(ec.SECP256R1())
    shared_secret = server_key.exchange(ec.ECDH(), client_key.public_key())
    return shared_secret

def generate_x25519_and_ed25519():
    kem_priv = x25519.X25519PrivateKey.generate()
    sig_priv = ed25519.Ed25519PrivateKey.generate()
    return kem_priv, sig_priv

def encrypt_aes_128(plaintext: bytes):
    # AES-128 Grover vulnerability
    key_128 = os.urandom(16)  # 128-bit key
    cipher = Cipher(algorithms.AES(key_128), modes.CBC(os.urandom(16)))
    encryptor = cipher.encryptor()
    return encryptor.update(plaintext) + encryptor.finalize()

def digest_sha256(data: bytes):
    # SHA-256 Sub-threshold under CNSA 2.0
    return hashlib.sha256(data).hexdigest()

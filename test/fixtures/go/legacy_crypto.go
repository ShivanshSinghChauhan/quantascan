package main

import (
	"crypto/aes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
)

// Intentional legacy crypto patterns for QuantaScan static analysis

func GenerateRSAKey() (*rsa.PrivateKey, error) {
	// RSA-2048 key generation (Shor's algorithm risk)
	return rsa.GenerateKey(rand.Reader, 2048)
}

func GenerateECDSAKey() (*ecdsa.PrivateKey, error) {
	// Pre-quantum P-256 ECDSA key generation
	return ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
}

func EncryptAES128(plaintext []byte) ([]byte, error) {
	// 16 bytes = 128-bit key (Grover's algorithm speedup vulnerability)
	key16 := make([]byte, 16)
	rand.Read(key16)
	block, err := aes.NewCipher(key16)
	if err != nil {
		return nil, err
	}
	_ = block
	return plaintext, nil
}

func HashSHA256(data []byte) [32]byte {
	// CNSA 2.0 sub-threshold check
	return sha256.Sum256(data)
}

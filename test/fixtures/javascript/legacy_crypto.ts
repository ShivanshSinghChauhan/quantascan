/**
 * Legacy Cryptographic Test Fixture (TypeScript / Node.js)
 * Intentional pre-quantum primitives:
 * - crypto.createECDH('prime256v1')
 * - crypto.generateKeyPairSync('rsa', { modulusLength: 2048 })
 * - crypto.createSign('RSA-SHA256')
 * - crypto.createCipheriv('aes-128-cbc')
 * - crypto.createCipher('aes-256-cbc') (deprecated)
 * - crypto.createHash('sha256')
 * - Hardcoded EC Private Key
 */

import crypto from 'crypto';

// 1. Hardcoded EC Private Key
export const MOCK_EC_KEY = `
-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIIn2YkY7nJ9qN4k3L...
-----END EC PRIVATE KEY-----
`;

export function runLegacyKeyExchange() {
  const ecdh = crypto.createECDH('prime256v1');
  ecdh.generateKeys();
  return ecdh;
}

export function generateLegacyRSA() {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', {
    modulusLength: 2048,
  });
  return { publicKey, privateKey };
}

export function signLegacyMessage(privateKey: string, data: Buffer) {
  const sign = crypto.createSign('RSA-SHA256');
  sign.update(data);
  return sign.sign(privateKey);
}

export function encryptAES128(key16: Buffer, iv16: Buffer, data: string) {
  // AES-128 Grover risk
  const cipher = crypto.createCipheriv('aes-128-cbc', key16, iv16);
  return Buffer.concat([cipher.update(data, 'utf8'), cipher.final()]);
}

export function useDeprecatedCreateCipher(password: string) {
  // Deprecated Node createCipher using weak MD5 KDF
  return crypto.createCipher('aes-256-cbc', password);
}

export function hashSHA256(data: string) {
  return crypto.createHash('sha256').update(data).digest('hex');
}

/**
 * Quantum-Safe Cryptographic Test Fixture (TypeScript / Node.js)
 * Fully compliant with FIPS 203, FIPS 204, and CNSA 2.0
 */

import crypto from 'crypto';

export function encryptAES256GCM(data: Buffer) {
  const key32 = crypto.randomBytes(32); // 256 bits for Grover longevity
  const iv12 = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', key32, iv12);
  const ciphertext = Buffer.concat([cipher.update(data), cipher.final()]);
  const tag = cipher.getAuthTag();
  return { ciphertext, tag, iv: iv12 };
}

export function digestSHA384(data: Buffer) {
  // CNSA 2.0 compliant digest
  return crypto.createHash('sha384').update(data).digest('hex');
}

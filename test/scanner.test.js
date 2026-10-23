import { describe, it } from 'node:test';
import assert from 'node:assert';
import path from 'path';
import { PQCScanner } from '../src/engine/scanner.js';
describe('PQCScanner Static Analysis Engine', () => {
    it('detects Python legacy cryptographic primitives with zero false negatives', async () => {
        const scanner = new PQCScanner();
        const result = await scanner.scan({
            targetDir: path.resolve('test/fixtures/python'),
            minSeverity: 'low',
        });
        const algos = result.findings.map((f) => f.algorithm);
        assert(result.findings.length >= 6, `Expected >= 6 findings, got ${result.findings.length}`);
        assert(algos.some((a) => a.includes('RSA-2048')), 'Did not detect RSA-2048');
        assert(algos.some((a) => a.includes('ECDH') || a.includes('P-256')), 'Did not detect ECDH / P-256');
        assert(algos.some((a) => a.includes('AES-128')), 'Did not detect AES-128');
        assert(algos.some((a) => a.includes('SHA-256')), 'Did not detect SHA-256');
        assert(algos.some((a) => a.includes('RSA Private Key')), 'Did not detect hardcoded RSA PEM');
        assert(algos.some((a) => a.includes('PyCrypto')), 'Did not detect PyCrypto import');
    });
    it('detects JavaScript/TypeScript legacy cryptographic primitives', async () => {
        const scanner = new PQCScanner();
        const result = await scanner.scan({
            targetDir: path.resolve('test/fixtures/javascript'),
            minSeverity: 'low',
        });
        const algos = result.findings.map((f) => f.algorithm);
        assert(result.findings.length >= 5, `Expected >= 5 findings, got ${result.findings.length}`);
        assert(algos.some((a) => a.includes('ECDH')), 'Did not detect Node ECDH');
        assert(algos.some((a) => a.includes('RSA')), 'Did not detect Node RSA');
        assert(algos.some((a) => a.includes('AES-128')), 'Did not detect AES-128');
        assert(algos.some((a) => a.includes('createCipher')), 'Did not detect deprecated createCipher');
        assert(algos.some((a) => a.includes('Elliptic Curve Private Key')), 'Did not detect hardcoded EC PEM');
    });
    it('detects Go legacy cryptographic primitives', async () => {
        const scanner = new PQCScanner();
        const result = await scanner.scan({
            targetDir: path.resolve('test/fixtures/go'),
            minSeverity: 'low',
        });
        const algos = result.findings.map((f) => f.algorithm);
        assert(result.findings.length >= 3, `Expected >= 3 findings, got ${result.findings.length}`);
        assert(algos.some((a) => a.includes('rsa')), 'Did not detect Go RSA');
        assert(algos.some((a) => a.includes('ecdsa') || a.includes('P-256')), 'Did not detect Go ECDSA');
        assert(algos.some((a) => a.includes('aes')), 'Did not detect Go AES-128');
    });
    it('detects Java legacy cryptographic primitives', async () => {
        const scanner = new PQCScanner();
        const result = await scanner.scan({
            targetDir: path.resolve('test/fixtures/java'),
            minSeverity: 'low',
        });
        const algos = result.findings.map((f) => f.algorithm);
        assert(result.findings.length >= 4, `Expected >= 4 findings, got ${result.findings.length}`);
        assert(algos.some((a) => a.includes('RSA')), 'Did not detect Java RSA KeyPairGenerator');
        assert(algos.some((a) => a.includes('EC')), 'Did not detect Java EC KeyPairGenerator');
        assert(algos.some((a) => a.includes('DES')), 'Did not detect Java DES Cipher');
        assert(algos.some((a) => a.includes('Certificate')), 'Did not detect hardcoded Certificate');
    });
});

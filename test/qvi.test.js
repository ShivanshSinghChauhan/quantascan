import { describe, it } from 'node:test';
import assert from 'node:assert';
import path from 'path';
import { PQCScanner } from '../src/engine/scanner.js';
import { QuantumScoringEngine } from '../src/engine/qvi.js';
describe('Quantum Vulnerability Index (QVI) Engine', () => {
    it('assigns 0 QVI and 100% readiness to zero findings', () => {
        const qvi = QuantumScoringEngine.calculateQVI([]);
        const readiness = QuantumScoringEngine.calculateReadiness(qvi);
        assert.strictEqual(qvi, 0);
        assert.strictEqual(readiness, 100);
    });
    it('calculates elevated QVI and reduced readiness for legacy codebase', async () => {
        const scanner = new PQCScanner();
        const result = await scanner.scan({
            targetDir: path.resolve('test/fixtures/python'),
        });
        assert(result.summary.quantumVulnerabilityIndex > 50, `Expected QVI > 50, got ${result.summary.quantumVulnerabilityIndex}`);
        assert(result.summary.postQuantumReadiness < 50, `Expected readiness < 50, got ${result.summary.postQuantumReadiness}`);
        assert.strictEqual(result.summary.cnsaCompliant, false);
        assert(result.summary.criticalDeprecations.length > 0);
    });
    it('enforces strict CNSA mode severity upgrades', async () => {
        const scanner = new PQCScanner();
        const standardResult = await scanner.scan({
            targetDir: path.resolve('test/fixtures/python'),
            cnsaMode: false,
        });
        const cnsaResult = await scanner.scan({
            targetDir: path.resolve('test/fixtures/python'),
            cnsaMode: true,
        });
        // In CNSA mode, SHA-256 and AES-128 are upgraded
        const standardSha = standardResult.findings.find((f) => f.algorithm.includes('SHA-256'));
        const cnsaSha = cnsaResult.findings.find((f) => f.algorithm.includes('SHA-256'));
        assert(standardSha?.severity === 'low');
        assert(cnsaSha?.severity === 'high');
    });
});

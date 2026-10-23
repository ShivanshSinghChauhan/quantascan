import { describe, it } from 'node:test';
import assert from 'node:assert';
import path from 'path';
import { PQCScanner } from '../dist/engine/scanner.js';
import { CBOMGenerator } from '../dist/formatters/cbom-generator.js';

describe('CycloneDX v1.6 CBOM Generator', () => {
  it('generates schema-compliant CycloneDX 1.6 CBOM with cryptographic properties', async () => {
    const scanner = new PQCScanner();
    const result = await scanner.scan({
      targetDir: path.resolve('test/fixtures/python'),
      minSeverity: 'low',
    });

    const cbom = CBOMGenerator.generate(result);

    assert.strictEqual(cbom.bomFormat, 'CycloneDX');
    assert.strictEqual(cbom.specVersion, '1.6');
    assert.strictEqual(cbom.version, 1);
    assert(cbom.serialNumber.startsWith('urn:uuid:'));
    assert(cbom.components.length > 0);

    for (const comp of cbom.components) {
      assert.strictEqual(comp.type, 'cryptographic-asset');
      assert(comp['bom-ref']);
      assert(comp.cryptoProperties);
      assert(comp.cryptoProperties.assetType);
      if (comp.cryptoProperties.algorithmProperties) {
        assert(comp.cryptoProperties.algorithmProperties.primitive);
      }
      assert(comp.evidence?.occurrences && comp.evidence.occurrences.length > 0);
    }

    assert(cbom.vulnerabilities && cbom.vulnerabilities.length > 0);
    for (const vuln of cbom.vulnerabilities) {
      assert(vuln.id.startsWith('PQC-VULN-'));
      assert(vuln.affects && vuln.affects.length > 0);
    }
  });
});

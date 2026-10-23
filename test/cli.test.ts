import { describe, it } from 'node:test';
import assert from 'node:assert';
import path from 'path';
import fs from 'fs';
import { runCLI } from '../dist/cli.js';

describe('QuantaScan CLI Interface', () => {
  it('executes cli-table format with exit code 0 when fail-on is not exceeded', async () => {
    const exitCode = await runCLI([
      'node',
      'pqc-scan',
      path.resolve('test/fixtures/python'),
      '--format=cli-table',
    ]);
    assert.strictEqual(exitCode, 0);
  });

  it('fails with exit code 1 when --fail-on critical threshold is violated', async () => {
    const exitCode = await runCLI([
      'node',
      'pqc-scan',
      path.resolve('test/fixtures/python'),
      '--fail-on=critical',
    ]);
    assert.strictEqual(exitCode, 1);
  });

  it('outputs CycloneDX v1.6 CBOM to a file', async () => {
    const tmpOut = path.resolve('test/fixtures/output-cbom.json');
    const exitCode = await runCLI([
      'node',
      'pqc-scan',
      path.resolve('test/fixtures/javascript'),
      '--format=cyclonedx-cbom',
      `--output=${tmpOut}`,
    ]);

    assert.strictEqual(exitCode, 0);
    assert(fs.existsSync(tmpOut));
    const content = JSON.parse(fs.readFileSync(tmpOut, 'utf-8'));
    assert.strictEqual(content.bomFormat, 'CycloneDX');
    assert.strictEqual(content.specVersion, '1.6');
    fs.unlinkSync(tmpOut);
  });

  it('outputs HTML interactive report to a file', async () => {
    const tmpHtml = path.resolve('test/fixtures/output-report.html');
    const exitCode = await runCLI([
      'node',
      'pqc-scan',
      path.resolve('test/fixtures/go'),
      '--format=html',
      `--output=${tmpHtml}`,
    ]);

    assert.strictEqual(exitCode, 0);
    assert(fs.existsSync(tmpHtml));
    const content = fs.readFileSync(tmpHtml, 'utf-8');
    assert(content.includes('QuantaScan CBOM & Vulnerability Report'));
    fs.unlinkSync(tmpHtml);
  });
});

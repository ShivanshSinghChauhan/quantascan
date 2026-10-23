import fs from 'fs';
import path from 'path';
import { Command } from 'commander';
import pc from 'picocolors';
import { PQCScanner } from './engine/scanner.js';
import { TableFormatter } from './formatters/table-formatter.js';
import { JsonFormatter } from './formatters/json-formatter.js';
import { CBOMGenerator } from './formatters/cbom-generator.js';
import { HtmlFormatter } from './formatters/html-formatter.js';
import { startLocalServer } from './server/web-server.js';
import { ScanOptions, Severity } from './types/index.js';

const SEVERITY_LEVELS: Record<Severity, number> = {
  info: 0,
  low: 1,
  medium: 2,
  high: 3,
  critical: 4,
};

export async function runCLI(argv = process.argv): Promise<number> {
  const program = new Command();

  program
    .name('pqc-scan')
    .description('QuantaScan: Post-Quantum Cryptography (PQC) Static Analysis CLI & CycloneDX v1.6 CBOM Generator')
    .version('1.0.0')
    .argument('[target-dir]', 'Directory to scan for cryptographic primitives', '.')
    .option(
      '-f, --format <format>',
      'Output format (cli-table, json, cyclonedx-cbom, html)',
      'cli-table'
    )
    .option(
      '-s, --min-severity <severity>',
      'Minimum severity threshold (low, medium, high, critical)',
      'low'
    )
    .option(
      '--cnsa-mode',
      'Strict enforcement of CNSA 2.0 algorithms and migration timelines',
      false
    )
    .option('-o, --output <filepath>', 'Save assessment / CBOM output to specified file path')
    .option(
      '--fail-on <severity>',
      'Exit with non-zero code if findings meet or exceed this severity (low, medium, high, critical)'
    )
    .option('--serve', 'Launch local interactive testing web portal and CBOM server', false)
    .option('-p, --port <port>', 'Port for local testing web portal', '3333');

  program.parse(argv);

  const options = program.opts();
  const [targetDirArg] = program.args;
  const targetDir = targetDirArg || '.';

  // Check if --serve is requested
  if (options.serve) {
    const port = parseInt(options.port, 10) || 3333;
    startLocalServer(port, targetDir);
    // Keep alive for server
    return new Promise(() => {});
  }

  const scanOptions: ScanOptions = {
    targetDir,
    format: options.format as any,
    minSeverity: options.minSeverity as any,
    cnsaMode: Boolean(options.cnsaMode),
    output: options.output,
    failOn: options.failOn as any,
  };

  try {
    const scanner = new PQCScanner();
    const result = await scanner.scan(scanOptions);

    let outputContent = '';
    const format = scanOptions.format || 'cli-table';

    switch (format) {
      case 'json':
        outputContent = JsonFormatter.render(result);
        break;
      case 'cyclonedx-cbom': {
        const cbom = CBOMGenerator.generate(result);
        outputContent = JSON.stringify(cbom, null, 2);
        break;
      }
      case 'html':
        outputContent = HtmlFormatter.render(result);
        break;
      case 'cli-table':
      default:
        outputContent = TableFormatter.render(result);
        break;
    }

    // Write to output file if specified
    if (scanOptions.output) {
      const outPath = path.resolve(scanOptions.output);
      fs.mkdirSync(path.dirname(outPath), { recursive: true });
      fs.writeFileSync(outPath, outputContent, 'utf-8');
      console.log(pc.green(`✔ Assessment saved to ${outPath}`));
    } else {
      console.log(outputContent);
    }

    // CI/CD Gate check via --fail-on
    if (scanOptions.failOn) {
      const threshold = SEVERITY_LEVELS[scanOptions.failOn];
      const failingFindings = result.findings.filter(
        (f) => SEVERITY_LEVELS[f.severity] >= threshold
      );

      if (failingFindings.length > 0) {
        console.error(
          pc.red(
            pc.bold(
              `\n✖ CI/CD Failure: Found ${failingFindings.length} cryptographic finding(s) with severity >= ${scanOptions.failOn.toUpperCase()}`
            )
          )
        );
        return 1;
      }
    }

    return 0;
  } catch (err: any) {
    console.error(pc.red(`Error during PQC scan: ${err.message}`));
    return 2;
  }
}

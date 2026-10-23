import http from 'http';
import url from 'url';
import path from 'path';
import pc from 'picocolors';
import { PQCScanner } from '../engine/scanner.js';
import { CBOMGenerator } from '../formatters/cbom-generator.js';
import { HtmlFormatter } from '../formatters/html-formatter.js';
import { JsonFormatter } from '../formatters/json-formatter.js';

export function startLocalServer(port = 3333, defaultDir = './test/fixtures'): http.Server {
  const scanner = new PQCScanner();

  const server = http.createServer(async (req, res) => {
    try {
      const parsedUrl = url.parse(req.url || '/', true);
      const pathname = parsedUrl.pathname || '/';

      // 1. API: /api/scan
      if (pathname === '/api/scan') {
        const targetDir = (parsedUrl.query.dir as string) || defaultDir;
        const cnsaMode = parsedUrl.query.cnsa === 'true';
        const minSeverity = (parsedUrl.query.severity as any) || 'low';

        const result = await scanner.scan({
          targetDir: path.resolve(targetDir),
          cnsaMode,
          minSeverity,
        });

        res.writeHead(200, {
          'Content-Type': 'application/json; charset=utf-8',
          'Access-Control-Allow-Origin': '*',
        });
        res.end(JsonFormatter.render(result));
        return;
      }

      // 2. API: /api/cbom
      if (pathname === '/api/cbom') {
        const targetDir = (parsedUrl.query.dir as string) || defaultDir;
        const cnsaMode = parsedUrl.query.cnsa === 'true';

        const result = await scanner.scan({
          targetDir: path.resolve(targetDir),
          cnsaMode,
        });
        const cbom = CBOMGenerator.generate(result);

        res.writeHead(200, {
          'Content-Type': 'application/json; charset=utf-8',
          'Access-Control-Allow-Origin': '*',
          'Content-Disposition': 'inline; filename="cyclonedx-cbom.json"',
        });
        res.end(JSON.stringify(cbom, null, 2));
        return;
      }

      // 3. /report - Standalone HTML view
      if (pathname === '/report') {
        const targetDir = (parsedUrl.query.dir as string) || defaultDir;
        const cnsaMode = parsedUrl.query.cnsa === 'true';

        const result = await scanner.scan({
          targetDir: path.resolve(targetDir),
          cnsaMode,
        });
        const html = HtmlFormatter.render(result);

        res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
        res.end(html);
        return;
      }

      // 4. Default: Live Interactive Dashboard
      if (pathname === '/') {
        const targetDir = (parsedUrl.query.dir as string) || defaultDir;
        const cnsaMode = parsedUrl.query.cnsa === 'true';

        const result = await scanner.scan({
          targetDir: path.resolve(targetDir),
          cnsaMode,
        });
        const html = renderLiveDashboard(result, targetDir, cnsaMode, port);

        res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
        res.end(html);
        return;
      }

      res.writeHead(404, { 'Content-Type': 'text/plain' });
      res.end('Not Found');
    } catch (err: any) {
      res.writeHead(500, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: err.message }));
    }
  });

  server.listen(port, () => {
    console.log(pc.green(pc.bold(`\n⚡ QuantaScan Live Testing Server running at:`)));
    console.log(pc.cyan(pc.bold(`   ➜ http://localhost:${port}/`)));
    console.log(pc.gray(`   ➜ CycloneDX 1.6 CBOM API: http://localhost:${port}/api/cbom`));
    console.log(pc.gray(`   ➜ JSON Findings API:     http://localhost:${port}/api/scan`));
    console.log(pc.gray(`   ➜ Standalone Report:     http://localhost:${port}/report\n`));
  });

  return server;
}

function renderLiveDashboard(
  result: any,
  currentDir: string,
  cnsaMode: boolean,
  port: number
): string {
  const { summary, findings } = result;
  const findingsJson = JSON.stringify(findings);

  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>QuantaScan Live Portal - PQC Static Analysis & CBOM Engine</title>
  <style>
    :root {
      --bg: #090d16;
      --card-bg: #121824;
      --border: #232d42;
      --text: #e2e8f0;
      --text-muted: #94a3b8;
      --accent: #38bdf8;
      --accent-glow: rgba(56, 189, 248, 0.2);
      --critical: #ef4444;
      --high: #f97316;
      --medium: #eab308;
      --low: #38bdf8;
      --safe: #22c55e;
    }
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body {
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
      background: var(--bg);
      color: var(--text);
      line-height: 1.5;
      padding: 24px;
    }
    .container { max-width: 1400px; margin: 0 auto; }
    .header {
      display: flex;
      justify-content: space-between;
      align-items: center;
      padding-bottom: 20px;
      border-bottom: 1px solid var(--border);
      margin-bottom: 24px;
      flex-wrap: wrap;
      gap: 16px;
    }
    .brand {
      display: flex;
      align-items: center;
      gap: 14px;
    }
    .brand-icon {
      width: 44px;
      height: 44px;
      background: linear-gradient(135deg, #0284c7, #6366f1);
      border-radius: 10px;
      display: flex;
      align-items: center;
      justify-content: center;
      font-size: 22px;
      font-weight: bold;
      color: #fff;
      box-shadow: 0 0 20px rgba(99, 102, 241, 0.4);
    }
    .brand-text h1 { font-size: 22px; font-weight: 800; color: #fff; letter-spacing: -0.5px; }
    .brand-text p { font-size: 13px; color: var(--text-muted); }
    .toolbar-actions { display: flex; gap: 10px; align-items: center; }
    .btn {
      padding: 8px 16px;
      border-radius: 6px;
      font-size: 13px;
      font-weight: 600;
      text-decoration: none;
      cursor: pointer;
      display: inline-flex;
      align-items: center;
      gap: 6px;
      border: 1px solid transparent;
      transition: all 0.2s ease;
    }
    .btn-primary {
      background: #0284c7;
      color: #fff;
    }
    .btn-primary:hover { background: #0369a1; }
    .btn-secondary {
      background: var(--card-bg);
      color: var(--text);
      border-color: var(--border);
    }
    .btn-secondary:hover { background: #1e293b; border-color: #475569; }
    .btn-cnsa {
      background: ${cnsaMode ? 'rgba(239, 68, 68, 0.2)' : 'rgba(255,255,255,0.05)'};
      color: ${cnsaMode ? 'var(--critical)' : 'var(--text-muted)'};
      border-color: ${cnsaMode ? 'var(--critical)' : 'var(--border)'};
    }
    .scan-form {
      background: var(--card-bg);
      border: 1px solid var(--border);
      border-radius: 8px;
      padding: 16px;
      margin-bottom: 24px;
      display: flex;
      gap: 12px;
      align-items: center;
      flex-wrap: wrap;
    }
    .input-field {
      flex: 1;
      min-width: 280px;
      background: #0a0e17;
      border: 1px solid var(--border);
      padding: 9px 14px;
      border-radius: 6px;
      color: #fff;
      font-family: monospace;
      font-size: 13px;
    }
    .input-field:focus { outline: none; border-color: var(--accent); }
    .stats-row {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(240px, 1fr));
      gap: 16px;
      margin-bottom: 24px;
    }
    .card {
      background: var(--card-bg);
      border: 1px solid var(--border);
      border-radius: 10px;
      padding: 20px;
      position: relative;
      overflow: hidden;
    }
    .card::before {
      content: '';
      position: absolute;
      top: 0; left: 0; right: 0; height: 3px;
      background: linear-gradient(90deg, var(--accent), transparent);
    }
    .card-label { font-size: 12px; text-transform: uppercase; font-weight: 700; color: var(--text-muted); letter-spacing: 0.5px; }
    .card-value { font-size: 32px; font-weight: 800; margin-top: 6px; }
    .card-subtext { font-size: 12px; color: var(--text-muted); margin-top: 4px; }
    .filter-panel {
      display: flex;
      gap: 12px;
      margin-bottom: 20px;
      flex-wrap: wrap;
      align-items: center;
    }
    .filter-select {
      background: var(--card-bg);
      border: 1px solid var(--border);
      color: var(--text);
      padding: 8px 12px;
      border-radius: 6px;
      font-size: 13px;
    }
    .findings-list { display: flex; flex-direction: column; gap: 16px; }
    .finding-item {
      background: var(--card-bg);
      border: 1px solid var(--border);
      border-radius: 8px;
      overflow: hidden;
      transition: border-color 0.2s;
    }
    .finding-item:hover { border-color: #3b82f6; }
    .finding-top {
      padding: 14px 18px;
      background: rgba(255,255,255,0.02);
      border-bottom: 1px solid var(--border);
      display: flex;
      justify-content: space-between;
      align-items: center;
      flex-wrap: wrap;
      gap: 10px;
    }
    .finding-title-group { display: flex; align-items: center; gap: 10px; }
    .badge-sev {
      font-size: 11px;
      font-weight: 700;
      padding: 3px 8px;
      border-radius: 4px;
      text-transform: uppercase;
    }
    .badge-critical { background: rgba(239,68,68,0.2); color: #f87171; border: 1px solid #ef4444; }
    .badge-high { background: rgba(249,115,22,0.2); color: #fb923c; border: 1px solid #f97316; }
    .badge-medium { background: rgba(234,179,8,0.2); color: #facc15; border: 1px solid #eab308; }
    .badge-low { background: rgba(56,189,248,0.2); color: #7dd3fc; border: 1px solid #38bdf8; }
    .finding-loc { font-family: monospace; font-size: 12px; color: var(--text-muted); }
    .finding-inner { padding: 18px; }
    .code-box {
      background: #080c14;
      border: 1px solid #1e293b;
      padding: 12px 14px;
      border-radius: 6px;
      font-family: monospace;
      font-size: 13px;
      margin: 10px 0;
      color: #93c5fd;
      overflow-x: auto;
    }
    .advisory-box {
      background: rgba(56, 189, 248, 0.05);
      border-left: 3px solid var(--accent);
      padding: 14px;
      border-radius: 0 6px 6px 0;
      margin-top: 12px;
    }
    .advisory-header { font-size: 13px; font-weight: 700; color: var(--accent); margin-bottom: 4px; }
    .snippet-preview {
      background: #080c14;
      padding: 10px;
      border-radius: 4px;
      margin-top: 8px;
      font-family: monospace;
      font-size: 12px;
      color: #cbd5e1;
      white-space: pre-wrap;
    }
  </style>
</head>
<body>
  <div class="container">
    <div class="header">
      <div class="brand">
        <div class="brand-icon">⚡</div>
        <div class="brand-text">
          <h1>QuantaScan Post-Quantum Assessment Portal</h1>
          <p>NIST FIPS 203 (ML-KEM) • FIPS 204 (ML-DSA) • FIPS 205 (SLH-DSA) • NSA CNSA 2.0</p>
        </div>
      </div>
      <div class="toolbar-actions">
        <a href="/api/cbom?dir=${encodeURIComponent(currentDir)}&cnsa=${cnsaMode}" target="_blank" class="btn btn-primary">
          📦 Download CycloneDX 1.6 CBOM
        </a>
        <a href="/api/scan?dir=${encodeURIComponent(currentDir)}&cnsa=${cnsaMode}" target="_blank" class="btn btn-secondary">
          { } JSON API
        </a>
        <a href="/report?dir=${encodeURIComponent(currentDir)}&cnsa=${cnsaMode}" target="_blank" class="btn btn-secondary">
          📊 Full HTML Report
        </a>
      </div>
    </div>

    <form class="scan-form" method="GET" action="/">
      <label style="font-size: 13px; font-weight: 600;">Target Directory:</label>
      <input type="text" name="dir" class="input-field" value="${currentDir}" placeholder="Relative or absolute path to codebase">
      <label class="btn btn-cnsa" style="cursor: pointer;">
        <input type="checkbox" name="cnsa" value="true" ${cnsaMode ? 'checked' : ''} onchange="this.form.submit()"> Strict CNSA 2.0 Mode
      </label>
      <button type="submit" class="btn btn-primary">Run Static Scan</button>
    </form>

    <div class="stats-row">
      <div class="card">
        <div class="card-label">Quantum Vulnerability Index (QVI)</div>
        <div class="card-value" style="color: ${summary.quantumVulnerabilityIndex > 50 ? 'var(--critical)' : summary.quantumVulnerabilityIndex > 20 ? 'var(--high)' : 'var(--safe)'}">
          ${summary.quantumVulnerabilityIndex} <span style="font-size: 16px; font-weight: 500; color: var(--text-muted);">/ 100</span>
        </div>
        <div class="card-subtext">Exponential dampening factor across ${summary.findingsCount} findings</div>
      </div>
      <div class="card">
        <div class="card-label">Post-Quantum Readiness</div>
        <div class="card-value" style="color: ${summary.postQuantumReadiness >= 75 ? 'var(--safe)' : summary.postQuantumReadiness >= 40 ? 'var(--high)' : 'var(--critical)'}">
          ${summary.postQuantumReadiness}%
        </div>
        <div class="card-subtext">${summary.postQuantumReadiness >= 80 ? 'Quantum Resilient' : 'Urgent Migration Needed'}</div>
      </div>
      <div class="card">
        <div class="card-label">Total Cryptographic Assets</div>
        <div class="card-value">${summary.totalCryptoAssets}</div>
        <div class="card-subtext">${summary.totalFilesScanned} source files scanned in ${summary.scanDurationMs}ms</div>
      </div>
      <div class="card">
        <div class="card-label">CNSA 2.0 Compliance</div>
        <div class="card-value" style="color: ${summary.cnsaCompliant ? 'var(--safe)' : 'var(--critical)'}">
          ${summary.cnsaCompliant ? '✔ Compliant' : '✖ Violations'}
        </div>
        <div class="card-subtext">${summary.cnsaViolationsCount} sub-threshold algorithm occurrences</div>
      </div>
    </div>

    <div class="filter-panel">
      <input type="text" id="liveSearch" class="input-field" placeholder="Filter by algorithm, file, or rule ID..." style="max-width: 400px;">
      <select id="liveSeverity" class="filter-select">
        <option value="all">All Severities</option>
        <option value="critical">Critical (${summary.bySeverity.critical})</option>
        <option value="high">High (${summary.bySeverity.high})</option>
        <option value="medium">Medium (${summary.bySeverity.medium})</option>
        <option value="low">Low (${summary.bySeverity.low})</option>
      </select>
      <select id="liveCategory" class="filter-select">
        <option value="all">All Crypto Categories</option>
        <option value="asymmetric-kem">Asymmetric Key Exchange / KEM</option>
        <option value="digital-signature">Digital Signatures</option>
        <option value="symmetric-crypto">Symmetric Ciphers (Grover)</option>
        <option value="hash-function">Hash Functions</option>
        <option value="hardcoded-secret">Hardcoded Secrets</option>
        <option value="legacy-provider">Legacy Providers</option>
      </select>
    </div>

    <div id="findingsList" class="findings-list"></div>
  </div>

  <script>
    const findings = ${findingsJson};
    const list = document.getElementById('findingsList');
    const search = document.getElementById('liveSearch');
    const sevFilter = document.getElementById('liveSeverity');
    const catFilter = document.getElementById('liveCategory');

    function renderFindings() {
      const q = search.value.toLowerCase();
      const sev = sevFilter.value;
      const cat = catFilter.value;

      const items = findings.filter(f => {
        if (sev !== 'all' && f.severity !== sev) return false;
        if (cat !== 'all' && f.category !== cat) return false;
        if (q && !f.algorithm.toLowerCase().includes(q) && !f.file.toLowerCase().includes(q) && !f.title.toLowerCase().includes(q)) return false;
        return true;
      });

      if (items.length === 0) {
        list.innerHTML = '<div style="padding: 40px; text-align: center; color: var(--text-muted); background: var(--card-bg); border-radius: 8px;">No cryptographic findings match the selected criteria.</div>';
        return;
      }

      list.innerHTML = items.map(f => \`
        <div class="finding-item">
          <div class="finding-top">
            <div class="finding-title-group">
              <span class="badge-sev badge-\${f.severity}">\${f.severity}</span>
              <strong style="color: #fff; font-size: 15px;">\${f.title}</strong>
            </div>
            <div class="finding-loc">
              <code>\${f.file}:\${f.location.startLine}:\${f.location.startColumn}</code>
              <span style="margin-left: 8px; opacity: 0.7;">[\${f.language.toUpperCase()}]</span>
            </div>
          </div>
          <div class="finding-inner">
            <p style="color: #cbd5e1; font-size: 14px;">\${f.description}</p>
            <div class="code-box"><code>\${escapeHtml(f.codeSnippet)}</code></div>
            <div class="advisory-box">
              <div class="advisory-header">➡ Recommended NIST Replacement: \${f.remediation.replacement} (\${f.remediation.nistStandard})</div>
              <p style="font-size: 13px; color: #e2e8f0;">\${f.remediation.advisory}</p>
              \${f.remediation.codeSnippet ? \`<div class="snippet-preview">\${escapeHtml(f.remediation.codeSnippet)}</div>\` : ''}
            </div>
          </div>
        </div>
      \`).join('');
    }

    function escapeHtml(s) {
      if (!s) return '';
      return s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
    }

    search.addEventListener('input', renderFindings);
    sevFilter.addEventListener('change', renderFindings);
    catFilter.addEventListener('change', renderFindings);
    renderFindings();
  </script>
</body>
</html>`;
}

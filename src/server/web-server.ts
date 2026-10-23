import http from 'http';
import url from 'url';
import path from 'path';
import pc from 'picocolors';
import { PQCScanner } from '../engine/scanner.js';
import { CBOMGenerator } from '../formatters/cbom-generator.js';
import { HtmlFormatter } from '../formatters/html-formatter.js';
import { JsonFormatter } from '../formatters/json-formatter.js';
import { Language } from '../types/index.js';

export function startLocalServer(port = 3333, defaultDir = './test/fixtures'): http.Server {
  const scanner = new PQCScanner();

  const server = http.createServer(async (req, res) => {
    try {
      const parsedUrl = url.parse(req.url || '/', true);
      const pathname = parsedUrl.pathname || '/';

      // Enable CORS for web integration
      res.setHeader('Access-Control-Allow-Origin', '*');
      res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
      res.setHeader('Access-Control-Allow-Headers', 'Content-Type');

      if (req.method === 'OPTIONS') {
        res.writeHead(204);
        res.end();
        return;
      }

      // POST /api/analyze - In-browser live code snippet scanner
      if (req.method === 'POST' && pathname === '/api/analyze') {
        let body = '';
        req.on('data', (chunk) => {
          body += chunk;
        });
        req.on('end', async () => {
          try {
            const data = JSON.parse(body || '{}');
            const code = data.code || '';
            const language = (data.language || 'python') as Language;
            const cnsaMode = Boolean(data.cnsa);

            const result = await scanner.scanSource(code, language, { cnsaMode });
            const cbom = CBOMGenerator.generate(result);

            res.writeHead(200, { 'Content-Type': 'application/json; charset=utf-8' });
            res.end(JSON.stringify({ result, cbom }));
          } catch (e: any) {
            res.writeHead(400, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ error: e.message }));
          }
        });
        return;
      }

      // GET /api/scan
      if (pathname === '/api/scan') {
        const targetDir = (parsedUrl.query.dir as string) || defaultDir;
        const cnsaMode = parsedUrl.query.cnsa === 'true';
        const minSeverity = (parsedUrl.query.severity as any) || 'low';

        const result = await scanner.scan({
          targetDir: path.resolve(targetDir),
          cnsaMode,
          minSeverity,
        });

        res.writeHead(200, { 'Content-Type': 'application/json; charset=utf-8' });
        res.end(JsonFormatter.render(result));
        return;
      }

      // GET /api/cbom
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
          'Content-Disposition': 'inline; filename="cyclonedx-cbom.json"',
        });
        res.end(JSON.stringify(cbom, null, 2));
        return;
      }

      // GET /report
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

      // Default: Live Interactive Dashboard with Online Code Playground
      if (pathname === '/') {
        const targetDir = (parsedUrl.query.dir as string) || defaultDir;
        const cnsaMode = parsedUrl.query.cnsa === 'true';

        const result = await scanner.scan({
          targetDir: path.resolve(targetDir),
          cnsaMode,
        });
        const html = renderLiveDashboard(result, targetDir, cnsaMode);

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
    console.log(pc.green(pc.bold(`\n⚡ QuantaScan Web Portal ready on port ${port}`)));
  });

  return server;
}

function renderLiveDashboard(result: any, currentDir: string, cnsaMode: boolean): string {
  const { summary, findings } = result;
  const findingsJson = JSON.stringify(findings);

  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>QuantaScan - Post-Quantum Cryptography Assessment Cloud Portal</title>
  <style>
    :root {
      --bg: #090d16;
      --card-bg: #121824;
      --border: #232d42;
      --text: #e2e8f0;
      --text-muted: #94a3b8;
      --accent: #38bdf8;
      --critical: #ef4444;
      --high: #f97316;
      --medium: #eab308;
      --low: #38bdf8;
      --safe: #22c55e;
    }
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body {
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
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
    .brand { display: flex; align-items: center; gap: 14px; }
    .brand-icon {
      width: 44px; height: 44px;
      background: linear-gradient(135deg, #0284c7, #6366f1);
      border-radius: 10px;
      display: flex; align-items: center; justify-content: center;
      font-size: 22px; font-weight: bold; color: #fff;
      box-shadow: 0 0 20px rgba(99, 102, 241, 0.4);
    }
    .brand-text h1 { font-size: 22px; font-weight: 800; color: #fff; }
    .brand-text p { font-size: 13px; color: var(--text-muted); }
    .toolbar-actions { display: flex; gap: 10px; align-items: center; }
    .btn {
      padding: 8px 16px; border-radius: 6px; font-size: 13px; font-weight: 600;
      text-decoration: none; cursor: pointer; display: inline-flex; align-items: center; gap: 6px;
      border: 1px solid transparent; transition: all 0.2s;
    }
    .btn-primary { background: #0284c7; color: #fff; }
    .btn-primary:hover { background: #0369a1; }
    .btn-secondary { background: var(--card-bg); color: var(--text); border-color: var(--border); }
    .btn-secondary:hover { background: #1e293b; }
    .tabs { display: flex; gap: 8px; margin-bottom: 20px; border-bottom: 1px solid var(--border); padding-bottom: 10px; }
    .tab-btn {
      background: transparent; color: var(--text-muted); border: none; padding: 8px 16px;
      border-radius: 6px; font-size: 14px; font-weight: 600; cursor: pointer;
    }
    .tab-btn.active { background: #1e293b; color: #fff; border-bottom: 2px solid var(--accent); }
    .playground-box {
      background: var(--card-bg); border: 1px solid var(--border); border-radius: 8px;
      padding: 20px; margin-bottom: 24px; display: none;
    }
    .playground-box.active { display: block; }
    textarea.code-editor {
      width: 100%; height: 180px; background: #080c14; border: 1px solid var(--border);
      border-radius: 6px; padding: 12px; font-family: monospace; font-size: 13px; color: #e2e8f0;
      resize: vertical;
    }
    .stats-row {
      display: grid; grid-template-columns: repeat(auto-fit, minmax(240px, 1fr)); gap: 16px; margin-bottom: 24px;
    }
    .card {
      background: var(--card-bg); border: 1px solid var(--border); border-radius: 10px; padding: 20px;
    }
    .card-label { font-size: 12px; text-transform: uppercase; font-weight: 700; color: var(--text-muted); }
    .card-value { font-size: 32px; font-weight: 800; margin-top: 6px; }
    .findings-list { display: flex; flex-direction: column; gap: 16px; }
    .finding-item {
      background: var(--card-bg); border: 1px solid var(--border); border-radius: 8px; overflow: hidden;
    }
    .finding-top {
      padding: 14px 18px; background: rgba(255,255,255,0.02); border-bottom: 1px solid var(--border);
      display: flex; justify-content: space-between; align-items: center;
    }
    .badge-sev { font-size: 11px; font-weight: 700; padding: 3px 8px; border-radius: 4px; text-transform: uppercase; }
    .badge-critical { background: rgba(239,68,68,0.2); color: #f87171; border: 1px solid #ef4444; }
    .badge-high { background: rgba(249,115,22,0.2); color: #fb923c; border: 1px solid #f97316; }
    .badge-medium { background: rgba(234,179,8,0.2); color: #facc15; border: 1px solid #eab308; }
    .badge-low { background: rgba(56,189,248,0.2); color: #7dd3fc; border: 1px solid #38bdf8; }
    .code-box {
      background: #080c14; border: 1px solid #1e293b; padding: 12px; border-radius: 6px;
      font-family: monospace; font-size: 13px; margin: 10px 0; color: #93c5fd; overflow-x: auto;
    }
    .advisory-box {
      background: rgba(56, 189, 248, 0.05); border-left: 3px solid var(--accent); padding: 14px;
      border-radius: 0 6px 6px 0; margin-top: 12px;
    }
  </style>
</head>
<body>
  <div class="container">
    <div class="header">
      <div class="brand">
        <div class="brand-icon">⚡</div>
        <div class="brand-text">
          <h1>QuantaScan Post-Quantum Assessment Cloud Portal</h1>
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

    <div class="tabs">
      <button class="tab-btn active" id="tabScanner" onclick="switchTab('scanner')">Directory Scanner</button>
      <button class="tab-btn" id="tabPlayground" onclick="switchTab('playground')">Online Code Playground</button>
    </div>

    <div id="scannerSection">
      <form class="scan-form" method="GET" action="/" style="display: flex; gap: 12px; margin-bottom: 24px; align-items: center;">
        <input type="text" name="dir" class="btn-secondary" style="flex: 1; padding: 9px 14px; border-radius: 6px; color: #fff;" value="${currentDir}">
        <label style="font-size: 13px; cursor: pointer; display: flex; align-items: center; gap: 6px;">
          <input type="checkbox" name="cnsa" value="true" ${cnsaMode ? 'checked' : ''} onchange="this.form.submit()"> Strict CNSA 2.0 Mode
        </label>
        <button type="submit" class="btn btn-primary">Scan Directory</button>
      </form>

      <div class="stats-row">
        <div class="card">
          <div class="card-label">Quantum Vulnerability Index (QVI)</div>
          <div class="card-value" style="color: ${summary.quantumVulnerabilityIndex > 50 ? 'var(--critical)' : summary.quantumVulnerabilityIndex > 20 ? 'var(--high)' : 'var(--safe)'}">
            ${summary.quantumVulnerabilityIndex} / 100
          </div>
        </div>
        <div class="card-card card">
          <div class="card-label">Post-Quantum Readiness</div>
          <div class="card-value" style="color: ${summary.postQuantumReadiness >= 75 ? 'var(--safe)' : 'var(--critical)'}">
            ${summary.postQuantumReadiness}%
          </div>
        </div>
        <div class="card">
          <div class="card-label">Total Cryptographic Assets</div>
          <div class="card-value">${summary.totalCryptoAssets}</div>
        </div>
        <div class="card">
          <div class="card-label">CNSA 2.0 Compliance</div>
          <div class="card-value" style="color: ${summary.cnsaCompliant ? 'var(--safe)' : 'var(--critical)'}">
            ${summary.cnsaCompliant ? '✔ Compliant' : '✖ Violations'}
          </div>
        </div>
      </div>

      <div id="findingsList" class="findings-list"></div>
    </div>

    <div id="playgroundSection" class="playground-box">
      <h3 style="margin-bottom: 10px; color: #fff;">Test Code Snippets in Real-Time</h3>
      <div style="display: flex; gap: 10px; margin-bottom: 12px;">
        <select id="pgLang" class="btn-secondary" style="padding: 6px 12px; border-radius: 4px;">
          <option value="python">Python</option>
          <option value="typescript">TypeScript / JavaScript</option>
          <option value="go">Go</option>
          <option value="java">Java</option>
        </select>
        <label style="font-size: 13px; display: flex; align-items: center; gap: 6px;">
          <input type="checkbox" id="pgCnsa"> Strict CNSA 2.0 Mode
        </label>
        <button class="btn btn-primary" onclick="analyzeSnippet()">Analyze Code</button>
      </div>
      <textarea id="pgCode" class="code-editor" placeholder="Paste cryptographic code here (e.g. from cryptography.hazmat.primitives.asymmetric import rsa)"></textarea>
      <div id="pgOutput" style="margin-top: 16px;"></div>
    </div>
  </div>

  <script>
    const findings = ${findingsJson};
    const list = document.getElementById('findingsList');

    function renderFindings(items) {
      if (!items || items.length === 0) {
        list.innerHTML = '<div style="padding: 40px; text-align: center; color: var(--text-muted); background: var(--card-bg); border-radius: 8px;">No cryptographic findings.</div>';
        return;
      }
      list.innerHTML = items.map(f => \`
        <div class="finding-item">
          <div class="finding-top">
            <div style="display: flex; align-items: center; gap: 8px;">
              <span class="badge-sev badge-\${f.severity}">\${f.severity}</span>
              <strong style="color: #fff;">\${f.title}</strong>
            </div>
            <div style="font-family: monospace; font-size: 12px; color: var(--text-muted);">
              \${f.file}:\${f.location.startLine} [\${f.language.toUpperCase()}]
            </div>
          </div>
          <div style="padding: 16px;">
            <p style="font-size: 14px; margin-bottom: 8px;">\${f.description}</p>
            <div class="code-box"><code>\${escapeHtml(f.codeSnippet)}</code></div>
            <div class="advisory-box">
              <div style="font-size: 13px; font-weight: 700; color: var(--accent);">➡ Recommended Replacement: \${f.remediation.replacement} (\${f.remediation.nistStandard})</div>
              <p style="font-size: 13px; margin-top: 4px;">\${f.remediation.advisory}</p>
            </div>
          </div>
        </div>
      \`).join('');
    }

    function switchTab(tab) {
      if (tab === 'scanner') {
        document.getElementById('scannerSection').style.display = 'block';
        document.getElementById('playgroundSection').style.display = 'none';
        document.getElementById('tabScanner').classList.add('active');
        document.getElementById('tabPlayground').classList.remove('active');
      } else {
        document.getElementById('scannerSection').style.display = 'none';
        document.getElementById('playgroundSection').style.display = 'block';
        document.getElementById('tabScanner').classList.remove('active');
        document.getElementById('tabPlayground').classList.add('active');
      }
    }

    async function analyzeSnippet() {
      const code = document.getElementById('pgCode').value;
      const language = document.getElementById('pgLang').value;
      const cnsa = document.getElementById('pgCnsa').checked;
      const out = document.getElementById('pgOutput');
      out.innerHTML = '<div style="color: var(--accent);">Analyzing AST for post-quantum vulnerabilities...</div>';

      try {
        const res = await fetch('/api/analyze', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ code, language, cnsa })
        });
        const data = await res.json();
        const f = data.result.findings;
        out.innerHTML = '<div style="margin-bottom: 12px; font-weight: bold;">Discovered ' + f.length + ' Cryptographic Finding(s) (QVI: ' + data.result.summary.quantumVulnerabilityIndex + '/100):</div>' +
          f.map(item => '<div class="finding-item" style="margin-bottom: 10px;"><div class="finding-top"><span class="badge-sev badge-' + item.severity + '">' + item.severity + '</span> <strong>' + item.title + '</strong></div><div style="padding: 12px;"><p>' + item.description + '</p><div class="advisory-box"><strong>Replacement:</strong> ' + item.remediation.replacement + ' (' + item.remediation.nistStandard + ')</div></div></div>').join('');
      } catch (err) {
        out.innerHTML = '<div style="color: var(--critical);">Analysis error: ' + err.message + '</div>';
      }
    }

    function escapeHtml(s) {
      if (!s) return '';
      return s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
    }

    renderFindings(findings);
  </script>
</body>
</html>`;
}

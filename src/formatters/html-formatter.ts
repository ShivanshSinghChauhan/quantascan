import { ScanResult, CryptoFinding } from '../types/index.js';

export class HtmlFormatter {
  public static render(result: ScanResult): string {
    const { summary, findings } = result;

    const findingsJson = JSON.stringify(findings);
    const summaryJson = JSON.stringify(summary);

    return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>QuantaScan - Post-Quantum Cryptography Assessment</title>
  <style>
    :root {
      --bg: #0d1117;
      --card-bg: #161b22;
      --border: #30363d;
      --text: #c9d1d9;
      --text-muted: #8b949e;
      --accent: #58a6ff;
      --critical: #f85149;
      --high: #d29922;
      --medium: #e3b341;
      --low: #388bfd;
      --safe: #3fb950;
    }
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body {
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Helvetica, Arial, sans-serif;
      background: var(--bg);
      color: var(--text);
      line-height: 1.5;
      padding: 24px;
    }
    .header {
      border-bottom: 1px solid var(--border);
      padding-bottom: 20px;
      margin-bottom: 24px;
      display: flex;
      justify-content: space-between;
      align-items: center;
    }
    .title { font-size: 24px; font-weight: 700; color: #fff; display: flex; align-items: center; gap: 10px; }
    .badge {
      font-size: 11px;
      padding: 3px 8px;
      border-radius: 12px;
      background: #238636;
      color: #fff;
      font-weight: 600;
    }
    .stats-grid {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
      gap: 16px;
      margin-bottom: 24px;
    }
    .stat-card {
      background: var(--card-bg);
      border: 1px solid var(--border);
      border-radius: 8px;
      padding: 18px;
    }
    .stat-value { font-size: 28px; font-weight: 700; margin-top: 4px; }
    .stat-label { font-size: 12px; text-transform: uppercase; color: var(--text-muted); font-weight: 600; }
    .qvi-high { color: var(--critical); }
    .qvi-med { color: var(--high); }
    .qvi-low { color: var(--safe); }
    .filter-bar {
      display: flex;
      gap: 12px;
      margin-bottom: 20px;
      flex-wrap: wrap;
    }
    .search-input, .select-filter {
      background: var(--card-bg);
      border: 1px solid var(--border);
      color: var(--text);
      padding: 8px 12px;
      border-radius: 6px;
      font-size: 14px;
    }
    .finding-card {
      background: var(--card-bg);
      border: 1px solid var(--border);
      border-radius: 8px;
      margin-bottom: 16px;
      overflow: hidden;
    }
    .finding-header {
      padding: 12px 16px;
      background: rgba(255,255,255,0.02);
      border-bottom: 1px solid var(--border);
      display: flex;
      justify-content: space-between;
      align-items: center;
    }
    .finding-body { padding: 16px; }
    .tag {
      font-size: 11px;
      font-weight: 600;
      padding: 2px 8px;
      border-radius: 4px;
      text-transform: uppercase;
    }
    .tag-critical { background: rgba(248,81,73,0.15); color: var(--critical); border: 1px solid var(--critical); }
    .tag-high { background: rgba(210,153,34,0.15); color: var(--high); border: 1px solid var(--high); }
    .tag-medium { background: rgba(227,179,65,0.15); color: var(--medium); border: 1px solid var(--medium); }
    .tag-low { background: rgba(56,139,253,0.15); color: var(--low); border: 1px solid var(--low); }
    pre {
      background: #090d13;
      padding: 12px;
      border-radius: 6px;
      overflow-x: auto;
      font-family: monospace;
      font-size: 13px;
      margin-top: 8px;
      border: 1px solid var(--border);
    }
    .remediation-box {
      background: rgba(56,139,253,0.06);
      border-left: 3px solid var(--accent);
      padding: 12px;
      margin-top: 12px;
      border-radius: 0 4px 4px 0;
    }
    .remediation-title { font-weight: 600; color: var(--accent); font-size: 13px; }
  </style>
</head>
<body>
  <div class="header">
    <div>
      <div class="title">
        <span>⚡ QuantaScan CBOM & Vulnerability Report</span>
        <span class="badge">NIST FIPS 203 / 204 / 205</span>
      </div>
      <div style="color: var(--text-muted); font-size: 13px; margin-top: 4px;">
        Post-Quantum Cryptography Static Analysis & Migration Advisory
      </div>
    </div>
    <div style="text-align: right; font-size: 12px; color: var(--text-muted);">
      <div>Scan Timestamp: ${summary.timestamp}</div>
      <div>Target: <code>${summary.targetDir}</code></div>
    </div>
  </div>

  <div class="stats-grid">
    <div class="stat-card">
      <div class="stat-label">Quantum Vulnerability Index (QVI)</div>
      <div class="stat-value ${summary.quantumVulnerabilityIndex > 50 ? 'qvi-high' : summary.quantumVulnerabilityIndex > 20 ? 'qvi-med' : 'qvi-low'}">
        ${summary.quantumVulnerabilityIndex} / 100
      </div>
    </div>
    <div class="stat-card">
      <div class="stat-label">Post-Quantum Readiness</div>
      <div class="stat-value" style="color: ${summary.postQuantumReadiness >= 75 ? 'var(--safe)' : 'var(--critical)'}">
        ${summary.postQuantumReadiness}%
      </div>
    </div>
    <div class="stat-card">
      <div class="stat-label">Total Cryptographic Assets</div>
      <div class="stat-value">${summary.totalCryptoAssets}</div>
    </div>
    <div class="stat-card">
      <div class="stat-label">CNSA 2.0 Compliance</div>
      <div class="stat-value" style="color: ${summary.cnsaCompliant ? 'var(--safe)' : 'var(--critical)'}">
        ${summary.cnsaCompliant ? '✔ Compliant' : '✖ Non-Compliant'}
      </div>
    </div>
  </div>

  <div class="filter-bar">
    <input type="text" id="searchInput" class="search-input" placeholder="Search algorithms, files, rules..." style="flex: 1;">
    <select id="severitySelect" class="select-filter">
      <option value="all">All Severities</option>
      <option value="critical">Critical</option>
      <option value="high">High</option>
      <option value="medium">Medium</option>
      <option value="low">Low</option>
    </select>
    <select id="categorySelect" class="select-filter">
      <option value="all">All Categories</option>
      <option value="asymmetric-kem">Asymmetric KEM</option>
      <option value="digital-signature">Digital Signature</option>
      <option value="symmetric-crypto">Symmetric Crypto</option>
      <option value="hash-function">Hash Function</option>
      <option value="hardcoded-secret">Hardcoded Secret</option>
      <option value="legacy-provider">Legacy Provider</option>
    </select>
  </div>

  <div id="findingsContainer"></div>

  <script>
    const findings = ${findingsJson};
    const container = document.getElementById('findingsContainer');
    const searchInput = document.getElementById('searchInput');
    const severitySelect = document.getElementById('severitySelect');
    const categorySelect = document.getElementById('categorySelect');

    function render() {
      const q = searchInput.value.toLowerCase();
      const sev = severitySelect.value;
      const cat = categorySelect.value;

      const filtered = findings.filter(f => {
        if (sev !== 'all' && f.severity !== sev) return false;
        if (cat !== 'all' && f.category !== cat) return false;
        if (q && !f.algorithm.toLowerCase().includes(q) && !f.file.toLowerCase().includes(q) && !f.title.toLowerCase().includes(q)) return false;
        return true;
      });

      if (filtered.length === 0) {
        container.innerHTML = '<div style="padding: 40px; text-align: center; color: var(--text-muted);">No cryptographic findings matching current filters.</div>';
        return;
      }

      container.innerHTML = filtered.map(f => \`
        <div class="finding-card">
          <div class="finding-header">
            <div>
              <span class="tag tag-\${f.severity}">\${f.severity}</span>
              <strong style="margin-left: 8px; color: #fff;">\${f.title}</strong>
              <span style="color: var(--text-muted); font-size: 13px; margin-left: 8px;">\${f.file}:\${f.location.startLine}</span>
            </div>
            <div style="font-size: 12px; color: var(--text-muted);">
              \${f.language.toUpperCase()} | \${f.primitive.toUpperCase()}
            </div>
          </div>
          <div class="finding-body">
            <div style="font-size: 14px; margin-bottom: 8px;">\${f.description}</div>
            <pre><code>\${escapeHtml(f.codeSnippet)}</code></pre>
            <div class="remediation-box">
              <div class="remediation-title">➡ Recommended Replacement: \${f.remediation.replacement} (\${f.remediation.nistStandard})</div>
              <div style="font-size: 13px; margin-top: 4px;">\${f.remediation.advisory}</div>
              \${f.remediation.codeSnippet ? \`<pre style="margin-top: 8px;"><code>\${escapeHtml(f.remediation.codeSnippet)}</code></pre>\` : ''}
            </div>
          </div>
        </div>
      \`).join('');
    }

    function escapeHtml(str) {
      if (!str) return '';
      return str.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
    }

    searchInput.addEventListener('input', render);
    severitySelect.addEventListener('change', render);
    categorySelect.addEventListener('change', render);

    render();
  </script>
</body>
</html>`;
  }
}

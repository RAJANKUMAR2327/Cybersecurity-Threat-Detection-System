"""
apply_darkweb.py
Adds the Dark Web Monitor tab to index.html
"""
import os

path = os.path.join(
    os.path.dirname(os.path.abspath(__file__)),
    "dashboard", "index.html"
)

with open(path, "r", encoding="utf-8") as f:
    html = f.read()

# Check if already patched
if "panel-darkweb" in html:
    print("Already patched!")
    exit()

# ── 1. Add nav item ───────────────────────────────────────────
NAV = """
    <div class="nav-item" data-panel="darkweb" onclick="showPanel('darkweb', this)">
      <span class="nav-icon">🕵️</span> Dark Web
      <span class="nav-badge" id="nav-badge-darkweb" style="display:none">!</span>
    </div>
"""
html = html.replace(
    '<div class="nav-item" data-panel="reports"',
    NAV + '\n    <div class="nav-item" data-panel="reports"'
)

# ── 2. Add panel HTML ─────────────────────────────────────────
PANEL = """
    <!-- DARK WEB MONITOR -->
    <div class="panel" id="panel-darkweb">

      <!-- Stats Row -->
      <div style="display:grid;grid-template-columns:repeat(4,1fr);gap:12px;margin-bottom:16px">
        <div class="metric-card danger">
          <div class="metric-glow"></div>
          <div class="metric-label">TOTAL CHECKS</div>
          <div class="metric-value" id="dw-total">0</div>
          <div class="metric-sub">queries run</div>
        </div>
        <div class="metric-card danger">
          <div class="metric-glow"></div>
          <div class="metric-label">BREACHES FOUND</div>
          <div class="metric-value" id="dw-breached">0</div>
          <div class="metric-sub">compromised targets</div>
        </div>
        <div class="metric-card danger">
          <div class="metric-glow"></div>
          <div class="metric-label">CRITICAL FINDINGS</div>
          <div class="metric-value" id="dw-critical">0</div>
          <div class="metric-sub">immediate action needed</div>
        </div>
        <div class="metric-card purple">
          <div class="metric-glow"></div>
          <div class="metric-label">MONITORING</div>
          <div class="metric-value" id="dw-monitoring">0</div>
          <div class="metric-sub">targets watched</div>
        </div>
      </div>

      <div class="grid-2">

        <!-- Left: Query Panel -->
        <div style="display:flex;flex-direction:column;gap:16px">

          <!-- Query Box -->
          <div class="card">
            <div class="card-header">
              <div class="card-title">🕵️ DARK WEB BREACH CHECK</div>
            </div>
            <div class="card-body">
              <div class="font-mono text-dim" style="font-size:10px;letter-spacing:1.5px;margin-bottom:10px">
                CHECK AN IP, EMAIL ADDRESS, OR DOMAIN
              </div>
              <div style="display:flex;gap:8px;margin-bottom:12px">
                <input type="text" id="dw-query"
                  placeholder="IP: 185.220.101.5 | Email: user@domain.com | Domain: example.com"
                  style="flex:1;background:var(--bg-deep);border:1px solid var(--border);
                  color:var(--text-main);padding:8px 12px;font-family:var(--font-mono);
                  font-size:12px;border-radius:3px;outline:none">
                <select id="dw-type" style="background:var(--bg-deep);border:1px solid var(--border);
                  color:var(--text-main);padding:8px;font-family:var(--font-mono);
                  font-size:12px;border-radius:3px;outline:none">
                  <option value="auto">Auto-detect</option>
                  <option value="ip">IP Address</option>
                  <option value="email">Email</option>
                  <option value="domain">Domain</option>
                </select>
                <button class="btn primary" onclick="darkwebCheck()">CHECK</button>
              </div>

              <!-- Quick check buttons -->
              <div style="margin-bottom:12px">
                <div class="font-mono text-dim" style="font-size:10px;margin-bottom:6px">QUICK CHECK KNOWN THREATS:</div>
                <div style="display:flex;flex-wrap:wrap;gap:6px">
                  <button class="btn" style="font-size:10px;padding:3px 8px" onclick="quickCheck('185.220.101.5','ip')">185.220.101.5 (Tor)</button>
                  <button class="btn" style="font-size:10px;padding:3px 8px" onclick="quickCheck('45.142.212.100','ip')">45.142.212.100 (Botnet)</button>
                  <button class="btn" style="font-size:10px;padding:3px 8px" onclick="quickCheck('194.165.16.10','ip')">194.165.16.10 (Ransomware)</button>
                  <button class="btn" style="font-size:10px;padding:3px 8px" onclick="quickCheck('test@test.com','email')">test@test.com</button>
                </div>
              </div>

              <div id="dw-result"></div>
            </div>
          </div>

          <!-- API Keys -->
          <div class="card">
            <div class="card-header"><div class="card-title">🔑 API CONFIGURATION</div></div>
            <div class="card-body">
              <div class="form-group" style="margin-bottom:10px">
                <label>HAVEIBEENPWNED API KEY</label>
                <div style="display:flex;gap:8px;margin-top:4px">
                  <input type="password" id="hibp-key"
                    placeholder="Get free key at haveibeenpwned.com/API/Key"
                    style="flex:1;background:var(--bg-deep);border:1px solid var(--border);
                    color:var(--text-main);padding:8px;font-family:var(--font-mono);
                    font-size:12px;border-radius:3px;outline:none">
                  <button class="btn primary" onclick="saveDWConfig()">SAVE</button>
                </div>
              </div>
              <div id="dw-config-msg" class="font-mono text-dim" style="font-size:11px"></div>
              <div style="margin-top:12px;border-top:1px solid var(--border);padding-top:10px">
                <div class="font-mono text-dim" style="font-size:10px;line-height:1.8">
                  <span class="text-accent">Without API key:</span> Uses built-in threat DB + heuristics<br>
                  <span class="text-accent">With HIBP key:</span> Real breach data for emails + domains<br>
                  Free key at: <span class="text-green">haveibeenpwned.com/API/Key</span>
                </div>
              </div>
            </div>
          </div>

          <!-- Continuous Monitoring -->
          <div class="card">
            <div class="card-header">
              <div class="card-title">👁️ CONTINUOUS MONITORING</div>
              <div class="card-badge" id="badge-dw-monitor">0 targets</div>
            </div>
            <div class="card-body">
              <div style="display:flex;gap:8px;margin-bottom:12px">
                <input type="text" id="dw-monitor-query"
                  placeholder="IP, email, or domain to watch..."
                  style="flex:1;background:var(--bg-deep);border:1px solid var(--border);
                  color:var(--text-main);padding:8px;font-family:var(--font-mono);
                  font-size:12px;border-radius:3px;outline:none">
                <button class="btn primary" onclick="addMonitorTarget()">+ WATCH</button>
              </div>
              <div id="dw-monitor-list" style="max-height:180px;overflow-y:auto">
                <div class="text-dim font-mono" style="font-size:11px;padding:10px;text-align:center">
                  No targets being monitored
                </div>
              </div>
            </div>
          </div>
        </div>

        <!-- Right: Results History -->
        <div class="card" style="height:fit-content">
          <div class="card-header">
            <div class="card-title">📋 CHECK HISTORY</div>
            <div class="card-badge" id="badge-dw-count">0 checks</div>
          </div>
          <div id="dw-history" style="max-height:800px;overflow-y:auto">
            <div class="text-dim font-mono" style="font-size:11px;padding:20px;text-align:center">
              No checks run yet
            </div>
          </div>
        </div>
      </div>
    </div>
"""

html = html.replace("  </main>", PANEL + "\n  </main>")

# ── 3. Add JavaScript ─────────────────────────────────────────
JS = """
// ── DARK WEB MONITOR ─────────────────────────────────────────
async function darkwebCheck() {
  const query = document.getElementById('dw-query').value.trim();
  const type  = document.getElementById('dw-type').value;
  if (!query) return;
  showDWLoading(query);
  try {
    const r = await fetch('/api/darkweb/check', {
      method:'POST', headers:{'Content-Type':'application/json'},
      body: JSON.stringify({query, type})
    });
    const data = await r.json();
    renderDWResult(data);
    refreshDWHistory();
    refreshDWStats();
  } catch(e) {
    document.getElementById('dw-result').innerHTML =
      '<div class="font-mono text-red" style="font-size:11px;padding:10px">' + e.message + '</div>';
  }
}

function quickCheck(query, type) {
  document.getElementById('dw-query').value = query;
  document.getElementById('dw-type').value  = type;
  darkwebCheck();
}

function showDWLoading(query) {
  document.getElementById('dw-result').innerHTML = `
    <div style="background:var(--bg-deep);border:1px solid var(--border);border-radius:4px;padding:16px;margin-top:10px">
      <div class="font-mono text-dim" style="font-size:11px;display:flex;align-items:center;gap:10px">
        <div class="status-dot" style="animation-duration:0.5s"></div>
        Scanning dark web databases for: <span class="text-accent">${query}</span>...
      </div>
    </div>`;
}

function renderDWResult(d) {
  const rc = {
    LOW:'var(--green)', MEDIUM:'var(--yellow)',
    HIGH:'var(--orange)', CRITICAL:'var(--red)'
  };
  const color = rc[d.risk_level] || 'var(--text-dim)';
  const icons  = {LOW:'✅', MEDIUM:'⚠️', HIGH:'🔴', CRITICAL:'🚨'};
  const icon   = icons[d.risk_level] || '❓';

  const badges = [
    d.is_tor_exit         ? '<span style="background:rgba(170,68,255,0.2);border:1px solid #aa44ff;color:#cc88ff;padding:2px 8px;border-radius:2px;font-size:10px;margin:2px">🧅 TOR EXIT NODE</span>' : '',
    d.is_botnet           ? '<span style="background:rgba(255,34,68,0.2);border:1px solid var(--red);color:var(--red);padding:2px 8px;border-radius:2px;font-size:10px;margin:2px">🤖 BOTNET C2</span>' : '',
    d.is_ransomware_infra ? `<span style="background:rgba(255,34,68,0.3);border:1px solid var(--red);color:var(--red);padding:2px 8px;border-radius:2px;font-size:10px;margin:2px">💀 RANSOMWARE: ${d.ransomware_group}</span>` : '',
    d.found_in_breach     ? `<span style="background:rgba(255,102,0,0.2);border:1px solid var(--orange);color:var(--orange);padding:2px 8px;border-radius:2px;font-size:10px;margin:2px">⚠️ ${d.breach_count} BREACH(ES)</span>` : '',
  ].filter(Boolean).join('');

  document.getElementById('dw-result').innerHTML = `
    <div style="background:var(--bg-deep);border:2px solid ${color};border-radius:4px;padding:16px;margin-top:10px">

      <!-- Header -->
      <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:12px">
        <div>
          <span style="font-size:20px">${icon}</span>
          <span class="font-mono" style="font-size:16px;font-weight:700;color:var(--text-bright);margin-left:8px">${d.query}</span>
          <span class="font-mono text-dim" style="font-size:10px;margin-left:8px">${d.query_type.toUpperCase()}</span>
        </div>
        <div style="text-align:right">
          <div style="font-family:var(--font-title);font-size:24px;font-weight:700;color:${color}">${d.risk_score}</div>
          <div class="font-mono" style="font-size:10px;color:${color}">${d.risk_level} RISK</div>
        </div>
      </div>

      <!-- Badges -->
      ${badges ? `<div style="margin-bottom:12px;font-family:var(--font-mono)">${badges}</div>` : ''}

      <!-- Breach List -->
      ${d.breaches.length ? `
        <div style="margin-bottom:12px">
          <div class="font-mono text-accent" style="font-size:10px;letter-spacing:1.5px;margin-bottom:8px">FOUND IN ${d.breach_count} DATABASE(S):</div>
          ${d.breaches.map(b => `
            <div style="background:rgba(255,34,68,0.08);border-left:3px solid var(--red-dim);padding:8px 12px;margin-bottom:6px;border-radius:0 3px 3px 0">
              <div style="font-weight:700;color:var(--text-bright);font-size:12px">${b.name}</div>
              <div class="font-mono text-dim" style="font-size:10px">${b.type} | ${b.year} | Source: ${b.source}</div>
              ${b.description ? `<div class="font-mono text-dim" style="font-size:10px;margin-top:4px">${b.description}</div>` : ''}
            </div>`).join('')}
        </div>` : `
        <div style="color:var(--green);font-family:var(--font-mono);font-size:12px;margin-bottom:12px">
          ✓ Not found in breach databases
        </div>`}

      <!-- Recommendations -->
      ${d.recommendations.length ? `
        <div style="border-top:1px solid var(--border);padding-top:12px">
          <div class="font-mono text-accent" style="font-size:10px;letter-spacing:1.5px;margin-bottom:8px">RECOMMENDATIONS:</div>
          ${d.recommendations.map(r => `
            <div style="display:flex;gap:8px;margin-bottom:6px;font-family:var(--font-mono);font-size:11px">
              <span style="color:var(--accent)">▶</span>
              <span class="text-dim">${r}</span>
            </div>`).join('')}
        </div>` : ''}

      <!-- Actions -->
      <div style="border-top:1px solid var(--border);padding-top:10px;margin-top:10px;display:flex;gap:8px;flex-wrap:wrap">
        <button class="btn danger" style="font-size:11px;padding:4px 10px"
          onclick="document.getElementById('block-ip').value='${d.query}';showPanel('blocker',document.querySelector('[data-panel=blocker]'))">
          🚫 Block IP
        </button>
        <button class="btn" style="font-size:11px;padding:4px 10px"
          onclick="document.getElementById('intel-ip').value='${d.query}';showPanel('intel',document.querySelector('[data-panel=intel]'));lookupIP()">
          🔍 Intel Lookup
        </button>
        <button class="btn" style="font-size:11px;padding:4px 10px"
          onclick="document.getElementById('dw-monitor-query').value='${d.query}';addMonitorTarget()">
          👁️ Add to Monitor
        </button>
      </div>
    </div>`;

  // Flash nav badge if critical
  if (d.risk_level === 'CRITICAL') {
    const badge = document.getElementById('nav-badge-darkweb');
    badge.style.display = 'inline';
    badge.textContent = '!';
  }
}

async function refreshDWHistory() {
  try {
    const results = await (await fetch('/api/darkweb/results?n=30')).json();
    document.getElementById('badge-dw-count').textContent = results.length + ' checks';
    const rc = {LOW:'var(--green)',MEDIUM:'var(--yellow)',HIGH:'var(--orange)',CRITICAL:'var(--red)'};
    document.getElementById('dw-history').innerHTML = results.length ?
      results.map(d => `
        <div style="padding:10px 16px;border-bottom:1px solid rgba(15,61,92,0.3);cursor:pointer"
          onclick="document.getElementById('dw-query').value='${d.query}';document.getElementById('dw-type').value='${d.query_type}';renderDWResult(${JSON.stringify(d).replace(/\\/g,'\\\\').replace(/'/g,"\\'")})">
          <div style="display:flex;justify-content:space-between;align-items:center">
            <div>
              <span class="font-mono" style="color:var(--text-bright);font-weight:700">${d.query}</span>
              <span class="font-mono text-dim" style="font-size:10px;margin-left:8px">${d.query_type}</span>
            </div>
            <div style="display:flex;align-items:center;gap:8px">
              <span class="font-mono" style="font-size:16px;font-weight:700;color:${rc[d.risk_level]||'var(--text-dim)'}">${d.risk_score}</span>
              <span style="color:${rc[d.risk_level]||'var(--text-dim)'};font-size:10px;font-weight:700">${d.risk_level}</span>
            </div>
          </div>
          <div style="display:flex;gap:6px;margin-top:4px;flex-wrap:wrap">
            ${d.is_tor_exit ? '<span style="font-size:9px;color:#cc88ff;font-family:var(--font-mono)">🧅 TOR</span>' : ''}
            ${d.is_botnet ? '<span style="font-size:9px;color:var(--red);font-family:var(--font-mono)">🤖 BOTNET</span>' : ''}
            ${d.is_ransomware_infra ? '<span style="font-size:9px;color:var(--red);font-family:var(--font-mono)">💀 RANSOMWARE</span>' : ''}
            ${d.found_in_breach ? `<span style="font-size:9px;color:var(--orange);font-family:var(--font-mono)">⚠️ ${d.breach_count} BREACH</span>` : ''}
            <span class="font-mono text-dim" style="font-size:9px;margin-left:auto">${d.datetime}</span>
          </div>
        </div>`).join('') :
      '<div class="text-dim font-mono" style="font-size:11px;padding:20px;text-align:center">No checks run yet</div>';
  } catch(e) {}
}

async function refreshDWStats() {
  try {
    const s = await (await fetch('/api/darkweb/stats')).json();
    document.getElementById('dw-total').textContent    = s.total_checks;
    document.getElementById('dw-breached').textContent = s.breached_found;
    document.getElementById('dw-critical').textContent = s.critical_findings;
    document.getElementById('dw-monitoring').textContent = s.monitoring_targets;
  } catch(e) {}
}

async function saveDWConfig() {
  const key = document.getElementById('hibp-key').value.trim();
  try {
    await fetch('/api/darkweb/config', {
      method:'POST', headers:{'Content-Type':'application/json'},
      body: JSON.stringify({hibp_key: key})
    });
    document.getElementById('dw-config-msg').innerHTML =
      '<span class="text-green">✓ HIBP key saved — email/domain checks now use real data</span>';
  } catch(e) {
    document.getElementById('dw-config-msg').innerHTML =
      '<span class="text-red">✗ Failed to save</span>';
  }
}

async function addMonitorTarget() {
  const query = document.getElementById('dw-monitor-query').value.trim();
  if (!query) return;
  try {
    await fetch('/api/darkweb/monitor', {
      method:'POST', headers:{'Content-Type':'application/json'},
      body: JSON.stringify({query, type:'auto'})
    });
    document.getElementById('dw-monitor-query').value = '';
    refreshMonitorList();
    refreshDWStats();
  } catch(e) {}
}

async function removeMonitorTarget(query) {
  try {
    await fetch('/api/darkweb/monitor/' + encodeURIComponent(query), {method:'DELETE'});
    refreshMonitorList();
    refreshDWStats();
  } catch(e) {}
}

async function refreshMonitorList() {
  try {
    const list = await (await fetch('/api/darkweb/monitor/list')).json();
    document.getElementById('badge-dw-monitor').textContent = list.length + ' targets';
    document.getElementById('dw-monitor-list').innerHTML = list.length ?
      list.map(t => `
        <div style="display:flex;justify-content:space-between;align-items:center;
          padding:8px 4px;border-bottom:1px solid rgba(15,61,92,0.3)">
          <span class="font-mono text-accent" style="font-size:12px">${t.query}</span>
          <div style="display:flex;gap:6px;align-items:center">
            <span class="font-mono text-dim" style="font-size:10px">${t.type}</span>
            <button class="btn" style="padding:2px 6px;font-size:10px;border-color:var(--red);color:var(--red)"
              onclick="removeMonitorTarget('${t.query}')">✕</button>
          </div>
        </div>`).join('') :
      '<div class="text-dim font-mono" style="font-size:11px;padding:10px;text-align:center">No targets</div>';
  } catch(e) {}
}

// Hook into showPanel
const _origDW = showPanel;
showPanel = function(name, el) {
  _origDW(name, el);
  if (name === 'darkweb') {
    refreshDWHistory();
    refreshDWStats();
    refreshMonitorList();
  }
};

socket.on('darkweb_result', d => {
  refreshDWHistory();
  refreshDWStats();
});
"""

html = html.replace("</script>", JS + "\n</script>")

with open(path, "w", encoding="utf-8") as f:
    f.write(html)

print(f"Done! Dark Web Monitor added. File size: {len(html):,} chars")

path = "dashboard/index.html"
with open(path, encoding="utf-8") as f:
    html = f.read()

# Find and replace ALL showPanel definitions with one clean version
import re

# Remove all existing showPanel overrides
html = re.sub(r'var _pOrig = showPanel;.*?showPanel = function\(name, el\) \{.*?\};\s*', '', html, flags=re.DOTALL)
html = re.sub(r'var _orig\w+ = showPanel;.*?showPanel = function\(name, el\) \{.*?\};\s*', '', html, flags=re.DOTALL)
html = re.sub(r'// ── HOOK INTO showPanel.*?showPanel = function.*?\};\s*', '', html, flags=re.DOTALL)
html = re.sub(r'// ================================================================\s*// UNIFIED NAVIGATION.*?// ================================================================', '', html, flags=re.DOTALL)

# Remove the original showPanel function too
html = re.sub(r'function showPanel\(name, el\) \{.*?\n\}', '', html, flags=re.DOTALL)

# Insert ONE clean showPanel right before the clock
CLEAN_NAV = """
// ================================================================
// NAVIGATION - single clean definition
// ================================================================
function showPanel(name, el) {
  document.querySelectorAll('.panel').forEach(function(p) {
    p.classList.remove('active');
  });
  document.querySelectorAll('.nav-item').forEach(function(n) {
    n.classList.remove('active');
  });
  var target = document.getElementById('panel-' + name);
  if (target) target.classList.add('active');
  if (el) el.classList.add('active');

  // Per-panel data loading
  if (name === 'threats')   loadThreats();
  if (name === 'flows')     loadFlows();
  if (name === 'malware')   loadMalware();
  if (name === 'intel')     loadIntelHistory();
  if (name === 'scanner')   loadDevices();
  if (name === 'inspector') loadInspector();
  if (name === 'blocker')   loadBlockList();
  if (name === 'darkweb')   { loadDWHistory(); loadDWStats(); loadDWWatchList(); }
  if (name === 'reports')   loadRptSummary();
  if (name === 'mitre')     renderMitre();
  if (name === 'ai')        loadAIPrompts();
  if (name === 'geomap')    loadGeoMap();
  if (name === 'vulns')     { fetch('/api/vuln/stats').then(function(r){return r.json();}).then(function(s){ document.getElementById('vuln-hosts').textContent=s.hosts_scanned; document.getElementById('vuln-critical').textContent=s.critical_hosts; document.getElementById('vuln-cves').textContent=s.total_cves; }).catch(function(){}); }
  if (name === 'honeypot')  loadHoneypotStatus();
  if (name === 'tl')        loadTimeline();
  if (name === 'alertcfg')  {}
}

"""

html = html.replace("// ================================================================\n// CLOCK", CLEAN_NAV + "// ================================================================\n// CLOCK")

with open(path, "w", encoding="utf-8") as f:
    f.write(html)

# Verify
with open(path, encoding="utf-8") as f:
    check = f.read()

count = check.count("function showPanel")
print(f"showPanel definitions found: {count}")
if count == 1:
    print("SUCCESS - exactly one showPanel defined")
else:
    print("WARNING - multiple definitions still exist")
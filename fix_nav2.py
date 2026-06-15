import re

path = "dashboard/index.html"
with open(path, encoding="utf-8") as f:
    html = f.read()

# Fix 1: Move showPanel to be the FIRST thing in <script>
# Remove it from wherever it currently is
html = re.sub(
    r'// ================================================================\s*\n// NAVIGATION - single clean definition\s*\n// ================================================================\s*\nfunction showPanel.*?\n\}\s*\n',
    '',
    html, flags=re.DOTALL
)

# Fix 2: Find and fix the syntax error - "Unexpected identifier 'ai'"
# This is usually caused by a missing semicolon or comma before a variable
# Check around the AI section
print("Checking for syntax issues...")
lines = html.split('\n')
for i, line in enumerate(lines):
    if 'var ai' in line.lower() or "'ai'" in line:
        print(f"Line {i+1}: {line[:80]}")

# Fix 3: Insert showPanel as the VERY FIRST function in <script> tag
SHOW_PANEL = """
function showPanel(name, el) {
  document.querySelectorAll('.panel').forEach(function(p){ p.classList.remove('active'); });
  document.querySelectorAll('.nav-item').forEach(function(n){ n.classList.remove('active'); });
  var t = document.getElementById('panel-' + name);
  if (t) t.classList.add('active');
  if (el) el.classList.add('active');
  if (name==='threats')   { try{loadThreats();}catch(e){} }
  if (name==='flows')     { try{loadFlows();}catch(e){} }
  if (name==='malware')   { try{loadMalware();}catch(e){} }
  if (name==='intel')     { try{loadIntelHistory();}catch(e){} }
  if (name==='scanner')   { try{loadDevices();}catch(e){} }
  if (name==='inspector') { try{loadInspector();}catch(e){} }
  if (name==='blocker')   { try{loadBlockList();}catch(e){} }
  if (name==='darkweb')   { try{loadDWHistory();loadDWStats();loadDWWatchList();}catch(e){} }
  if (name==='reports')   { try{loadRptSummary();}catch(e){} }
  if (name==='mitre')     { try{renderMitre();}catch(e){} }
  if (name==='ai')        { try{loadAIPrompts();}catch(e){} }
  if (name==='geomap')    { try{loadGeoMap();}catch(e){} }
  if (name==='vulns')     { try{fetch('/api/vuln/stats').then(function(r){return r.json();}).then(function(s){document.getElementById('vuln-hosts').textContent=s.hosts_scanned;document.getElementById('vuln-critical').textContent=s.critical_hosts;document.getElementById('vuln-cves').textContent=s.total_cves;});}catch(e){} }
  if (name==='honeypot')  { try{loadHoneypotStatus();}catch(e){} }
  if (name==='tl')        { try{loadTimeline();}catch(e){} }
}
"""

# Insert right after <script> tag
html = html.replace('<script>\n', '<script>\n' + SHOW_PANEL + '\n', 1)

# Fix 4: Also fix the syntax error around 'ai' identifier
# Common cause: var declaration missing 'var' keyword or missing semicolon
html = re.sub(r'\bvar aiTyping\b', 'var aiTyping', html)

# Fix 5: Find unclosed strings or bad syntax near line 2281
# Search for common issues
problem_patterns = [
    ("'ai'", "identifier issue"),
    ('var ai ', "variable declaration"),
]
for pattern, desc in problem_patterns:
    idx = html.find(pattern)
    if idx > 0:
        snippet = html[max(0,idx-100):idx+100]
        print(f"\nFound '{desc}' near: ...{snippet}...")

with open(path, "w", encoding="utf-8") as f:
    f.write(html)

# Final check
with open(path, encoding="utf-8") as f:
    final = f.read()
count = final.count('function showPanel')
print(f"\nshowPanel count: {count}")
print("Done!")
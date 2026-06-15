import re

path = "dashboard/index.html"
with open(path, encoding="utf-8") as f:
    html = f.read()

# Fix broken regex: text.replace(/<actual newline>/g,'<br>')
# Should be: text.replace(/\n/g,'<br>')
html = re.sub(
    r"text\.replace\(/\n/g,'<br>'\)",
    r"text.replace(/\\n/g,'<br>')",
    html
)

# Also fix the multi-step .replace() chain for AI formatting
# Find the pattern with ## headers, ** bold, - bullets, and \n
old_pattern = re.compile(
    r"var fmt = text\s*\n\s*\.replace\(/## \(\.\*\)/g,'<div[^']*'\)\s*\n\s*\.replace\(/\\\*\\\*\(\.\*\?\)\\\*\\\*/g,'<strong[^']*'\)\s*\n\s*\.replace\(/\^- \(\.\*\)/gm,'<div[^']*'\)\s*\n\s*\.replace\(/\n/g,'<br>'\);",
    re.DOTALL
)

new_block = """var fmt = text
      .replace(/## (.*)/g,'<div style="font-weight:700;color:var(--text-bright);margin:8px 0 4px">$1</div>')
      .replace(/\\*\\*(.*?)\\*\\*/g,'<strong style="color:var(--text-bright)">$1</strong>')
      .replace(/^- (.*)/gm,'<div style="padding-left:12px;color:var(--text-dim)">\\u2022 $1</div>')
      .replace(/\\n/g,'<br>');"""

html = old_pattern.sub(new_block, html)

# Save
with open(path, "w", encoding="utf-8") as f:
    f.write(html)

# Verify - check for actual newlines inside regex literals (broken pattern)
import re as re2
broken = re2.findall(r"replace\(/\n/g", html)
print(f"Broken /\\n/g patterns remaining: {len(broken)}")

# Show the fixed lines
lines = html.split('\n')
for i, line in enumerate(lines):
    if 'text.replace' in line or '.replace(/\\n/g' in line:
        print(f"{i+1}: {line.strip()[:100]}")

print("Done!")
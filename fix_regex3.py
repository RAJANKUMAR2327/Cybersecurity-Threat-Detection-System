import re

path = "dashboard/index.html"
with open(path, encoding="utf-8") as f:
    html = f.read()

# Fix 1: the simple broken regex from earlier
html = re.sub(
    r"text\.replace\(/\n/g,'<br>'\)",
    r"text.replace(/\\n/g,'<br>')",
    html
)

# Fix 2: find ANY remaining occurrence of a literal newline inside replace(/ ... /g pattern
# Generic fix: replace(/<NEWLINE>/g  ->  replace(/\n/g
html = html.replace("replace(/\n/g", "replace(/\\n/g")

# Fix 3: fix the multi-line .replace chain - use plain string replace, not regex
old = """var fmt = text
      .replace(/## (.*)/g,'<div style="font-weight:700;color:var(--text-bright);margin:8px 0 4px">$1</div>')
      .replace(/\\*\\*(.*?)\\*\\*/g,'<strong style="color:var(--text-bright)">$1</strong>')
      .replace(/^- (.*)/gm,'<div style="padding-left:12px;color:var(--text-dim)">\\u2022 $1</div>')
      .replace(/\\n/g,'<br>');"""

new = """var fmt = text
      .replace(/## (.*)/g,'<div style="font-weight:700;color:var(--text-bright);margin:8px 0 4px">$1</div>')
      .replace(/\\*\\*(.*?)\\*\\*/g,'<strong style="color:var(--text-bright)">$1</strong>')
      .replace(/^- (.*)/gm,'<div style="padding-left:12px;color:var(--text-dim)">\\u2022 $1</div>')
      .replace(/\\n/g,'<br>');"""

# Just check for any remaining literal newlines inside replace(/.../g) calls
pattern = re.compile(r"replace\(/((?:[^/\n]|\\.)*)\n((?:[^/\n]|\\.)*)/g")
def fixer(m):
    return "replace(/" + m.group(1) + "\\n" + m.group(2) + "/g"

prev = ""
while prev != html:
    prev = html
    html = pattern.sub(fixer, html)

with open(path, "w", encoding="utf-8") as f:
    f.write(html)

# Verify - count actual newline chars between replace(/ and /g on same logical regex
import re as re2
issues = 0
for m in re2.finditer(r"replace\(/[^/]*\n[^/]*/g", html):
    issues += 1
print(f"Remaining broken regex patterns: {issues}")
print("Done!")
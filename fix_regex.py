path = "dashboard/index.html"
with open(path, encoding="utf-8") as f:
    html = f.read()

# Show what's around line 1650
lines = html.split('\n')
print("=== Lines 1645-1655 ===")
for i in range(1644, min(1656, len(lines))):
    print(f"{i+1}: {lines[i]}")
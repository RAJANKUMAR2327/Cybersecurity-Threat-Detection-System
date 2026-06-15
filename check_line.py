path = "dashboard/index.html"
with open(path, encoding="utf-8") as f:
    lines = f.readlines()

print(f"Total lines: {len(lines)}")
print("=== Lines 1645-1660 ===")
for i in range(1644, min(1662, len(lines))):
    print(f"{i+1}: {repr(lines[i])}")
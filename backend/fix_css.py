import sys
import os

path = r"c:\Users\Ameena Nazneen\Desktop\final project\frontend\src\CodeGuard.css"
with open(path, 'r', encoding='utf-8') as f:
    lines = f.readlines()

new_lines = []
for line in lines:
    new_lines.append(line)
    if ".fix-explanation {" in line:
        new_lines.append("  white-space: pre-wrap;\n")

with open(path, 'w', encoding='utf-8') as f:
    f.writelines(new_lines)

print("✅ CSS Fix applied successfully.")

import sys, os
sys.path.insert(0, os.path.abspath('backend'))
from dotenv import load_dotenv
load_dotenv()

from backend.llm.sast_marker import analyze_code_with_gemini, MARKER

code = open('C:/tmp/test_clone_vfa/app/app.py', 'r').read()
print(f"File length: {len(code)} chars, {len(code.splitlines())} lines")
result = analyze_code_with_gemini(code)

markers_found = [line for line in result.split('\n') if MARKER in line]
print(f"\n✅ Markers found: {len(markers_found)}")
for m in markers_found:
    print(f"  >> {m.strip()[:120]}")

import os, sys, json

# ONLY add backend/ to sys.path - NOT 'final project/' which causes conflicts
THIS_DIR = os.path.dirname(os.path.abspath(__file__))
if THIS_DIR not in sys.path:
    sys.path.insert(0, THIS_DIR)
os.chdir(THIS_DIR)

from dotenv import load_dotenv
load_dotenv('.env')

from backend.llm.gemini_client import call_gemini
from backend.llm.sast_marker import _extract_json, _ask_for_vulns, MARKER
print(f"MARKER: '{MARKER}'")

# Simple vulnerable code
CODE = "1: var x = req.body.name;\n2: db.find({name: x});\n3: res.send('<h1>' + x + '</h1>');"

print("\n=== TEST: call_gemini raw ===")
raw = call_gemini('Find security vulnerabilities. Return JSON array: [{"line":1,"type":"INJECTION","severity":"Critical","snippet":"code"}]\n\nCODE:\n' + CODE)
print(f"RAW ({len(raw)} chars): {raw[:2000]}")

parsed = _extract_json(raw)
print(f"\nParsed type: {type(parsed)}")
if parsed:
    print(f"Parsed: {json.dumps(parsed, indent=2)[:500]}")
    if isinstance(parsed, dict):
        print(f"Dict keys: {list(parsed.keys())}")
else:
    print("Parsed: None")

print("\n=== TEST: _ask_for_vulns ===")
vulns = _ask_for_vulns(CODE, call_gemini)
print(f"Vulns: {len(vulns)}")
for v in vulns:
    print(f"  L{v.get('line')}: {v.get('type')} {v.get('severity')} - {str(v.get('description',''))[:60]}")

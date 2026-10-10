# backend/pipeline/run_pipeline.py
from llm.sast_marker import scan_and_mark_code
from llm.auto_fixer import remediate_marked_code

def run_pipeline(code: str):
    print("🔍 Running SAST marker...")
    marked = scan_and_mark_code(code)

    print("\n🚧 Marked Code:\n")
    print(marked)

    print("\n🛠️ Running Auto Fixer...")
    fixed = remediate_marked_code(marked)

    print("\n✅ Fixed Code:\n")
    print(fixed)

    return fixed

import sys
import os

# Set up paths
backend_dir = os.getcwd()
if backend_dir not in sys.path:
    sys.path.append(backend_dir)

from backend.llm.auto_fixer import remediate_marked_code

# The exactly problematic code reported by the user
vulnerable_code = """
import sqlite3
def login(u, p):
    db = sqlite3.connect("users.db")
    c = db.cursor()
    # CodeGuard7219834THISISANERROR [INJECTION:CRITICAL]
    c.execute("INSERT INTO users (user, password, failures) VALUES ('%s', '%s', '%d')" %(u, p, 0))  
    db.commit()
"""

print("🔍 Testing Auto-Fixer on SQL Injection...")
result = remediate_marked_code(vulnerable_code)

print("\n--- FIXED CODE ---")
print(result.get('fixed_code', 'NO FIXED CODE'))

print("\n--- EXPLANATION ---")
print(result.get('explanation', 'NO EXPLANATION'))

# Check for parameterized tokens (?, %s as params)
is_fixed = "?" in result['fixed_code'] or (", (u, p, 0)" in result['fixed_code'].replace(" ", ""))
if is_fixed:
    print("\n✅ SUCCESS: Parameterized query detected.")
else:
    print("\n❌ FAILURE: Fix is likely still vulnerable or identical.")

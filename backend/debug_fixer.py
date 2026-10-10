import os
import sys

# Set up path to include the backend subdirectory
current_dir = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, current_dir)

from backend.llm.auto_fixer import remediate_marked_code
from backend.llm.sast_marker import MARKER

code = """
import sqlite3
c = sqlite3.connect('users.db').cursor()
u, p = 'admin', 'pass'
c.execute("SELECT * FROM users WHERE username = '{}' and password = '{}'".format(u, p))
# CodeGuard7219834THISISANERROR [INJECTION:CRITICAL]
"""

print("🚀 Starting local remediation test...")
try:
    result = remediate_marked_code(code)
    print("✅ SUCCESS!")
    print(f"Fixed Code: {result.get('fixed_code')}")
except Exception as e:
    print(f"❌ FAILED: {e}")

import os
import sys
from dotenv import load_dotenv

# Ensure the backend directory is in the path
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
if BASE_DIR not in sys.path:
    sys.path.append(BASE_DIR)

load_dotenv()

from backend.llm.sast_marker import scan_and_mark_code

# VULPY-like snippet for testing
code = """
from flask import Flask, request, render_template_string
from database import db

app = Flask(__name__)

@app.route('/hello')
def hello():
    name = request.args.get('name')
    # Potential SSTI - vulnerable
    template = f"<h1>Hello {name}!!</h1>"
    return render_template_string(template)

@app.route('/user')
def get_user():
    user_id = request.args.get('id')
    # Potential SQLi - vulnerable
    query = "SELECT * FROM users WHERE id = '" + user_id + "'"
    results = db.session.execute(query)
    return "User search result"

@app.route('/cmd')
def run_cmd():
    target = request.args.get('target')
    # Potential Command Injection - vulnerable
    import os
    os.system("ping -c 1 " + target)
    return "Scan complete"
"""

print("🔍 Running SAST marker on Vulpy-like snippet...")
# Correctly pass the filename '.py' to trigger Python-specific heuristics
marked = scan_and_mark_code(code, filename="vulpy_test.py")

print("\n--- MARKED CODE ---\n")
print(marked)

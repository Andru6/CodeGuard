import sys
import os
import json
from dotenv import load_dotenv

# Load .env before anything else
load_dotenv()

# Fix Windows console encoding
if sys.platform == 'win32':
    try:
        sys.stdout.reconfigure(encoding='utf-8')
    except AttributeError:
        pass

# Add project root to sys.path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from backend.llm.sast_marker import analyze_code_with_gemini, triage_code_with_llama8b

# Test Code: Obvious NoSQL Injection & Hardcoded Secret
vulnerable_code = """
const express = require('express');
const router = express.Router();
const db = require('../models/db');

router.post('/login', (req, res) => {
    const query = { 
        username: req.body.username, 
        password: req.body.password 
    };
    
    // UNSAFE: NoSQL Injection via $ne or other operators if body is not sanitized
    db.users.findOne(query, (err, user) => {
        if (user) {
            const secret = "SuperSecretAPIKey12345"; // HARDCODED SECRET
            res.send("Logged in!");
        } else {
            res.status(401).send("Failed");
        }
    });
});

module.exports = router;
"""

def test_detection():
    print("LOG: Starting Diagnostic Scan...")
    
    # Phase 1: Triage
    print("--- Phase 1: Triage (Llama 8B) ---")
    snippets = triage_code_with_llama8b(vulnerable_code)
    print(f"Flagged Snippets: {json.dumps(snippets, indent=2)}")
    
    # Phase 2: Deep Analysis
    print("\n--- Phase 2: Deep Analysis (Gemini) ---")
    if not snippets:
        print("❌ Triage failed to find issues. Deep analysis won't run.")
        return

    marked_code = analyze_code_with_gemini(vulnerable_code, snippets)
    
    print("\n--- Resulting Marked Code ---")
    print(marked_code)
    
    if "CodeGuard" in marked_code:
        print("\n✅ SUCCESS: Vulnerabilities detected!")
    else:
        print("\n❌ FAILURE: No vulnerabilities detected.")

if __name__ == "__main__":
    test_detection()

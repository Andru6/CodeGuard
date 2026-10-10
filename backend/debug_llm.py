import os
import json
import sys
from dotenv import load_dotenv

# Add the project root to sys.path
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

load_dotenv()

from backend.llm.sast_marker import analyze_code_with_gemini, triage_code_with_llama8b

PHP_SQLI_CODE = """
<?php
$conn = mysqli_connect("localhost", "db_user", "db_pass", "database");
$id = $_GET['id'];
$query = "SELECT * FROM users WHERE id = " . $id;
$result = mysqli_query($conn, $query);
while($row = mysqli_fetch_assoc($result)) {
    echo "User: " . $row['username'];
}
?>
"""

JS_XSS_CODE = """
function greet() {
    const urlParams = new URLSearchParams(window.location.search);
    const name = urlParams.get('name');
    document.getElementById('welcome').innerHTML = "Hello, " + name;
}
"""

def test_triage():
    print("--- Skipping Triage (Avoiding Groq 429) ---")
    # is_php_sus = triage_code_with_groq(PHP_SQLI_CODE)
    # is_js_sus = triage_code_with_groq(JS_XSS_CODE)
    # print(f"PHP SQLi Suspicious: {is_php_sus}")
    # print(f"JS XSS Suspicious: {is_js_sus}")

def test_deep_analysis():
    mock_triage = [{"line": 1, "reason": "Test"}]
    print("\n--- Testing Deep Analysis (Gemini) ---")
    print("Analyzing PHP SQLi...")
    marked_php = analyze_code_with_gemini(PHP_SQLI_CODE, mock_triage)
    print("\nMARKED PHP CONTENT:")
    print(marked_php)
    
    print("\nAnalyzing JS XSS...")
    marked_js = analyze_code_with_gemini(JS_XSS_CODE, mock_triage)
    print("\nMARKED JS CONTENT:")
    print(marked_js)

if __name__ == "__main__":
    if not os.getenv("GOOGLE_API_KEY"):
        print("❌ Error: GOOGLE_API_KEY not set in environment.")
        sys.exit(1)
    
    test_triage()
    test_deep_analysis()

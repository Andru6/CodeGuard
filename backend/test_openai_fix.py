import os
import sys

# Ensure backend package can be found
sys.path.append(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from dotenv import load_dotenv
load_dotenv()

from backend.llm.auto_fixer import remediate_marked_code
from backend.llm.openai_client import call_openai

def test_openai_direct():
    print("--- TEST 1: Direct OpenAI Call ---")
    prompt = "Fix this XSS: res.send('<h1>' + req.query.name + '</h1>');"
    system_instruction = "You are a security fixer. Return ONLY JSON: {\"fixed_code\": \"...\", \"explanation\": \"...\"}"
    try:
        res = call_openai(prompt, system_instruction=system_instruction)
        print(f"OpenAI Response: {res}")
    except Exception as e:
        print(f"OpenAI Direct Failed: {e}")

def test_openai_integration():
    print("\n--- TEST 2: Auto-Fixer Integration (Forcing OpenAI) ---")
    # We will temporarily MOCK the GOOGLE_API_KEY to be empty in this process to force OpenAI fallback
    os.environ["GOOGLE_API_KEY"] = "" 
    
    code = """
    app.get('/search', (req, res) => {
        const query = req.query.q;
        res.send('Search results for: ' + query); // CodeGuard7219834THISISANERROR [XSS:HIGH]
    });
    """
    
    try:
        result = remediate_marked_code(code)
        print(f"FIXED CODE:\n{result['fixed_code']}")
        print(f"EXPLANATION: {result['explanation']}")
    except Exception as e:
        print(f"Integration Test Failed: {e}")

if __name__ == "__main__":
    test_openai_direct()
    test_openai_integration()

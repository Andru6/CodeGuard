import requests
import os

# Manual ENV parsing for speed
api_key = None
with open(".env", "r") as f:
    for line in f:
        if line.startswith("GOOGLE_API_KEY="):
            api_key = line.strip().split("=")[1].replace("'", "").replace('"', "").strip()

if not api_key:
    print("FATAL: API Key not found in .env")
    exit(1)

# Priority List based on your latest scan and screenshot
candidates = [
    "gemini-2.5-flash-lite", 
    "gemini-2.5-flash-lite-001",
    "gemini-3.1-flash",
    "gemini-2.0-flash-lite",
    "gemini-1.5-flash"
]

print(f"🔍 Testing Endpoint Access with key ending in ...{api_key[-5:]}")

for model in candidates:
    url = f"https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent?key={api_key}"
    try:
        r = requests.post(url, json={"contents": [{"parts": [{"text": "hi"}]}]}, timeout=10)
        if r.status_code == 200:
            print(f"✅ SUCCESS: Model found: {model}")
            # If we find a success, we stop here.
            exit(0)
        else:
            print(f"❌ FAIL: {model} (HTTP {r.status_code})")
    except Exception as e:
        print(f"❌ ERROR: {model} ({e})")

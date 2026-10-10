import requests
import json
import os

# Manual ENV parsing for speed
api_key = None
with open(".env", "r") as f:
    for line in f:
        if line.startswith("GOOGLE_API_KEY="):
            api_key = line.split("=")[1].strip()
            break

def test_model(model_id):
    print(f"Testing {model_id}...")
    url = f"https://generativelanguage.googleapis.com/v1beta/models/{model_id}:generateContent?key={api_key}"
    payload = {
        "contents": [{"parts": [{"text": "Hello"}]}]
    }
    r = requests.post(url, json=payload)
    print(f"Status: {r.status_code}")
    if r.status_code != 200:
        print(f"Response: {r.text[:200]}")
    return r.status_code

test_model("gemini-2.5-flash-lite")
test_model("gemini-1.5-flash")
test_model("gemini-2.0-flash-lite")

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

if not api_key:
    print("API Key not found in .env")
    exit(1)

url = f"https://generativelanguage.googleapis.com/v1beta/models?key={api_key}"
try:
    r = requests.get(url)
    with open("models_debug.json", "w") as f:
        json.dump(r.json(), f, indent=2)
    print("Model list saved to models_debug.json")
except Exception as e:
    print(f"Error: {e}")

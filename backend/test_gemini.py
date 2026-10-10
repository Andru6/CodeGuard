import os
import requests
import json
from dotenv import load_dotenv

load_dotenv()

api_key = os.getenv("GOOGLE_API_KEY")
model_name = "gemini-2.0-flash" # Trying the standard one

url = f"https://generativelanguage.googleapis.com/v1beta/models/{model_name}:generateContent?key={api_key}"
headers = {"Content-Type": "application/json"}
payload = {"contents": [{"parts": [{"text": "Hello, respond with 'OK' if you see this."}]}]}

print(f"Testing Gemini model: {model_name}...")
response = requests.post(url, headers=headers, data=json.dumps(payload))
print(f"Status Code: {response.status_code}")
print(f"Response: {response.text}")

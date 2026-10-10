import os
import requests
import json
from dotenv import load_dotenv

load_dotenv()

api_key = os.getenv("GROQ_API_KEY")
url = "https://api.groq.com/openai/v1/chat/completions"
headers = {
    "Authorization": f"Bearer {api_key}",
    "Content-Type": "application/json"
}
payload = {
    "model": "llama-3.3-70b-versatile",
    "messages": [{"role": "user", "content": "Respond with 'OK'."}]
}

print(f"Testing Groq API...")
response = requests.post(url, headers=headers, data=json.dumps(payload))
print(f"Status Code: {response.status_code}")
print(f"Response: {response.text}")

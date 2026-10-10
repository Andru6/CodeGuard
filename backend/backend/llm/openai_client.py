import os
import sys
import requests
import json
import time

def call_openai(prompt, system_instruction=None):
    """
    Calls OpenAI GPT-4o-mini. 
    High reliability fallback for remediation when Gemini/Groq are throttled.
    """
    api_key = os.getenv("OPENAI_API_KEY")
    if not api_key:
        raise Exception("OPENAI_API_KEY not found in environment.")

    url = "https://api.openai.com/v1/chat/completions"
    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json"
    }
    
    payload = {
        "model": "gpt-4o-mini",
        "messages": [
            {
                "role": "system",
                "content": system_instruction or "You are an elite security remediation engine."
            },
            {
                "role": "user",
                "content": prompt
            }
        ],
        "temperature": 0
    }

    retries = 3
    for i in range(retries):
        try:
            r = requests.post(url, headers=headers, json=payload, timeout=60)
            if r.status_code == 200:
                return r.json()["choices"][0]["message"]["content"]
            elif r.status_code == 429:
                wait = (i + 1) * 5
                print(f"⚠️ OpenAI Rate Limit (429). Waiting {wait}s...", file=sys.stderr)
                time.sleep(wait)
            else:
                raise Exception(f"OpenAI API failed ({r.status_code}): {r.text}")
        except Exception as e:
            if i == retries - 1: raise e
            time.sleep(2)
            
    return None

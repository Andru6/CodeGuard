import os
import requests
import json

def call_groq(prompt, system_instruction=None, model="llama-3.3-70b-versatile"):
    """
    Calls the Groq Cloud API to process content.
    """
    api_key = os.getenv("GROQ_API_KEY")
    if not api_key:
        raise Exception("GROQ_API_KEY not found in environment")

    url = "https://api.groq.com/openai/v1/chat/completions"
    
    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json"
    }

    payload = {
        "model": model,
        "messages": [
            {
                "role": "system",
                "content": system_instruction or "You are a helpful security assistant."
            },
            {
                "role": "user",
                "content": prompt
            }
        ],
        "temperature": 0.0,
        "max_tokens": 4096
    }

    import time
    
    max_retries = 3
    for attempt in range(max_retries):
        try:
            # Use a longer timeout for the versatile model
            response = requests.post(url, headers=headers, data=json.dumps(payload), timeout=25)
            
            if response.status_code == 429:
                wait_time = (attempt + 1) * 3
                print(f"⚠️ Groq Rate Limit (429). Retrying in {wait_time}s...")
                time.sleep(wait_time)
                continue
                
            if response.status_code != 200:
                raise Exception(f"Groq API Error ({response.status_code}): {response.text}")

            result = response.json()
            try:
                return result['choices'][0]['message']['content']
            except (KeyError, IndexError):
                raise Exception(f"Unexpected JSON format from Groq: {result}")
        except (requests.exceptions.Timeout, requests.exceptions.ReadTimeout):
            if attempt == max_retries - 1: raise
            print(f"⚠️ Groq Timeout ({attempt+1}/{max_retries})...")
            time.sleep(2)
        except Exception as e:
            if attempt == max_retries - 1: raise
            print(f"⚠️ Groq Error: {e}. Retrying...")
            time.sleep(1)

    raise Exception("Groq call failed after 3 attempts")

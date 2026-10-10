import os
import requests
import json
import threading

# Allowing 7 concurrent scanner workers for Claude (OpenRouter)
claude_limit = threading.Semaphore(7)

def call_openrouter(prompt, system_instruction=None):
    """
    Calls Claude 3.5 Sonnet through the OpenRouter API
    with a 7-worker concurrency limit.
    """
    api_key = os.getenv("OPENROUTER_API_KEY")
    if not api_key:
        raise Exception("OPENROUTER_API_KEY not found in environment.")

    url = "https://openrouter.ai/api/v1/chat/completions"
    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json",
        "HTTP-Referer": "https://github.com/alexeygrigorev/codeguard",
        "X-Title": "CodeGuard Security Audit"
    }

    messages = []
    if system_instruction:
        messages.append({"role": "system", "content": system_instruction})
    messages.append({"role": "user", "content": prompt})

    payload = {
        "model": "anthropic/claude-3.5-sonnet",
        "messages": messages,
        "temperature": 0
    }

    with claude_limit:
        try:
            response = requests.post(url, headers=headers, json=payload, timeout=60)
            if response.status_code == 200:
                result = response.json()
                if 'choices' in result and len(result['choices']) > 0:
                    return result['choices'][0]['message']['content']
                else:
                    raise Exception("OpenRouter returned no content.")
            else:
                raise Exception(f"OpenRouter API failed with status {response.status_code}: {response.text}")
        except Exception as e:
            raise Exception(f"Error calling OpenRouter: {e}")

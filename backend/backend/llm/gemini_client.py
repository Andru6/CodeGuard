import os
import sys
import requests
import json
import time
import threading

# Strictly limiting Gemini to 3 concurrent fixes to protect 15 RPM quota
gemini_limit = threading.Semaphore(3)

# Fix Windows console encoding for emoji
if hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(encoding='utf-8', errors='replace')

def call_gemini(prompt, system_instruction=None, exclude_groq=False):
    """
    BULLETPROOF CALL: Ensures a non-empty string is ALWAYS returned or an exception is raised.
    """
    api_key = os.getenv("GOOGLE_API_KEY")
    errors_log = []

    # --- Choice 1: Direct Google API (Primary: 2.5 Flash Lite) ---
    if api_key:
        with gemini_limit:
            api_key = api_key.strip("'").strip('"')
            url = f"https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-flash-lite:generateContent?key={api_key}"
            headers = { "Content-Type": "application/json" }
            
            payload = {
                "contents": [{"parts": [{"text": f"{system_instruction}\n\n{prompt}" if system_instruction else prompt}]}],
                "generationConfig": { "temperature": 0 }
            }

            try:
                r = requests.post(url, headers=headers, json=payload, timeout=60)
                if r.status_code == 200:
                    data = r.json()
                    # Safe deep-access for content
                    cand = data.get('candidates', [{}])[0]
                    content = cand.get('content', {}).get('parts', [{}])[0].get('text')
                    if content and len(content.strip()) > 0:
                        return content
                    else:
                        errors_log.append("Google API returned empty response")
                else:
                    if r.status_code == 429:
                        print(f"⚠️ Gemini 2.5 Throttled (429).", file=sys.stderr)
                    errors_log.append(f"Google API HTTP {r.status_code}")
            except Exception as e:
                errors_log.append(f"Google API error: {e}")

    # --- Choice 2: OpenAI Fallback ---
    if not exclude_groq:
        try:
            from .openai_client import call_openai
            print(f"📡 Using OpenAI Fallback...", file=sys.stderr)
            res = call_openai(prompt, system_instruction=system_instruction)
            if res and len(res.strip()) > 0: return res
            else: errors_log.append("OpenAI returned empty response")
        except Exception as e:
            errors_log.append(f"OpenAI error: {e}")

    # --- Choice 3: Groq Fallback ---
    if not exclude_groq:
        groq_key = os.getenv("GROQ_API_KEY")
        if groq_key:
            try:
                from .groq_client import call_groq
                res = call_groq(prompt, system_instruction=system_instruction, model="llama-3.3-70b-versatile")
                if res and len(res.strip()) > 0: return res
                else: errors_log.append("Groq returned empty response")
            except Exception as e:
                errors_log.append(f"Groq error: {e}")

    raise Exception(f"All providers failed: {'; '.join(errors_log)}")

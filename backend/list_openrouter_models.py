import requests
import os

API_KEY = os.getenv("OPENROUTER_API_KEY")

if not API_KEY:
    raise RuntimeError("OPENROUTER_API_KEY not set")

resp = requests.get(
    "https://openrouter.ai/api/v1/models",
    headers={"Authorization": f"Bearer {API_KEY}"}
)

resp.raise_for_status()

models = resp.json()["data"]

print("=== AVAILABLE MODELS ===")
for m in models:
    print(m["id"])

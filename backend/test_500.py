import urllib.request
import urllib.error
import json
import re

url = 'http://localhost:5000/api/auth/google'
data = json.dumps({"token": "dummy_token"}).encode('utf-8')
req = urllib.request.Request(url, data=data, headers={"Content-Type": "application/json"})

try:
    with urllib.request.urlopen(req) as f:
        print(f.read().decode('utf-8'))
except urllib.error.HTTPError as e:
    print(f"HTTPError: {e.code}")
    body = e.read().decode('utf-8')
    m = re.search(r'(?s)<div class="traceback">(.*?)</div>', body)
    if m:
        text = re.sub('<[^<]+>', '', m.group(1))
        print("TRACEBACK EXTRACTED:")
        print(text)
    else:
        print("Found HTML, throwing crude text:")
        print(re.sub('<[^<]+>', '', body)[:3000])
except Exception as e:
    print(f"Other error: {e}")

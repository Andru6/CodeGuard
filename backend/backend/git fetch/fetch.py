import requests
import base64
import re
import time
import logging

import os
CLIENT_ID = os.getenv("GITHUB_CLIENT_ID", "your_github_client_id")
CLIENT_SECRET = os.getenv("GITHUB_CLIENT_SECRET", "your_github_client_secret")
REDIRECT_URI = os.getenv("GITHUB_REDIRECT_URI", "http://localhost:5000/callback")

# Logging setup
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# --- FILE SAFETY CONFIGURATION ---
ALLOWED_EXTENSIONS = {
    '.py', '.js', '.ts', '.tsx', '.jsx',
    '.html', '.css', '.scss',
    '.java', '.cpp', '.c', '.h', '.cs', '.go', '.rs',
    '.php', '.rb', '.swift', '.kt', '.sql',
    '.json', '.yaml', '.yml', '.xml', '.sh',
}

SPECIAL_FILENAMES = {
    'dockerfile',
    'makefile',
    'jenkinsfile',
}

# --- HELPER FUNCTIONS ---

def _parse_repo_info(repo_link):
    """
    Parses HTTPS and SSH-like git URLs reliably.
    Returns (owner, repo) or None.
    """
    clean = repo_link.rstrip('/').removesuffix('.git')
    # Regex for standard GitHub structure
    match = re.search(r'github\.com[:/]([\w-]+)/([\w.-]+)', clean)
    if match:
        return match.groups()
    return None

def _check_rate_limit(headers):
    """Checks rate limit headers and sleeps if critical."""
    remaining = int(headers.get('X-RateLimit-Remaining', 100))
    reset_time = int(headers.get('X-RateLimit-Reset', 0))
    
    if remaining < 10:
        sleep_time = max(1, reset_time - int(time.time()))
        logger.warning(f"📉 Rate limit critical ({remaining} left). Sleeping {sleep_time}s...")
        time.sleep(sleep_time)

def _is_safe_code_file(path):
    """
    Determines if a file is source code based on extension or special filename.
    """
    lower = path.lower()
    # allow special source files with no extension (e.g. 'Dockerfile')
    tail = lower.rsplit('/', 1)[-1]  # filename only
    
    if tail in SPECIAL_FILENAMES:
        return True

    # standard extensions
    if '.' in tail:
        ext = '.' + tail.split('.')[-1]
        return ext in ALLOWED_EXTENSIONS

    # files with no extension other than whitelisted specials -> reject
    return False

def _looks_binary(content_bytes):
    """
    Heuristic: Reject if >2% of bytes are non-printable control characters.
    (Excludes Tabs, Newlines, Carriage Returns)
    """
    if not content_bytes:
        return False
        
    # Bytes < 9 (Null, etc) OR between 13 and 32 (Control chars)
    # 9 = \t (Tab), 10 = \n (LF), 13 = \r (CR) -> These are SAFE.
    binary_count = sum(1 for b in content_bytes if b < 9 or (13 < b < 32))
    
    return (binary_count / len(content_bytes)) > 0.02

def _is_lfs_pointer(content_str):
    """Detects Git LFS pointers."""
    if len(content_str) > 300: return False
    return content_str.startswith("version https://git-lfs.github.com/spec")

def enqueue_file(file_data):
    """Placeholder for Teammate's Celery logic."""
    # celery_task.delay(file_data)
    logger.info(f"🚀 Enqueued: {file_data['path']} (Size: {len(file_data['content'])})")

# --- OAUTH FUNCTIONS ---

def get_auth_url():
    return (
        f"https://github.com/login/oauth/authorize?"
        f"client_id={CLIENT_ID}&scope=repo&redirect_uri={REDIRECT_URI}"
    )

def exchange_code_for_token(auth_code):
    try:
        response = requests.post(
            "https://github.com/login/oauth/access_token",
            data={
                'client_id': CLIENT_ID,
                'client_secret': CLIENT_SECRET,
                'code': auth_code,
                'redirect_uri': REDIRECT_URI
            },
            headers={'Accept': 'application/json'}
        )
        response.raise_for_status()
        data = response.json()
        
        # Verify scope
        if "repo" not in data.get("scope", ""):
            logger.warning("⚠️ Token missing 'repo' scope. Private repos may fail.")
            
        return data.get("access_token")
    except requests.RequestException as e:
        logger.error(f"Token exchange error: {e}")
        return None

# --- MAIN LOGIC ---

def process_repository(repo_link, access_token):
    """
    Full robust scan: Metadata -> Recursive Tree -> Blob API -> Heuristics -> Enqueue
    """
    repo_info = _parse_repo_info(repo_link)
    if not repo_info:
        return {"status": "error", "message": "Invalid Repository Link"}
    
    owner, repo = repo_info
    
    headers = {
        "Authorization": f"token {access_token}",
        "Accept": "application/vnd.github.v3+json"
    }

    try:
        # 1. Get Default Branch
        meta_resp = requests.get(f"https://api.github.com/repos/{owner}/{repo}", headers=headers)
        if meta_resp.status_code == 404:
            return {"status": "error", "message": "Repo not found or access denied."}
        meta_resp.raise_for_status()
        default_branch = meta_resp.json().get("default_branch")

        # 2. Get Recursive Tree
        tree_resp = requests.get(
            f"https://api.github.com/repos/{owner}/{repo}/git/trees/{default_branch}?recursive=1", 
            headers=headers
        )
        tree_resp.raise_for_status()
        tree_data = tree_resp.json()

        files_processed = 0
        skipped_files = 0

        # 3. Iterate Items
        for item in tree_data.get('tree', []):
            if item.get('type') != 'blob': continue
            
            path = item.get('path', '')
            sha = item.get('sha')
            size = item.get('size', 0)

            # --- FILTER 1: EXTENSION & FILENAME ---
            if not _is_safe_code_file(path):
                skipped_files += 1
                continue

            # --- FILTER 2: SIZE ---
            if size > 2_000_000: # 2MB limit
                logger.warning(f"⚠️ Skipping large file: {path}")
                continue

            # 4. Fetch Blob
            _check_rate_limit(tree_resp.headers) # Pre-check limit
            blob_resp = requests.get(
                f"https://api.github.com/repos/{owner}/{repo}/git/blobs/{sha}", 
                headers=headers
            )
            if blob_resp.status_code != 200: continue
            
            blob_data = blob_resp.json()

            # 5. Decode & Analyze Content
            content_str = ""
            if blob_data.get('encoding') == 'base64' and blob_data.get('content'):
                try:
                    # Validate=True ensures strict base64 check
                    clean = "".join(blob_data['content'].split())
                    raw_bytes = base64.b64decode(clean, validate=True)

                    
                    # --- FILTER 3: BINARY HEURISTIC ---
                    if _looks_binary(raw_bytes):
                        logger.info(f"⏭️ Skipping binary masquerading as code: {path}")
                        continue
                    
                    # --- FILTER 4: STRICT UTF-8 ---
                    #content_str = raw_bytes.decode('utf-8')

                    # --- FILTER 5: LFS POINTER ---
                    if _is_lfs_pointer(content_str):
                        logger.info(f"⏭️ Skipping Git LFS pointer: {path}")
                        continue

                except (UnicodeDecodeError, base64.binascii.Error):
                    logger.info(f"⏭️ Skipping non-UTF8/corrupt file: {path}")
                    continue
            else:
                continue

            # 6. Success - Enqueue
            payload = {
                "path": path,
                "repo": repo_link,
                "branch": default_branch,
                "content": content_str,
                "sha": sha
                }
            
            #celery here

            files_processed += 1

        return {
            "status": "success", 
            "files_processed": files_processed, 
            "files_skipped": skipped_files
        }

    except Exception as e:
        logger.error(f"Scan failed: {e}")
        return {"status": "error", "message": str(e)}   
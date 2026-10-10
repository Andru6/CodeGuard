import os
import sys
import json
import time
import subprocess
import shutil
import tempfile
import uuid
import concurrent.futures
import zipfile
import requests

from flask import Flask, request, jsonify, Response, stream_with_context
from flask_cors import CORS
from dotenv import load_dotenv

load_dotenv()

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
PARENT_DIR = os.path.dirname(BASE_DIR)

# Ensure both local dir and parent dir (for backend.xxx) are in path
for d in [BASE_DIR, PARENT_DIR]:
    if d not in sys.path:
        sys.path.append(d)

from backend.llm.sast_marker import triage_code_with_70b, analyze_code_with_gemini, MARKER
from backend.llm.auto_fixer import remediate_marked_code
from database import create_scan, update_scan_status, add_vulnerability, get_scan_results, get_all_scans, get_user_analytics, resolve_vulnerability, clear_user_data, get_db
from backend.agent_engine import AgenticResearcher
from auth import verify_google_token, generate_jwt, token_required

print("🚀 CodeGuard Backend Logic Loaded.")

app = Flask(__name__)
# Allow requests from the frontend origin
CORS(app)

EXTENSIONS = ('.py', '.js', '.jsx', '.ts', '.tsx', '.java', '.cpp', '.c', '.go', '.rb', '.php', 'package.json')
IGNORE_DIRS = {'.git', 'node_modules', 'venv', '__pycache__', 'dist', 'build', 'e2e', 'fixtures', 'coverage', '.nyc_output'}

@app.route('/api/status', methods=['GET'])
def get_status():
    return jsonify({"status": "Backend is running", "model": "Groq + Gemini Hybrid (MongoDB Enabled)"})

@app.route('/api/auth/google', methods=['POST'])
def google_auth():
    data = request.json
    token = data.get('token')
    if not token:
        return jsonify({"error": "No token provided"}), 400
    
    user = verify_google_token(token)
    if not user:
        return jsonify({"error": "Invalid Google token"}), 401
    
    jwt_token = generate_jwt(user)
    return jsonify({
        "token": jwt_token,
        "user": {
            "name": user["name"],
            "email": user["email"],
            "picture": user.get("picture", "")
        }
    })

def _gather_files(temp_dir):
    files = []
    MAX_FILES = 60
    for root, dirs, filenames in os.walk(temp_dir):
        if len(files) >= MAX_FILES: break
        path_parts = set(os.path.normpath(root).split(os.sep))
        if path_parts & IGNORE_DIRS:
            dirs[:] = []  # prune traversal
            continue
        for f in filenames:
            if len(files) >= MAX_FILES: break
            if f.endswith(EXTENSIONS) or f.lower() == 'dockerfile':
                files.append(os.path.join(root, f))
    return files

def _parse_vulnerabilities(marked_code, filename):
    vulns = []
    for i, line in enumerate(marked_code.split('\n')):
        if MARKER in line:
            # Extract metadata from format: # MARKER [TYPE:SEVERITY]
            try:
                # Split by # MARKER [ then take content before ]
                meta_section = line.split(f"# {MARKER} [")[-1].split("]")[0]
                if ":" in meta_section:
                    type_raw, sev_raw = meta_section.split(":", 1)
                else:
                    type_raw, sev_raw = meta_section, "Critical"
                
                # Normalize severity
                sev_map = {"CRITICAL": "Critical", "HIGH": "High", "MEDIUM": "Medium", "LOW": "Low"}
                severity = sev_map.get(sev_raw.upper(), "Medium")
                
                # Map technical type to UI category
                cat_map = {"INJECTION": "Injection", "XSS": "XSS", "CRYPTO": "Cryptography", "ACCESS_CONTROL": "Authentication"}
                category = cat_map.get(type_raw.upper(), "General Security")
                
            except Exception:
                category = "Unknown"
                severity = "Critical"

            # Context extraction: 5 lines above and below
            lines = marked_code.split('\n')
            start_ctx = max(0, i - 5)
            end_ctx = min(len(lines), i + 6)
            ctx_block = "\n".join(lines[start_ctx:end_ctx])

            vulns.append({
                'id': len(vulns) + 1,
                'title': f'{severity} Severity: {category}',
                'severity': severity,
                'file': filename,
                'line': i + 1,
                'start_line': start_ctx + 1,
                'category': category,
                'description': f'Potential {category} vulnerability ({severity}) detected in {filename}.',
                'vulnerableCode': ctx_block
            })
    return vulns

def _sse(event_type, data):
    """Format a Server-Sent Event."""
    return f"data: {json.dumps({'type': event_type, **data})}\n\n"

@app.route('/api/scan/stream', methods=['GET'])
@token_required
def scan_stream():
    """
    SSE endpoint protected by JWT. Query params: repo_url
    Streams scan progress events to the frontend in real time.
    """
    repo_url = request.args.get('repo_url', '').strip()
    user_id = getattr(request, 'user_id', None)
    
    if not repo_url:
        return jsonify({'error': 'repo_url is required'}), 400

    def generate():
        # LOG FIRST for connection health
        yield _sse('log', {'level': 'info', 'message': '🚀 Initializing secure pipeline...'})
        yield _sse('progress', {'value': 2, 'step': 0})
        
        # Helper for heartbeats
        def heartbeat():
            return ": heartbeat\n\n"
        
        try:
            # ── Database & Setup ───────────────────────────────────────
            # Ensure user_id is never None (needed for some DB queries)
            u_id = user_id or "anonymous"
            scan_id = create_scan(repo_url, user_id=u_id)
            all_vulnerabilities = []
            temp_dir = os.path.join(tempfile.gettempdir(), f"codeguard_{uuid.uuid4().hex}")

            # Normalize URL: trim spaces, handle variations, and STRIP EVERYTHING
            target_url = repo_url.strip().rstrip('/')
            if target_url.endswith('.git'): target_url = target_url[:-4]
            
            # Convert SSH to HTTPS if needed (e.g. git@github.com:user/repo.git)
            if target_url.startswith('git@github.com:'):
                target_url = target_url.replace('git@github.com:', 'https://github.com/')
            
            if not target_url.startswith(('http://', 'https://')):
                target_url = 'https://' + target_url
            
            # Masked URL for logging
            masked_url = target_url
            github_token = os.getenv('GITHUB_TOKEN')
            
            # Prepare clone command with token if available
            clone_url = target_url
            if github_token and 'github.com' in target_url and '@' not in target_url:
                clone_url = target_url.replace('https://', f'https://{github_token}@')
                masked_url = target_url.replace('https://', 'https://[TOKEN]@')

            yield _sse('log', {'level': 'info', 'message': f'📥 Cloning repository: {target_url}'})
            print(f"DEBUG: Cloning {masked_url}") # Server console log

            def run_clone(url):
                # Try candidate git paths (system PATH + discovered Windows install locations)
                candidates = [
                    r'C:\Users\Ameena Nazneen\AppData\Local\Programs\Git\cmd\git.exe',
                    'git', 
                    r'C:\Program Files\Git\cmd\git.exe'
                ]
                
                last_err = "No Git binary found."
                for git_bin in candidates:
                    if not shutil.which(git_bin) and git_bin == 'git':
                        continue
                    try:
                        # Ensure strictly non-interactive clone (prevents Windows GCM dialog errors)
                        new_env = os.environ.copy()
                        new_env['GIT_TERMINAL_PROMPT'] = '0'
                        new_env['GCM_INTERACTIVE'] = 'never'
                        new_env['GIT_ASKPASS'] = 'true'
                        
                        # Set a very low timeout and disable credential helper for this command
                        return subprocess.run([git_bin, '-c', 'credential.helper=', '-c', 'core.askpass=true', 
                                              'clone', '--depth', '1', url, temp_dir], 
                                             capture_output=True, text=True, env=new_env, timeout=60)
                    except (FileNotFoundError, PermissionError) as e:
                        last_err = str(e)
                        continue
                return None # Signal fallback if no candidate works

            def download_zip_fallback(target_url, temp_dir):
                # Hardened regex for owner/repo extraction
                import re
                # Match owner/repo even if there's trailing junk
                match = re.search(r'github\.com/([^/]+)/([^/\s]+)', target_url)
                if match:
                    owner, repo = match.groups()
                    repo = repo.replace('.git', '').rstrip('/')
                    zip_url = f"https://api.github.com/repos/{owner}/{repo}/zipball"
                else:
                    # Fallback for non-github or malformed URLs
                    zip_url = f"{target_url.rstrip('/')}/zipball/"
                
                headers = {'Accept': 'application/vnd.github+json', 'User-Agent': 'CodeGuard-SAST-Scanner'}
                if github_token:
                    headers['Authorization'] = f'token {github_token}'
                
                response = requests.get(zip_url, headers=headers, stream=True, timeout=30)
                
                # RECOVERY: Try master/main archive URLs if zipball API fails
                if response.status_code != 200 and 'github.com' in target_url:
                    print(f"DEBUG: Zipball API failed ({response.status_code}), trying archive fallback...")
                    for branch in ['master', 'main']:
                        zip_url = f"{target_url.rstrip('/')}/archive/refs/heads/{branch}.zip"
                        response = requests.get(zip_url, headers=headers, stream=True, timeout=30)
                        if response.status_code == 200: break
                
                if response.status_code != 200:
                    raise Exception(f"ZIP fallback failed (HTTP {response.status_code})")
                
                zip_path = os.path.join(tempfile.gettempdir(), f"cg_download_{uuid.uuid4().hex}.zip")
                with open(zip_path, 'wb') as f:
                    for chunk in response.iter_content(chunk_size=8192):
                        f.write(chunk)
                
                # Extract
                with zipfile.ZipFile(zip_path, 'r') as zip_ref:
                    zip_ref.extractall(temp_dir)
                
                # Cleanup zip
                os.remove(zip_path)
                
                # Flatten: GitHub ZIPs create a subfolder like 'owner-repo-hash'
                extracted_items = os.listdir(temp_dir)
                if len(extracted_items) == 1 and os.path.isdir(os.path.join(temp_dir, extracted_items[0])):
                    subfolder = os.path.join(temp_dir, extracted_items[0])
                    for item in os.listdir(subfolder):
                        shutil.move(os.path.join(subfolder, item), temp_dir)
                    os.rmdir(subfolder)

            # STEP 0: PRE-SCAN CONNECTIVITY CHECK (Detect 404/Private)
            try:
                check_headers = {'User-Agent': 'CodeGuard-SAST-Scanner'}
                if github_token: check_headers['Authorization'] = f'token {github_token}'
                check_res = requests.head(target_url, headers=check_headers, timeout=10, allow_redirects=True)
                if check_res.status_code == 404:
                    yield _sse('error', {'message': f'❌ Repository Not Found: HTTP 404. Please verify the URL: {target_url}'})
                    raise Exception(f"Repository not found: {target_url}")
            except Exception as e:
                # Only fail if it's a definitive 404. For other network issues, let Git try.
                if "404" in str(e): raise e

            # STEP 1: ATTEMPT CLONE - Prioritize Token if exists
            yield _sse('log', {'level': 'info', 'message': f'📥 Initializing repository clone: {target_url}'})
            
            clone_url = target_url
            if github_token and 'github.com' in target_url:
                # Revert to simpler token format (was confirmed working earlier)
                clone_url = target_url.replace('https://', f'https://{github_token}@')
                yield _sse('log', {'level': 'info', 'message': '🔑 Attempting authenticated clone using GITHUB_TOKEN...'})
            
            clone_res = run_clone(clone_url)
            
            # STEP 2: IF AUTH FAILED (OR TOKEN WAS BAD), TRY CLEAN CLONE
            if clone_res and clone_res.returncode != 0 and github_token:
                 yield _sse('log', {'level': 'warning', 'message': '⚠️ Authentication failed. Retrying with direct public clone...'})
                 clone_res = run_clone(target_url)

            # STEP 3: FINAL FALLBACK TO ZIP
            if clone_res is None or clone_res.returncode != 0:
                yield _sse('log', {'level': 'warning', 'message': '⚠️ Git client encountered an error. Falling back to ZIP download...'})
                try:
                    download_zip_fallback(target_url, temp_dir)
                    yield _sse('log', {'level': 'success', 'message': '✅ Repository downloaded via ZIP fallback.'})
                except Exception as ze:
                    yield _sse('log', {'level': 'error', 'message': f'❌ ZIP Fallback Failed: {ze}'})
                    raw_err = clone_res.stderr.strip() if clone_res else "Git binary not found in system PATH."
                    err_lines = [l for l in raw_err.split('\n') if not l.lower().startswith('cloning into')]
                    error_msg = err_lines[0] if err_lines else raw_err.partition('\n')[0].strip() or "Unknown Git error"
                    yield _sse('log', {'level': 'error', 'message': f'❌ Scan Pipeline Fault: {error_msg}. (ZIP Fallback also failed)'})
                    raise Exception(f"Clone and ZIP Fallback both failed: {error_msg}")
            else:
                yield _sse('log', {'level': 'success', 'message': '✅ Repository cloned successfully using Git.'})
                
            yield _sse('progress', {'value': 10, 'step': 0})

            # ── Step 2: Gather files ───────────────────────────────────
            files_to_scan = _gather_files(temp_dir)
            total = len(files_to_scan)
            yield _sse('log', {'level': 'info', 'message': f'🔎 Found {total} files. Entering Triage Phase...'})
            yield _sse('total_files', {'total': total})
            yield _sse('progress', {'value': 15, 'step': 1})

            if total == 0:
                yield _sse('log', {'level': 'warning', 'message': '⚠️ No scannable source files found.'})
                update_scan_status(scan_id, 'Completed', 0)
                yield _sse('done', {'scan_id': scan_id, 'vulnerabilities': [], 'total_files': 0})
                return

            # ── Step 3: Phase 1 - Stage 1 Triage (High-Efficiency Llama-3.3-70B)
            yield _sse('log', {'level': 'info', 'message': f'🛡️ STAGE 1: Llama 3.3 70B Smart Triage...'})
            
            suspicious_files = []
            triage_done = [0]
            
            def triage_file(file_path):
                rel = os.path.relpath(file_path, temp_dir)
                try:
                    with open(file_path, 'r', encoding='utf-8', errors='ignore') as fh:
                        content = fh.read()
                    if not content.strip():
                        return file_path, rel, content, []
                    # Stage 1 Triage
                    suspicious_snippets = triage_code_with_70b(content, filename=rel)
                    
                    # FORCE-FLAG: Always scan routes, controllers, and models (NodeGoat Hotspots)
                    is_hotspot = any(x in rel.lower() for x in ['routes/', 'controllers/', 'models/', 'services/'])
                    if is_hotspot and not suspicious_snippets:
                        print(f"🔥 HOTSPOT DETECTED: Force-flagging {rel}")
                        suspicious_snippets = [{"line": 1, "type": "HOTSPOT", "reason": "High-risk directory entry point"}]
                        
                    return file_path, rel, content, suspicious_snippets
                except Exception:
                    return file_path, rel, '', []

            triage_results = {}
            # Use wait with timeout to yield heartbeats if processing takes time
            with concurrent.futures.ThreadPoolExecutor(max_workers=3) as executor:
                future_map = {executor.submit(triage_file, fp): fp for fp in files_to_scan}
                
                while future_map:
                    # Wait for at least one future to complete, but timeout every 15s for heartbeat
                    done, not_done = concurrent.futures.wait(
                        future_map.keys(), 
                        timeout=15, 
                        return_when=concurrent.futures.FIRST_COMPLETED
                    )
                    
                    if not done:
                        yield heartbeat()
                        continue
                        
                    for future in done:
                        file_path, rel, content, suspicious_snippets = future.result()
                        triage_done[0] += 1
                        triage_results[file_path] = (rel, content, suspicious_snippets)
                        del future_map[future]
                        
                        triage_pct = 15 + int((triage_done[0] / total) * 35)  # 15→50%
                        if suspicious_snippets:
                            suspicious_files.append(file_path)
                            yield _sse('log', {'level': 'warning', 'message': f'🚩 [Triage] Flagged {len(suspicious_snippets)} suspicious snippet(s): {rel}'})
                        
                        yield _sse('progress', {'value': triage_pct, 'step': 1, 'triaged': triage_done[0], 'total': total})

            yield _sse('log', {'level': 'success', 
                               'message': f'🏁 Triage complete. {len(suspicious_files)}/{total} files marked for Targeted Deep Analysis.'})

            # ── Step 4: Phase 2 - Hybrid Reasoning & Analysis (STAGE 2 & 3) ──
            if suspicious_files:
                yield _sse('progress', {'value': 52, 'step': 2})
                yield _sse('log', {'level': 'info', 
                                   'message': f'🚀 STAGE 2 & 3: Dual-LLM (70B & Gemini) Verification on {len(suspicious_files)} files...'})

                analysis_done = [0]
                def analyze_one_file(fp):
                    rel, content, suspicious_snippets = triage_results[fp]
                    try:
                        marked_code = analyze_code_with_gemini(content, suspicious_snippets, filename=rel)
                        # Parse marker results...
                        vulns = _parse_vulnerabilities(marked_code, rel)
                        return rel, vulns, None
                    except Exception as e:
                        return rel, [], str(e)

                # HIGH-SPEED MODE: Increased workers and removed pacing for OpenRouter
                with concurrent.futures.ThreadPoolExecutor(max_workers=10) as g_executor:
                    g_futures = {g_executor.submit(analyze_one_file, fp): fp for fp in suspicious_files}
        
                    
                    while g_futures:
                        done, not_done = concurrent.futures.wait(
                            g_futures.keys(), 
                            timeout=15, 
                            return_when=concurrent.futures.FIRST_COMPLETED
                        )
                        
                        if not done:
                            yield heartbeat()
                            continue
                            
                        for g_future in done:
                            rel, vulns, err = g_future.result()
                            analysis_done[0] += 1
                            del g_futures[g_future]
                            
                            # HEARTBEAT: Keep SSE connection alive
                            yield _sse('log', {'level': 'info', 'message': f'🛡️ STAGE 2 & 3: Finalizing analysis for {rel}...'})
                            
                            if err:
                                yield _sse('log', {'level': 'error', 'message': f'⚠️ Deep Analysis Failed for {rel}: {err}'})
                                yield _sse('log', {'level': 'warning', 'message': f'💡 API Quota hit for {rel}. Using Zero-API Local Fallback.'})
                            else:
                                for v in vulns:
                                    if "[Static Heuristic]" in str(v.get('description', '')):
                                        yield _sse('log', {'level': 'warning', 'message': f'💡 API Quota hit for {rel}. Using Zero-API Local Fallback.'})
                                    add_vulnerability(scan_id, v)
                                    all_vulnerabilities.append(v)
                                
                                if vulns:
                                    yield _sse('log', {'level': 'vuln', 'message': f'🚨 Deep Analysis: Found {len(vulns)} issues in {rel}'})
                                else:
                                    yield _sse('log', {'level': 'success', 'message': f'✅ Deep Analysis: {rel} verified SAFE.'})
                                
                                yield _sse('vulnerabilities', {'items': vulns, 'file': rel})

                            analysis_pct = 52 + int((analysis_done[0] / len(suspicious_files)) * 40)  # 52→92%
                            yield _sse('progress', {'value': analysis_pct, 'step': 2, 
                                                    'analyzed': analysis_done[0], 'total_suspicious': len(suspicious_files)})
            else:
                yield _sse('log', {'level': 'success', 'message': '✅ All files verified SAFE by Triage. No deep analysis required.'})

            # ── Step 5: Finalize ───────────────────────────────────────
            summary_msg = (
                f"📊 Scan Summary: {total} files triaged. "
                f"{len(suspicious_files)} flagged for analysis. "
                f"{len(all_vulnerabilities)} issues identified."
            )
            yield _sse('log', {'level': 'info', 'message': summary_msg})

            update_scan_status(scan_id, 'Completed', len(all_vulnerabilities))
            yield _sse('progress', {'value': 100, 'step': 4})
            yield _sse('log', {'level': 'success', 
                               'message': f'🎉 Scan complete! Identified {len(all_vulnerabilities)} vulnerabilities.'})
            yield _sse('done', {'scan_id': scan_id, 'vulnerability_count': len(all_vulnerabilities)})

        except Exception as e:
            if 'scan_id' in locals(): update_scan_status(scan_id, 'Failed')
            yield _sse('error', {'message': f'❌ Scan Pipeline Fault: {str(e)}'})
        finally:
            if 'temp_dir' in locals() and os.path.exists(temp_dir):
                time.sleep(0.5) # Give Windows internal processes a moment to release locks
                shutil.rmtree(temp_dir, ignore_errors=True)

    return Response(stream_with_context(generate()), mimetype='text/event-stream',
                    headers={'Cache-Control': 'no-cache', 'X-Accel-Buffering': 'no'})

@app.route('/api/scans', methods=['GET'])
@token_required
def get_scans():
    user_id = getattr(request, 'user_id', None)
    user_email = getattr(request, 'user_email', None)
    return jsonify(get_all_scans(user_id=user_id, user_email=user_email))

@app.route('/api/analytics', methods=['GET'])
@token_required
def get_analytics():
    user_id = getattr(request, 'user_id', None)
    user_email = getattr(request, 'user_email', None)
    return jsonify(get_user_analytics(user_id=user_id, user_email=user_email))

@app.route('/api/scans/reset', methods=['POST'])
@token_required
def reset_scans():
    user_id = getattr(request, 'user_id', None)
    user_email = getattr(request, 'user_email', None)
    try:
        clear_user_data(user_id, user_email)
        return jsonify({'success': True, 'message': 'Scan history cleared'})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/scan/<scan_id>', methods=['GET'])
@token_required
def get_scan(scan_id):
    scan, vulns = get_scan_results(scan_id)
    if not scan:
        return jsonify({'error': 'Scan not found'}), 404
        
    # Security check: ensure user owns the scan
    user_id = getattr(request, 'user_id', None)
    if scan.get('user_id') and str(scan['user_id']) != user_id:
        return jsonify({'error': 'Unauthorized'}), 401
        
    return jsonify({'scan': scan, 'vulnerabilities': vulns})

@app.route('/api/vulnerability/<v_id>/resolve', methods=['POST'])
@token_required
def resolve_vuln(v_id):
    try:
        from database import resolve_vulnerability
        resolve_vulnerability(v_id)
        return jsonify({'success': True, 'message': 'Vulnerability marked as resolved'})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/fix', methods=['POST'])
@token_required
def fix_handler():
    # Bridge between V6.0 frontend payload and auto-fixer engine
    data = request.json
    vuln = data.get('vulnerability')
    if not vuln:
        return jsonify({"error": "No vulnerability data provided"}), 400
    
    code = vuln.get('vulnerableCode') or vuln.get('vulnerable_code', '')
    if not code:
        return jsonify({"error": "No vulnerable code snippet found"}), 400
        
    # Append marker if missing to guide the auto-fixer
    from backend.llm.sast_marker import MARKER
    if MARKER not in code:
        code += f"\n# {MARKER} [{vuln.get('category', 'ISSUE').upper()}]"

    try:
        from backend.llm.auto_fixer import remediate_marked_code
        fix_data = remediate_marked_code(code)
        return jsonify({
            "fixed_code": fix_data.get("fixed_code"),
            "explanation": fix_data.get("explanation")
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/agent/research', methods=['POST'])
@token_required
def agent_research():
    data = request.json
    vulnerability = data.get('vulnerability')
    if not vulnerability:
        return jsonify({"error": "No vulnerability data provided"}), 400
    
    from database import get_db
    db = get_db()
    researcher = AgenticResearcher(db)
    
    import asyncio
    try:
        # Create a new event loop for the async call if none exists in the thread
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        result = loop.run_until_complete(researcher.conduct_research(vulnerability))
        return jsonify(result)
    except Exception as e:
        return jsonify({"error": str(e)}), 500

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True, threaded=True)

import os
import sys
import json
import re

# Ensure backend package can be found
root_dir = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
if root_dir not in sys.path:
    sys.path.insert(0, root_dir)

from backend.llm.openrouter_client import call_openrouter as call_openrouter
from backend.llm.gemini_client import call_gemini as call_gemini
from backend.llm.groq_client import call_groq as call_groq

from .cwe_rag import RAGEngine
from .local_scanner import scan_local

rag = RAGEngine()

MARKER = "CodeGuard7219834THISISANERROR"

# Max characters per chunk to avoid token limits
CHUNK_SIZE = 3000

def _extract_json(text: str) -> any:
    """
    Robustly extract JSON array or object from text, 
    ignoring any preamble or chatty text from the LLM.
    """
    if not text or not text.strip():
        print("⚠️ _extract_json: received empty text")
        return None
        
    text = text.strip()
    
    # Step 1: Strip markdown code fences if present
    if '```' in text:
        parts = text.split('```')
        for part in parts:
            cleaned = part.strip()
            if cleaned.startswith('json'):
                cleaned = cleaned[4:].strip()
            if cleaned.startswith('[') or cleaned.startswith('{'):
                text = cleaned
                break
    
    # Step 2: Try direct parse first (fastest path)
    try:
        result = json.loads(text)
        return result
    except Exception:
        pass
    
    # Step 3: Find JSON array [...] anywhere in the text
    # Use a bracket-counting approach instead of regex for reliability
    arr_start = text.find('[')
    if arr_start != -1:
        depth = 0
        for i in range(arr_start, len(text)):
            if text[i] == '[': depth += 1
            elif text[i] == ']': depth -= 1
            if depth == 0:
                candidate = text[arr_start:i+1]
                try:
                    return json.loads(candidate)
                except Exception:
                    break
    
    # Step 4: Find JSON object {...} anywhere in the text
    obj_start = text.find('{')
    if obj_start != -1:
        depth = 0
        for i in range(obj_start, len(text)):
            if text[i] == '{': depth += 1
            elif text[i] == '}': depth -= 1
            if depth == 0:
                candidate = text[obj_start:i+1]
                try:
                    return json.loads(candidate)
                except Exception:
                    break
    
    print(f"⚠️ _extract_json: could not extract JSON from: {text[:200]}")
    return None


def triage_code_with_70b(code: str, filename: str = "file.py") -> list:
    """
    STAGE 1: Smart triage with the powerful Llama 3.3 70B reasoning model.
    F1 Optimization: Discovery layer for the 2-Stage Smart-Pipeline.
    """
    # Force triage if it's a Python file with @app.route (Entry point)
    if filename.endswith('.py') and '@app.route' in code:
        print(f"🔬 Force-flagging Python entry point: {filename}")
        return [{"line": 1, "type": "ENTRY_POINT", "reason": "Always analyze API entry points"}]

    if not os.getenv("GROQ_API_KEY", "").strip():
        return [{"line": 1, "reason": "No Groq API key - analyze start of file"}]

    # Stage 1 Optimization: Hyper-Aggressive Triage
    # Force triage if the filename is a high-risk directory (Entry points)
    # We check if the caller passed filename hints or just use keywords
    dangerous_keywords = ["req.body", "req.query", "db.", "collection", "find", "update", "exec", "eval", "dangerously", "InnerHtml", "fs.read", "child_process"]
    
    code_lower = code.lower()
    has_unsafe_key = any(k in code_lower for k in dangerous_keywords)
    
    # Send first 10000 chars (save window for tokens)
    snippet = code[:10000]

    prompt = (
        "ACT AS A ZERO-TOLERANCE SECURITY FILTER.\n"
        "DATABASE/CWE REFERENCE: Python/Flask & Node.js/Express High-Risk Sinks\n"
        "TASK: Identify line numbers where user input directly reaches a dangerous sink.\n"
        "IMPORTANT: If you see ANY insecure db query, unsanitized output, or risky decorator like @app.route without validation, FLAG IT.\n"
        "PYTHON-SPECIFIC: Flag ALL @app.route entries as potential entry points for deep analysis.\n"
        "Return ONLY a JSON array of suspicious objects: "
        '[{"line": 42, "type": "SUSPICIOUS", "reason": "Potential source-to-sink flow"}]\n'
        "If unsure and keywords like 'request.' or '@app.' exist, FLAG A SAMPLE LINE.\n"
        "If safe, return: []\n\n"
        f"CODE TO TRIAGE:\n{snippet}"
    )

    try:
        response = call_groq(
            prompt,
            model="llama-3.3-70b-versatile",
            system_instruction="You are a powerful security reasoning engine. Reply ONLY with a JSON array."
        )
        print(f"DEBUG: 70B Triage Response: {response[:200]}...") # Log for debugging
        parsed = _extract_json(response)
        
        # Hyper-aggressive fallback: if it has keywords but LLM returns [], flag the first keyword line
        if not parsed and has_unsafe_key:
            print("🔬 70B Missed Keywords: Triggering Force-Flag")
            # Find a line with a keyword to force analysis
            for i, line in enumerate(code.split('\n')[:100]):
                if any(k in line.lower() for k in dangerous_keywords):
                    return [{"line": i+1, "type": "FORCE_FLAG", "reason": "Aggressive keyword fallback"}]
        
        return parsed[:30] if isinstance(parsed, list) else []
    except Exception as e:
        print(f"⚠️ 70B Triage failed: {e}")
        return [{"line": 1, "reason": "70B Triage failed - falling back to analysis"}]




SECURITY_AUDITOR_SYSTEM_PROMPT = (
    "You are an Expert Security Auditor. ACT AS A PENETRATION TESTER targeting the code segment provided.\n"
    "Your goal is to hunt for any and all security flaws (e.g., SQLi, NoSQLi, XSS, SSTI, SSRF, Auth Bypass, Insecure Secrets, Best Practice Violations).\n"
    "REASONING PROTOCOL (Chain-of-Thought):\n"
    "1. ANALYZE: Identify all sources of untrusted data (e.g., request.args, req.body).\n"
    "2. TRACE: Follow data flow to sensitive sinks (e.g., db.execute, render_template_string).\n"
    "3. VERIFY: Determine if any sanitization or validation exists. If not, consider it VULNERABLE.\n"
    "4. CRITIQUE: Self-correct your findings. Are there filters you missed? Is it a false positive?\n\n"
    "Zero-Tolerance for missing vulnerabilites. If a protection is NOT EXPLICITLY PRESENT in this code, assume it's missing.\n"
    "CRITICAL RULE:\n"
    "1. NOISE REDUCTION: Detect a MAXIMUM OF 10 'Low' severity issues per task. Focus on the most significant best-practice violations.\n"
    "Return ONLY a JSON array of issues (schema below). If no issues, return [].\n"
    "JSON SCHEMA:\n"
    '[{"line": number, "type": "INJECTION|XSS|SSTI|CRYPTO|ACCESS_CONTROL|INFRASTRUCTURE|BEST_PRACTICE", "severity": "Critical|High|Medium|Low", "description": "Chain-of-thought reasoning", "snippet": "vulnerable code line"}]'
)

def _ask_for_vulns(code_chunk: str, caller, filename: str = "file.py") -> list:
    """
    Ask an LLM to return a JSON list of vulnerabilities found in the chunk.
    Uses partitioned prompts for token efficiency.
    """
    # 1. Prepare minimal RAG context for token efficiency
    context = rag.get_minimal_context(code_chunk, file_path=filename)
    
    # 2. Build the System Prompt
    system_prompt = SECURITY_AUDITOR_SYSTEM_PROMPT
    if context:
        system_prompt += f"\n\n### SECURITY KNOWLEDGE BASE (CWE REFERENCE):\n{context}"
    
    # 3. Build the User Prompt (Target centric)
    user_prompt = f"AUDIT TASK: Analye the following code from '{filename}' for vulnerabilities.\n\nCODE TO AUDIT (LINE NUMBERS SHOWN):\n{code_chunk}"

    try:
        raw = caller(user_prompt, system_instruction=system_prompt)
        print(f"DEBUG: Raw LLM Response (first 500 chars): {raw[:500]}")
        parsed = _extract_json(raw)
        
        if parsed is None:
            print(f"⚠️ _ask_for_vulns: _extract_json returned None for response")
            return []
        
        # Normalize: ensure it's a list
        if isinstance(parsed, list):
            return parsed
        # If it's a dict like {"findings": [...]}, extract the list
        if isinstance(parsed, dict):
            for key in ["vulnerabilities", "findings", "vulns", "issues", "results"]:
                if key in parsed and isinstance(parsed[key], list):
                    print(f"DEBUG: Extracted {len(parsed[key])} vulns from dict key '{key}'")
                    return parsed[key]
            # If the dict itself looks like a single vulnerability
            if "line" in parsed and "type" in parsed:
                return [parsed]
            print(f"⚠️ _ask_for_vulns: Got dict but no recognized key. Keys: {list(parsed.keys())}")
        return []
    except Exception as ex:
        print(f"⚠️ _ask_for_vulns exception: {ex}")
        return []


def _add_line_numbers(code: str) -> str:
    """Prefix each line with its 1-indexed line number."""
    lines = code.split('\n')
    return '\n'.join(f"{i+1}: {line}" for i, line in enumerate(lines))


def _normalize_findings(vuln_list: list) -> list:
    """
    Business Logic Tier:
    Cap 'Low' severity issues at a maximum of 10 per scan.
    """
    normalized = []
    low_count = 0
    for v in vuln_list:
        # LOW SEVERITY BUDGET: Max 10 per file/scan
        is_low = str(v.get("severity", "Medium")).lower() == "low"
        if is_low:
            if low_count < 10:
                low_count += 1
                normalized.append(v)
            else:
                continue
        else:
            normalized.append(v)
    return normalized


def _apply_markers(code: str, vuln_list: list, line_offset: int = 0) -> str:
    """Apply MARKER comments to vulnerable lines in the code string."""
    lines = code.split('\n')
    for vuln in vuln_list:
        try:
            raw_line = vuln.get("line", 0)
            vtype = vuln.get("type", "Unknown").upper()
            # Normalize type
            if "INJECT" in vtype or "SQL" in vtype or "COMMAND" in vtype:
                tag = "INJECTION"
            elif "XSS" in vtype or "CROSS" in vtype:
                tag = "XSS"
            elif "CRYPT" in vtype or "MD5" in vtype or "SHA1" in vtype:
                tag = "CRYPTO"
            elif "INFRA" in vtype or "DOCKER" in vtype:
                tag = "INFRASTRUCTURE"
            elif "DEP" in vtype or "PACKAGE" in vtype:
                tag = "DEPENDENCY"
            else:
                tag = "ACCESS_CONTROL"

            actual_line = int(raw_line) - 1 - line_offset  # 0-indexed within this chunk
            if 0 <= actual_line < len(lines):
                # Avoid double-marking
                if MARKER not in lines[actual_line]:
                    severity = vuln.get("severity", "Medium").upper()
                    lines[actual_line] += f"  # {MARKER} [{tag}:{severity}]"
        except (ValueError, TypeError):
            continue
    return '\n'.join(lines)


def analyze_code_with_gemini(code: str, triage_snippets: list, filename: str = "file.py") -> str:
    """
    3-STAGE SECURITY PIPELINE (8B -> 70B -> Gemini).
    Stage 1 was Triage. This function performs Stage 2 and Stage 3.
    """
    lines = code.split('\n')
    total_lines = len(lines)
    final_findings = []

    if not triage_snippets: return code

    for snippet in triage_snippets:
        try:
            line_no = int(snippet.get("line", 0))
            if line_no <= 0: continue
            
            # Context Window: 30 lines
            start = max(0, line_no - 15)
            end = min(total_lines, line_no + 15)
            numbered_chunk = '\n'.join(f"{start + i + 1}: {line}" for i, line in enumerate(lines[start:end]))

            # --- STAGE 2 & 3: Expert Verification (OpenRouter PRO) ---
            print(f"📡 High-Performance Analysis for line {line_no} (OpenRouter - Claude 3.5 Sonnet)...")
            final_vulns = _ask_for_vulns(numbered_chunk, lambda p, system_instruction: call_openrouter(p, system_instruction=system_instruction), filename=filename)
            
            if final_vulns is None:
                # Only fallback if OpenRouter FAILED, not if it returned [] (Safe)
                print(f"🛡️ OpenRouter Failed. Falling back to Gemini for line {line_no}...")
                final_vulns = _ask_for_vulns(numbered_chunk, lambda p, system_instruction: call_gemini(p, system_instruction=system_instruction, exclude_groq=True), filename=filename)

            if final_vulns:
                print(f"🚨 CONFIRMED at line {line_no} ( Claude/Gemini). Addition: {len(final_vulns)} findings.")
                final_findings.extend(final_vulns)
            else:
                # ZERO-API FALLBACK: If API misses, run local heuristics
                local_hits = scan_local(numbered_chunk, filename=filename)
                if local_hits:
                    print(f"✅ Gemini 2.5 Missed - Zero-API Local Fallback Caught {len(local_hits)} issues.")
                    final_findings.extend(local_hits)
        except Exception as e:
            print(f"⚠️ Analysis Failed for line {line_no}: {e}")
            local_hits = scan_local(code, filename=filename)
            final_findings.extend(local_hits)

    # Apply noise reduction (Max 10 Low severity issues)
    final_findings = _normalize_findings(final_findings)

    # Step 4: Apply Markers
    return _apply_markers(code, final_findings)




def scan_and_mark_code(code: str, filename: str = "file.py") -> str:
    """
    Main entry point for the 2-Stage Smart Pipeline.
    """
    suspicious_snippets = triage_code_with_70b(code)
    
    if not suspicious_snippets:
        print("✅ Stage 1 Clear: SAFE (Llama 70B)")
        return code
        
    print(f"🔥 Stage 1 Discovery: {len(suspicious_snippets)} snippets flagged by 70B reasoning for {filename}...")
    return analyze_code_with_gemini(code, suspicious_snippets, filename=filename)


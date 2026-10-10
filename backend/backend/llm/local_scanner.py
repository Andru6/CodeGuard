import re
import os

def scan_local(code: str, filename: str = "") -> list:
    """
    Zero-API High-Speed Security Scanner.
    Detects classic source-to-sink patterns in Node.js, PHP, and Python.
    """
    findings = []
    lines = code.split('\n')
    ext = os.path.splitext(filename)[1].lower() if filename else ".js"

    # --- SHARED PATTERNS (Secrets, eval, etc.) ---
    patterns = [
        (r"(eval|exec|spawn)\(.*\b(req|request|input|data)\b", "RCE", "Critical", "Potential Remote Code Execution from user input."),
        (r"(password|secret|api_key|token|private_key)\s*[:=]\s*['\"][a-zA-Z0-9_\-]{8,}['\"]", "SECRET", "High", "Hardcoded sensitive credential detected."),
    ]

    # --- STACK-SPECIFIC RULES ---
    
    # Node.js / Juice Shop / NodeGoat
    if ext in ['.js', '.ts', '.jsx', '.tsx']:
        patterns += [
            (r"\.(find|findOne|update|deleteMany|remove)\(.*\b(req\.body|req\.query|req\.params)\b", "NOSQLI", "Critical", "Unsanitized user input utilized in NoSQL query."),
            (r"\.query\(.*\$[a-zA-Z].*\b(req\.body|req\.query)\b", "INJECTION", "Critical", "Raw database query containing unsanitized user input."),
            (r"res\.(send|write|end)\(.*(req\.body|req\.query|req\.params).*", "XSS", "High", "Reflection of raw user input into HTTP response (Possible XSS)."),
            (r"res\.redirect\(.*(req\.body|req\.query|req\.params).*", "REDIRECT", "Medium", "Open Redirect vulnerability via unvalidated user input."),
            (r"cookieSession\(", "SESSION", "High", "Insecure cookie session configuration detected."),
            (r"innerHtml\s*=", "XSS", "High", "Direct use of innerHtml could lead to XSS."),
        ]
    
    # PHP / DVWA
    elif ext == '.php':
        patterns += [
            (r"mysqli?_query\(.*(\$_GET|\$_POST|\$_REQUEST).*", "SQLI", "Critical", "Classic PHP SQL Injection from global input."),
            (r"exec\(.*(\$_GET|\$_POST|\$_REQUEST).*", "RCE", "Critical", "System command execution from user input."),
            (r"echo\s+.*(\$_GET|\$_POST|\$_REQUEST).*", "XSS", "High", "Raw reflection of PHP global input leading to XSS."),
        ]
        
    # Python / Vulnerable Flask App / Vulpy
    elif ext == '.py':
        # Specific patterns for Flask/Python security
        patterns += [
            (r"\.execute\(.*(request\.args|request\.form|request\.values).*", "SQLI", "Critical", "Unsafe usage of Flask request data in database query."),
            (r"render_template_string\(.*(\{\{|\b(request|input))\b.*", "SSTI", "Critical", "Server-Side Template Injection via Flask request data."),
            (r"subprocess\.(run|Popen|call)\(.*\b(request|input)\b", "RCE", "Critical", "Shell command execution using Flask request data."),
            (r"os\.system\(.*\b(request|input)\b", "RCE", "Critical", "Insecure os.system() call with user input."),
            (r"pickle\.(load|loads)\(", "DESERIALIZATION", "Critical", "Insecure deserialization via pickle module."),
            (r"yaml\.load\(", "DESERIALIZATION", "High", "Insecure YAML loading. Use yaml.safe_load()."),
            (r"\|safe\b", "XSS", "High", "Jinja2 |safe filter used on potential user input."),
            (r"Markup\(.*(request|input)", "XSS", "High", "Manual HTML markup construction with user input."),
            (r"DEBUG\s*=\s*True", "DEBUG_MODE", "High", "Flask debug mode enabled in source code."),
            (r"SESSION_COOKIE_(HTTPONLY|SECURE)\s*=\s*False", "BEST_PRACTICE", "Low", "Insecure session cookie configuration."),
            (r"app\.config\['SECRET_KEY'\]\s*=\s*['\"][a-zA-Z0-9_\-]{8,}['\"]", "SECRET", "High", "Hardcoded Flask SECRET_KEY detected."),
        ]

    # --- RUN SCAN ---
    for i, line in enumerate(lines):
        line_no = i + 1
        for regex, kind, sev, desc in patterns:
            if re.search(regex, line, re.IGNORECASE):
                findings.append({
                    "line": line_no,
                    "type": kind,
                    "severity": sev,
                    "description": f"[Static Heuristic] {desc}",
                    "snippet": line.strip()
                })
    
    # Dedup findings by line and type
    seen = set()
    unique = []
    for f in findings:
        key = (f["line"], f["type"])
        if key not in seen:
            unique.append(f)
            seen.add(key)
            
    return unique

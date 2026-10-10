import os
import sys
import re
from backend.llm.sast_marker import MARKER
from backend.llm.gemini_client import call_gemini

def remediate_marked_code(code: str) -> dict:
    """
    HYBRID DEEP-CONTEXT ENGINE (V11 Clean Format):
    Contextual fixes + Standard vertical separation.
    Fixed with 'white-space: pre-wrap' in CSS.
    """
    lines = code.splitlines()
    target_idx = -1
    for i, line in enumerate(lines):
        if MARKER in line:
            # Code is on same line or above
            if len(line.split('#')[0].strip()) > 5: target_idx = i
            elif i > 0: target_idx = i - 1
            break
            
    if target_idx == -1:
        return {"error": "Missing CodeGuard marker."}

    v_line = lines[target_idx].split('#')[0].strip()
    
    # HYBRID CONTEXT-AWARE PROMPT (Clean Edition)
    prompt = (
        "Role: Expert Security Researcher.\n"
        "Task: Fix this Python SQL/SSTI vulnerability.\n"
        "FORMAT YOUR RESPONSE EXACTLY AS FOLLOWS:\n"
        "FIXED CODE: [single secure line]\n"
        "EXPLANATION: [3-4 clear bullet points on technical reasoning]\n"
        "MITIGATION: [exact security pattern used]\n\n"
        "EXEMPLAR:\n"
        "Before: c.execute(\"SELECT * FROM users WHERE ID='%s'\" % id)\n"
        "FIXED CODE: c.execute(\"SELECT * FROM users WHERE ID=?\", (id,))\n"
        "EXPLANATION: \n- String formatting allows arbitrary SQL injection via parameters.\n- No data sanitization on input.\n- Parameterization ensures values are treated as data, not commands.\n"
        "MITIGATION: Query Parameterization (Binding)\n\n"
        "YOUR TASK (NO PARROTING):\n"
        f"Before: {v_line}\n"
    )

    try:
        print(f"🛡️ Clean Fix for: {v_line[:50]}...")
        raw = call_gemini(prompt)
        if not raw: raise Exception("No response.")
            
        # Robust Keyphrase Parsing with Clean Newlines
        parts = {"fixed_line": "", "explanation": "", "mitigation": ""}
        current_part = None
        
        for l in raw.split('\n'):
            l_s = l.strip()
            if not l_s: continue
            
            if "FIXED CODE:" in l_s:
                parts["fixed_line"] = l_s.split(":", 1)[1].strip().replace("```python", "").replace("```", "").strip()
                current_part = "fixed_line"
            elif "EXPLANATION:" in l_s:
                first_point = l_s.split(":", 1)[1].strip().strip("- •*")
                parts["explanation"] = f"• {first_point}" if first_point else ""
                current_part = "explanation"
            elif "MITIGATION:" in l_s:
                parts["mitigation"] = l_s.split(":", 1)[1].strip()
                current_part = "mitigation"
            elif current_part == "explanation":
                clean_point = l_s.strip("- •*")
                if clean_point:
                    if parts["explanation"]: parts["explanation"] += "\n"
                    parts["explanation"] += f"• {clean_point}"

        fixed_line = parts["fixed_line"]
        if not fixed_line:
             fixed_line = raw.strip().split('\n')[0].replace("FIXED CODE:", "").replace("```python", "").strip()
        
        # REMOVE ANY LEFTOVER MARKERS (LLM PARROTING PROTECTION)
        # We strip both the exact MARKER and any generic 'CodeGuard' comments the LLM might include
        fixed_line = re.sub(r'#.*' + re.escape(MARKER) + r'.*', '', fixed_line).strip()
        fixed_line = re.sub(r'#.*CodeGuard\d*.*', '', fixed_line).strip()
             
        # Simple \n formatting works now that CSS 'white-space: pre-wrap' is active
        full_explanation = f"{parts['explanation']}\n\n**MITIGATION STRATEGY:**\n{parts['mitigation']}"

        # ANTI-PARROT GUARD
        norm_v = re.sub(r'\s+', '', v_line).lower()
        norm_f = re.sub(r'\s+', '', fixed_line).lower()
        
        if norm_v == norm_f or len(fixed_line) < 5:
             raise Exception("AI returned identical/incomplete code. Use fallback for better reasoning.")

        new_lines = list(lines)
        new_lines[target_idx] = fixed_line

        # FINAL SANITIZATION: Strip ALL markers from the entire fixed block 
        # to ensure the 'Fixed Area' in UI is completely clean.
        final_fixed_code = "\n".join(new_lines)
        final_fixed_code = re.sub(r'#.*' + re.escape(MARKER) + r'.*', '', final_fixed_code)
        final_fixed_code = re.sub(r'#.*CodeGuard\d*.*', '', final_fixed_code)

        return {
            "fixed_code": final_fixed_code,
            "explanation": full_explanation
        }
    except Exception as e:
        raise Exception(f"Failed to generate fix: {str(e)}")

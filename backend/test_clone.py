import subprocess
import os
import shutil
import tempfile
import uuid

def test_clone():
    target_url = "https://github.com/skp98/Vulnerable-Flask-App"
    temp_dir = os.path.join(tempfile.gettempdir(), f"test_clone_{uuid.uuid4().hex}")
    
    # Use the absolute path I discovered
    git_bin = r'C:\Users\Ameena Nazneen\AppData\Local\Programs\Git\cmd\git.exe'
    
    new_env = os.environ.copy()
    new_env['GIT_TERMINAL_PROMPT'] = '0'
    new_env['GCM_INTERACTIVE'] = 'never'
    new_env['GIT_ASKPASS'] = 'true'
    
    print(f"--- ATTEMPT 1: Clone Vulnerable-Flask-App with Windows Hardening ---")
    try:
        # Use the server.py logic (with absolute path)
        res = subprocess.run([git_bin, '-c', 'credential.helper=', '-c', 'core.askpass=true', 
                              'clone', '--depth', '1', target_url, temp_dir], 
                             capture_output=True, text=True, env=new_env, timeout=60)
        
        print(f"Return Code: {res.returncode}")
        print(f"STDOUT: {res.stdout}")
        print(f"STDERR: {res.stderr}")
        
    except Exception as e:
        print(f"Error: {e}")
    finally:
        shutil.rmtree(temp_dir, ignore_errors=True)

if __name__ == "__main__":
    test_clone()

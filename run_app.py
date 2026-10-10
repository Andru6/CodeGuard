import subprocess
import os
import sys
import time
import signal

def run_app():
    print("🚀 Starting CodeGuard Unified Application...")
    
    # 1. Install dependencies if needed (optional, depends on user preference)
    # print("📦 Installing dependencies...")
    # subprocess.run(["pip", "install", "-r", "backend/requirements.txt"])
    # subprocess.run(["npm", "install"], cwd="frontend")
    
    # 2. Start Backend
    print("🤖 Starting Backend Server (Flask)...")
    backend_proc = subprocess.Popen(
        [sys.executable, "backend/server.py"],
        env=os.environ.copy()
    )
    
    # 3. Start Frontend
    print("🌐 Starting Frontend Development Server (Vite)...")
    frontend_proc = subprocess.Popen(
        ["npm", "run", "dev"],
        cwd="frontend",
        shell=True if os.name == 'nt' else False
    )
    
    print("\n✅ Application is launching!")
    print("Backend: http://localhost:5000")
    print("Frontend: Check the Vite output for the URL (usually http://localhost:5173)")
    print("\nPress Ctrl+C to stop both servers.")
    
    try:
        while True:
            time.sleep(1)
            if backend_proc.poll() is not None:
                print("❌ Backend process exited.")
                break
            if frontend_proc.poll() is not None:
                print("❌ Frontend process exited.")
                break
    except KeyboardInterrupt:
        print("\n🛑 Stopping servers...")
    finally:
        backend_proc.terminate()
        frontend_proc.terminate()
        print("Done.")

if __name__ == "__main__":
    run_app()

#!/bin/bash

# CodeGuard Website Launch Script (Git Bash Version)
echo "--------------------------------------------------"
echo "🚀 Launching CodeGuard Website..."
echo "--------------------------------------------------"

# 1. Kill any existing processes (optional, but cleaner)
echo "🛑 Cleaning up old processes..."
pkill -f "python backend/server.py" 2>/dev/null
pkill -f "vite" 2>/dev/null

# 2. Check and start Backend
echo "📡 Starting Backend (Flask)..."
if [ ! -d "backend/venv" ]; then
    echo "⚠️ venv not found. Please run ./setup.sh first."
    exit 1
fi

source backend/venv/Scripts/activate
python backend/server.py > backend_log.txt 2>&1 &
BACKEND_PID=$!
echo "✅ Backend started (PID: $BACKEND_PID)"

# 3. Check and start Frontend
echo "💻 Starting Frontend (React/Vite)..."
cd frontend
npm run dev > ../frontend_log.txt 2>&1 &
FRONTEND_PID=$!
cd ..
echo "✅ Frontend started (PID: $FRONTEND_PID)"

# 4. Wait a bit for startup
echo "⏳ Waiting for services to initialize..."
sleep 5

# 5. Open Browser
echo "🌐 Opening CodeGuard on http://localhost:5173"
start http://localhost:5173

echo "--------------------------------------------------"
echo "✅ CodeGuard is now LIVE!"
echo "Press Ctrl+C in this terminal if you wish to stop."
echo "--------------------------------------------------"

# Keep script running to maintain child processes
wait

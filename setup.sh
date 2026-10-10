#!/bin/bash

# CodeGuard Setup Script (Git Bash Version)
echo "--------------------------------------------------"
echo "🛠️  Setting up CodeGuard Environment..."
echo "--------------------------------------------------"

# 1. Setup Python Virtual Environment
echo "🐍 Setting up Python venv..."
if [ ! -d "backend/venv" ]; then
    python -m venv backend/venv
    echo "✅ venv created."
else
    echo "ℹ️  venv already exists."
fi

# 2. Install Python Dependencies
echo "📦 Installing backend dependencies..."
source backend/venv/Scripts/activate
pip install -r backend/requirements.txt
echo "✅ Backend ready."

# 3. Install Node.js Dependencies
echo "📦 Installing frontend dependencies..."
cd frontend
npm install
cd ..
echo "✅ Frontend ready."

echo "--------------------------------------------------"
echo "✨ Setup Complete!"
echo "Now run: ./launch.sh to start the website."
echo "--------------------------------------------------"

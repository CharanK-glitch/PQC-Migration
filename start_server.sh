#!/bin/bash
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# pgcrypto PQC Scanner - Persistent Server Launcher
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"
cd "$DIR"

PORT=8765
LOG_FILE="$DIR/server.log"

# Stop any existing process running on port 8765
PID=$(lsof -ti :$PORT)
if [ -n "$PID" ]; then
    echo "Stopping existing server (PID: $PID)..."
    kill -9 $PID 2>/dev/null || true
    sleep 1
fi

echo "Starting pgcrypto PQC Scanner server on port $PORT..."
nohup python3 server.py > "$LOG_FILE" 2>&1 &

NEW_PID=$!
echo "Server started successfully with PID: $NEW_PID"
echo "Log file : $LOG_FILE"
echo "Local    : http://127.0.0.1:$PORT"

IP=$(python3 -c 'import socket; s=socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.connect(("8.8.8.8", 80)); print(s.getsockname()[0]); s.close()' 2>/dev/null || echo "127.0.0.1")
echo "Network  : http://$IP:$PORT"

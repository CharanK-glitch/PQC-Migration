#!/bin/bash
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# pgcrypto PQC Scanner - Persistent Server Launcher
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"
cd "$DIR"

PORT=8765
LOG_FILE="$DIR/server.log"

# Stop an existing instance of this server, but do not kill an unrelated service.
PIDS=$(lsof -tiTCP:$PORT -sTCP:LISTEN 2>/dev/null || true)
for PID in $PIDS; do
    COMMAND=$(ps -p "$PID" -o command= 2>/dev/null || true)
    case "$COMMAND" in
        *"$DIR/server.py"*|*"server.py"*)
            echo "Stopping existing server (PID: $PID)..."
            kill "$PID" 2>/dev/null || true
            ;;
        *)
            echo "Port $PORT is already in use by PID $PID: $COMMAND" >&2
            exit 1
            ;;
    esac
done

for ATTEMPT in {1..10}; do
    if [ -z "$(lsof -tiTCP:$PORT -sTCP:LISTEN 2>/dev/null || true)" ]; then
        break
    fi
    sleep 1
done

if [ -n "$(lsof -tiTCP:$PORT -sTCP:LISTEN 2>/dev/null || true)" ]; then
    echo "Port $PORT is still occupied; refusing to report a successful start." >&2
    exit 1
fi

PYTHON="$DIR/.venv/bin/python"
if [ ! -f "$PYTHON" ]; then
    PYTHON="python3"
fi

echo "Starting pgcrypto PQC Scanner server on port $PORT..."
nohup "$PYTHON" server.py > "$LOG_FILE" 2>&1 &

NEW_PID=$!

READY=0
for ATTEMPT in {1..15}; do
    if curl --silent --fail --max-time 1 "http://127.0.0.1:$PORT/api/status" >/dev/null; then
        READY=1
        break
    fi
    if ! kill -0 "$NEW_PID" 2>/dev/null; then
        break
    fi
    sleep 1
done

if [ "$READY" -ne 1 ]; then
    echo "Dashboard did not become ready. Check $LOG_FILE for startup errors." >&2
    exit 1
fi

echo "Server is responding with PID: $NEW_PID"
echo "Log file : $LOG_FILE"
echo "Local    : http://127.0.0.1:$PORT"

IP=$("$PYTHON" -c 'import socket; s=socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.connect(("8.8.8.8", 80)); print(s.getsockname()[0]); s.close()' 2>/dev/null || echo "127.0.0.1")
if [ "$IP" = "127.0.0.1" ]; then
    echo "Network  : no LAN IPv4 address detected; remote devices cannot use the local URL"
else
    echo "Network  : http://$IP:$PORT"
fi

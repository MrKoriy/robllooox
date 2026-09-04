#!/bin/bash
set -e

DIR="$(cd "$(dirname "$0")" && pwd)"
PAYLOAD="$DIR/payload.dylib"
PROC="${1:-RobloxPlayer}"
UID_VAL=$(id -u)
SOCKET="/tmp/inj_ipc_${UID_VAL}.sock"

if [ ! -f "$PAYLOAD" ]; then
    echo "[-] Error: payload.dylib not found. Building now..."
    "$DIR/build.sh"
fi

PID=$(pgrep -x "$PROC" | head -n 1)

if [ -z "$PID" ]; then
    echo "[-] Process '$PROC' is not running."
    echo "[!] Usage: $0 [ProcessName]"
    exit 1
fi

echo "[+] Target Process: $PROC (PID: $PID)"
echo "[+] Injected Payload: $PAYLOAD"

# dlopen with a path already loaded in the process is a NO-OP (constructors
# do not re-run). Copy to a fresh path so every injection loads a new image.
FRESH="/tmp/inj_payload_$(date +%s).dylib"
cp "$PAYLOAD" "$FRESH" || { echo "[-] cp failed"; exit 1; }

echo "[*] Attaching via LLDB..."

lldb -p "$PID" -b \
  -o "expr void* \$handle = (void*)dlopen(\"$FRESH\", 2);" \
  -o "expr if (\$handle == 0) { (char*)dlerror(); }" \
  -o "detach" \
  -o "quit"

echo "[+] Injection command sent."

# Verify the payload actually came up
for i in 1 2 3 4 5; do
    if [ -S "$SOCKET" ]; then
        if echo "__PING__" | nc -U "$SOCKET" 2>/dev/null | grep -q PONG; then
            echo "[+] Verified: IPC server is up at $SOCKET"
            exit 0
        fi
    fi
    sleep 1
done

echo "[!] Warning: IPC socket not responding yet at $SOCKET"
echo "    Check logs: tail -f /tmp/inj_payload_${UID_VAL}.log"

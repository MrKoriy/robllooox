#!/bin/bash
set -e

DIR="$(cd "$(dirname "$0")" && pwd)"
PAYLOAD="$DIR/payload.dylib"
TARGET="${1:-/Applications/Roblox.app/Contents/MacOS/RobloxPlayer}"
UID_VAL=$(id -u)

if [ ! -f "$PAYLOAD" ]; then
    echo "[-] Error: payload.dylib not found in $DIR!"
    echo "[*] Building payload.dylib..."
    "$DIR/build.sh"
fi

if [ ! -f "$TARGET" ]; then
    echo "[-] Error: Target executable not found at: $TARGET"
    echo "[!] Usage: $0 [path_to_executable]"
    exit 1
fi

echo "[+] Launching target: $TARGET"
echo "[+] Injected payload: $PAYLOAD"
echo "[!] NOTE: On modern macOS, DYLD_INSERT_LIBRARIES requires the target binary"
echo "    to be unsigned/ad-hoc signed (or SIP partially disabled)."
echo "[i] IPC socket (on success): /tmp/inj_ipc_${UID_VAL}.sock"
echo "[i] Payload log:             /tmp/inj_payload_${UID_VAL}.log"

export DYLD_INSERT_LIBRARIES="$PAYLOAD"
exec "$TARGET"

#!/bin/bash
set -e

DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$DIR"

echo "[*] Building payload.dylib..."
make clean || true
make all

if [ -f "payload.dylib" ]; then
    echo "[+] Successfully built payload.dylib:"
    file payload.dylib
    codesign -v payload.dylib && echo "[+] Code signature verified."
else
    echo "[-] Build failed."
    exit 1
fi

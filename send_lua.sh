#!/bin/bash
# send_lua.sh - Утилита для отправки Lua-кода через IPC сокет инжектора

UID_VAL=$(id -u)
SOCKET="/tmp/inj_ipc_${UID_VAL}.sock"

if [ ! -S "$SOCKET" ]; then
    SOCKET="./inj_ipc.sock"
fi

if [ ! -S "$SOCKET" ]; then
    echo "[-] Error: IPC socket not found."
    echo "    Make sure payload.dylib is loaded and running in the target process."
    exit 1
fi

if [ -n "$1" ] && [ -f "$1" ]; then
    echo "[+] Sending Lua file '$1' to socket ($SOCKET)..."
    nc -U "$SOCKET" < "$1"
elif [ -n "$1" ]; then
    # Inline code: ./send_lua.sh 'print(1+1)'
    printf '%s' "$1" | nc -U "$SOCKET"
elif [ ! -t 0 ]; then
    nc -U "$SOCKET"
else
    echo "Usage:"
    echo "  $0 script.lua"
    echo "  $0 'print(1+1)'"
    echo "  echo 'print(123)' | $0"
fi

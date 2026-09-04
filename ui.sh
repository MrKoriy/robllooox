#!/bin/bash
# ui.sh — запуск веб-интерфейса управления
DIR="$(cd "$(dirname "$0")" && pwd)"
exec python3 "$DIR/ui/server.py" "$@"

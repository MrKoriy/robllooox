#!/bin/bash
# pc_sample_cli.sh — PC-sampling via repeated lldb attach (working CLI pattern)
# Usage: pc_sample_cli.sh <pid> <samples> <outfile>
PID="${1:?pid required}"
N="${2:-60}"
OUT="${3:-/tmp/pc_samples.txt}"
PIDN=0

: > "$OUT"
for i in $(seq 1 "$N"); do
    PC=$(lldb -p "$PID" -b -o "register read pc" -o "detach" -o "quit" 2>/dev/null | \
         grep -o 'pc = 0x[0-9a-f]*' | head -1 | awk '{print $3}')
    if [ -n "$PC" ]; then
        echo "$PC" >> "$OUT"
        PIDN=$((PIDN+1))
    fi
    printf "\r%d/%d samples (%d pcs)" "$i" "$N" "$PIDN"
done
echo
echo "wrote $PIDN samples to $OUT"
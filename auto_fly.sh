#!/bin/bash
# auto_fly.sh — waits for the player to join a game, then injects fly.lua
# through the IPC socket. The patched payload routes plain Lua through the
# game-state executor (luau_load pipeline), so plain scripts just work.
# Retries while scripts error (e.g. executed against the menu DataModel
# before the real game VM takes over).

DIR="$(cd "$(dirname "$0")" && pwd)"
UID_VAL=$(id -u)
SOCKET="/tmp/inj_ipc_${UID_VAL}.sock"
FLY="$DIR/fly.lua"
LAUNCH_LOG="/tmp/inj_launch.log"
LOG="/tmp/auto_fly.log"

log() { echo "$(date +%H:%M:%S) $*" >> "$LOG"; }

: > "$LOG"
log "auto_fly monitor started (socket=$SOCKET)"

in_game=0
ITER=0
while [ $ITER -lt 200 ]; do
    ITER=$((ITER + 1))

    if grep -q "\[fly\] loaded" "$LAUNCH_LOG" 2>/dev/null; then
        log "FLY LOADED (confirmed in launch log)"
        echo "FLY_LOADED" >> "$LOG"
        exit 0
    fi

    if [ $in_game -eq 0 ]; then
        if grep -qE "Joining game|startUGCGame|joinDataModel" "$LAUNCH_LOG" 2>/dev/null; then
            in_game=1
            log "player joined a game — injecting fly"
        else
            sleep 4
            continue
        fi
    fi

    RESP=$(nc -U "$SOCKET" < "$FLY" 2>/dev/null)
    if [ $((ITER % 6)) -eq 1 ]; then
        log "fly resp: $(echo "$RESP" | head -c 300)"
    fi
    if echo "$RESP" | grep -q "ret=-4"; then
        log "SEGV inside exec — VM may be corrupted, stopping retries"
        echo "SEGV_STOP" >> "$LOG"
        exit 2
    fi
    sleep 5
done

log "TIMEOUT after ~17 min"
echo "TIMEOUT" >> "$LOG"
exit 1

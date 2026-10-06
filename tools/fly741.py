#!/usr/bin/env python3
"""fly741.py — fly driver over the pcall-hook deferred-exec pipeline.

Usage:
  python3 tools/fly741.py          # find game universe, fly: pulses at ~11Hz
  Ctrl-C                            # zero velocity + disarm

The staged pulse (all ops from the verified wire map, no branches):
  reads camera LookVector, sets HumanoidRootPart.AssemblyLinearVelocity
  = look * SPEED — fly where you look. PlatformStand keeps physics off
  the character's back.
"""
import os, re, sys, time, socket, subprocess

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from run741 import build, send, SOCKET

LOG = f"/tmp/inj_payload_{os.getuid()}.log"
SPEED = 60
HZ = 11

PULSE = f"""
local ws = game.Workspace
local cam = ws.CurrentCamera
local lv = cam.CFrame.LookVector
local root = ws:FindFirstChild(game.Players.LocalPlayer.Name).HumanoidRootPart
root.AssemblyLinearVelocity = Vector3.new(lv.X*{SPEED}, lv.Y*{SPEED}, lv.Z*{SPEED})
"""

STOP = """
local ws = game.Workspace
local root = ws:FindFirstChild(game.Players.LocalPlayer.Name).HumanoidRootPart
root.AssemblyLinearVelocity = Vector3.new(0, 0, 0)
"""

NAME_PROBE = 'return game.Players.LocalPlayer.Name'

def arm(src):
    blob = build(src)
    r = send("__ARM__ BC:" + blob.hex())
    return r

def poll():
    return send("__POLL__")

def find_game_g(timeout=90):
    """Fire the probe repeatedly: on the menu universe LocalPlayer is nil ->
    the chunk errors (rc != 0); on the game universe it returns rc=0.
    The poll reports the fired G + rc — pin the first G with rc=0."""
    deadline = time.time() + timeout
    while time.time() < deadline:
        r = arm(NAME_PROBE)
        if "ARMED" not in r:
            print("[fly] arm failed:", r.strip())
            time.sleep(2); continue
        time.sleep(1.0)
        p = poll()
        m = re.search(r"state=DONE.*?G=(0x[0-9a-f]+).*?rc=(-?\d+)", p, re.S)
        if not m:
            continue
        G, rc = m.group(1), int(m.group(2))
        print(f"[fly] probe fired on G={G} rc={rc}")
        if rc == 0:
            send(f"__ARMG__ {G}")
            print(f"[fly] pinned game universe G={G}")
            return G
    return None

def main():
    print("[fly] probing for the game universe...")
    G = find_game_g()
    if not G:
        print("[fly] no game universe found — is the player in a game?")
        return 1
    print("[fly] arming pulse...")
    r = arm(PULSE)
    if "ARMED" not in r:
        print("[fly] pulse arm failed:", r.strip()); return 1
    print(f"[fly] FLYING — look-direction flight at {SPEED} studs/s, {HZ} Hz pulses.")
    print("[fly] Ctrl-C to land.")
    n_ok = n_err = 0
    try:
        while True:
            t0 = time.time()
            send("__REARM__")
            time.sleep(0.25 / 1)   # rearm fires on the next game pcall
            p = poll()
            if "rc=0" not in p:
                n_err += 1
                if n_err % 10 == 1:
                    print("[fly] pulse errors:", p.strip().splitlines()[-1] if p.strip() else "?")
            else:
                n_ok += 1
            dt = time.time() - t0
            time.sleep(max(0.01, 1.0 / HZ - dt))
    except KeyboardInterrupt:
        pass
    print("\n[fly] landing...")
    arm(STOP)
    time.sleep(1.5)
    print(poll().strip())
    send("__DISARM__")
    print(f"[fly] done. pulses ok={n_ok} err={n_err}")
    return 0

if __name__ == "__main__":
    sys.exit(main())

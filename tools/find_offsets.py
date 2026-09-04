#!/usr/bin/env python3
"""
find_offsets.py — Offset and RTTI finder for macOS RobloxPlayer binary.
"""
import os
import re
import subprocess
import sys
from pathlib import Path

TARGET = Path("/Applications/Roblox.app/Contents/MacOS/RobloxPlayer")

def main():
    if not TARGET.exists():
        print(f"[-] Target binary not found: {TARGET}")
        sys.exit(1)

    print(f"[+] Inspecting target: {TARGET}")

    cmd = ["strings", str(TARGET)]
    res = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True, errors="replace")

    interesting = [
        "ScriptContext",
        "TaskScheduler",
        "DataModel",
        "lua_State",
        "luau_load",
        "luau_compile",
        "ExtraSpace",
        "Luau"
    ]

    found = {}
    for line in res.stdout.splitlines():
        for key in interesting:
            if key in line:
                found.setdefault(key, set()).add(line)

    for key, matches in found.items():
        print(f"\n=== Found matches for '{key}' ({len(matches)} items) ===")
        for m in sorted(matches)[:15]:
            print(f"  - {m}")

if __name__ == "__main__":
    main()

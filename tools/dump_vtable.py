#!/usr/bin/env python3
"""dump_vtable.py — read ScriptContext vtable slots from the Mach-O file.

Usage: dump_vtable.py <vtable_link_addr> <slide> [max_slots]

Reads slots from the file section containing the vtable, masks PAC bits
(low 48), keeps slots that land inside __text, writes them to
/tmp/vtable_slots.txt (runtime addresses).
"""
import struct
import subprocess
import sys

BINARY = "/Applications/Roblox.app/Contents/MacOS/RobloxPlayer"
TEXT_LINK = 0x100001cc0
TEXT_SIZE = 0x5513b14

def parse_sections():
    out = []
    text = subprocess.run(["otool", "-l", BINARY], capture_output=True, text=True).stdout
    lines = text.splitlines()
    cur = None
    for l in lines:
        s = l.strip()
        if s.startswith("sectname"):
            if cur: out.append(cur)
            cur = {"sectname": s.split()[1], "segname": ""}
        elif cur is not None:
            f = s.split()
            if len(f) >= 2:
                key, val = f[0], f[1]
                if key == "segname":
                    cur["segname"] = val
                elif key in ("addr", "size", "offset"):
                    try: cur[key] = int(val, 0)
                    except: pass
    if cur: out.append(cur)
    return out

def main():
    if len(sys.argv) < 3:
        print("usage: dump_vtable.py <vtable_link_addr> <slide> [max_slots]")
        return 1
    vtable_link = int(sys.argv[1], 16)
    slide = int(sys.argv[2], 16)
    max_slots = int(sys.argv[3]) if len(sys.argv) > 3 else 160

    sections = parse_sections()
    sec = next((s for s in sections
                if s.get("addr") <= vtable_link < s.get("addr") + s.get("size", 0)),
               None)
    if not sec:
        print("vtable not in any section"); return 1
    print(f"vtable link {vtable_link:#x} in {sec['segname']},{sec['sectname']} "
          f"fileoff {sec['offset']:#x}")

    with open(BINARY, "rb") as f:
        f.seek(sec["offset"] + (vtable_link - sec["addr"]))
        raw = f.read(max_slots * 8)

    slots = []
    for i in range(max_slots):
        val = struct.unpack_from("<Q", raw, i * 8)[0]
        addr = val & 0xFFFFFFFFFFFF  # low 48, drop PAC signature
        if TEXT_LINK <= addr < TEXT_LINK + TEXT_SIZE:
            slots.append((i, addr))
        elif addr != 0:
            pass  # non-code slot (data pointer / null), skip silently

    print(f"{len(slots)} code slots in __text")
    with open("/tmp/vtable_slots.txt", "w") as f:
        for i, link in slots:
            f.write(f"{i:#x} {link + slide:#x}\n")
    print("written to /tmp/vtable_slots.txt (runtime addrs)")

if __name__ == "__main__":
    sys.exit(main())
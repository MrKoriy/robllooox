#!/usr/bin/env python3
"""analyze_pc.py — map sampled PCs to RobloxPlayer __text, find hot clusters.

Known verified runtime addresses (0.734.0.7340915, slide 0x480000):
  luaD_growstack  runtime 0x1006a511c (link 0x10022511c)
  luaG_typeerror  runtime 0x101c3f2a8 (link 0x1018bf2a8)
  luaL_argerror   runtime 0x101c6bc38 (link 0x1017ebc38)
  lua_resume      runtime 0x1006ea954 (link 0x10026a954)
"""
import sys
from collections import Counter

SLIDE = 0x480000
TEXT_LINK = 0x100001cc0
TEXT_SIZE = 0x5513b14
TEXT_RUNTIME_BASE = TEXT_LINK + SLIDE

VERIFIED = {
    "luaD_growstack": 0x1006a511c,
    "luaG_typeerror": 0x101c3f2a8,
    "luaL_argerror": 0x101c6bc38,
    "lua_resume": 0x1006ea954,
}

def main(path="/tmp/pc_samples.txt"):
    pcs = []
    with open(path) as f:
        for line in f:
            line = line.strip()
            if not line or not line.startswith("0x"):
                continue
            try:
                pcs.append(int(line, 16))
            except ValueError:
                continue

    n = len(pcs)
    if n == 0:
        print("no samples")
        return

    in_roblox = [pc for pc in pcs if TEXT_RUNTIME_BASE <= pc < TEXT_RUNTIME_BASE + TEXT_SIZE]
    other = [pc for pc in pcs if pc < TEXT_RUNTIME_BASE or pc >= TEXT_RUNTIME_BASE + TEXT_SIZE]
    print(f"samples: {n} total, {len(in_roblox)} in Roblox __text, {len(other)} outside")

    # hottest exact PCs in roblox text
    c = Counter(in_roblox)
    print("\ntop Roblox PCs:")
    for pc, cnt in c.most_common(12):
        link = pc - SLIDE
        tag = ""
        for name, va in VERIFIED.items():
            if link == va:
                tag = f"  <== {name}"
        print(f"  {pc:#x} x{cnt}{tag}")

    # cluster: group PCs within 0x4000 windows, take hottest window
    if in_roblox:
        clusters = Counter()
        for pc in in_roblox:
            clusters[pc >> 14] += 1
        win, cnt = clusters.most_common(1)[0]
        lo, hi = win << 14, (win << 14) + 0x4000
        print(f"\nhottest 16KB window: {lo:#x}-{hi:#x} ({cnt} hits, {cnt/len(in_roblox)*100:.0f}%)")

    # outside-roblox top
    if other:
        co = Counter(other)
        print("\ntop outside PCs:")
        for pc, cnt in co.most_common(6):
            print(f"  {pc:#x} x{cnt}")

if __name__ == "__main__":
    main(sys.argv[1] if len(sys.argv) > 1 else "/tmp/pc_samples.txt")
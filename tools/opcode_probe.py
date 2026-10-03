#!/usr/bin/env python3
"""opcode_probe.py — Luau dispatch-table extractor/classifier for RobloxPlayer 0.739 (arm64).

Usage:
  python3 tools/opcode_probe.py [--json OUT] [--csv OUT]

Method (all offline, file-based, link-time space):
  1. Locate the 2x256 dispatch array in __DATA_CONST (0x106874b30 in 0.739).
  2. For each non-null handler: extent (terminator + entry-check), instructions.
  3. Signature: size, indirect exits (br/blr + ret pc offset), BL callees,
     adrp+add string refs, movz immediates.
  4. Auto-anchors from rare (<=4 binary-wide callers) callees and strings.
     Known 0.739 facts: slot 3 = NEWCLOSURE (sole luaF_newLclosure caller),
     slot 54 = CLOSEUPVALS (sole luaF_findupval caller).
"""
import sys, struct, json, math, re, argparse
from collections import defaultdict, Counter

BINARY = "/Applications/Roblox.app/Contents/MacOS/RobloxPlayer"
DISPATCH_ADDR = 0x106874b30   # 0.739; re-discover via --find when it shifts
DISPATCH_SLOTS = 256

d = open(BINARY, "rb").read()

SECTS = []
def _parse():
    ncmds, = struct.unpack_from("<I", d, 16)
    off = 32
    for _ in range(ncmds):
        cmd, size = struct.unpack_from("<II", d, off)
        if cmd == 0x19:
            vmaddr, vmsize, fileoff, filesize, maxprot, initprot, nsects, sflags = struct.unpack_from("<QQQQiiII", d, off+24)
            so = off + 72
            for i in range(nsects):
                sect = d[so:so+80]
                saddr, ssize = struct.unpack_from("<QQ", sect, 32)
                soff, _a, _r, _n, sflags2 = struct.unpack_from("<IIIII", sect, 48)
                stype = sflags2 & 0xFF
                if stype in (0x1, 0x12) or ssize == 0:
                    so += 80; continue
                SECTS.append((saddr, ssize, soff, bool(sflags2 & 0x80000400)))
                so += 80
        off += size
_parse()

def in_code(a): return any(vm <= a < vm+sz for vm, sz, off, ic in SECTS if ic)
def u32(a):
    for vm, sz, soff, ic in SECTS:
        if vm <= a < vm+sz: return struct.unpack_from("<I", d, soff + (a-vm))[0]
    return None
def read(a, n):
    for vm, sz, soff, ic in SECTS:
        if vm <= a < vm+sz: return d[soff+(a-vm): soff+(a-vm)+n]
    return None
def cstr_at(a, maxlen=64):
    r = read(a, maxlen)
    if not r: return None
    z = r.split(b"\0")[0]
    if len(z) < 3: return None
    try: s = z.decode()
    except: return None
    return s if all(32 <= ord(c) < 127 for c in s) else None

def is_terminator(i):
    return ((i & 0xFFE0001F) == 0xD65F0000      # ret
            or (i & 0xFC000000) == 0x14000000   # b
            or (i & 0xFFFFFC1F) == 0xD61F0000   # br/blr
            or i == 0xD4200000)                 # brk

def fn_end(fn, limit=0x30000):
    a = fn + 4
    while a < fn + limit:
        i = u32(a)
        if i is None: return a
        if is_terminator(i):
            for k in (4, 8):
                ni = u32(a + k)
                if ni == 0xD503233F or (ni is not None and (ni & 0xFFE003E0) == 0xA9000000):
                    return a + k
            return a
        a += 4
    return fn + limit

def decode_adrp(insn, pc):
    if (insn & 0x9F000000) != 0x90000000: return None
    immlo = (insn >> 29) & 3
    immhi = (insn >> 5) & 0x7FFFF
    v = (immhi << 2) | immlo
    if v & (1 << 20): v -= (1 << 21)
    return insn & 0x1F, (pc & ~0xFFF) + (v << 12)

def decode_add(insn):
    if (insn & 0xFF000000) != 0x91000000: return None
    sh = (insn >> 22) & 3
    if sh > 1: return None
    imm = (insn >> 10) & 0xFFF
    if sh == 1: imm <<= 12
    return insn & 0x1F, (insn >> 5) & 0x1F, imm

def decode_movz(insn):
    if (insn & 0x7F800000) != 0x52800000: return None
    return (insn >> 0) & 0x1F, ((insn >> 5) & 0xFFFF) | (((insn >> 21) & 1) << 16)

def decode_br(i):
    if (i & 0xFFFFFC1F) != 0xD61F0000: return None
    return "br" if (i & 0x3F) == 0x10 else "blr"  # crude; both D61F0xxx

# ---- dispatch slots -------------------------------------------------------
def find_dispatch(hint=DISPATCH_ADDR):
    """scan window around hint for a 256-slot table of code pointers with a NULL gap pattern"""
    return hint

def load_slots(addr=DISPATCH_ADDR):
    s2h = {}
    for i in range(DISPATCH_SLOTS):
        r = read(addr + i*8, 8)
        if r is None: continue
        q, = struct.unpack("<Q", r)
        if q and in_code(q): s2h[i] = q
    # second mirror
    for i in range(DISPATCH_SLOTS):
        r = read(addr + (DISPATCH_SLOTS + i)*8, 8)
        if r is None: continue
        q, = struct.unpack("<Q", r)
        if q and s2h.get(i) not in (None, q):
            print(f"  ! mirror mismatch slot {i}: {s2h.get(i):#x} vs {q:#x}", file=sys.stderr)
    return s2h

# ---- binary-wide BL index -------------------------------------------------
def build_bl_index():
    idx = defaultdict(int)
    for vm, sz, soff, ic in SECTS:
        if not ic: continue
        for a in range(vm, vm+sz, 4):
            i = u32(a)
            if i is not None and (i & 0xFC000000) == 0x94000000:
                o = i & 0x03FFFFFF
                if o & (1 << 25): o -= (1 << 26)
                idx[a + (o << 2)] += 1
    return idx

def classify(s2h, blidx):
    rows = []
    for slot, h in sorted(s2h.items()):
        end = fn_end(h)
        regs, strs, calls, movzs, ind = {}, [], set(), [], []
        for a in range(h, end, 4):
            i = u32(a)
            if i is None: break
            if (i & 0xFFFFFC1F) == 0xD61F0000:
                ind.append(a - h)  # indirect exit offset
                continue
            adr = decode_adrp(i, a)
            if adr:
                regs[adr[0]] = adr[1]; continue
            add = decode_add(i)
            if add and add[1] in regs:
                s = cstr_at(regs[add[1]] + add[2])
                if s: strs.append(s)
                continue
            mz = decode_movz(i)
            if mz and mz[1] > 2: movzs.append(mz[1])
            if (i & 0xFC000000) == 0x94000000:
                o = i & 0x03FFFFFF
                if o & (1 << 25): o -= (1 << 26)
                calls.add(a + (o << 2))
        rare = sorted((hex(c), blidx.get(c, 0)) for c in calls if blidx.get(c, 0) <= 4)
        rows.append(dict(slot=slot, handler=hex(h), size=end-h,
                         retpc=ind[0] if ind else None, n_ind=len(ind),
                         n_calls=len(calls), strings=strs[:4],
                         movz=movzs[:8], rare_callees=rare))
    return rows

ANCHORS = {
    # verified 0.739 content anchors
    3:  ("NEWCLOSURE",  "sole luaF_newLclosure caller"),
    54: ("CLOSEUPVALS", "sole luaF_findupval caller"),
}

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--json", default="/tmp/opcode739_report.json")
    ap.add_argument("--csv", default="")
    args = ap.parse_args()

    s2h = load_slots()
    print(f"dispatch @ {DISPATCH_ADDR:#x}: {len(s2h)} non-null slots")
    blidx = build_bl_index()
    rows = classify(s2h, blidx)
    for r in rows:
        tag, why = ANCHORS.get(r["slot"], (None, None))
        if tag:
            r["anchor"] = tag
            r["anchor_why"] = why

    # signature clusters (small exact-size families)
    sizes = Counter((r["size"], r["n_ind"], r["n_calls"]) for r in rows)
    print("\nexact signature clusters (size, n_indirect, n_calls):")
    for k, n in sizes.most_common(12):
        slots = [r["slot"] for r in rows if (r["size"], r["n_ind"], r["n_calls"]) == k]
        print(f"  {k}: x{n}  slots={slots[:12]}")

    print("\nanchored / stringed / rare-callee handlers:")
    for r in rows:
        if r.get("anchor") or r["strings"] or r["rare_callees"]:
            print(f"  slot {r['slot']:3d} {r['handler']} sz={r['size']:4d} retpc={r['retpc']}"
                  f" strs={r['strings']} rare={r['rare_callees']} anchor={r.get('anchor')}")

    json.dump(rows, open(args.json, "w"), indent=0)
    print(f"\nwrote {args.json}")
    if args.csv:
        with open(args.csv, "w") as f:
            f.write("slot,handler,size,retpc,n_indirect,n_calls,anchor\n")
            for r in rows:
                f.write(f"{r['slot']},{r['handler']},{r['size']},{r['retpc']},{r['n_ind']},{r['n_calls']},{r.get('anchor','')}\n")
        print(f"wrote {args.csv}")

if __name__ == "__main__":
    main()

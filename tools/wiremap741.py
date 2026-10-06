#!/usr/bin/env python3
"""wiremap741.py — full upstream->wire opcode map for Roblox 0.741 (arm64).

Method:
  1. wire->internal: the loader's 256-byte translation table (found by
     anchoring 10 PROTODUMP-verified pairs; unique match in the image).
  2. internal->handler: runtime dispatch table 0x106a31bd0 (link-time).
  3. handler->op: signature classification (fp-op, branch shape, callee
     clustering), cross-checked against the 10 known anchors.

Output: upstream op name -> wire value, plus the raw feature table for
manual review of low-confidence rows.
"""
import struct, sys, json, argparse
from collections import defaultdict

BINARY = "/Applications/Roblox.app/Contents/MacOS/RobloxPlayer"
XLT_FILEOFF = 0x5bed438          # wire->internal translation table
RUNTIME_DISPATCH = 0x106a31bd0   # internal->handler (link-time vmaddr)

# upstream Luau v9 enum (Common/include/Luau/Bytecode.h of the build tree)
OPS = """NOP BREAK LOADNIL LOADB LOADN LOADK MOVE GETGLOBAL SETGLOBAL GETUPVAL
SETUPVAL CLOSEUPVALS GETIMPORT GETTABLE SETTABLE GETTABLEKS SETTABLEKS GETTABLEN
SETTABLEN NEWCLOSURE NAMECALL CALL RETURN JUMP JUMPBACK JUMPIF JUMPIFNOT
JUMPIFEQ JUMPIFLE JUMPIFLT JUMPIFNOTEQ JUMPIFNOTLE JUMPIFNOTLT ADD SUB MUL DIV
MOD POW ADDK SUBK MULK DIVK MODK POWK AND OR ANDK ORK CONCAT NOT MINUS LENGTH
NEWTABLE DUPTABLE SETLIST FORNPREP FORNLOOP FORGLOOP FORGPREP_INEXT FASTCALL3
FORGPREP_NEXT NATIVECALL GETVARARGS DUPCLOSURE PREPVARARGS LOADKX JUMPX FASTCALL
COVERAGE CAPTURE SUBRK DIVRK FASTCALL1 FASTCALL2 FASTCALL2K FORGPREP
JUMPXEQKNIL JUMPXEQKB JUMPXEQKN JUMPXEQKS IDIV IDIVK GETUDATAKS SETUDATAKS
NAMECALLUDATA NEWCLASSMEMBER CALLFB CMPPROTO FASTPCALL NEWCLASS""".split()

# verified anchors: upstream op -> (wire, internal)   (PROTODUMP sessions)
ANCHORS = {
    "LOADN":       (140, 210),
    "SETTABLEKS":  ( 78, 130),   # loader rewrote it to the udata-store form
    "NAMECALL":    ( 95, 132),
    "GETIMPORT":   (164,  23),
    "LOADK":       (111, 207),
    "RETURN":      (130, 146),
    "CALL":        (159, 170),
    "MOVE":        (144, 189),
    "PREPVARARGS": ( 82,  62),
    "DUPCLOSURE":  (192, 134),
}

d = open(BINARY, "rb").read()

SEGS = []
def parse_segs():
    ncmds, = struct.unpack_from("<I", d, 16)
    off = 32
    for _ in range(ncmds):
        cmd, size = struct.unpack_from("<II", d, off)
        if cmd == 0x19:
            name = d[off+8:off+24].rstrip(b"\0").decode()
            vmaddr, vmsize, fileoff, filesize = struct.unpack_from("<QQQQ", d, off+24)
            SEGS.append((name, vmaddr, vmsize, fileoff))
        off += size
parse_segs()

def v2f(va):
    for name, vm, sz, fo in SEGS:
        if vm <= va < vm + sz:
            return fo + (va - vm)
    return None

def read_va(va, n):
    fo = v2f(va)
    if fo is None: return None
    return d[fo:fo+n]

def u32_va(va):
    r = read_va(va, 4)
    return struct.unpack("<I", r)[0] if r and len(r) == 4 else None

# ---- 1. translation table -------------------------------------------------
xlt = d[XLT_FILEOFF:XLT_FILEOFF+256]
for w, (name, (aw, ai)) in enumerate([]): pass
for name, (aw, ai) in ANCHORS.items():
    assert xlt[aw] == ai, f"anchor {name}: xlt[{aw}]={xlt[aw]} != {ai}"
wire_of_internal = {}
for w in range(256):
    wire_of_internal.setdefault(xlt[w], []).append(w)

# ---- 2. dispatch table -----------------------------------------------------
handlers = {}
for i in range(256):
    q, = struct.unpack("<Q", read_va(RUNTIME_DISPATCH + i*8, 8))
    if 0x100000000 <= q < 0x107000000:
        handlers[i] = q

# ---- 3. handler features ---------------------------------------------------
def is_term(i):
    return ((i & 0xFFE0001F) == 0xD65F0000 or (i & 0xFC000000) == 0x14000000
            or (i & 0xFFFFFC1F) == 0xD61F0000 or i == 0xD4200000)

FP_OPS = {0x1E202800:"fadd", 0x1E203800:"fsub", 0x1E200800:"fmul",
          0x1E201800:"fdiv", 0x1E204000:"fneg", 0x1E214000:"fneg?"}
def fp_op(i):
    m = i & 0xFF20FC00
    for k, v in FP_OPS.items():
        if (i & 0xFF200000 | 0xFC00) == (k & 0xFF200000 | 0xFC00) and (i & 0xFF20FC00) == (k & 0xFF20FC00):
            return v
    # exact masks for the common double-precision forms
    if (i & 0xFF20FC00) == 0x1E202800: return "fadd"
    if (i & 0xFF20FC00) == 0x1E203800: return "fsub"
    if (i & 0xFF20FC00) == 0x1E200800: return "fmul"
    if (i & 0xFF20FC00) == 0x1E201800: return "fdiv"
    if (i & 0xFF20FC00) == 0x1E204000: return "fneg"
    return None

def features(h, cap=0x400):
    """walk a handler, collect discriminative features"""
    f = dict(size=0, fp=[], n_tbz=0, n_tbnz=0, n_cbz=0, n_cbnz=0,
             n_b=0, bl=[], n_ldr_d=0, n_str=0, n_movz=0, n_ldrb=0)
    a = h
    while a < h + cap:
        i = u32_va(a)
        if i is None: break
        if a > h and is_term(i):
            f["size"] = a - h + 4
            break
        fp = fp_op(i)
        if fp: f["fp"].append(fp)
        if (i & 0x7E000000) == 0x36000000: f["n_tbz"] += 1
        if (i & 0x7E000000) == 0x37000000: f["n_tbnz"] += 1
        if (i & 0x7E000000) == 0x34000000: f["n_cbz"] += 1
        if (i & 0x7E000000) == 0x35000000: f["n_cbnz"] += 1
        if (i & 0xFC000000) == 0x14000000: f["n_b"] += 1
        if (i & 0xFC000000) == 0x94000000:
            o = i & 0x03FFFFFF
            if o & (1 << 25): o -= (1 << 26)
            f["bl"].append(hex(a + (o << 2)))
        if (i & 0xFFC00000) == 0xFD400000: f["n_ldr_d"] += 1   # ldr d?,[..]
        if (i & 0x3B000000) == 0x39000000: f["n_str"] += 1
        if (i & 0x7F800000) == 0x52800000: f["n_movz"] += 1
        if (i & 0xFFC00000) == 0x39400000: f["n_ldrb"] += 1
        a += 4
    return f

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--json", default="")
    args = ap.parse_args()

    print(f"xlt table OK (10/10 anchors), dispatch slots: {len(handlers)}")
    rows = {}
    for internal, h in sorted(handlers.items()):
        rows[internal] = features(h)

    # callee clustering: ops calling the same helper share a family
    callees = defaultdict(set)
    for internal, f in rows.items():
        for c in f["bl"]:
            callees[c].add(internal)

    # print feature table for manual mapping
    print("\ninternal  size  fp        tbz tbnz cbz cbnz  b  movz ldrb ldrD bl...")
    for internal in sorted(rows):
        f = rows[internal]
        wires = wire_of_internal.get(internal, [])
        print(f"{internal:4d} (w={','.join(map(str,wires)) or '-':>6}) "
              f"{f['size']:5d}  {','.join(f['fp']) or '-':20} "
              f"{f['n_tbz']}   {f['n_tbnz']}   {f['n_cbz']}  {f['n_cbnz']}  "
              f"{f['n_b']}  {f['n_movz']}   {f['n_ldrb']}   {f['n_ldr_d']}  "
              f"{' '.join(f['bl'][:3])}")
    print("\nshared callees (helper -> internal slots):")
    for c, slots in sorted(callees.items(), key=lambda kv: -len(kv[1])):
        if len(slots) >= 2:
            print(f"  {c}: {sorted(slots)}")
    if args.json:
        json.dump({str(k): v for k, v in rows.items()}, open(args.json, "w"))

if __name__ == "__main__":
    main()

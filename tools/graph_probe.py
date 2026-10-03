#!/usr/bin/env python3
"""graph_probe.py — offline call-graph probe for RobloxPlayer (arm64), file-based, link-time space.

  --fn <hex> [win]      function report: extent, adrp+add/adrp+ldr materializations
  --callers <hex>       all BL sites targeting fn + distinct callers
  --blr                 small functions containing exactly-one-BLR (rawrunprotected shape)
  --slot <hex>          data slots holding this pointer (8B absolute match)
  --pairs               luaL_Reg-style {&name, fn} pairs across data sections
"""
import sys, struct

BINARY = "/Applications/Roblox.app/Contents/MacOS/RobloxPlayer"
BASE = 0x100000000

d = open(BINARY, "rb").read()

SECTS = []  # (vmaddr, size, offset, is_code, label)
def parse():
    magic, cputype, cpusub, ftype, ncmds, sizeofcmds, flags, res = struct.unpack_from("<IiiIIIII", d, 0)
    off = 32
    for _ in range(ncmds):
        cmd, size = struct.unpack_from("<II", d, off)
        if cmd == 0x19:  # LC_SEGMENT_64
            segname = d[off+8:off+24].rstrip(b"\x00").decode()
            vmaddr, vmsize, fileoff, filesize, maxprot, initprot, nsects, sflags = struct.unpack_from("<QQQQiiII", d, off+24)
            so = off + 72
            for i in range(nsects):
                sect = d[so:so+80]
                sname = sect[0:16].rstrip(b"\x00").decode()
                saddr, ssize = struct.unpack_from("<QQ", sect, 32)
                soff, salign, sreloff, snreloc, sflags2 = struct.unpack_from("<IIIII", sect, 48)
                stype = sflags2 & 0xFF
                is_code = bool(sflags2 & 0x80000400)
                if stype in (0x1, 0x12) or ssize == 0:
                    so += 80; continue
                SECTS.append((saddr, ssize, soff, is_code, f"{segname},{sname}"))
                so += 80
        off += size
parse()

CODE = [(vm, sz) for vm, sz, off, ic, lb in SECTS if ic]
def in_code(a):
    return any(vm <= a < vm + sz for vm, sz in CODE)

def addr2file(a):
    for vmaddr, ssize, soff, is_code, label in SECTS:
        if vmaddr <= a < vmaddr + ssize:
            return soff + (a - vmaddr), label
    return None, None

def u32(a):
    fo, _ = addr2file(a)
    if fo is None: return None
    return struct.unpack_from("<I", d, fo)[0]

def read(a, n):
    fo, _ = addr2file(a)
    if fo is None: return None
    return d[fo:fo+n]

def cstr(a, maxlen=96):
    fo, _ = addr2file(a)
    if fo is None: return None
    end = d.find(b"\x00", fo)
    if end < 0 or end - fo > maxlen: return None
    s = d[fo:end]
    if not s or not all(32 <= c < 127 for c in s): return None
    return s.decode()

def decode_adrp(insn, pc):
    if (insn & 0x9F000000) != 0x90000000: return None
    immlo = (insn >> 29) & 3
    immhi = (insn >> 5) & 0x7FFFF
    v = (immhi << 2) | immlo
    if v & (1 << 20): v -= (1 << 21)
    rd = insn & 0x1F
    return rd, (pc & ~0xFFF) + (v << 12)

def decode_add(insn):
    if (insn & 0xFF000000) != 0x91000000: return None
    sh = (insn >> 22) & 3
    if sh > 1: return None
    imm = (insn >> 10) & 0xFFF
    if sh == 1: imm <<= 12
    return insn & 0x1F, (insn >> 5) & 0x1F, imm

def decode_ldr_uoff(insn):
    if (insn & 0xFFC00000) != 0xF9400000: return None
    rt = insn & 0x1F
    rn = (insn >> 5) & 0x1F
    imm = ((insn >> 10) & 0xFFF) << 3
    return rt, rn, imm

def decode_bl(insn, pc):
    top = insn & 0xFC000000
    if top not in (0x14000000, 0x94000000): return None
    imm = insn & 0x03FFFFFF
    if imm & (1 << 25): imm -= (1 << 26)
    return pc + (imm << 2)

def fn_report(fn, wlen=0x300):
    ptrs, bls, reg_page = [], [], {}
    a = fn
    last_active = fn
    for k in range(wlen // 4):
        insn = u32(a)
        if insn is None: break
        active = False
        r = decode_adrp(insn, a)
        if r:
            reg_page[r[0]] = (a, r[1]); active = True
        else:
            ad = decode_add(insn)
            if ad:
                rd, rn, imm = ad
                if rn in reg_page and reg_page[rn][0] >= a - 0x40:
                    ptrs.append((a, reg_page[rn][1] + imm, "add")); active = True
            ld = decode_ldr_uoff(insn)
            if ld:
                rt, rn, imm = ld
                if rn in reg_page and reg_page[rn][0] >= a - 0x40:
                    ptrs.append((a, reg_page[rn][1] + imm, "ldr")); active = True
            bt = decode_bl(insn, a)
            if bt: bls.append((a, bt)); active = True
        if active: last_active = a
        a += 4
    return ptrs, bls, last_active

def walk_back(start):
    """nearest plausible entry <= start; returns entry addr"""
    lo = max(vm for vm, sz, off, ic, lb in SECTS if ic and vm <= start) if CODE else start - 0x10000
    a = start
    while a > max(start - 0x10000, lo):
        insn = u32(a)
        if insn is None: break
        # prologue-ish: stp x.., x.., [sp,#-N]! or sub sp or pacibsp
        if (insn & 0xFF800000) == 0xA9800000 and ((insn >> 5) & 0x1F) == 31:
            return a
        if (insn & 0xFF000000) == 0xD1000000 and (insn & 0x1F) == 31 and ((insn >> 5) & 0x1F) == 31:
            return a
        if insn == 0xD503237F:
            return a
        a -= 4
    return None

def callers_of(fn):
    sites, callers = [], {}
    for vm, sz, off, ic, label in SECTS:
        if not ic: continue
        a = vm
        fo_end = off + sz
        while a + 4 <= vm + sz:
            insn = u32(a)
            if insn is None: break
            bt = decode_bl(insn, a)
            if bt == fn and (insn & 0xFC000000) == 0x94000000:
                c = walk_back(a)
                sites.append((a, c))
                if c: callers[c] = callers.get(c, 0) + 1
            a += 4
    return sites, callers

def slots_holding(q):
    hits = []
    pat = struct.pack("<Q", q)
    start = 0
    while True:
        i = d.find(pat, start)
        if i < 0: break
        # file offset -> vmaddr
        for vmaddr, ssize, soff, is_code, label in SECTS:
            if soff <= i < soff + ssize:
                hits.append((vmaddr + (i - soff), label))
                break
        start = i + 1
    return hits

def blr_wrappers():
    """functions whose body (up to ~0x80 bytes) contains exactly one BLR and no BL"""
    out = []
    for vm, sz, off, ic, label in SECTS:
        if not ic: continue
        a = vm
        while a + 4 <= vm + sz:
            insn = u32(a)
            if insn is None: break
            # entry heuristic: stp pre-index through sp
            if (insn & 0xFF800000) == 0xA9800000 and ((insn >> 5) & 0x1F) == 31:
                blrs, bls, n = 0, 0, 0
                b = a
                while b < a + 0x80:
                    i2 = u32(b)
                    if i2 is None: break
                    if (i2 & 0xFFFFFC1F) == 0xD63F0000: blrs += 1
                    if (i2 & 0xFC000000) == 0x94000000: bls += 1
                    if i2 == 0xD65F03C0: break  # ret
                    b += 4; n += 1
                if blrs == 1 and bls == 0 and n >= 3:
                    out.append(a)
                a = b + 4
            else:
                a += 4
    return out

def tag(q):
    if q == 0: return "NULL"
    if in_code(q): return "CODE"
    s = cstr(q)
    if s is not None: return f"STR {s!r}"
    return "data"

def main():
    if "--pairs" in sys.argv:
        seen = {}
        for off in range(0x5e00000, min(len(d) - 8, 0x6a00000), 8):
            q0 = struct.unpack_from("<Q", d, off)[0]
            if not (0x105e00000 <= q0 < 0x107000000): continue
            s = cstr(q0)
            if not s or len(s) > 20: continue
            q1 = struct.unpack_from("<Q", d, off + 8)[0]
            if not in_code(q1): continue
            seen.setdefault(s, set()).add(q1)
        for s in sorted(seen):
            print(f"{s:16s} {[hex(x) for x in sorted(seen[s])]}")
        return
    if "--blr" in sys.argv:
        ws = blr_wrappers()
        print(f"single-BLR wrappers: {len(ws)}")
        for a in ws:
            print(f"  {a:#x}")
        return
    if "--callers" in sys.argv:
        fn = int(sys.argv[sys.argv.index("--callers") + 1], 16)
        sites, callers = callers_of(fn)
        print(f"callers of {fn:#x}: {len(sites)} site(s)")
        for s, c in sites:
            print(f"  bl @ {s:#x}  caller ≈ {c:#x}" if c else f"  bl @ {s:#x}")
        return
    if "--slot" in sys.argv:
        q = int(sys.argv[sys.argv.index("--slot") + 1], 16)
        for vm, label in slots_holding(q):
            print(f"  slot {vm:#x}  [{label}]")
        return
    if "--fn" in sys.argv:
        i = sys.argv.index("--fn")
        fn = int(sys.argv[i + 1], 16)
        wlen = int(sys.argv[i + 2], 16) if len(sys.argv) > i + 2 else 0x300
        ptrs, bls, last = fn_report(fn, wlen)
        print(f"== fn {fn:#x} (window {wlen:#x}, last active insn {last:#x}) ==")
        print(" materialized pointers:")
        for site, val, how in ptrs:
            print(f"   {how:3s} @ {site:#x} -> {val:#x}  [{tag(val)}]")
        print(" branches:")
        for site, tgt in bls:
            fi = u32(tgt)
            extra = f"  first {fi:#x}" if fi is not None else ""
            print(f"   @ {site:#x} -> {tgt:#x}{extra}")
        return
    print(__doc__)

if __name__ == "__main__":
    main()

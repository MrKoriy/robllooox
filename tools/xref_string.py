#!/usr/bin/env python3
"""xref_string.py — find code references (adrp+add / adrp+ldr) to a string in
a Mach-O arm64 binary. Usage:

    python3 tools/xref_string.py <binary> "<string>" [--all]

Prints: string vmaddr, then each xref instruction vmaddr + the register and
resolved target. Used to locate functions by their string constants when
updating signatures for a new Roblox version.
"""
import struct
import sys


def load_sections(data):
    """Return list of (segname, sectname, vmaddr, size, fileoff)."""
    magic, = struct.unpack_from("<I", data, 0)
    if magic != 0xFEEDFACF:
        sys.exit("not a 64-bit Mach-O")
    ncmds, = struct.unpack_from("<I", data, 16)
    off = 32
    sections = []
    for _ in range(ncmds):
        cmd, cmdsize = struct.unpack_from("<II", data, off)
        if cmd == 0x19:  # LC_SEGMENT_64
            segname = data[off + 8:off + 24].rstrip(b"\0").decode()
            vmaddr, vmsize, fileoff = struct.unpack_from("<QQQ", data, off + 24)
            nsects, = struct.unpack_from("<I", data, off + 64)
            soff = off + 72
            for s in range(nsects):
                sect = data[soff:soff + 16].rstrip(b"\0").decode()
                addr, size = struct.unpack_from("<QQ", data, soff + 32)
                foff, = struct.unpack_from("<I", data, soff + 48)
                sections.append((segname, sect, addr, size, foff))
                soff += 80
        off += cmdsize
    return sections


def decode_adrp(insn, pc):
    """Return (reg, page_target) for an ADRP, else None."""
    if (insn & 0x9F000000) != 0x90000000:
        return None
    rd = insn & 0x1F
    immlo = (insn >> 29) & 3
    immhi = (insn >> 5) & 0x7FFFF
    imm = (immhi << 2) | immlo
    if imm & (1 << 20):
        imm -= 1 << 21
    return rd, pc + (imm << 12)


def main():
    if len(sys.argv) < 3:
        print(__doc__)
        return
    path = sys.argv[1]
    needle = sys.argv[2].encode()
    find_all = "--all" in sys.argv
    data = open(path, "rb").read()
    sections = load_sections(data)

    def vaddr_of(off):
        for seg, sect, addr, size, foff in sections:
            if foff <= off < foff + size:
                return addr + (off - foff)
        return None

    # every occurrence of the string
    targets = []
    idx = 0
    while True:
        i = data.find(needle, idx)
        if i < 0:
            break
        va = vaddr_of(i)
        if va:
            targets.append(va)
            print(f"string @ {va:#x}")
        idx = i + 1
        if not find_all:
            break
    if not targets:
        sys.exit("string not found")

    tset = set(targets)
    pages = {t & ~0xFFF for t in targets}

    # scan executable sections for adrp; resolve following add/ldr
    hits = []
    for seg, sect, addr, size, foff in sections:
        if sect not in ("__text", "__stubs"):
            continue
        text = data[foff:foff + size]
        prev_adrp = {}  # reg -> (pc, page)
        for pc_off in range(0, len(text) - 4, 4):
            insn, = struct.unpack_from("<I", text, pc_off)
            pc = addr + pc_off
            ad = decode_adrp(insn, pc)
            if ad:
                prev_adrp[ad[0]] = (pc, ad[1])
                continue
            # ADD (immediate) Xd, Xn, #imm12 << shift
            if (insn & 0x9F000000) == 0x91000000:
                rd = (insn >> 0) & 0x1F
                rn = (insn >> 5) & 0x1F
                imm12 = (insn >> 10) & 0xFFF
                sh = (insn >> 22) & 3
                if sh == 1:
                    imm12 <<= 12
                if rn in prev_adrp:
                    apc, page = prev_adrp[rn]
                    if page in pages:
                        tgt = page + imm12
                        if tgt in tset:
                            hits.append((apc, pc, rd, tgt))
                prev_adrp.pop(rd, None)
                continue
            # LDR (unsigned imm) Xt, [Xn, #imm]
            if (insn & 0xBFC00000) == 0xB9400000 or (insn & 0xBFC00000) == 0xF9400000:
                rn = (insn >> 5) & 0x1F
                if rn in prev_adrp:
                    apc, page = prev_adrp.pop(rn)
                    size_bits = 2 if (insn & 0x40000000) else 3
                    imm = ((insn >> 10) & 0xFFF) << size_bits
                    if page in pages:
                        tgt = page + imm
                        if tgt in tset:
                            hits.append((apc, pc, (insn) & 0x1F, tgt))
                continue
            # register overwrite invalidates
            rd = insn & 0x1F
            prev_adrp.pop(rd, None)

    for apc, pc, rd, tgt in hits:
        print(f"xref: adrp@{apc:#x} use@{pc:#x} x{rd} -> {tgt:#x}")


if __name__ == "__main__":
    main()

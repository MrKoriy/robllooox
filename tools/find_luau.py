#!/usr/bin/env python3
"""
find_luau.py — Offline signature extractor for Roblox Luau C functions.

Strategy (no Ghidra/IDA, no live process, no hallucinated offsets):
  1. Parse Mach-O sections of RobloxPlayer via `otool -l`.
  2. Find a distinctive Luau error string ("stack overflow", "attempt to call")
     -> its link-time vmaddr.
  3. Scan __TEXT code for an ADRP+ADD pair referencing that vmaddr (the xref).
  4. Walk back from the xref to the function prologue (pacibsp / stp x29,x30).
  5. Print the function's link-time vmaddr + first 16 bytes = a signature
     suitable for the dylib's pattern scanner.

Everything is derived from real file bytes. Re-run after every Roblox update.
"""
import ctypes, struct, subprocess, sys, mmap, os

BINARY = "/Applications/Roblox.app/Contents/MacOS/RobloxPlayer"
TARGET_STRINGS = [
    b"stack overflow\x00",
    b"attempt to call",
    b"attempt to index",
    b"attempt to perform arithmetic",
    b"attempt to concatenate",
    b"attempt to compare",
    b"bad argument",
    b"invalid key to",
    b"attempt to yield across",
    b"cannot resume",             # luaD_resume error path
    b"non-suspended coroutine",
    b"too many results to resume",
    b"cannot resume non-suspended",
    b"C stack overflow",
    b"attempt to resume",         # lua_resume caller errors
    b"unexpected symbol",         # lparser.cpp
    b"unexpected end of file",
    b"malformed number",
    b"unfinished string",
    b"ambiguous syntax",
    b"invalid escape sequence",
    b"syntax error",
    b"number has no integer representation",
    b"function arguments expected",
    b"expression expected",
    b"name expected",
    b"%=s expected",              # generic "%s expected" in parser
]

UINT = ctypes.c_uint32

def parse_sections():
    """Parse `otool -l` output into section dicts. Numeric fields use base 0
    so both decimal (offset) and hex (addr/size) are handled."""
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

def u32(b, off):
    return struct.unpack_from("<I", b, off)[0]

def sign_extend(v, bits):
    if v & (1 << (bits-1)):
        return v - (1 << bits)
    return v

def decode_adrp(insn):
    # ADRP: bit31=1, bits30:29=immlo, bits28:24=10000, bits23:5=immhi, bits4:0=Rd
    if (insn & 0x9F000000) != 0x90000000: return None
    immlo = (insn >> 29) & 0x3
    immhi = (insn >> 5) & 0x7FFFF
    imm = sign_extend((immhi << 2) | immlo, 21) << 12
    rd = insn & 0x1F
    return rd, imm

def decode_add_imm(insn):
    # ADD (immediate) 64-bit: bits31:24=10010001 (0x91)
    if (insn & 0xFF000000) != 0x91000000: return None
    imm12 = (insn >> 10) & 0xFFF
    sh = (insn >> 22) & 0x3   # shift
    rn = (insn >> 5) & 0x1F
    rd = insn & 0x1F
    if sh == 1: imm12 <<= 12
    return rd, rn, imm12

PROLOGUE_PACIBSP = 0xD503237F  # pacibsp / pacisp (sign return address)
def is_prologue(insn):
    # Strict: canonical frame-setup `stp x29, x30, [sp, #-imm]!`
    # STP pre-index 64-bit: top byte 0xa9, bit23=1 (writeback), Rt=29, Rt2=30, Rn=31(sp)
    if (insn & 0xFF800000) == 0xA9800000:
        rt  = insn & 0x1F
        rn  = (insn >> 5) & 0x1F
        rt2 = (insn >> 10) & 0x1F
        if rt == 29 and rn == 31 and rt2 == 30:
            return True
    # pacibsp at function entry (arm64e sign-return-address)
    if insn == PROLOGUE_PACIBSP:
        return True
    return False

def find_string_vmaddr(sections, data, needle):
    for s in sections:
        if s.get("segname") in ("__TEXT","__DATA","__DATA_CONST") and "offset" in s and "size" in s and "addr" in s:
            off = s["offset"]; size = s["size"]
            blob = data[off:off+size]
            idx = blob.find(needle)
            if idx >= 0:
                return s["addr"] + idx, s
    return None, None

def scan_xref(text_section, data, target_vmaddr):
    """Find an ADRP referencing the string's page. The ADD/LDR that completes
    the address may not be the very next instruction, but the ADRP alone
    localizes the function. Returns (adrp_link_addr, adrp_file_off)."""
    base_off = text_section["offset"]
    base_vmaddr = text_section["addr"]
    target_page = target_vmaddr & ~0xFFF
    blob = data[base_off:base_off+text_section["size"]]
    for i in range(0, len(blob)-4, 4):
        insn = u32(blob, i)
        a = decode_adrp(insn)
        if not a: continue
        _rd, imm = a
        pc = base_vmaddr + i
        page = (pc & ~0xFFF) + imm
        if page == target_page:
            return pc, i
    return None, None

def function_start(text_section, data, xref_off):
    """Walk back from xref to nearest canonical prologue. If the prologue is
    `stp x29,x30,...` but the preceding instruction is `pacibsp`, the true
    entry is 4 bytes earlier (arm64e sign-return-address prologue)."""
    base_off = text_section["offset"]
    off = xref_off
    while off > 0:
        insn = u32(data, base_off + off)
        if is_prologue(insn):
            if (insn & 0xFFFFFFFF) != PROLOGUE_PACIBSP and off >= 4:
                prev = u32(data, base_off + off - 4)
                if prev == PROLOGUE_PACIBSP:
                    return off - 4
            return off
        off -= 4
        if xref_off - off > 0x10000: break
    return None

def decode_bl(insn):
    """BL (0x94...) or B (0x14...): branch with link / unconditional.
    Returns word-offset, or None."""
    op = insn & 0xFC000000
    if op == 0x94000000 or op == 0x14000000:
        imm = insn & 0x03FFFFFF
        if imm & (1 << 25): imm -= (1 << 26)
        return imm << 2
    return None

def find_callers(text_section, data, func_vmaddr):
    """Find BL call sites targeting func_vmaddr; walk back to each caller's
    prologue. Returns list of (caller_link_addr, call_site_link_addr, sig)."""
    base_off = text_section["offset"]
    base_vmaddr = text_section["addr"]
    blob = data[base_off:base_off+text_section["size"]]
    callers = []
    seen = set()
    for i in range(0, len(blob)-4, 4):
        insn = u32(blob, i)
        off = decode_bl(insn)
        if off is None: continue
        pc = base_vmaddr + i
        if pc + off != func_vmaddr: continue
        fstart = function_start(text_section, data, i)
        if fstart is None: continue
        if fstart in seen: continue
        seen.add(fstart)
        fstart_link = base_vmaddr + fstart
        sig = bytes(data[base_off+fstart : base_off+fstart+16])
        callers.append((fstart_link, pc, sig))
    return callers

def main():
    if not os.path.exists(BINARY):
        print(f"[-] {BINARY} not found"); sys.exit(1)
    sections = parse_sections()
    text = next((s for s in sections if s.get("segname")=="__TEXT" and s.get("sectname")=="__text"), None)
    if not text:
        print("[-] __TEXT,__text not found"); sys.exit(1)
    print(f"[+] __text: vmaddr={text['addr']:#x} size={text['size']:#x} fileoff={text['offset']:#x}")

    with open(BINARY, "rb") as f:
        f.seek(0, 2); flen = f.tell(); f.seek(0)
        data = mmap.mmap(f.fileno(), flen, access=mmap.ACCESS_READ)

    # Header export mode: argv[1] == "--header"
    gen_header = (len(sys.argv) > 1 and sys.argv[1] == "--header")

    # Caller mode: argv[1] = hex link-vmaddr of a known function
    if len(sys.argv) > 1 and not gen_header and sys.argv[1].startswith("0x"):
        target = int(sys.argv[1], 16)
        raw = len(sys.argv) > 2 and sys.argv[2] == "raw"
        if raw:
            base_off = text["offset"]; base_vmaddr = text["addr"]
            blob = data[base_off:base_off+text["size"]]
            n = 0
            for i in range(0, len(blob)-4, 4):
                insn = u32(blob, i)
                off = decode_bl(insn)
                if off is None: continue
                pc = base_vmaddr + i
                if pc + off != target: continue
                print(f"  bl @ {pc:#x}")
                n += 1
            print(f"  total {n} BL sites")
            return
        print(f"\n=== finding callers of {target:#x} ===")
        callers = find_callers(text, data, target)
        print(f"  {len(callers)} distinct caller(s):")
        for addr, site, sig in callers[:40]:
            print(f"    caller @ {addr:#x}  (bl @ {site:#x})  sig={sig.hex()}")
        return

    extracted_sigs = {}
    for needle in TARGET_STRINGS:
        print(f"\n=== searching for {needle!r} ===")
        vaddr, sec = find_string_vmaddr(sections, data, needle)
        if not vaddr:
            print("  not found"); continue
        print(f"  string @ {vaddr:#x} (in {sec.get('segname')},{sec.get('sectname')})")
        xref_link, xref_off = scan_xref(text, data, vaddr)
        if xref_link is None:
            print("  no ADRP+ADD xref in __text"); continue
        print(f"  xref @ {xref_link:#x} (file off {xref_off:#x})")
        fstart = function_start(text, data, xref_off)
        if fstart is None:
            print("  function start not found (walking back failed)"); continue
        fstart_link = text["addr"] + fstart
        sig = data[text["offset"]+fstart : text["offset"]+fstart+16]
        print(f"  function @ {fstart_link:#x}")
        print(f"  signature (16 bytes): {sig.hex()}")
        print(f"  masked pattern: {' '.join(f'{b:02x}' for b in sig)}")
        key = needle.decode('utf-8', errors='ignore').replace("\x00", "").strip()
        extracted_sigs[key] = (fstart_link, sig.hex())

    if gen_header:
        hdr_path = os.path.join(os.path.dirname(__file__), "..", "luau_signatures.h")
        with open(hdr_path, "w") as hf:
            hf.write("/* Auto-generated by tools/find_luau.py */\n")
            hf.write("#ifndef LUAU_SIGNATURES_H\n#define LUAU_SIGNATURES_H\n\n")
            hf.write("#include <stdint.h>\n\n")
            for k, (vaddr, sig_hex) in extracted_sigs.items():
                safe_name = k.replace("\x00", "").replace(" ", "_").replace("-", "_").replace("'", "").replace("\"", "")
                hf.write(f"/* Pattern for '{k}' */\n")
                hf.write(f"#define LUAU_SIG_{safe_name.upper()}_VMADDR 0x{vaddr:x}ULL\n")
                bytes_str = ", ".join(f"0x{sig_hex[i:i+2]}" for i in range(0, len(sig_hex), 2))
                hf.write(f"static const uint8_t LUAU_SIG_{safe_name.upper()}_BYTES[16] = {{ {bytes_str} }};\n\n")
            hf.write("#endif /* LUAU_SIGNATURES_H */\n")
        print(f"\n[+] Written signatures to {hdr_path}")

if __name__ == "__main__":
    main()

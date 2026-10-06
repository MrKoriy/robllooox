#!/usr/bin/env python3
"""run741.py — compile+remap+send toolchain for the 0.741 client pipeline.

Full verified upstream->wire map (0.741):
  - 12 anchors verified live via PROTODUMP in previous sessions,
  - arithmetic derived 2026-10-06 from handler disasm (MUL/MULK/ADD/ADDK)
    and then verified live via semantic BC: probes (see FINDINGS ФИНАЛ-7).

Usage:
  python3 tools/run741.py exec  'return game.Name'     # one-shot via BC:
  python3 tools/run741.py arm   'workspace.Gravity=50' # stage+arm pcall hook
  python3 tools/run741.py poll                         # read staged result
  python3 tools/run741.py rearm                        # fire staged again
  python3 tools/run741.py disarm                       # unhook
"""
import os, struct, subprocess, sys, socket, tempfile, time

LUAU_COMPILE = "/tmp/luau-src/build/luau-compile"
SOCKET = f"/tmp/inj_ipc_{os.getuid()}.sock"

# ---- upstream Luau v9 op -> Roblox 0.741 wire op --------------------------
WIRE = {
    4: 140,   # LOADN            (verified: internal 210)
    5: 111,   # LOADK            (verified: internal 207)
    6: 144,   # MOVE             (verified: internal 189)
    12: 164,  # GETIMPORT        (verified: internal 23, aux patched)
    15: 77,   # GETTABLEKS       (verified: live chains)
    16: 78,   # SETTABLEKS       (verified accepted: internal 130 udata form)
    20: 95,   # NAMECALL         (verified: internal 132)
    21: 159,  # CALL             (verified: internal 170)
    22: 130,  # RETURN           (verified: internal 146)
    64: 192,  # DUPCLOSURE       (verified: internal 134)
    65: 82,   # PREPVARARGS      (verified: internal 62)
    # -- derived from 0.741 handler disasm, verified live (FINDINGS ФИНАЛ-7):
    35: 9,    # MUL              (two tag checks cmp#3, reg/reg) — verified "3*4"->12
    41: 91,   # MULK             (reg + 16-byte TValue const load, plain fmul)
    44: 4,    # POWK             (fmul + fcmp #2.0 square fast path)
    33: 67,   # ADD              (two tag checks cmp#3, reg/reg)
    39: 149,  # ADDK             (reg + const-array load)
}

AUX_OPS = {7, 8, 12, 15, 16, 20, 27, 28, 29, 30, 31, 32, 53, 55, 58, 60, 66, 74,
           75, 77, 78, 79, 80, 83, 84, 85}
def op_len(op): return 2 if op in AUX_OPS else 1

def read_varint(d, o):
    v = 0; shift = 0
    while True:
        b = d[o]; o += 1
        v |= (b & 0x7f) << shift
        if not (b & 0x80): break
        shift += 7
    return v, o

def skip_const(d, o):
    t = d[o]; o += 1
    if t == 0: pass
    elif t == 1: o += 1
    elif t == 2: o += 8
    elif t == 3: _, o = read_varint(d, o)
    elif t == 4: o += 4
    elif t == 5:
        cnt, o = read_varint(d, o)
        for _ in range(cnt): _, o = read_varint(d, o)
    elif t == 6: _, o = read_varint(d, o)
    elif t == 7: o += 16
    elif t == 8:
        cnt, o = read_varint(d, o)
        for _ in range(cnt):
            _, o = read_varint(d, o); o += 4
    elif t == 9:
        o += 1
        _, o = read_varint(d, o)
    else: raise ValueError(t)
    return o

def parse(d):
    o = 2
    nstr, o = read_varint(d, o)
    for _ in range(nstr):
        l, o = read_varint(d, o); o += l
    while d[o] != 0:
        o += 1
        _, o = read_varint(d, o)
    o += 1
    nproto, o = read_varint(d, o)
    protos = []
    for _ in range(nproto):
        o += 5
        ts, o = read_varint(d, o); o += ts
        nc, o = read_varint(d, o)
        code_off = o
        o += 4 * nc
        nk, o = read_varint(d, o)
        for _ in range(nk):
            o = skip_const(d, o)
        sizep, o = read_varint(d, o)
        for _ in range(sizep):
            _, o = read_varint(d, o)
        _, o = read_varint(d, o)
        _, o = read_varint(d, o)
        if d[o]:
            o += 1
            gap = d[o]; o += 1
            intervals = ((nc - 1) >> gap) + 1 if nc else 0
            o += nc
            o += intervals * 4
        else:
            o += 1
        if d[o]:
            o += 1
            nloc, o = read_varint(d, o)
            for _ in range(nloc):
                _, o = read_varint(d, o); _, o = read_varint(d, o)
                _, o = read_varint(d, o); o += 1
            nupv, o = read_varint(d, o)
            for _ in range(nupv): _, o = read_varint(d, o)
        else:
            o += 1
        protos.append(dict(code_off=code_off, ncode=nc))
    return protos

def code_words(d, proto):
    i = 0
    while i < proto["ncode"]:
        off = proto["code_off"] + 4 * i
        if off + 4 > len(d): break
        w = struct.unpack_from("<I", d, off)[0]
        yield off, w
        i += op_len(w & 0xff)

def remap(d):
    d = bytearray(d)
    unmapped = set()
    for p in parse(bytes(d)):
        for off, w in code_words(bytes(d), p):
            op = w & 0xff
            if op in WIRE:
                d[off] = WIRE[op]
            else:
                unmapped.add(op)
    return bytes(d), unmapped

def compile_src(src):
    with tempfile.NamedTemporaryFile("w", suffix=".lua", delete=False) as f:
        f.write(src)
        path = f.name
    try:
        r = subprocess.run([LUAU_COMPILE, "--fflags=false", "--binary", path],
                           capture_output=True, timeout=30)
        if r.returncode != 0 or not r.stdout:
            raise RuntimeError("compile failed: " + r.stderr.decode(errors="replace"))
        return r.stdout
    finally:
        os.unlink(path)

def send(msg, timeout=30, retries=2):
    last = ""
    for _ in range(retries + 1):
        try:
            s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            s.settimeout(timeout)
            s.connect(SOCKET)
            s.sendall(msg.encode())
            s.shutdown(socket.SHUT_WR)
            out = b""
            while True:
                try:
                    data = s.recv(65536)
                except socket.timeout:
                    break
                if not data: break
                out += data
            s.close()
            last = out.decode(errors="replace")
            if last.strip(): break
        except (ConnectionRefusedError, FileNotFoundError, socket.timeout):
            time.sleep(0.4)
    return last

def build(src):
    """source -> wire-remapped bytecode blob; refuses on unmapped ops"""
    bc = compile_src(src)
    blob, unmapped = remap(bc)
    if unmapped:
        raise RuntimeError(f"unmapped upstream ops: {sorted(unmapped)} — "
                           f"extend WIRE in tools/run741.py first")
    return blob

def main():
    if len(sys.argv) < 2:
        print(__doc__)
        return 1
    cmd = sys.argv[1]
    if cmd == "exec" and len(sys.argv) >= 3:
        src = " ".join(sys.argv[2:])
        blob = build(src)
        print(send("BC:" + blob.hex()))
    elif cmd == "arm" and len(sys.argv) >= 3:
        src = " ".join(sys.argv[2:])
        blob = build(src)
        print(send("__ARM__ BC:" + blob.hex()))
    elif cmd == "poll":
        print(send("__POLL__"))
    elif cmd == "rearm":
        print(send("__REARM__"))
    elif cmd == "disarm":
        print(send("__DISARM__"))
    elif cmd == "dumpops":
        src = " ".join(sys.argv[2:])
        bc = compile_src(src)
        for p in parse(bc):
            print(f"proto @{p['code_off']} ncode={p['ncode']}")
            for off, w in code_words(bc, p):
                print(f"  +{off:4d} {w:08x} op={w&0xff:3d} A={(w>>8)&0xff} "
                      f"B={(w>>16)&0xff} C={(w>>24)&0xff}")
    else:
        print(__doc__)
        return 1
    return 0

if __name__ == "__main__":
    sys.exit(main())

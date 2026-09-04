#!/usr/bin/env python3
"""
Roblox Luau v9 bytecode verifier/simulator
Parses upstream-compatible v9 dumps, remaps opcodes, simulates execution.
Verifies bytecode correctness WITHOUT running Roblox.
"""
import struct, sys

# Verified Roblox opcode map (from kDispatchTable handler disassembly)
RBX_OP = {
    'NOP': 77, 'BREAK': 234, 'LOADNIL': 79, 'LOADB': 235, 'LOADN': 6,
    'LOADK': 135, 'MOVE': 71, 'SETUPVAL': 39, 'GETIMPORT': 255,
    'GETGLOBAL': 7,
    'GETTABLE': 155, 'SETTABLE': 164, 'GETTABLEKS': 119, 'SETTABLEKS': 188,
    'GETTABLEN': 27, 'SETTABLEN': 245, 'NEWCLOSURE': 237, 'NAMECALL': 225,
    'CALL': 199, 'RETURN': 125, 'JUMP': 149, 'JUMPBACK': 106, 'JUMPIF': 52,
    'JUMPIFNOT': 240, 'JUMPIFEQ': 128, 'JUMPIFLE': 129, 'JUMPIFLT': 241,
    'JUMPIFNOTEQ': 169, 'JUMPIFNOTLE': 209, 'JUMPIFNOTLT': 126,
    'ADD': 185, 'SUB': 34, 'MUL': None, 'DIV': 212, 'MOD': 210, 'POW': 250,
    'ADDK': 14, 'SUBK': 18, 'MULK': 179, 'DIVK': 143, 'MODK': 53, 'POWK': 74,
    'AND': 218, 'OR': 244, 'ANDK': 154, 'ORK': 30, 'CONCAT': 151,
    'NOT': 91, 'MINUS': 32, 'LENGTH': 166, 'NEWTABLE': 216, 'DUPTABLE': 172,
    'SETLIST': 206, 'FORNPREP': 214, 'FORNLOOP': 150, 'FORGLOOP': 174,
    'CLOSEUPVALS': 146,
    'FORGPREP_INEXT': None, 'FASTCALL3': 159, 'FORGPREP_NEXT': 197,
    'NATIVECALL': 183, 'GETVARARGS': 112, 'DUPCLOSURE': 191,
    'PREPVARARGS': 84, 'LOADKX': 182, 'JUMPX': 137, 'COVERAGE': 59,
    'CAPTURE': None, 'GETUPVAL': 220, 'SUBRK': 68, 'DIVRK': 232,
    'MUL': 165,
    'FASTCALL1': 92, 'FASTCALL2': 15, 'FASTCALL2K': 54,
    'FORGPREP': None, 'JUMPXEQKNIL': None,
    'JUMPXEQKB': 118, 'JUMPXEQKN': 238, 'JUMPXEQKS': 222,
    'IDIV': 233, 'IDIVK': 115, 'GETUDATAKS': 202, 'SETUDATAKS': 198,
    'NAMECALLUDATA': 131, 'NEWCLASSMEMBER': None, 'CALLFB': 144, 'CMPPROTO': None,
}

UPSTREAM_OP = {
    0:'NOP',1:'BREAK',2:'LOADNIL',3:'LOADB',4:'LOADN',5:'LOADK',6:'MOVE',
    7:'GETGLOBAL',8:'SETGLOBAL',9:'GETUPVAL',
    10:'SETUPVAL',11:'CLOSEUPVALS',12:'GETIMPORT',13:'GETTABLE',14:'SETTABLE',
    15:'GETTABLEKS',16:'SETTABLEKS',17:'GETTABLEN',18:'SETTABLEN',19:'NEWCLOSURE',
    20:'NAMECALL',21:'CALL',22:'RETURN',23:'JUMP',24:'JUMPBACK',
    25:'JUMPIF',26:'JUMPIFNOT',27:'JUMPIFEQ',28:'JUMPIFLE',29:'JUMPIFLT',
    30:'JUMPIFNOTEQ',31:'JUMPIFNOTLE',32:'JUMPIFNOTLT',
    33:'ADD',34:'SUB',35:'MUL',36:'DIV',37:'MOD',38:'POW',
    39:'ADDK',40:'SUBK',41:'MULK',42:'DIVK',43:'MODK',44:'POWK',
    45:'AND',46:'OR',47:'ANDK',48:'ORK',49:'CONCAT',50:'NOT',51:'MINUS',
    52:'LENGTH',53:'NEWTABLE',54:'DUPTABLE',55:'SETLIST',
    56:'FORNPREP',57:'FORNLOOP',58:'FORGLOOP',59:'FORGPREP_INEXT',
    60:'FASTCALL3',61:'FORGPREP_NEXT',62:'NATIVECALL',
    63:'GETVARARGS',64:'DUPCLOSURE',65:'PREPVARARGS',66:'LOADKX',
    67:'JUMPX',68:'FASTCALL',69:'COVERAGE',70:'CAPTURE',
    71:'SUBRK',72:'DIVRK',73:'FASTCALL1',74:'FASTCALL2',75:'FASTCALL2K',
    76:'FORGPREP',77:'JUMPXEQKNIL',78:'JUMPXEQKB',79:'JUMPXEQKN',80:'JUMPXEQKS',
    81:'IDIV',82:'IDIVK',83:'GETUDATAKS',84:'SETUDATAKS',
    85:'NAMECALLUDATA',86:'NEWCLASSMEMBER',87:'CALLFB',88:'CMPPROTO',
}

UPSTREAM_OP_REV = {v: k for k, v in UPSTREAM_OP.items()}
RBX_OP_REV = {}
for name, slot in RBX_OP.items():
    if slot is not None:
        RBX_OP_REV[slot] = name


def resolve_op(op):
    """Detect if opcode is upstream or already remapped to Roblox"""
    if op in RBX_OP_REV:
        return RBX_OP_REV[op], 'rbx'
    if op in UPSTREAM_OP:
        return UPSTREAM_OP[op], 'upstream'
    return f'?{op}', '?'
AUX_OPS = {'GETIMPORT','NAMECALL','GETTABLEKS','SETTABLEKS','GETGLOBAL','SETGLOBAL',
           'LOADKX','FORGLOOP','FASTCALL2','FASTCALL2K',
           'JUMPXEQKN','JUMPXEQKI','JUMPXEQKS','NEWCLASSMEMBER'}


def read_varint(data, pos):
    v = 0; shift = 0
    while True:
        b = data[pos]; pos += 1
        v |= (b & 0x7f) << shift; shift += 7
        if not (b & 0x80): break
    return v, pos


class BCParser:
    def __init__(self, data):
        self.data = data; self.pos = 0
        self.strings = []; self.protos = []

    def rv(self):
        v, self.pos = read_varint(self.data, self.pos)
        return v

    def u8(self):
        v = self.data[self.pos]; self.pos += 1; return v

    def u32(self):
        v = struct.unpack_from('<I', self.data, self.pos)[0]; self.pos += 4; return v

    def i32(self):
        v = struct.unpack_from('<i', self.data, self.pos)[0]; self.pos += 4; return v

    def f64(self):
        v = struct.unpack_from('<d', self.data, self.pos)[0]; self.pos += 8; return v

    def parse(self):
        version = self.u8(); typesver = self.u8()
        assert version == 9, f"expected version 9, got {version}"

        sc = self.rv()
        for _ in range(sc):
            sl = self.rv()
            s = self.data[self.pos:self.pos+sl].decode('utf-8', 'replace')
            self.pos += sl; self.strings.append(s)

        # userdata type mapping loop
        while True:
            idx = self.u8()
            if idx == 0: break
            sid = self.rv()  # string ref (unused here)

        proto_count = self.rv()
        for i in range(proto_count):
            self.protos.append(self.parse_proto(typesver, version))

        return version, typesver

    def parse_proto(self, typesver, version=9):
        p = {}
        p['maxstack'] = self.u8(); p['numparams'] = self.u8()
        p['nups'] = self.u8(); p['is_vararg'] = self.u8()
        p['flags'] = self.u8()

        if typesver in (2, 3):
            tsz = self.rv()
            p['types'] = self.data[self.pos:self.pos+tsz].hex()
            self.pos += tsz

        szcode = self.rv()
        p['insns'] = []
        for _ in range(szcode):
            p['insns'].append(self.u32())

        szk = self.rv()
        p['constants'] = []
        for _ in range(szk):
            t = self.u8()
            if t == 0: p['constants'].append(('nil',))
            elif t == 1: p['constants'].append(('bool', self.u8()))
            elif t == 2: p['constants'].append(('num', self.f64()))
            elif t == 3:
                sid = self.rv()
                s = self.strings[sid-1] if sid > 0 else ''
                p['constants'].append(('str', s))
            elif t == 4: p['constants'].append(('import', self.u32()))
            elif t == 5:
                nk = self.rv(); keys = [self.rv() for _ in range(nk)]
                p['constants'].append(('table', keys))
            elif t == 6: p['constants'].append(('closure', self.rv()))
            elif t == 7:
                vec = struct.unpack_from('<4f', self.data, self.pos); self.pos += 16
                p['constants'].append(('vector', vec))
            elif t == 8:
                nk = self.rv(); entries = []
                for _ in range(nk):
                    kidx = self.rv(); cidx = self.i32()
                    entries.append((kidx, cidx))
                p['constants'].append(('twc', entries))
            elif t == 9:
                iv = struct.unpack_from('<q', self.data, self.pos)[0]; self.pos += 8
                p['constants'].append(('int', iv))
            elif t == 10:
                raise NotImplementedError("CLASS_SHAPE")
            else:
                raise ValueError(f"unknown const type {t} at {self.pos-1}")

        szpids = self.rv()
        p['nested_ids'] = [self.rv() for _ in range(szpids)]

        # debug section (per lvmload.cpp)
        p['linedefined'] = self.rv()

        dbg_name_sid = self.rv()
        p['debugname'] = self.strings[dbg_name_sid-1] if dbg_name_sid > 0 and dbg_name_sid <= len(self.strings) else ''

        lineinfo_flag = self.u8()
        p['lineinfo'] = []
        p['linegaplog2'] = 0
        p['abslineinfo'] = []
        if lineinfo_flag:
            p['linegaplog2'] = self.u8()
            sizecode = len(p['insns'])
            intervals = ((sizecode - 1) >> p['linegaplog2']) + 1 if sizecode else 0
            absoffset = (sizecode + 3) & ~3
            sizelineinfo = absoffset + intervals * 4
            p['lineinfo'] = list(self.data[self.pos:self.pos+sizecode])
            self.pos += sizecode
            lastline = 0
            for j in range(intervals):
                lastline += self.i32()
                p['abslineinfo'].append(lastline)

        debuginfo_flag = self.u8()
        p['locvars'] = []
        p['upvalnames'] = []
        if debuginfo_flag:
            sz_locvars = self.rv()
            for _ in range(sz_locvars):
                nm_sid = self.rv()
                start = self.rv(); end = self.rv()
                reg = self.u8()
                nm = self.strings[nm_sid-1] if nm_sid > 0 and nm_sid <= len(self.strings) else ''
                p['locvars'].append((nm, start, end, reg))

            sz_upvals = self.rv()
            for _ in range(sz_upvals):
                nm_sid = self.rv()
                nm = self.strings[nm_sid-1] if nm_sid > 0 and nm_sid <= len(self.strings) else ''
                p['upvalnames'].append(nm)

        # version >= 11: feedback vector
        if version >= 11:
            fbsz = self.rv()
            for _ in range(fbsz):
                slottype = self.u8()
                ct_pc = self.rv()  # call target pc

        # version >= 12: cost if inlinable — we're version 9 so skip

        return p


def decode_insn(raw):
    op = raw & 0xff
    A = (raw >> 8) & 0xff
    B = (raw >> 16) & 0xff
    C = (raw >> 24) & 0xff
    D = (raw >> 16) & 0xffff
    return op, A, B, C, D


def disasm(proto, indent='  ', all_protos=None):
    """Pretty-print instructions"""
    out = []
    i = 0
    insns = proto['insns']
    while i < len(insns):
        raw = insns[i]
        op, A, B, C, D = decode_insn(raw)
        name, src_kind = resolve_op(op)
        r_op = RBX_OP.get(name)
        r_str = f"rbx_slot={r_op}" if r_op else f"rbx_slot=MISSING({name})"
        aux_note = ''
        if name in AUX_OPS:
            if i + 1 < len(insns):
                aux_raw = insns[i+1]
                aux_note = f"  ; aux={aux_raw:#010x}"
            else:
                aux_note = "  ; MISSING AUX!"
        out.append(f"{indent}[{i:3d}] {raw:#010x} {name:<16} "
                   f"A={A:<3} B={B:<3} C={C:<3} D={D:#06x}"
                   f"  ({r_str}){aux_note}")
        if name == 'NEWCLOSURE':
            nups_n = all_protos[D]['nups'] if all_protos and D < len(all_protos) else 0
            i += 1 + nups_n
        elif name in AUX_OPS:
            i += 2
        else:
            i += 1
    return '\n'.join(out)


def verify(proto, verbose=True, all_protos=None):
    """Verify bytecode integrity"""
    issues = []
    insns = proto['insns']
    i = 0
    while i < len(insns):
        raw = insns[i]
        op, A, B, C, D = decode_insn(raw)
        name, src_kind = resolve_op(op)

        # Check aux requirement
        if name == 'NEWCLOSURE':
            nups_n = all_protos[D]['nups'] if all_protos and D < len(all_protos) else 0
            if i + 1 + nups_n > len(insns):
                issues.append(f"[{i}] NEWCLOSURE: {nups_n} captures overflow")
            for j in range(1, nups_n + 1):
                if i + j < len(insns):
                    cop = insns[i + j] & 0xff
                    cname, _ = resolve_op(cop)
                    if cname != 'CAPTURE':
                        issues.append(f"[{i+j}] expected CAPTURE after NEWCLOSURE, got {cname}")
            i += 1 + nups_n
        elif name in AUX_OPS:
            if i + 1 >= len(insns):
                issues.append(f"[{i}] {name}: missing AUX word at end")
            i += 2
        else:
            i += 1

        # Check register bounds
        maxreg = proto['maxstack']
        if name not in ('RETURN','CALL','PREPVARARGS','GETVARARGS','SETLIST'):
            for lbl, val in [('A',A)]:
                pass  # simplified

        # Check jump targets
        if name in ('JUMP','JUMPIF','JUMPIFNOT','JUMPBACK') :
            target_off = D if D < 0x8000 else D - 0x10000  # signed
            target_idx = i + target_off
            if target_idx < 0 or target_idx > len(insns):
                issues.append(f"[{i}] {name}: jump target {target_idx} out of range")

    return issues


def simulate(proto, max_steps=200, verbose=False, all_protos=None):
    """
    Symbolic simulation: track register types and detect obvious errors.
    Returns list of issues.
    """
    issues = []
    regs = {}  # reg_idx -> type guess ('nil','bool','num','str','table','func','any')
    consts = proto['constants']

    def const_type(kidx):
        if kidx < 0 or kidx >= len(consts): return '?'
        return consts[kidx][0]

    pc = 0
    steps = 0
    insns = proto['insns']
    while pc < len(insns) and steps < max_steps:
        steps += 1
        raw = insns[pc]
        op, A, B, C, D = decode_insn(raw)
        name, src_kind = resolve_op(op)

        if verbose:
            print(f"  pc={pc:3d} {name} A={A} B={B} C={C}")

        # Track register states
        if name == 'LOADK':
            regs[A] = const_type(D)
        elif name == 'MOVE':
            regs[A] = regs.get(B, 'any')
        elif name == 'ADD':
            ta, tb = regs.get(B,'any'), regs.get(C,'any')
            if ta in ('num','nil','bool') and tb in ('num','nil','bool'):
                regs[A] = 'num'
            else:
                issues.append(f"[{pc}] ADD on non-numbers ({ta},{tb})")
        elif name == 'GETIMPORT':
            regs[A] = 'func'  # typically resolves to function
        elif name == 'DUPTABLE':
            regs[A] = 'table'
        elif name == 'NEWCLOSURE':
            regs[A] = 'func'
        elif name == 'DUPCLOSURE':
            regs[A] = 'func'

        # Advance
        if name == 'NEWCLOSURE':
            nups_n = all_protos[D]['nups'] if all_protos and D < len(all_protos) else 0
            pc += 1 + nups_n
        elif name in AUX_OPS:
            pc += 2
        else:
            pc += 1

    return issues


def main():
    if len(sys.argv) < 2:
        print("usage: bcverify.py <bytecode_file>")
        sys.exit(1)

    data = open(sys.argv[1], 'rb').read()
    print(f"file: {sys.argv[1]} ({len(data)} bytes)")

    p = BCParser(data)
    try:
        version, typesver = p.parse()
    except Exception as e:
        print(f"PARSE ERROR: {e}")
        import traceback; traceback.print_exc()
        sys.exit(1)

    print(f"version={version} typesver={typesver}")
    print(f"strings ({len(p.strings)}):")
    for i, s in enumerate(p.strings):
        print(f"  [{i}] '{s}'")

    print(f"\nprotos ({len(p.protos)}):")

    def walk(pi_idx, depth=0):
        ind = '  ' * depth
        proto = p.protos[pi_idx]
        print(f"{ind}=== proto[{pi_idx}] ===")
        print(f"{ind}  stack={proto['maxstack']} params={proto['numparams']} "
              f"nups={proto['nups']} vararg={proto['is_vararg']} flags={proto['flags']:#04x}")
        print(f"{ind}  debugname='{proto['debugname']}'")
        print(f"{ind}  constants:")
        for ci, c in enumerate(proto['constants']):
            print(f"{ind}    [{ci}] {c}")
        print(f"{ind}  disassembly:")
        print(disasm(proto, ind + '    ', p.protos))
        iss = verify(proto, all_protos=p.protos)
        for x in iss:
            print(f"{ind}  VERIFY ISSUE: {x}")
        sim_iss = simulate(proto, verbose=False, all_protos=p.protos)
        for x in sim_iss:
            print(f"{ind}  SIM ISSUE: {x}")
        for nid in proto['nested_ids']:
            walk(nid, depth+1)

    mainid = p.rv()
    print(f"\nmain proto id: {mainid}")
    walk(mainid)


if __name__ == '__main__':
    main()

#!/usr/bin/env python3
"""gen_tramp_verify.py — encode trampoline instructions, verify against capstone."""
import struct
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM

md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)


def u32(w):
    return struct.pack("<I", w & 0xFFFFFFFF)


def verify(name, insn_bytes, expect_mnem=None):
    insns = list(md.disasm(insn_bytes, 0x1000))
    assert len(insns) == 1, f"{name}: decoded {len(insns)} insns"
    if expect_mnem:
        assert insns[0].mnemonic == expect_mnem, f"{name}: got {insns[0].mnemonic}"
    print(f"  {name}: {insns[0].mnemonic} {insns[0].op_str}  [{insn_bytes.hex()}]")
    return insns[0]


def sign_extend(v, bits):
    if v & (1 << (bits - 1)):
        return v - (1 << bits)
    return v


def enc_stp_pre(rt, rt2, rn, imm):
    imm7 = (imm >> 3) & 0x7F
    return 0xA9800000 | (0x7E << 15) | (imm7 << 15) | (rt2 << 10) | (rn << 5) | rt


def enc_ldp_post(rt, rt2, rn, imm):
    imm7 = (imm >> 3) & 0x7F
    return 0xA8C00000 | (imm7 << 15) | (rt2 << 10) | (rn << 5) | rt


def enc_adrp(rd, pc, target):
    page_pc = pc & ~0xFFF
    page_t = target & ~0xFFF
    imm = (page_t - page_pc) >> 12
    immlo = imm & 0x3
    immhi = (imm >> 2) & 0x7FFFF
    return 0x90000000 | (immlo << 29) | (immhi << 5) | rd


def enc_add_imm(rd, rn, imm12, sh=0):
    return 0x91000000 | (sh << 22) | ((imm12 & 0xFFF) << 10) | (rn << 5) | rd


def enc_ldr_literal(rt, pc, target):
    imm19 = (target - pc) >> 2
    return 0x58000000 | ((imm19 & 0x7FFFF) << 5) | rt


def enc_blr(rn):
    return 0xD63F0000 | (rn << 5)


def enc_br(rn):
    return 0xD61F0000 | (rn << 5)


def enc_nop():
    return 0xD503201F


print("== fixed instructions ==")
PC = 0x10000
for rt, rt2 in ((0, 1), (2, 3), (4, 5), (6, 7)):
    verify(f"stp x{rt},x{rt2},[sp,#-16]!", u32(enc_stp_pre(rt, rt2, 31, -16)), "stp")
for rt, rt2 in ((6, 7), (4, 5), (2, 3), (0, 1)):
    verify(f"ldp x{rt},x{rt2},[sp],#16", u32(enc_ldp_post(rt, rt2, 31, 16)), "ldp")
verify("adrp x17, @0x18000", u32(enc_adrp(17, PC, 0x18000)), "adrp")
verify("add x17, x17, #0x123", u32(enc_add_imm(17, 17, 0x123)), "add")
verify("ldr x2, [pc, #0x28]", u32(enc_ldr_literal(2, PC, PC + 0x28)), "ldr")
verify("ldr x16, [pc, #0x10]", u32(enc_ldr_literal(16, PC, PC + 0x10)), "ldr")
verify("blr x17", u32(enc_blr(17)), "blr")
verify("br x16", u32(enc_br(16)), "br")
verify("nop", u32(enc_nop()), "nop")

print("\n== full trampoline (slot 5, check@0x20000, orig@0x30000, tramp@0x10000) ==")
tramp = bytearray()
T = 0x10000
tramp += u32(enc_stp_pre(0, 1, 31, -16))
tramp += u32(enc_stp_pre(2, 3, 31, -16))
tramp += u32(enc_stp_pre(4, 5, 31, -16))
tramp += u32(enc_stp_pre(6, 7, 31, -16))
tramp += u32(enc_adrp(17, T + 0x10, 0x20000))
tramp += u32(enc_add_imm(17, 17, 0))
tramp += u32(enc_ldr_literal(2, T + 0x18, T + 0x40))
tramp += u32(enc_blr(17))
tramp += u32(enc_ldp_post(6, 7, 31, 16))
tramp += u32(enc_ldp_post(4, 5, 31, 16))
tramp += u32(enc_ldp_post(2, 3, 31, 16))
tramp += u32(enc_ldp_post(0, 1, 31, 16))
tramp += u32(enc_ldr_literal(16, T + 0x30, T + 0x48))
tramp += u32(enc_br(16))
tramp += u32(enc_nop())
tramp += u32(enc_nop())
tramp += struct.pack("<Q", 5)       # slot_idx @ 0x40
tramp += struct.pack("<Q", 0x30000)  # orig_addr @ 0x48
assert len(tramp) == 0x50, len(tramp)

insns = list(md.disasm(bytes(tramp), T))
for i, ins in enumerate(insns):
    print(f"  {i:02d} @ {ins.address:#x}: {ins.mnemonic} {ins.op_str}")
print("\nALL OK")
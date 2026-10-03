# Roblox Luau v9 — Verified Opcode Map

## Source
kDispatchTable @ __DATA_CONST link 0x106eed6c0 (file offset 0x6eed6c0)
91 non-null slots. All handlers disassembled from /tmp/roblox_disasm.txt.

## Verified Mappings (upstream_op → roblox_slot)

### Core execution
| Upstream | Op | Name | Roblox Slot | Verified By |
|----------|-----|------|-------------|-------------|
| 0 | NOP | 77 | tentative |
| 1 | BREAK | 234 | assumed |
| 2 | LOADNIL | 79 | assumed |
| 3 | LOADB | 235 | assumed |
| 4 | LOADN | 6 | ✓ handler reads A,D |
| 5 | LOADK | 135 | ✓ k[D]→base[A] |
| 6 | MOVE | 71 | ✓ base[B]→base[A] |
| 10 | SETUPVAL | 39 | assumed |
| 11 | CLOSEUPVALS | **146** | ✓ calls luaF_close |
| 12 | GETIMPORT | 255 | ✓ fast path + luaV_getimport slow path |

### Table ops
| 13 | GETTABLE | 155 | ✓ base[A]=base[B][base[C]] |
| 14 | SETTABLE | 164 | ✓ base[B][base[C]]=base[A] |
| 15 | GETTABLEKS | **119** | ✓ A=dest,B=table,C=hash hint,aux=key (slot95 has DIFFERENT operand order: A=table,C=dest - do NOT use) |
| 16 | SETTABLEKS | **188** | ✓ inline hash lookup, base[B][k[aux]]=base[A] |
| 17 | GETTABLEN | 27 | ✓ |
| 18 | SETTABLEN | 245 | ✓ |

### Functions/calls
| 19 | NEWCLOSURE | 237 | ✓ proto[k[D]], luaF_newLclosure |
| 20 | NAMECALL | 225 | ✓ aux=const key idx, pc+=2 |
| 21 | CALL | 199 | ✓ B-1 args, C-1 results |
| 22 | RETURN | 125 | ✓ copies B values from base[A] |
| 87 | CALLFB | 144 | assumed |

### Control flow
| 23 | JUMP | 149 | ✓ pc += D*4 |
| 24 | JUMPBACK | 106 | ✓ backward jump |
| 25 | JUMPIF | 52 | ✓ if truthy jump D |
| 26 | JUMPIFNOT | 240 | ✓ if falsy jump D |
| 27 | JUMPIFEQ | 128 | ✓ |
| 28 | JUMPIFLE | 129 | ✓ |
| 29 | JUMPIFLT | 241 | ✓ |
| 30 | JUMPIFNOTEQ | 169 | ✓ |
| 31 | JUMPIFNOTLE | 209 | ✓ |
| 32 | JUMPIFNOTLT | 126 | ✓ |

### Arithmetic (register)
| 33 | ADD | 185 | ✓ fadd base[B]+base[C]→base[A] |
| 34 | SUB | 34 | ✓ fsub |
| 35 | MUL | **165** | ✓ fmul base[B]*base[C]→base[A] |
| 36 | DIV | 212 | ✓ fdiv |
| 37 | MOD | 210 | ✓ fmod via fmul/ftrunc |
| 38 | POW | 250 | ✓ bl _pow |

### Arithmetic (constant K)
| 39 | ADDK | 14 | ✓ fadd base[B]+k[C] |
| 40 | SUBK | 18 | ✓ |
| 41 | MULK | 179 | ✓ fmul |
| 42 | DIVK | 143 | ✓ fdiv |
| 43 | MODK | 53 | ✓ |
| 44 | POWK | **74** | ✓ checks exp==2 for fmul fast path |
| 71 | SUBRK | **68** | ✓ fsub k[B]-base[C]→base[A] |
| 72 | DIVRK | **232** | ✓ fdiv k[B]/base[C]→base[A] |

### Logic
| 45 | AND | 218 | ✓ |
| 46 | OR | 244 | ✓ |
| 47 | ANDK | 154 | ✓ |
| 48 | ORK | 30 | ✓ |
| 49 | CONCAT | 151 | ✓ |
| 50 | NOT | 91 | ✓ |
| 51 | MINUS | 32 | ✓ fneg |
| 52 | LENGTH | 166 | ✓ |

### Tables/loops
| 53 | NEWTABLE | 216 | ✓ |
| 54 | DUPTABLE | 172 | ✓ clone k[D] template |
| 55 | SETLIST | 206 | ✓ sets table[i]=base[A+i], B==0 uses top |
| 56 | FORNPREP | 214 | ✓ check idx vs limit, D=exit offset |
| 57 | FORNLOOP | **150** | ✓ counter+=step; if done→exit else backward jump |
| 58 | FORGLOOP | 174 | ✓ generic iterator loop, uses aux |

### Varargs/misc
| 63 | GETVARARGS | 112 | ✓ copy to base[A], B limits count |
| 64 | DUPCLOSURE | 191 | ✓ clone k[D] closure |
| 65 | PREPVARARGS | 84 | ✓ adjust stack for vararg func |
| 66 | LOADKX | 182 | ✓ load k[aux] |
| 67 | JUMPX | 137 | ✓ 25-bit offset |
| 68 | FASTCALL | 120 | ✓ |
| 69 | COVERAGE | 59 | ✓ |
| 73 | FASTCALL1 | 92 | ✓ fastcall table @ 0x106eeb9b8 |
| 74 | FASTCALL2 | 15 | ✓ |
| 75 | FASTCALL2K | 54 | ✓ |
| 76 | FORGPREP_NEXT | 197 | ✓ |
| 60 | FASTCALL3 | 159 | ✓ |
| 62 | NATIVECALL | 183 | ✓ |
| 81 | IDIV | 233 | ✓ |
| 82 | IDIVK | 115 | ✓ |

## Key Findings

1. **FORNLOOP is slot 150** — NOT in original rbxRemapOp. Handler increments
   base[A+2] (counter) by base[A+1] (step), then checks exit condition and does
   backward jump via D field.

2. **SETTABLEKS is slot 188** — inline hash optimization: computes string hash,
   looks up in table's hash part, stores directly if found.

3. **POWK is slot 74** — has special case for exponent==2 using fmul instead of pow().

4. **SUBRK/DIVRK are slots 68/232** — reversed operand order vs upstream.

5. **CLOSEUPVALS is slot 146** — calls luaF_close helper at 0x102c4998c.

6. **AUX word usage (compiler release/730 matches Roblox natively)**: these ops consume
   the NEXT word as auxiliary: GETGLOBAL(slot 7, string const), SETGLOBAL,
   GETTABLEKS(119), SETTABLEKS(188), NAMECALL(225), GETIMPORT(255), LOADKX(182),
   FORGLOOP(174, vararg count byte), FASTCALL2(15)/FASTCALL2K(54) (extra reg),
   JUMPXEQKN/S/KI. Compiler already emits aux words; operand encodings verified to
   match Roblox handlers exactly — NO post-processing needed.

7. **Encoding matches upstream-730**: A(bits 8-15), B(16-23), C(24-31), D(signed 16).
   Only the opcode byte differs.

8. **GETGLOBAL = slot 7** (identity mapping correct): hash prediction in C + key in aux.
   Earlier CMPPROTO guess was WRONG. SETGLOBAL(upstream 8): slot 8 is NULL — avoid
   explicit _G writes or locate the real slot later.

9. **CAPTURE consumed inline by NEWCLOSURE(slot 237)**: handler reads `nups` capture
   words directly after NEWCLOSURE from the stream (never dispatched). Capture type in
   bits 8-15: 0=copy value base[C], 1=open upvalue (luaF_findupval @0x102c498d0),
   2=proto upvalue copy. NEWCLOSURE D=proto id; count = protos[pid].nups.

10. **slot[95] ≠ compiler GETTABLEKS**: it computes dest from C field and table from A
    (opposite order). slot[119] is the true GETTABLEKS: A=dest, B=table, C=hash hint,
    aux=key const idx, slow path via helper @0x102c5d254.

7. **Encoding matches upstream**: A(bits 8-15), B(16-23), C(24-31), D(signed 16-bit).
   No operand rearrangement needed — only the opcode byte differs.

8. **GETGLOBAL(7) falls through to identity** = slot 7. Handler confirmed:
   checks function type + predicted hash slot, loads from env table.
   SETGLOBAL(8) → slot 8 is NULL but compiler doesn't emit it with -O1+.

## Unverified Slots (no upstream counterpart or unused)
| Slot | Address | Notes |
|------|---------|-------|
| 1 | 0x102c637e0 | unknown |
| 38 | 0x102c672b4 | loop-related? |
| 68 | 0x102c67014 | SUBRK ✓ |
| 74 | 0x102c67590 | POWK ✓ |
| 83 | 0x102c67208 | comparison variant? |
| 119 | 0x102c64928 | GETTABLEKS fast-path (inline hash) |
| 120 | 0x102c6461c | FASTCALL variant? |
| 133 | 0x102c63d3c | GETTABLEKS variant |
| 142 | 0x102c64224 | NEWTABLE with aux |
| 146 | 0x102c63b54 | CLOSEUPVALS ✓ |
| 150 | 0x102c64a00 | FORNLOOP ✓ |
| 165 | 0x102c64f7c | MUL ✓ |
| 174 | 0x102c64d60 | FORGLOOP ✓ |
| 188 | 0x102c6428c | SETTABLEKS ✓ |
| 189 | 0x102c64708 | FASTCALL2 variant |
| 220 | 0x102c64f44 | GETUPVAL-like? |
| 224 | 0x102c646ec | ? |
| 232 | 0x102c64fdc | DIVRK ✓ |
| 236 | 0x102c67e74 | vector math helper |

## Build Artifacts
- Compiler binary: `/var/folders/.../luau-v9/build/luau-compile` (rebuilt Aug 24 13:36)
- Test payload bc: `/tmp/payload.bc` (95 bytes)
- Hex payload: `/tmp/payload_hex.txt`

---

# 0.739 dispatch-экстракция (2026-09-22, tools/opcode_probe.py)

- **kDispatchTable = 0x106874b30 (link)**, 2×256: основной + зеркало с ДРУГИМИ
  адресами (94 зеркальных расхождений) — зеркало это НЕ дубликат, а вторая
  точка входа (fastpath/ profiling-варианты). Обрабатывать как отдельные таблицы.
- 94 non-null слота (не 91 как в 0.735/0.736), все хендлеры — блоки ВНУТРИ
  luaV_execute (0x102977d9c, span 0x93c4), уникальных тел 91.
- **Старая карта 0.735 мертва**: пересечение занятых слотов 28/74 при
  случайных ~27 — полный ремап. Прямое наследование слота НЕ работает
  (735 CLOSEUPVALS=146 → 739 slot 54; 735 NEWCLOSURE=237 → 739 slot 3).
- Контентные якоря (доказаны BL-анализом, бинарно-уникальны):
  - **slot 3 = NEWCLOSURE** (единственный хендлер, зовущий luaF_newLclosure
    @0x102972788 среди 46 callers по бинару)
  - **slot 54 = CLOSEUPVALS** (единственный зовущий luaF_findupval @0x102977740)
  - slot 13 — пара к NEWCLOSURE (общий helper 0x10297789c, 2 callers)
  - slot 169 несёт строку "iterate over" (FORGLOOP-семья?)
  - slot 0, 67, 126, 227, 219, 66, 104 — редкие callee-якоря, см. отчёт
- Signature-кластеры (size, n_indirect, n_calls) в /tmp/opcode739_report.json:
  8×(60,0,0) slots=[15,39,70,75,82,171,184,230] — JUMP-семья?
  5×(68,0,0) slots=[21,71,111,233,241] — LOADN/LOADB/NIL-семья?
- **NInd-загадка**: 0 хендлеров с ret-return — весь VM-exit через общий
  эпилог luaV_execute (br-хвосты), т.е. хендлеры НЕ самодостаточные функции.
  Полная верификация 91 слота офлайн почти невозможна без интерпретации
  потоков внутри гигантского тела — нужен ЖИВОЙ прогон (ресайн + bp на
  dispatch) или интерпретация CFG.
- rbxRemapOp/bcverify на 0.735-карте — НЕГОДНЫ для 0.739 (как и предсказано).
  Мост: у нас есть 3 доказанных якоря + 91 сигнатура; после adhoc-ресайна
  bp на диспетчере даст (op → handler) маппинг живьём за один джойн.

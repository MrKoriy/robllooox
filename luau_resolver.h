/*
 * luau_resolver.h — version-agnostic Luau symbol resolver for RobloxPlayer
 * (macOS arm64 / arm64e).
 *
 * Problem it exists for
 * ---------------------
 * Every executor address in this project used to be a link-time constant
 * captured from one client build (0.735). Roblox re-links the binary on every
 * update, so those constants keep pointing at whatever now lives at that
 * offset — the process dies in the middle of a resume instead of reporting a
 * version mismatch. FINDINGS.md records the same trap twice (0.732 -> 0.735 ->
 * 0.736, opcode map and dispatch tables reshuffled).
 *
 * How it resolves
 * ---------------
 * The Luau error strings are far more stable than code offsets. For each
 * wanted function we:
 *   1. find the C string in the image's data sections (needle + NUL),
 *   2. scan the code sections for the ADRP that references that string's page
 *      and confirm the address is completed by a following ADD (or by an LDR
 *      of a data slot holding the pointer),
 *   3. walk back from the xref to the canonical function prologue
 *      (`stp x29, x30, [sp, #-N]!`, with `pacibsp` handled as the real entry).
 *
 * The core is pure decoding logic over lr_image_t, so the SAME code runs:
 *   - in-process: executor_core.cpp feeds it mach_vm_read_overwrite and
 *     runtime addresses (see executor_resolve / __RESOLVE__),
 *   - offline:    tools/resolver_selftest.cpp feeds it an mmap of the file and
 *     link-time vmaddrs, which is how the resolver itself is verified.
 *
 * Nothing here is allowed to fault: every read is a callback that returns 0 on
 * failure, and every walk is bounded.
 */

#ifndef LUAU_RESOLVER_H
#define LUAU_RESOLVER_H

#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>

#ifdef __cplusplus
extern "C" {
#endif

#define LR_MAX_SECTIONS 96

/* One file-backed Mach-O section. vmaddr is in whatever address space the
 * caller works in (runtime for the dylib, link-time for the offline tool). */
typedef struct {
    uintptr_t   vmaddr;
    uintptr_t   size;
    int         is_code;
    const char* label;   /* "seg,sect" for reports; static storage */
} lr_section_t;

typedef struct {
    const lr_section_t* sections;
    int      n_sections;
    /* must return 1 on success, 0 on any failure — never fault */
    int    (*read)(void* ctx, uintptr_t addr, void* dst, size_t len);
    void*    ctx;
    uint8_t* scratch;      /* caller-provided chunk buffer, >= 0x1000 bytes */
    size_t   scratch_len;
} lr_image_t;

enum {
    LR_OK                 = 0,
    LR_ERR_NO_IMAGE       = -1,
    LR_ERR_NO_STRING      = -2,
    LR_ERR_NO_XREF        = -3,
    LR_ERR_NO_PROLOGUE    = -4,
    LR_ERR_NO_ANCHOR      = -5,
    LR_ERR_NO_PATTERN     = -6,
};

enum {
    LR_METHOD_NONE        = 0,
    LR_METHOD_ANCHOR      = 1,  /* exact ADD/LDR completion of the ADRP */
    LR_METHOD_ANCHOR_PAGE = 2,  /* same page, completion not confirmed */
    LR_METHOD_PATTERN     = 3,  /* raw prologue bytes */
};

typedef struct {
    uintptr_t fn;          /* function entry */
    uintptr_t anchor_addr; /* the C string that was found */
    uintptr_t xref_addr;   /* ADRP site that referenced it */
    int       method;
    uint32_t  prefix[4];   /* first 4 instructions of fn */
    int       occurrences; /* copies of the anchor text in the image */
    int       xrefs;       /* exact xrefs that reach the chosen copy */
    int       page_only;   /* ADRPs on the same page whose completion failed */
    int       distinct_fn; /* distinct functions reachable from those xrefs */
    int       boundary_proven; /* entry preceded by a terminator (real boundary) */
} lr_result_t;

typedef struct {
    const char* name;
    const char* anchors[4]; /* priority order, NULL-terminated */
    int         required;   /* 1 = execution is impossible without it */
} lr_symbol_t;

typedef struct {
    const char* name;
    lr_result_t res;
    int         status;     /* LR_OK or LR_ERR_* */
    const char* anchor_used;
    int         required;
    int         verified_extra; /* other anchors confirmed inside the same fn */
} lr_sym_result_t;

/* ------------------------------------------------------------------ */
/* Instruction decoding                                                */
/* ------------------------------------------------------------------ */

#define LR_PACIBSP 0xD503237Fu

static inline int lr_read(const lr_image_t* img, uintptr_t addr, void* dst, size_t len) {
    if (!img || !img->read || !len) return 0;
    return img->read(img->ctx, addr, dst, len);
}

static inline int lr_u32_direct(const lr_image_t* img, uintptr_t addr, uint32_t* out) {
    uint32_t v = 0;
    if (!lr_read(img, addr, &v, sizeof(v))) return 0;
    *out = v;
    return 1;
}

/* ADRP: bit31=1, immlo=bits30:29, 10000=bits28:24, immhi=bits23:5, Rd=bits4:0 */
static inline int lr_decode_adrp(uint32_t insn, uint32_t* rd, int64_t* imm) {
    if ((insn & 0x9F000000u) != 0x90000000u) return 0;
    uint32_t immlo = (insn >> 29) & 0x3u;
    uint32_t immhi = (insn >> 5) & 0x7FFFFu;
    int64_t  v = (int64_t)((immhi << 2) | immlo);
    if (v & (1LL << 20)) v -= (1LL << 21);
    if (rd)  *rd = insn & 0x1Fu;
    if (imm) *imm = v << 12;
    return 1;
}

/* ADD (immediate), 64-bit: 10010001 imm12 shift Rn Rd */
static inline int lr_decode_add_imm(uint32_t insn, uint32_t* rd, uint32_t* rn, uint32_t* imm) {
    if ((insn & 0xFF000000u) != 0x91000000u) return 0;
    uint32_t sh = (insn >> 22) & 0x3u;
    if (sh > 1) return 0;
    uint32_t imm12 = (insn >> 10) & 0xFFFu;
    if (sh == 1) imm12 <<= 12;
    if (rd) *rd = insn & 0x1Fu;
    if (rn) *rn = (insn >> 5) & 0x1Fu;
    if (imm) *imm = imm12;
    return 1;
}

/* LDR Xt, [Xn, #imm12*8] (unsigned offset, 64-bit) */
static inline int lr_decode_ldr_uoff(uint32_t insn, uint32_t* rt, uint32_t* rn, uint32_t* imm) {
    if ((insn & 0xFFC00000u) != 0xF9400000u) return 0;
    if (rt) *rt = insn & 0x1Fu;
    if (rn) *rn = (insn >> 5) & 0x1Fu;
    if (imm) *imm = ((insn >> 10) & 0xFFFu) << 3;
    return 1;
}

/* BL / B: sign-extended 26-bit word offset */
static inline int lr_decode_branch(uint32_t insn, int64_t* off) {
    uint32_t op = insn & 0xFC000000u;
    if (op != 0x94000000u && op != 0x14000000u) return 0;
    int64_t imm = (int64_t)(insn & 0x03FFFFFFu);
    if (imm & (1LL << 25)) imm -= (1LL << 26);
    if (off) *off = imm << 2;
    return 1;
}

/* A canonical frame setup: `stp x29, x30, [sp, #-imm]!` (what most tools look
 * for). Used as a high-confidence entry marker. */
static inline int lr_is_prologue(uint32_t insn) {
    if ((insn & 0xFF800000u) == 0xA9800000u) {
        uint32_t rt  = insn & 0x1Fu;
        uint32_t rn  = (insn >> 5) & 0x1Fu;
        uint32_t rt2 = (insn >> 10) & 0x1Fu;
        if (rt == 29 && rn == 31 && rt2 == 30) return 1;
    }
    return insn == LR_PACIBSP;
}

/* Optimized builds often save callee-saved registers FIRST, so the function
 * does not begin with the x29/x30 pair: `stp x20, x19, [sp, #-0x20]!` followed
 * by `stp x29, x30, [sp, #0x10]` is just as much an entry. Any pre-index store
 * of a register pair through SP counts as a frame setup. */
static inline int lr_is_frame_push(uint32_t insn) {
    if ((insn & 0xFF800000u) != 0xA9800000u) return 0;   /* STP pre-index */
    return ((insn >> 5) & 0x1Fu) == 31u;                 /* base = SP */
}

/* Some functions never push a frame at all and only carve out locals:
 * `sub sp, sp, #imm`. Also an entry marker (verified in this build: lua_resume
 * starts with exactly this). */
static inline int lr_is_stack_alloc(uint32_t insn) {
    if ((insn & 0xFF000000u) != 0xD1000000u) return 0;   /* SUB (immediate) 64 */
    if (((insn >> 22) & 0x3u) > 1u) return 0;            /* no / lsl #12 shift */
    return (insn & 0x1Fu) == 31u && ((insn >> 5) & 0x1Fu) == 31u; /* sp, sp, #imm */
}

/* Instruction that can only end a function (or be padding between two). */
static inline int lr_is_terminator(uint32_t insn) {
    if (insn == 0x00000000u) return 1;                    /* zero padding */
    if (insn == 0xD503201Fu) return 1;                    /* nop padding */
    if (insn == LR_PACIBSP)  return 1;                    /* next fn's own entry */
    if ((insn & 0xFFFFFC1Fu) == 0xD65F0000u) return 1;    /* ret [Xn] */
    if ((insn & 0xFFFFFC1Fu) == 0xD61F0000u) return 1;    /* br Xn */
    if ((insn & 0xFC000000u) == 0x14000000u) return 1;    /* b (tail call) */
    if ((insn & 0xFFE0001Fu) == 0xD4200000u) return 1;    /* brk #imm */
    return 0;
}

/* ------------------------------------------------------------------ */
/* Windowed reads (keep syscall count sane, stay inside sections)      */
/* ------------------------------------------------------------------ */

typedef struct {
    const lr_image_t* img;
    const lr_section_t* sec;
    uintptr_t base;
    size_t    len;
} lr_window_t;

static inline const lr_section_t* lr_section_for(const lr_image_t* img, uintptr_t addr, int want_code) {
    if (!img) return NULL;
    for (int i = 0; i < img->n_sections; i++) {
        const lr_section_t* s = &img->sections[i];
        if (want_code >= 0 && s->is_code != want_code) continue;
        if (addr >= s->vmaddr && addr < s->vmaddr + s->size) return s;
    }
    return NULL;
}

static inline void lr_window_init(lr_window_t* w, const lr_image_t* img) {
    w->img = img;
    w->sec = NULL;
    w->base = 0;
    w->len = 0;
}

static inline int lr_window_u32(lr_window_t* w, uintptr_t addr, uint32_t* out) {
    if (!w->img->scratch || w->img->scratch_len < 0x1000) {
        return lr_u32_direct(w->img, addr, out);
    }
    if (addr < w->base || addr + 4 > w->base + w->len) {
        /* reload: page-aligned, never crossing the section that holds addr */
        const lr_section_t* sec = lr_section_for(w->img, addr, -1);
        if (!sec) return 0;
        uintptr_t base = addr & ~(uintptr_t)0xFFF;
        if (base < sec->vmaddr) base = sec->vmaddr;
        size_t want = w->img->scratch_len & ~(size_t)0xFFF;
        uintptr_t sec_end = sec->vmaddr + sec->size;
        if (base + want > sec_end) want = (size_t)(sec_end - base);
        if (want < 4) return 0;
        if (!lr_read(w->img, base, w->img->scratch, want)) return 0;
        w->sec  = sec;
        w->base = base;
        w->len  = want;
    }
    memcpy(out, w->img->scratch + (addr - w->base), 4);
    return 1;
}

/* ------------------------------------------------------------------ */
/* Step 1: locate the anchor string                                    */
/* ------------------------------------------------------------------ */

/* Collect every occurrence of needle (followed by NUL, so "stack overflow"
 * does not match inside "C stack overflow"... which is itself a full string —
 * both are valid anchors, and disambiguation happens by xref count instead). */
static inline int lr_find_cstr_all(const lr_image_t* img, const char* needle,
                                   uintptr_t* out, int max_out) {
    if (!img || !needle || !out || max_out <= 0) return 0;
    size_t nlen = strlen(needle);
    if (!nlen) return 0;
    size_t need = nlen + 1;
    uint8_t* buf = img->scratch;
    size_t cap = img->scratch_len;
    if (!buf || cap < need + 0x1000) return 0;

    int found = 0;
    for (int s = 0; s < img->n_sections && found < max_out; s++) {
        const lr_section_t* sec = &img->sections[s];
        if (sec->is_code) continue;
        uintptr_t pos = sec->vmaddr;
        uintptr_t end = sec->vmaddr + sec->size;
        while (pos < end && found < max_out) {
            size_t want = cap;
            if (pos + want > end) want = (size_t)(end - pos);
            if (want < need) break;
            if (!lr_read(img, pos, buf, want)) break;
            for (size_t i = 0; i + need <= want && found < max_out; i++) {
                if (buf[i] == (uint8_t)needle[0] &&
                    memcmp(buf + i, needle, nlen) == 0 && buf[i + nlen] == 0) {
                    out[found++] = pos + i;
                }
            }
            if (want <= nlen) break;
            pos += want - nlen; /* overlap the tail so strings on a chunk seam still match */
        }
    }
    return found;
}

/* ------------------------------------------------------------------ */
/* Step 2: xrefs to that string                                        */
/* ------------------------------------------------------------------ */

typedef struct {
    uintptr_t adrp_addr;
    uintptr_t completion;  /* address the ADD/LDR resolved to (0 if page-only) */
    int       exact;
} lr_xref_t;

/* Does the ADRP at insn_addr materialise `target` nearby?
 *
 * The completion is not always in-place and not always the next instruction:
 * clang emits `adrp x8, page` / `add x1, x8, #off` just as often as the
 * in-place form, and a string addressed through a data slot shows up as
 * `adrp x8, page` / `ldr x1, [x8, #off]` where the slot holds the pointer.
 * The window is 12 instructions forward — enough for argument setup between
 * the pair, short enough to stay inside the same basic block in practice. */
static inline int lr_xref_completes(const lr_image_t* img, uintptr_t insn_addr,
                                    uint32_t adrp_insn, uintptr_t page,
                                    uintptr_t target, uintptr_t* completion) {
    uint32_t rd = 0;
    int64_t  imm = 0;
    if (!lr_decode_adrp(adrp_insn, &rd, &imm)) return 0;
    uint32_t v = 0;
    for (int k = 1; k <= 12; k++) {
        uintptr_t at = insn_addr + (uintptr_t)k * 4;
        if (!lr_u32_direct(img, at, &v)) break;
        uint32_t drd = 0, rn = 0, off = 0;
        if (lr_decode_add_imm(v, &drd, &rn, &off)) {
            if (rn == rd) {
                uintptr_t val = page + off;
                if (val == target) { if (completion) *completion = val; return 1; }
            }
            continue;
        }
        if (lr_decode_ldr_uoff(v, &drd, &rn, &off)) {
            if (rn == rd) {
                uintptr_t slot = page + off;
                uint64_t stored = 0;
                if (!lr_read(img, slot, &stored, sizeof(stored))) continue;
                /* arm64e: const data may carry chained-fixup metadata / PAC */
                if ((stored & 0xFFFFFFFFFULL) == (target & 0xFFFFFFFFFULL)) {
                    if (completion) *completion = slot;
                    return 1;
                }
            }
            continue;
        }
        /* an unrelated write to the ADRP register ends the search */
        uint32_t wd = 0;
        if (lr_decode_adrp(v, &wd, &imm) && wd == rd) break;
    }
    return 0;
}

/* Split results: confirmed materialisations in exact_out, same-page ADRPs that
 * never completed in page_out. The whole code range is always scanned, so a
 * late confirmation is never dropped because earlier page matches filled a
 * buffer. */
static inline int lr_find_xrefs(const lr_image_t* img, uintptr_t target,
                                lr_xref_t* exact_out, int max_exact,
                                lr_xref_t* page_out, int max_page,
                                int* n_page_total) {
    if (n_page_total) *n_page_total = 0;
    if (!img) return 0;
    uintptr_t target_page = target & ~(uintptr_t)0xFFF;
    int n_exact = 0, n_page = 0;
    lr_window_t w;
    lr_window_init(&w, img);
    uint32_t insn = 0;
    for (int s = 0; s < img->n_sections; s++) {
        const lr_section_t* sec = &img->sections[s];
        if (!sec->is_code) continue;
        w.base = 0; w.len = 0;
        for (uintptr_t a = sec->vmaddr; a + 4 <= sec->vmaddr + sec->size; a += 4) {
            if (!lr_window_u32(&w, a, &insn)) break;
            uint32_t rd = 0;
            int64_t  imm = 0;
            if (!lr_decode_adrp(insn, &rd, &imm)) continue;
            uintptr_t page = (a & ~(uintptr_t)0xFFF) + (uintptr_t)imm;
            if (page != target_page) continue;
            uintptr_t completion = 0;
            if (lr_xref_completes(img, a, insn, page, target, &completion)) {
                if (exact_out && n_exact < max_exact) {
                    exact_out[n_exact].adrp_addr  = a;
                    exact_out[n_exact].completion = completion;
                    exact_out[n_exact].exact      = 1;
                }
                n_exact++;
            } else {
                if (page_out && n_page < max_page) {
                    page_out[n_page].adrp_addr  = a;
                    page_out[n_page].completion = 0;
                    page_out[n_page].exact      = 0;
                }
                n_page++;
            }
        }
    }
    if (n_page_total) *n_page_total = n_page;
    return n_exact < max_exact ? n_exact : max_exact;
}

/* ------------------------------------------------------------------ */
/* Step 3: walk back to the function entry                             */
/* ------------------------------------------------------------------ */

/* Is `entry` a real function entry? True when the instructions just before it
 * are a terminator or padding — i.e. the previous function ended there. This
 * is what keeps the walk-back from stepping over a function that happens to
 * set up its frame without the x29/x30 pair (measured on 0.739: several Luau
 * functions do, which silently produced wrong functions before this check). */
static inline int lr_is_entry_boundary(const lr_image_t* img, uintptr_t entry) {
    const lr_section_t* sec = lr_section_for(img, entry - 4, 1);
    if (entry == 0 || !sec || entry - 4 < sec->vmaddr) return 1; /* start of code */
    lr_window_t w;
    lr_window_init(&w, img);
    uint32_t v = 0;
    for (int k = 1; k <= 8; k++) {          /* allow a short padding run */
        uintptr_t at = entry - (uintptr_t)k * 4;
        if (!lr_window_u32(&w, at, &v)) return 1;
        if (lr_is_terminator(v)) return 1;
        if (lr_is_frame_push(v) || lr_is_prologue(v) || lr_is_stack_alloc(v))
            return 0;                        /* we are inside another function */
        if (k >= 2) return 0;                /* real code: not a boundary */
    }
    return 0;
}

/* Walk back from an xref to its function entry. Returns the first candidate
 * with a proven boundary; if none qualifies, the nearest candidate is returned
 * and the caller can see it via lr_result_t.boundary_proven == 0. */
static inline int lr_function_start_internal(const lr_image_t* img, uintptr_t from,
                                             uintptr_t* out, int* proven) {
    if (proven) *proven = 0;
    if (!img || !out) return 0;
    const lr_section_t* sec = lr_section_for(img, from, 1);
    if (!sec) return 0;
    uintptr_t limit = 0x10000;
    if (from - sec->vmaddr < limit) limit = from - sec->vmaddr;
    lr_window_t w;
    lr_window_init(&w, img);
    uint32_t insn = 0;
    uintptr_t nearest = 0;
    for (uintptr_t back = 0; back <= limit; back += 4) {
        uintptr_t at = from - back;
        if (!lr_window_u32(&w, at, &insn)) break;
        if (!lr_is_frame_push(insn) && !lr_is_stack_alloc(insn) && insn != LR_PACIBSP)
            continue;
        uintptr_t cand = at;
        if (insn != LR_PACIBSP && at >= 4) {
            uint32_t prev = 0;
            if (lr_window_u32(&w, at - 4, &prev) && prev == LR_PACIBSP) cand = at - 4;
        }
        if (!nearest) nearest = cand;
        if (lr_is_entry_boundary(img, cand)) {
            *out = cand;
            if (proven) *proven = 1;
            return 1;
        }
    }
    if (nearest) { *out = nearest; return 1; }
    return 0;
}

static inline int lr_function_start(const lr_image_t* img, uintptr_t from,
                                    uintptr_t* out) {
    int proven = 0;
    return lr_function_start_internal(img, from, out, &proven);
}

/* ------------------------------------------------------------------ */
/* Resolution entry points                                             */
/* ------------------------------------------------------------------ */

static inline int lr_resolve_anchor(const lr_image_t* img, const char* anchor,
                                    lr_result_t* out) {
    if (!img || !out || !anchor) return LR_ERR_NO_IMAGE;
    memset(out, 0, sizeof(*out));

    uintptr_t occ[24];
    int nocc = lr_find_cstr_all(img, anchor, occ, 24);
    if (!nocc) return LR_ERR_NO_STRING;

    /* Pick the copy the code actually materialises: most confirmations wins.
     *
     * Page-only matches must NOT be treated as evidence: on this build the
     * hot .cstring pages carry thousands of ADRPs, and ranking by them made
     * unrelated functions collide (lua_resume and luaG_runerror resolved to
     * the same address). They are still counted, because the report should
     * say how much noise the page contains. */
    int best_occ = -1, best_score = -1, best_exact = 0, best_page = 0;
    lr_xref_t ex[64], pg[4];
    for (int i = 0; i < nocc; i++) {
        int n_page_total = 0;
        int ne = lr_find_xrefs(img, occ[i], ex, 64, pg, 4, &n_page_total);
        if (!ne) continue;
        int score = ne * 64 + (n_page_total > 8 ? 8 : n_page_total);
        if (score > best_score) {
            best_score = score;
            best_occ   = i;
            best_exact = ne;
            best_page  = n_page_total;
        }
    }
    if (best_occ < 0) return LR_ERR_NO_XREF;

    out->anchor_addr = occ[best_occ];
    out->occurrences = nocc;
    out->xrefs       = best_exact;
    out->page_only   = best_page;
    out->method      = LR_METHOD_ANCHOR;

    /* Group the confirmed xrefs by the function they live in and take the
     * function with the most references: the raiser of an error string
     * usually mentions it more than once (one site per branch), while a
     * passing-through caller holds a single copy. */
    {
        int n_page_total = 0;
        int ne = lr_find_xrefs(img, occ[best_occ], ex, 64, pg, 4, &n_page_total);
        uintptr_t fn_of[64];
        int cnt_of[64], proven_of[64];
        uintptr_t first_of[64];
        int nfn = 0;
        for (int k = 0; k < ne; k++) {
            uintptr_t fn = 0;
            int proven = 0;
            if (!lr_function_start_internal(img, ex[k].adrp_addr, &fn, &proven)) continue;
            int at = -1;
            for (int q = 0; q < nfn; q++) if (fn_of[q] == fn) { at = q; break; }
            if (at < 0) {
                fn_of[nfn] = fn;
                cnt_of[nfn] = 0;
                proven_of[nfn] = proven;
                first_of[nfn] = ex[k].adrp_addr;
                at = nfn++;
            }
            cnt_of[at]++;
            if (proven) proven_of[at] = 1;
        }
        out->distinct_fn = nfn;
        int best_fn = -1;
        for (int q = 0; q < nfn; q++) {
            if (best_fn < 0) { best_fn = q; continue; }
            /* a proven entry beats an unproven one; then more references win */
            if (proven_of[q] != proven_of[best_fn]) {
                if (proven_of[q]) best_fn = q;
                continue;
            }
            if (cnt_of[q] > cnt_of[best_fn]) best_fn = q;
        }
        if (best_fn < 0) return LR_ERR_NO_PROLOGUE;
        out->xref_addr      = first_of[best_fn];
        out->boundary_proven = proven_of[best_fn];
        out->fn             = fn_of[best_fn];
        if (!lr_section_for(img, out->fn, 1)) return LR_ERR_NO_PROLOGUE;
    }
    if (!out->xref_addr) return LR_ERR_NO_XREF;

    lr_window_t w;
    lr_window_init(&w, img);
    for (int k = 0; k < 4; k++) {
        uint32_t v = 0;
        if (!lr_window_u32(&w, out->fn + (uintptr_t)k * 4, &v)) break;
        out->prefix[k] = v;
    }
    return LR_OK;
}

/* Raw 16-byte prologue match. Kept as a fallback for functions with no stable
 * string anchor; stale patterns are NOT wired into the symbol table on
 * purpose — a wrong prologue pattern is exactly the failure this file exists
 * to remove. */
static inline int lr_scan_pattern(const lr_image_t* img, const uint8_t* pattern,
                                  size_t pattern_len, lr_result_t* out,
                                  int* hits_out, int max_hits) {
    if (!img || !pattern || !pattern_len || !out) return LR_ERR_NO_IMAGE;
    memset(out, 0, sizeof(*out));
    int hits = 0;
    uintptr_t first = 0;
    for (int s = 0; s < img->n_sections; s++) {
        const lr_section_t* sec = &img->sections[s];
        if (!sec->is_code) continue;
        uintptr_t end = sec->vmaddr + sec->size;
        for (uintptr_t a = sec->vmaddr; a + pattern_len <= end; a += 4) {
            uint8_t buf[32];
            if (pattern_len > sizeof(buf)) return LR_ERR_NO_PATTERN;
            if (!lr_read(img, a, buf, pattern_len)) break;
            if (memcmp(buf, pattern, pattern_len) != 0) continue;
            if (!hits) first = a;
            if (++hits >= max_hits) break;
        }
        if (hits >= max_hits) break;
    }
    if (hits_out) *hits_out = hits;
    if (!hits) return LR_ERR_NO_PATTERN;
    out->fn          = first;
    out->method      = LR_METHOD_PATTERN;
    out->occurrences = hits;  /* >1 means the pattern is ambiguous */
    return LR_OK;
}

/* Every BL/B in the image that targets fn, each mapped back to its caller's
 * entry. Used to derive functions that have no string anchor of their own
 * (e.g. lua_newthread, called from the coroutine.create wrapper). */
static inline int lr_find_callers(const lr_image_t* img, uintptr_t fn,
                                  uintptr_t* callers, uintptr_t* sites, int max_out) {
    if (!img || !fn || !max_out) return 0;
    int found = 0;
    lr_window_t w;
    lr_window_init(&w, img);
    uint32_t insn = 0;
    for (int s = 0; s < img->n_sections && found < max_out; s++) {
        const lr_section_t* sec = &img->sections[s];
        if (!sec->is_code) continue;
        w.base = 0; w.len = 0;
        for (uintptr_t a = sec->vmaddr; a + 4 <= sec->vmaddr + sec->size && found < max_out; a += 4) {
            if (!lr_window_u32(&w, a, &insn)) break;
            int64_t off = 0;
            if (!lr_decode_branch(insn, &off)) continue;
            if (a + (uintptr_t)off != fn) continue;
            uintptr_t start = 0;
            if (!lr_function_start(img, a, &start)) continue;
            int dup = 0;
            for (int q = 0; q < found; q++) if (callers[q] == start) { dup = 1; break; }
            if (dup) continue;
            callers[found] = start;
            sites[found]   = a;
            found++;
        }
    }
    return found;
}

/* ------------------------------------------------------------------ */
/* Symbol table                                                        */
/* ------------------------------------------------------------------ */

/* Anchors below are verified present in the live client strings (see the
 * __RESOLVE__ report / tools/resolver_selftest.py output). Empty anchor lists
 * are honest gaps: those symbols have no stable string of their own and must
 * be derived through lr_find_callers() from an anchored library function. */
static const lr_symbol_t lr_symbol_table[] = {
    { "lua_resume",     { "cannot resume %s coroutine",
                          "cannot resume non-suspended coroutine",
                          "too many results to resume", 0 }, 1 },
    { "luaD_growstack", { "stack overflow", "C stack overflow", 0 }, 0 },
    { "luaG_runerror",  { "attempt to index %s with '%s'",
                          "attempt to perform arithmetic (%s) on %s",
                          "attempt to concatenate %s with %s", 0 }, 0 },
    /* 0.739: the legacy "bad argument #%d to '%s'" text never materialises;
     * Roblox's arg-error family uses "invalid argument #%d (%s expected, got %s)"
     * (raised by luaL_error via luaL_argmsg / type-mismatch paths). */
    { "luaL_argerror",  { "invalid argument #%d (%s expected, got %s)",
                          "missing argument #%d (%s expected)", 0 }, 0 },
    /* 0.739: derived anchors. luau_load is the bytecode loader itself — both
     * version checks of undump live in it. lua_newthread's only stable
     * fingerprint is the LUA_TTHREAD (0x8) tag constant. */
    { "luau_load",      { "%s: bytecode version mismatch (expected [%d..%d], got %d)",
                          "%s: bytecode type version mismatch (expected [%d..%d], got %d)",
                          "%s: bytecode corrupted", 0 }, 1 },
    /* Derived, not anchored: lr_derive_newthread() walks the luaL_Reg table
     * (create pair + isyieldable slot arithmetic) and picks the BL target of
     * coroutine.create carrying the LUA_TTHREAD tag. 0.739-verified. */
    { "lua_newthread",  { 0 }, 1 },
    /* Derived via the lbaselib registration layout: pcall is the slot before
     * xpcall (lr_derive_pcall_from_xpcall). */
    { "lua_pcall",      { 0 }, 1 },
    /* Derived from the call graph: the caller of luau_load that the
     * loadstring wrapper also reaches (lr_derive_rawload). 0.739: 0x10140ce20
     * is the compile-and-load core, the wrapper sits at 0x10141a830. */
    { "rawload",        { 0 }, 1 },
    { "loadstring",     { "loadstring() is not available",
                          "loadstring() is not available in RobloxScript context.", 0 }, 1 },
    { "compile",        { 0 }, 1 },
};
#define LR_SYMBOL_COUNT ((int)(sizeof(lr_symbol_table) / sizeof(lr_symbol_table[0])))

static inline const lr_symbol_t* lr_symbol_by_name(const char* name) {
    for (int i = 0; i < LR_SYMBOL_COUNT; i++)
        if (strcmp(lr_symbol_table[i].name, name) == 0) return &lr_symbol_table[i];
    return NULL;
}

/* Does the function at fn contain a confirmed reference to `target`? */
static inline int lr_fn_contains_xref(const lr_image_t* img, uintptr_t fn,
                                      uintptr_t target) {
    lr_xref_t ex[64], pg[4];
    int n_page_total = 0;
    int ne = lr_find_xrefs(img, target, ex, 64, pg, 4, &n_page_total);
    for (int k = 0; k < ne; k++) {
        uintptr_t f = 0;
        if (lr_function_start(img, ex[k].adrp_addr, &f) && f == fn) return 1;
    }
    return 0;
}

/* ------------------------------------------------------------------ */
/* Derivation layer: symbols without string anchors                    */
/* ------------------------------------------------------------------ */

/* Strip-proof primitives. Everything below works from the two things link-
 * time data cannot hide: the {name, fn} luaL_Reg tables still sitting in
 * const data, and the call graph itself. All of it was validated against the
 * 0.739 client offline (tools/graph_probe.py prints the same evidence). */

#define LR_LUA_TTHREAD              0x6  /* raw LUA_TTHREAD                 */
#define LR_LUA_TTHREAD_COLLECTABLE  0xa  /* TTHREAD | bit5 (Luau collectable) */

typedef struct { uintptr_t name_addr; uintptr_t fn; uintptr_t slot_addr; } lr_reg_pair_t;

/* The whole region the caller's body occupies, bounded by a terminator or by
 * the next frame setup. Every materialisation scan needs this to stay inside
 * one function — walking a fixed window kept spilling into library neighbours. */
static inline uintptr_t lr_fn_end(const lr_image_t* img, uintptr_t fn);

/* All BL targets of fn (distinct), bounded by the function's real extent.
 * Scanning a fixed window instead pulled resume's movz constants into
 * create's fingerprint (0.739: that misderives lua_newthread). */
static inline int lr_fn_bl_targets(const lr_image_t* img, uintptr_t fn,
                                   uintptr_t* out, int max_out) {
    if (!img || !fn || !max_out) return 0;
    uintptr_t end = lr_fn_end(img, fn);
    const lr_section_t* sec = lr_section_for(img, fn, 1);
    if (!sec) return 0;
    uintptr_t sec_end = sec->vmaddr + sec->size;
    if (end > sec_end) end = sec_end;
    lr_window_t w;
    lr_window_init(&w, img);
    uint32_t insn = 0;
    int n = 0;
    for (uintptr_t a = fn; a + 4 <= end && n < max_out; a += 4) {
        if (!lr_window_u32(&w, a, &insn)) break;
        if ((insn & 0xFC000000u) != 0x94000000u) continue;  /* BL only */
        int64_t off = 0;
        lr_decode_branch(insn, &off);
        uintptr_t t = a + (uintptr_t)off;
        if (!lr_section_for(img, t, 1)) continue;
        int dup = 0;
        for (int q = 0; q < n; q++) if (out[q] == t) { dup = 1; break; }
        if (!dup) out[n++] = t;
    }
    return n;
}

/* The whole region the caller's body occupies, bounded by a terminator or by
 * the next frame setup. Every materialisation scan needs this to stay inside
 * one function — walking a fixed window kept spilling into library neighbours. */
/* Plausible function ENTRY: PACIBSP, pre-index stp onto sp, or sub sp.
 * Used to confirm that a terminator really closes the body — internal early
 * rets and loop `b`s are followed by ordinary code, not a new prologue. */
static inline int lr_is_fn_entry(uint32_t insn) {
    if (insn == LR_PACIBSP) return 1;
    if (insn == 0x00000000u || insn == 0xD503201Fu) return 1;   /* padding    */
    /* stp Xt,Xt2,[sp,#-imm]!  (64-bit int, pre-index, sp base)              */
    if ((insn & 0xFFC00000u) == 0xA9800000u && ((insn >> 5) & 0x1Fu) == 0x1Fu) return 1;
    /* sub sp, sp, #imm */
    if ((insn & 0xFFC003FFu) == 0xD10003FFu) return 1;
    return 0;
}

static inline uintptr_t lr_fn_end(const lr_image_t* img, uintptr_t fn) {
    const lr_section_t* sec = lr_section_for(img, fn, 1);
    if (!sec) return fn;
    uintptr_t limit = fn + 0x20000;                      /* no Luau fn is bigger */
    uintptr_t end = (sec->vmaddr + sec->size < limit) ? sec->vmaddr + sec->size : limit;
    lr_window_t w;
    lr_window_init(&w, img);
    uint32_t insn = 0;
    /* A boundary is a terminator CONFIRMED by a function entry within the
     * next 8 instructions. First-ret stopping alone truncated bodies; a
     * next-insn-only check overextended them: out-of-line error tails
     * (adrp/add/bl luaL_error) sit between the last ret and the neighbour's
     * prologue, and the scan swallowed the neighbour's movz constants
     * (0.739: xmove's tail manufactured a false LUA_TTHREAD tag match). */
    for (uintptr_t a = fn + 4; a < end; a += 4) {
        if (!lr_window_u32(&w, a, &insn)) break;
        if (!lr_is_terminator(insn)) continue;
        for (int k = 1; k <= 8; k++) {
            uint32_t nxt = 0;
            if (!lr_window_u32(&w, a + 4 * (uintptr_t)k, &nxt)) return end;
            if (lr_is_fn_entry(nxt)) return a + 4 * (uintptr_t)k;
        }
    }
    return end;
}

/* MOVZ w?, #imm (32-bit form; the compiler emits no 64-bit form for tag constants). */
static inline int lr_is_movz_imm(uint32_t insn, uint32_t* imm) {
    if ((insn & 0x7F800000u) != 0x52800000u) return 0;
    if (imm) *imm = (insn >> 5) & 0xFFFF;
    return 1;
}

/* luaE_newthread fingerprint: the collectable LUA_TTHREAD tag materialised
 * as MOVZ in the body. 0.739 disassembly of the real callee (0x10294d4c8):
 *   bl <allocator>  ->  mov w9, #0xa ; str w9, [x8, #0xc]   (tag = TTHREAD(6)|bit5)
 * The raw tag 8 seen at create's first BL site is the wasm-style factory
 * 0x102952e6c parameter — a red herring (29 of 35 callers pass #7). Scans are
 * bounded by lr_fn_end so windows never leak into the next function. */
static inline uintptr_t lr_derive_newthread_from(const lr_image_t* img, uintptr_t create_fn) {
    uintptr_t targets[16];
    int nt = lr_fn_bl_targets(img, create_fn, targets, 16);
    uintptr_t hit = 0;
    for (int k = 0; k < nt; k++) {
        if (targets[k] == create_fn) continue;
        uintptr_t end = lr_fn_end(img, targets[k]);
        lr_window_t w;
        lr_window_init(&w, img);
        uint32_t insn = 0;
        for (uintptr_t a = targets[k]; a < end; a += 4) {
            uint32_t imm = 0;
            if (!lr_window_u32(&w, a, &insn)) break;
            if (lr_is_movz_imm(insn, &imm) &&
                (imm == LR_LUA_TTHREAD || imm == LR_LUA_TTHREAD_COLLECTABLE)) {
                if (hit && hit != targets[k]) return 0;   /* ambiguous */
                hit = targets[k];
                break;
            }
        }
    }
    return hit;
}

/* Coroutine library registration cross-check: pairs of {char* name, fn} in
 * const data (the luaL_Reg arrays survive stripping). When the pair named
 * "isyieldable" is found, create sits 5 slots earlier (upstream order:
 * create, running, status, wrap, yield, isyieldable) — in 0.739 both copies
 * of the array agree on this arithmetic. */
static inline int lr_find_reg_pairs(const lr_image_t* img, const char* name,
                                    lr_reg_pair_t* out, int max_out) {
    if (!img || !name || !max_out) return 0;
    uintptr_t occ[8];
    int nocc = lr_find_cstr_all(img, name, occ, 8);
    if (!nocc) return 0;
    int n = 0;
    /* Bulk-read each data section once and scan it in memory. On the live
     * image lr_read is a mach trap (~1µs); per-8-byte reads over tens of MB
     * turned this loop into minutes. With a section-sized buffer the scan is
     * pure memory traffic. The scratch buffer must hold a whole section;
     * fall back to the old path when it is too small. */
    size_t maxsec = 0;
    for (int s = 0; s < img->n_sections; s++) {
        const lr_section_t* sec = &img->sections[s];
        if (!sec->is_code && sec->size > maxsec && sec->size <= (256u << 20))
            maxsec = sec->size;
    }
    uint8_t* bulk = NULL;
    if (maxsec) bulk = (uint8_t*)malloc(maxsec + 64);
    for (int s = 0; s < img->n_sections && n < max_out; s++) {
        const lr_section_t* sec = &img->sections[s];
        if (sec->is_code) continue;
        if (sec->size < 16 || sec->size > (256u << 20)) continue;
        if (bulk && lr_read(img, sec->vmaddr, bulk, sec->size)) {
            const uintptr_t base = sec->vmaddr;
            for (uintptr_t off = 0; off + 16 <= sec->size && n < max_out; off += 8) {
                uint64_t a, b;
                memcpy(&a, bulk + off, 8);
                memcpy(&b, bulk + off + 8, 8);
                if (!lr_section_for(img, (uintptr_t)b, 1)) continue;          /* fn in code */
                if (lr_section_for(img, (uintptr_t)a, 1)) continue;           /* name not code */
                int named = 0;
                for (int q = 0; q < nocc; q++)
                    if ((a & 0xFFFFFFFFULL) == (occ[q] & 0xFFFFFFFFULL)) { named = 1; break; }
                if (!named) continue;                                         /* both lib copies match */
                int dup = 0;
                for (int q = 0; q < n; q++) if (out[q].fn == (uintptr_t)b) { dup = 1; break; }
                if (dup) continue;
                out[n].name_addr = (uintptr_t)a;
                out[n].fn        = (uintptr_t)b;
                out[n].slot_addr = base + off;
                n++;
            }
            continue;
        }
        /* fallback: per-slot reads (slow path, offline / small sections) */
        for (uintptr_t base = sec->vmaddr; base + 16 <= sec->vmaddr + sec->size; base += 8) {
            for (int k = 0; k < 32 && n < max_out; k++) {
                uintptr_t slot = base + (uintptr_t)k * 16;
                if (slot + 16 > sec->vmaddr + sec->size) break;
                uint64_t a = 0, b = 0;
                if (!lr_read(img, slot, &a, 8) || !lr_read(img, slot + 8, &b, 8)) break;
                if (!lr_section_for(img, (uintptr_t)b, 1)) continue;          /* fn in code */
                if (lr_section_for(img, (uintptr_t)a, 1)) continue;           /* name not code */
                int named = 0;
                for (int q = 0; q < nocc; q++)
                    if ((a & 0xFFFFFFFFULL) == (occ[q] & 0xFFFFFFFFULL)) { named = 1; break; }
                if (!named) continue;                                         /* both lib copies match */
                int dup = 0;
                for (int q = 0; q < n; q++) if (out[q].fn == (uintptr_t)b) { dup = 1; break; }
                if (dup) continue;
                out[n].name_addr = (uintptr_t)a;
                out[n].fn        = (uintptr_t)b;
                out[n].slot_addr = slot;
                n++;
            }
        }
    }
    free(bulk);
    return n;
}

/* lua_newthread: three independent gates must agree, none uses a stale
 * address:
 *   1. the "isyieldable" luaL_Reg name is a unique cstring; both array copies
 *      register it, and slot arithmetic (upstream lcorolib order: create,
 *      running, status, wrap, yield, isyieldable) re-derives the SAME create
 *      from both copies — isyieldable[-5].fn == create;
 *   2. at least one {"create", fn} pair in const data confirms that fn;
 *   3. among create's BL targets exactly one non-self function carries the
 *      LUA_TTHREAD tag as a MOVZ constant — that callee is luaE_newthread.
 * (Primary gate is isyieldable, not "create": the bare name collides with
 * unrelated {name, fn} tables elsewhere in Roblox const data.) */
typedef struct { uintptr_t fn; int via_bl; int slot_copies; int create_pairs; } lr_newthread_result_t;

static inline int lr_derive_newthread(const lr_image_t* img, lr_newthread_result_t* out) {
    if (!img || !out) return LR_ERR_NO_IMAGE;
    memset(out, 0, sizeof(*out));

    /* gate 1: both isyieldable slots must agree on create */
    lr_reg_pair_t iy[8];
    int niy = lr_find_reg_pairs(img, "isyieldable", iy, 8);
    if (!niy) return LR_ERR_NO_STRING;
    uintptr_t create_fn = 0;
    for (int k = 0; k < niy; k++) {
        uint64_t nm = 0, f = 0;
        if (!lr_read(img, iy[k].slot_addr - 5 * 16, &nm, 8)) continue;
        if (!lr_read(img, iy[k].slot_addr - 5 * 16 + 8, &f, 8)) continue;
        if (!create_fn) create_fn = (uintptr_t)f;
        else if ((uintptr_t)f != create_fn) return LR_ERR_NO_PATTERN;
    }
    if (!create_fn) return LR_ERR_NO_XREF;
    out->slot_copies = niy;

    /* gate 2: a {"create", fn} pair corroborates the slot arithmetic */
    lr_reg_pair_t cr[8];
    int ncr = lr_find_reg_pairs(img, "create", cr, 8);
    for (int k = 0; k < ncr; k++)
        if (cr[k].fn == create_fn) out->create_pairs++;
    if (!out->create_pairs) return LR_ERR_NO_PATTERN;

    /* gate 3: the tagged callee */
    out->fn     = lr_derive_newthread_from(img, create_fn);
    out->via_bl = out->fn != 0;
    if (!out->via_bl) return LR_ERR_NO_PATTERN;
    return LR_OK;
}

/* lua_resume vs lua_close: both carry "cannot resume %s coroutine"-family
 * strings in 0.735-era reasoning, but close carries "cannot close %s coroutine"
 * and resume owns the nres write. In 0.739 both strings materialise in ONE
 * region (be9c..c2c0) — the resume entry is the one that BLs a stack-alloc
 * prologue callee (rawrunprotected shape: sub sp, sp, #imm as first insn). */
static inline int lr_resume_looks_public(const lr_image_t* img, uintptr_t fn) {
    uintptr_t targets[24];
    int nt = lr_fn_bl_targets(img, fn, targets, 24);
    for (int k = 0; k < nt; k++) {
        uint32_t first = 0;
        if (!lr_u32_direct(img, targets[k], &first)) continue;
        if (lr_is_stack_alloc(first)) return 1;
    }
    return 0;
}

/* lua_pcall: no stable string of its own, and in 0.739 the lbaselib
 * registration is CODE-based (no {"xpcall", fn} pointer slots exist in const
 * data — verified). The registering function is the unique raiser of the
 * unique "xpcall" cstring; it materialises the "pcall" cstring too, and each
 * setfield sequence loads its lua_CFunction with adrp+add right around the
 * name setup. Gates: both names materialise in one function; each name site
 * has a code-pointer completion within 24 insns; the two luaB_* functions are
 * .text-adjacent (they compile next to each other). */
static inline uintptr_t lr_find_completion_site(const lr_image_t* img, uintptr_t fn,
                                                uintptr_t fn_end, uintptr_t target,
                                                uintptr_t* site_out) {
    lr_window_t w;
    lr_window_init(&w, img);
    uint32_t insn = 0;
    for (uintptr_t a = fn; a + 8 <= fn_end; a += 4) {
        if (!lr_window_u32(&w, a, &insn)) break;
        uint32_t rd = 0;
        int64_t  imm = 0;
        if (!lr_decode_adrp(insn, &rd, &imm)) continue;
        uintptr_t page = (a & ~(uintptr_t)0xFFF) + (uintptr_t)imm;
        for (int k = 1; k <= 4 && a + (k + 1) * 4 <= fn_end; k++) {
            uint32_t v2 = 0;
            if (!lr_u32_direct(img, a + k * 4, &v2)) break;
            uint32_t d = 0, r = 0, off = 0;
            if (lr_decode_add_imm(v2, &d, &r, &off) && r == rd) {
                if (page + off == target) { if (site_out) *site_out = a; return 1; }
                break;
            }
        }
    }
    return 0;
}

/* A code-pointer (adrp+add completing into __TEXT) materialised within maxlook
 * insns around `site` — forward first, then backward: compiler order between
 * the function-pointer load and the name load varies. */
static inline uintptr_t lr_code_ptr_near(const lr_image_t* img, uintptr_t site, int maxlook) {
    for (int dir = 0; dir < 2; dir++) {
        for (int k = 1; k <= maxlook; k++) {
            uintptr_t a = dir == 0 ? site + (uintptr_t)k * 4
                                   : site - (uintptr_t)k * 4;
            uint32_t insn = 0;
            if (!lr_u32_direct(img, a, &insn)) break;
            uint32_t rd = 0;
            int64_t  imm = 0;
            if (!lr_decode_adrp(insn, &rd, &imm)) continue;
            uintptr_t page = (a & ~(uintptr_t)0xFFF) + (uintptr_t)imm;
            for (int j = 1; j <= 4; j++) {
                uint32_t v2 = 0;
                if (!lr_u32_direct(img, a + j * 4, &v2)) break;
                uint32_t d = 0, r = 0, off = 0;
                if (lr_decode_add_imm(v2, &d, &r, &off) && r == rd) {
                    uintptr_t val = page + off;
                    if (lr_section_for(img, val, 1)) return val;
                    break;
                }
            }
        }
    }
    return 0;
}

static inline int lr_derive_pcall(const lr_image_t* img, uintptr_t* pcall_out,
                                  uintptr_t* xpcall_out) {
    if (!img) return LR_ERR_NO_IMAGE;
    lr_result_t tmp;
    if (lr_resolve_anchor(img, "xpcall", &tmp) != LR_OK) return LR_ERR_NO_STRING;
    uintptr_t reg_fn  = tmp.fn;
    uintptr_t reg_end = lr_fn_end(img, reg_fn);
    uintptr_t xpcall_str = tmp.anchor_addr;

    /* the "pcall" occurrence materialised in the same registration fn */
    uintptr_t occ[8];
    int nocc = lr_find_cstr_all(img, "pcall", occ, 8);
    uintptr_t pcall_str = 0;
    for (int k = 0; k < nocc; k++)
        if (lr_find_completion_site(img, reg_fn, reg_end, occ[k], NULL)) { pcall_str = occ[k]; break; }
    if (!pcall_str) return LR_ERR_NO_XREF;

    uintptr_t site_p = 0, site_x = 0;
    if (!lr_find_completion_site(img, reg_fn, reg_end, pcall_str, &site_p))  return LR_ERR_NO_XREF;
    if (!lr_find_completion_site(img, reg_fn, reg_end, xpcall_str, &site_x)) return LR_ERR_NO_XREF;
    uintptr_t fn_p = lr_code_ptr_near(img, site_p, 24);
    uintptr_t fn_x = lr_code_ptr_near(img, site_x, 24);
    if (!fn_p || !fn_x || fn_p == fn_x) return LR_ERR_NO_PATTERN;
    uintptr_t delta = fn_p > fn_x ? fn_p - fn_x : fn_x - fn_p;
    if (delta > 0x1000) return LR_ERR_NO_PATTERN;   /* not .text-adjacent */
    if (pcall_out)  *pcall_out  = fn_p;
    if (xpcall_out) *xpcall_out = fn_x;
    return LR_OK;
}

/* rawload: Roblox's (L, chunk, chunkname, env) wrapper around luau_load.
 * Fingerprint: a caller of luau_load that is ALSO reachable from the
 * loadstring wrapper (luaB_loadstring raises "loadstring() is not available"
 * upstream family strings; its fn calls the compile-and-load core). No 0.735
 * address involved. */
static inline uintptr_t lr_derive_rawload(const lr_image_t* img,
                                          uintptr_t luau_load_fn,
                                          uintptr_t loadstring_wrapper_fn) {
    if (!luau_load_fn) return 0;
    uintptr_t callers[64], sites[64];
    int nc = lr_find_callers(img, luau_load_fn, callers, sites, 64);
    if (!nc) return 0;
    if (!loadstring_wrapper_fn) {
        /* no loadstring wrapper to intersect with: single-caller heuristic is
         * too weak here, refuse honestly */
        return nc == 1 ? callers[0] : 0;
    }
    uintptr_t ls_targets[48];
    int nt = lr_fn_bl_targets(img, loadstring_wrapper_fn, ls_targets, 48);
    for (int k = 0; k < nc; k++) {
        for (int q = 0; q < nt; q++) {
            if (callers[k] != ls_targets[q]) continue;
            return callers[k];
        }
    }
    return 0;
}

/* compile: the compiler function called by loadstring right before rawload */
static inline uintptr_t lr_derive_compile(const lr_image_t* img,
                                          uintptr_t loadstring_wrapper_fn,
                                          uintptr_t rawload_fn) {
    if (!img || !loadstring_wrapper_fn || !rawload_fn) return 0;
    uintptr_t ls_targets[64];
    int nt = lr_fn_bl_targets(img, loadstring_wrapper_fn, ls_targets, 64);
    for (int q = 1; q < nt; q++) {
        if (ls_targets[q] == rawload_fn) {
            return ls_targets[q - 1];
        }
    }
    return 0;
}

/* lua_resume: disambiguate luaB_coresume vs lua_resume by status check at +0x20 */
static inline uintptr_t lr_derive_resume(const lr_image_t* img) {
    if (!img) return 0;
    uintptr_t occ[24];
    int nocc = lr_find_cstr_all(img, "cannot resume %s coroutine", occ, 24);
    if (!nocc) return 0;
    lr_xref_t ex[64], pg[4];
    int n_page_total = 0;
    int ne = lr_find_xrefs(img, occ[0], ex, 64, pg, 4, &n_page_total);
    if (!ne) return 0;
    for (int i = 0; i < ne; i++) {
        uintptr_t xref = ex[i].adrp_addr;
        lr_window_t w;
        lr_window_init(&w, img);
        for (uintptr_t back = 4; back <= 0x800; back += 4) {
            uintptr_t at = xref - back;
            uint32_t insn = 0;
            if (!lr_window_u32(&w, at, &insn)) break;
            if (lr_is_frame_push(insn) || lr_is_stack_alloc(insn)) {
                uint32_t check = 0;
                if (lr_window_u32(&w, at + 0x20, &check) && (check & 0xFFC003FF) == 0x39400C28) {
                    return at;
                }
            }
        }
    }
    return 0;
}


/* Cross-check: a function that raises one of a family of errors names the
 * other members of the family too (one site per branch). Requiring a second
 * anchor to land in the same function is what catches a walk-back that
 * stopped at a neighbouring function. */
static inline int lr_resolve_symbol(const lr_image_t* img, const lr_symbol_t* sym,
                                    lr_sym_result_t* out) {
    if (!sym || !out) return LR_ERR_NO_IMAGE;
    memset(out, 0, sizeof(*out));
    out->name     = sym->name;
    out->required = sym->required;
    if (!sym->anchors[0]) return out->status = LR_ERR_NO_ANCHOR;
    int last = LR_ERR_NO_STRING;
    for (int a = 0; sym->anchors[a]; a++) {
        int rc = lr_resolve_anchor(img, sym->anchors[a], &out->res);
        if (rc != LR_OK) { last = rc; continue; }
        out->anchor_used = sym->anchors[a];
        out->status = LR_OK;
        for (int b = 0; sym->anchors[b]; b++) {
            if (b == a) continue;
            lr_result_t tmp;
            if (lr_resolve_anchor(img, sym->anchors[b], &tmp) != LR_OK) continue;
            if (tmp.fn == out->res.fn) {
                /* an independent anchor of the same family reaches the same
                 * function — the strongest confirmation available offline */
                out->verified_extra++;
            } else if (lr_fn_contains_xref(img, out->res.fn, tmp.anchor_addr)) {
                out->verified_extra++;
            }
        }
        return out->status;
    }
    return out->status = last;
}

static inline int lr_resolve_all(const lr_image_t* img, lr_sym_result_t* out,
                                 int max_out, int* out_n) {
    int n = 0;
    for (int i = 0; i < LR_SYMBOL_COUNT && n < max_out; i++)
        lr_resolve_symbol(img, &lr_symbol_table[i], &out[n++]);
    if (out_n) *out_n = n;
    return n;
}

#ifdef __cplusplus
}
#endif

#endif /* LUAU_RESOLVER_H */

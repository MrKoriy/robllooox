/*
 * resolver_selftest.cpp — offline verification for luau_resolver.h.
 *
 * Runs the EXACT resolver code the dylib uses (same header, same decoder, same
 * prologue walk-back) against the RobloxPlayer file on disk, in link-time
 * address space. "RobloxPlayer + 0x…" in a FINDINGS note can then be checked
 * against this output directly.
 *
 *   build:  make resolvetest          (or: clang++ -std=c++17 -O2 tools/resolver_selftest.cpp)
 *
 * Exit status: 0 when every anchored symbol resolves to a plausible function
 * entry inside a code section; 1 otherwise. Symbols with no anchor of their
 * own are reported as GAP and do not fail the run — they are the known
 * remaining work, not a silent assumption.
 */

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

#include <mach-o/loader.h>
#include <mach-o/nlist.h>

#include "../luau_resolver.h"

#ifndef S_ATTR_PURE_INSTRUCTIONS
#define S_ATTR_PURE_INSTRUCTIONS 0x80000000u
#endif
#ifndef S_ATTR_SOME_INSTRUCTIONS
#define S_ATTR_SOME_INSTRUCTIONS 0x00000400u
#endif
#ifndef SECTION_TYPE
#define SECTION_TYPE 0x000000ffu
#endif

#define DEFAULT_BINARY "/Applications/Roblox.app/Contents/MacOS/RobloxPlayer"
#define MAX_SEC 128

typedef struct {
    const uint8_t* file;
    size_t         file_len;
    lr_section_t   sections[MAX_SEC];
    int            n_sections;
    uint8_t        uuid[16];
    uint32_t       cputype;
} host_t;

static host_t g_host;

/* ---- file-backed reader: address space == link-time vmaddr ---- */

/* The reader needs file offsets, which lr_section_t does not carry — keep a
 * parallel table on the host side, kept index-aligned with g_host.sections. */
typedef struct {
    uintptr_t vmaddr;
    uintptr_t size;
    uint64_t  offset;
} host_map_t;

static host_map_t g_map[MAX_SEC];

static int host_read_real(void* ctx, uintptr_t addr, void* dst, size_t len) {
    host_t* h = (host_t*)ctx;
    uint8_t* out = (uint8_t*)dst;
    size_t done = 0;
    while (done < len) {
        uintptr_t a = addr + done;
        int found = 0;
        for (int i = 0; i < h->n_sections; i++) {
            const host_map_t* m = &g_map[i];
            if (a < m->vmaddr || a >= m->vmaddr + m->size) continue;
            size_t avail = (size_t)(m->vmaddr + m->size - a);
            size_t take = len - done < avail ? len - done : avail;
            if (m->offset + (a - m->vmaddr) + take > h->file_len) return 0;
            memcpy(out + done, h->file + m->offset + (a - m->vmaddr), take);
            done += take;
            found = 1;
            break;
        }
        if (!found) return 0;
    }
    return 1;
}

/* ---- Mach-O parsing ---- */

static int parse_macho(const uint8_t* file, size_t len) {
    if (len < sizeof(struct mach_header_64)) return -1;
    const struct mach_header_64* mh = (const struct mach_header_64*)file;
    if (mh->magic != MH_MAGIC_64) {
        fprintf(stderr, "[-] not a thin little-endian 64-bit Mach-O (magic %#x)\n", mh->magic);
        return -1;
    }
    g_host.cputype = mh->cputype;

    const struct load_command* lc = (const struct load_command*)(mh + 1);
    for (uint32_t i = 0; i < mh->ncmds; i++) {
        if (lc->cmd == LC_SEGMENT_64) {
            const struct segment_command_64* seg = (const struct segment_command_64*)lc;
            const struct section_64* sects = (const struct section_64*)(seg + 1);
            for (uint32_t s = 0; s < seg->nsects; s++) {
                const struct section_64* sec = &sects[s];
                uint32_t type = sec->flags & SECTION_TYPE;
                if (type == S_ZEROFILL || type == S_THREAD_LOCAL_ZEROFILL) continue;
                if (!sec->size) continue;
                if (g_host.n_sections >= MAX_SEC) continue;
                int is_code = (sec->flags & (S_ATTR_PURE_INSTRUCTIONS | S_ATTR_SOME_INSTRUCTIONS)) != 0;
                char label[40];
                snprintf(label, sizeof(label), "%s,%s", seg->segname, sec->sectname);

                lr_section_t* d = &g_host.sections[g_host.n_sections];
                d->vmaddr  = sec->addr;
                d->size    = sec->size;
                d->is_code = is_code;
                d->label   = strdup(label);
                g_map[g_host.n_sections].vmaddr = sec->addr;
                g_map[g_host.n_sections].size   = sec->size;
                g_map[g_host.n_sections].offset = sec->offset;
                g_host.n_sections++;
            }
        } else if (lc->cmd == LC_UUID) {
            const struct uuid_command* uc = (const struct uuid_command*)lc;
            memcpy(g_host.uuid, uc->uuid, 16);
        }
        lc = (const struct load_command*)((const uint8_t*)lc + lc->cmdsize);
    }
    return g_host.n_sections ? 0 : -1;
}

/* ---- reporting ---- */

static const char* method_name(int m) {
    switch (m) {
        case LR_METHOD_ANCHOR:      return "anchor";
        case LR_METHOD_ANCHOR_PAGE: return "anchor(page-only)";
        case LR_METHOD_PATTERN:     return "pattern";
        default:                    return "-";
    }
}

typedef struct { const char* name; uintptr_t legacy; const char* note; } legacy_t;

/* Link-time constants the executor still carries from earlier builds. */
static const legacy_t g_legacy[] = {
    { "lua_resume",     0x102c48ab0ULL, "0.735" },
    { "lua_newthread",  0x102c529f0ULL, "0.735" },
    { "luau_load",      0x102c5b648ULL, "0.735" },
    { "rawload",        0x101533becULL, "0.735" },
    { "luaD_growstack", 0x100219bb0ULL, "0.732" },
    { "luaL_argerror",  0x10179d510ULL, "0.732" },
};

/* Diagnostic: which functions reference this anchor text, and where?
 * This is how anchor choices are validated against the real binary instead of
 * assumed. Usage: resolver_selftest --dump-anchor "cannot resume %s coroutine" */
static void dump_anchor(const lr_image_t* img, const char* text, int max) {
    uintptr_t occ[24];
    int nocc = lr_find_cstr_all(img, text, occ, 24);
    printf("-- anchor \"%s\": %d occurrence(s) --\n", text, nocc);
    for (int i = 0; i < nocc && i < max; i++) {
        lr_xref_t ex[64], pg[4];
        int n_page_total = 0;
        int ne = lr_find_xrefs(img, occ[i], ex, 64, pg, 4, &n_page_total);
        printf("  [%d] str @ %#lx  exact=%d page_only=%d\n",
               i, (unsigned long)occ[i], ne, n_page_total);
        for (int k = 0; k < ne; k++) {
            uintptr_t fn = 0;
            int proven = 0;
            lr_function_start_internal(img, ex[k].adrp_addr, &fn, &proven);
            printf("        xref @ %#lx -> fn %#lx%s\n",
                   (unsigned long)ex[k].adrp_addr, (unsigned long)fn,
                   proven ? " (proven)" : " (unproven)");
        }
    }
    printf("\n");
}

/* Diagnostic: list the direct BL targets inside one function. The game's own
 * coroutine library must call the real lua_resume, so this is how the public
 * entry gets identified instead of guessed. */
static void dump_callees(const lr_image_t* img, uintptr_t fn, size_t len) {
    printf("-- callees of %#lx (window %#zx) --\n", (unsigned long)fn, len);
    for (uintptr_t a = fn; a + 4 <= fn + len; a += 4) {
        uint32_t v = 0;
        if (!lr_u32_direct(img, a, &v)) break;
        int64_t off = 0;
        if (!lr_decode_branch(v, &off)) continue;
        uint32_t op = v & 0xFC000000u;
        printf("   %s @ %#lx -> %#lx\n",
               op == 0x94000000u ? "bl" : "b ",
               (unsigned long)a, (unsigned long)(a + (uintptr_t)off));
    }
}

/* Diagnostic: how does this build materialise a given string address?
 * Prints the next few instructions of every page-matching ADRP so the decoder
 * assumptions can be checked against real code instead of guessed. */
static void dump_xrefs(const lr_image_t* img, uintptr_t str_addr, int max) {
    static lr_xref_t ex[64], pg[64];
    int n_page_total = 0;
    int ne = lr_find_xrefs(img, str_addr, ex, 64, pg, 64, &n_page_total);
    printf("-- xref dump for string %#lx --\nexact=%d  page_only_total=%d\n",
           (unsigned long)str_addr, ne, n_page_total);
    for (int i = 0; i < ne && i < max; i++) {
        printf("[exact %2d] adrp @ %#lx  completes to %#lx\n",
               i, (unsigned long)ex[i].adrp_addr, (unsigned long)ex[i].completion);
        for (int k = 0; k < 4; k++) {
            uint32_t v = 0;
            if (!lr_u32_direct(img, ex[i].adrp_addr + (uintptr_t)k * 4, &v)) break;
            printf("            +%d: %08x\n", k * 4, v);
        }
    }
    for (int i = 0; i < n_page_total && i < max; i++) {
        printf("[page  %2d] adrp @ %#lx  (no completion)\n", i, (unsigned long)pg[i].adrp_addr);
        for (int k = 0; k < 6; k++) {
            uint32_t v = 0;
            if (!lr_u32_direct(img, pg[i].adrp_addr + (uintptr_t)k * 4, &v)) break;
            printf("            +%d: %08x\n", k * 4, v);
        }
    }
    printf("\n");
}

int main(int argc, char** argv) {
    const char* path = (argc > 1) ? argv[1] : DEFAULT_BINARY;
    if (argc > 2 && strcmp(argv[1], "--dump-anchor") == 0) {
        path = DEFAULT_BINARY;
        int max = (argc > 3) ? atoi(argv[3]) : 24;
        int fd = open(path, O_RDONLY);
        if (fd < 0) { perror("open"); return 2; }
        struct stat st;
        if (fstat(fd, &st) != 0) { perror("fstat"); return 2; }
        size_t flen = (size_t)st.st_size;
        void* base = mmap(NULL, flen, PROT_READ, MAP_PRIVATE, fd, 0);
        if (base == MAP_FAILED) { perror("mmap"); return 2; }
        g_host.file = (const uint8_t*)base;
        g_host.file_len = flen;
        if (parse_macho(g_host.file, flen) != 0) return 2;
        uint8_t* scratch = (uint8_t*)malloc(1 << 20);
        lr_image_t img;
        memset(&img, 0, sizeof(img));
        img.sections = g_host.sections;
        img.n_sections = g_host.n_sections;
        img.read = host_read_real;
        img.ctx = &g_host;
        img.scratch = scratch;
        img.scratch_len = 1 << 20;
        dump_anchor(&img, argv[2], max);
        return 0;
    }
    if (argc > 2 && strcmp(argv[1], "--dump-callees") == 0) {
        path = DEFAULT_BINARY;
        size_t len = (argc > 3) ? (size_t)strtoull(argv[3], NULL, 16) : 0x300;
        int fd = open(path, O_RDONLY);
        if (fd < 0) { perror("open"); return 2; }
        struct stat st;
        if (fstat(fd, &st) != 0) { perror("fstat"); return 2; }
        size_t flen = (size_t)st.st_size;
        void* base = mmap(NULL, flen, PROT_READ, MAP_PRIVATE, fd, 0);
        if (base == MAP_FAILED) { perror("mmap"); return 2; }
        g_host.file = (const uint8_t*)base;
        g_host.file_len = flen;
        if (parse_macho(g_host.file, flen) != 0) return 2;
        uint8_t* scratch = (uint8_t*)malloc(1 << 20);
        lr_image_t img;
        memset(&img, 0, sizeof(img));
        img.sections = g_host.sections;
        img.n_sections = g_host.n_sections;
        img.read = host_read_real;
        img.ctx = &g_host;
        img.scratch = scratch;
        img.scratch_len = 1 << 20;
        dump_callees(&img, (uintptr_t)strtoull(argv[2], NULL, 16), len);
        return 0;
    }
    if (argc > 3 && strcmp(argv[1], "--dump-xrefs") == 0) {
        /* --dump-xrefs <hexstringaddr> [max] */
        path = DEFAULT_BINARY;
        const char* hex = argv[2];
        int max = (argc > 3) ? atoi(argv[3]) : 3;
        int fd = open(path, O_RDONLY);
        if (fd < 0) { perror("open"); return 2; }
        struct stat st;
        if (fstat(fd, &st) != 0) { perror("fstat"); return 2; }
        size_t flen = (size_t)st.st_size;
        void* base = mmap(NULL, flen, PROT_READ, MAP_PRIVATE, fd, 0);
        if (base == MAP_FAILED) { perror("mmap"); return 2; }
        g_host.file = (const uint8_t*)base;
        g_host.file_len = flen;
        if (parse_macho(g_host.file, flen) != 0) return 2;
        uint8_t* scratch = (uint8_t*)malloc(1 << 20);
        lr_image_t img;
        memset(&img, 0, sizeof(img));
        img.sections = g_host.sections;
        img.n_sections = g_host.n_sections;
        img.read = host_read_real;
        img.ctx = &g_host;
        img.scratch = scratch;
        img.scratch_len = 1 << 20;
        dump_xrefs(&img, (uintptr_t)strtoull(hex, NULL, 16), max);
        return 0;
    }
    int fd = open(path, O_RDONLY);
    if (fd < 0) { perror("open"); return 2; }
    struct stat st;
    if (fstat(fd, &st) != 0) { perror("fstat"); return 2; }
    size_t flen = (size_t)st.st_size;
    void* base = mmap(NULL, flen, PROT_READ, MAP_PRIVATE, fd, 0);
    if (base == MAP_FAILED) { perror("mmap"); return 2; }

    printf("== luau_resolver self-test ==\nfile:   %s\nsize:   %zu bytes\ncputype: %u\n",
           path, flen, (unsigned)((const struct mach_header_64*)base)->cputype);

    g_host.file = (const uint8_t*)base;
    g_host.file_len = flen;
    if (parse_macho(g_host.file, flen) != 0) return 2;

    printf("uuid:   %02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x\n",
           g_host.uuid[0], g_host.uuid[1], g_host.uuid[2], g_host.uuid[3],
           g_host.uuid[4], g_host.uuid[5], g_host.uuid[6], g_host.uuid[7],
           g_host.uuid[8], g_host.uuid[9], g_host.uuid[10], g_host.uuid[11],
           g_host.uuid[12], g_host.uuid[13], g_host.uuid[14], g_host.uuid[15]);

    int n_code = 0, n_data = 0;
    for (int i = 0; i < g_host.n_sections; i++) (g_host.sections[i].is_code ? n_code : n_data)++;
    uintptr_t text_lo = 0, text_hi = 0;
    for (int i = 0; i < g_host.n_sections; i++) {
        const lr_section_t* s = &g_host.sections[i];
        if (!s->is_code) continue;
        if (!text_lo || s->vmaddr < text_lo) text_lo = s->vmaddr;
        if (s->vmaddr + s->size > text_hi) text_hi = s->vmaddr + s->size;
    }
    printf("sections: %d (code %d, data %d)  code range: %#lx - %#lx\n\n",
           g_host.n_sections, n_code, n_data,
           (unsigned long)text_lo, (unsigned long)text_hi);

    uint8_t* scratch = (uint8_t*)malloc(1 << 20);
    if (!scratch) { fprintf(stderr, "[-] oom\n"); return 2; }

    lr_image_t img;
    memset(&img, 0, sizeof(img));
    img.sections    = g_host.sections;
    img.n_sections  = g_host.n_sections;
    img.read        = host_read_real;
    img.ctx         = &g_host;
    img.scratch     = scratch;
    img.scratch_len = 1 << 20;

    lr_sym_result_t results[LR_SYMBOL_COUNT];
    int n = 0;
    lr_resolve_all(&img, results, LR_SYMBOL_COUNT, &n);

    int ok_anchored = 0, total_anchored = 0, hard_fail = 0, warn = 0, req_gaps = 0;
    char req_gap_names[256] = {0};

    printf("-- symbols --\n");
    for (int i = 0; i < n; i++) {
        const lr_sym_result_t* r = &results[i];
        const lr_symbol_t* sym = lr_symbol_by_name(r->name);
        int anchored = sym && sym->anchors[0] != NULL;
        if (anchored) total_anchored++;
        if (!anchored && sym && sym->required) {
            req_gaps++;
            if (strlen(req_gap_names) + strlen(r->name) + 3 < sizeof(req_gap_names)) {
                if (req_gap_names[0]) strcat(req_gap_names, ", ");
                strcat(req_gap_names, r->name);
            }
        }

        if (r->status == LR_OK && r->res.fn) {
            const lr_section_t* sec = lr_section_for(&img, r->res.fn, 1);
            printf("%-16s OK   fn=%#lx  in=%-14s method=%-8s occ=%d exact=%d page=%d fns=%d verified=%d%s\n",
                   r->name, (unsigned long)r->res.fn,
                   sec ? sec->label : "OUTSIDE CODE",
                   method_name(r->res.method),
                   r->res.occurrences, r->res.xrefs, r->res.page_only,
                   r->res.distinct_fn, r->verified_extra,
                   r->res.boundary_proven ? "" : " (entry unproven)");
            printf("%-16s      anchor=\"%s\" @ %#lx  xref @ %#lx%s\n", "",
                   r->anchor_used ? r->anchor_used : "?",
                   (unsigned long)r->res.anchor_addr,
                   (unsigned long)r->res.xref_addr,
                   r->res.distinct_fn > 1 ? "  [AMBIGUOUS]" : "");
            printf("%-16s      prefix: %08x %08x %08x %08x\n", "",
                   r->res.prefix[0], r->res.prefix[1], r->res.prefix[2], r->res.prefix[3]);

            for (size_t k = 0; k < sizeof(g_legacy) / sizeof(g_legacy[0]); k++) {
                if (strcmp(g_legacy[k].name, r->name) != 0) continue;
                long long delta = (long long)r->res.fn - (long long)g_legacy[k].legacy;
                printf("%-16s      old %s constant %#lx -> now %#lx (delta %+lld) %s\n", "",
                       g_legacy[k].note, (unsigned long)g_legacy[k].legacy,
                       (unsigned long)r->res.fn, delta,
                       r->res.fn == g_legacy[k].legacy ? "SAME" : "DRIFTED");
            }

            /* self-consistency: the entry must look like a function start */
            uint32_t first = r->res.prefix[0];
            if (!lr_is_frame_push(first) && !lr_is_stack_alloc(first) &&
                first != LR_PACIBSP) {
                printf("%-16s      WARN: entry bytes are not a frame setup\n", "");
            }
            /* a required symbol must survive the cross-anchor check when the
             * symbol actually has a second anchor materialised in this build */
            if (sym && sym->required && sym->anchors[1] && r->verified_extra == 0) {
                printf("%-16s      FAIL: no second anchor of this family lands in the\n"
                       "%-16s      resolved function — resolution is suspect\n", "", "");
                hard_fail++;
            }
            if (r->res.distinct_fn > 1 && sym && sym->required)
                printf("%-16s      NOTE: %d functions reference this anchor; picked the one\n"
                       "%-16s      with the most references — verify by disassembly\n", "", r->res.distinct_fn, "");
            if (anchored) ok_anchored++;
        } else {
            const char* why = "unresolved";
            switch (r->status) {
                case LR_ERR_NO_ANCHOR:  why = "no anchor text"; break;
                case LR_ERR_NO_STRING:  why = "anchor text absent from this build"; break;
                case LR_ERR_NO_XREF:    why = "anchor has no code xref (ADRP)"; break;
                case LR_ERR_NO_PROLOGUE:why = "walk-back found no prologue"; break;
                default: break;
            }
            if (anchored) {
                int req = sym && sym->required;
                if (req) hard_fail++;
                else      warn++;
                printf("%-16s %s (%s)\n", r->name, req ? "FAIL" : "WARN", why);
            } else {
                printf("%-16s GAP  (%s) — derive via lr_find_callers()\n", r->name, why);
            }
        }
    }

    /* call-graph helper evidence: who calls the resolved lua_resume? */
    for (int i = 0; i < n; i++) {
        if (strcmp(results[i].name, "lua_resume") != 0 || results[i].status != LR_OK) continue;
        uintptr_t callers[16], sites[16];
        int nc = lr_find_callers(&img, results[i].res.fn, callers, sites, 16);
        printf("\n-- lr_find_callers(lua_resume @ %#lx): %d site(s) --\n",
               (unsigned long)results[i].res.fn, nc);
        for (int k = 0; k < nc; k++)
            printf("   bl @ %#lx  in fn @ %#lx\n",
                   (unsigned long)sites[k], (unsigned long)callers[k]);
    }

    /* ---- derivation layer: symbols without string anchors ---- */
    printf("\n-- derivation --\n");
    int derived_ok = 0, derived_want = 0;

    /* helper: find a luaL_Reg pair by exact fn value (pcall needs xpcall's fn) */
    auto pair_by_fn = [&](uintptr_t fn, lr_reg_pair_t* out) -> int {
        for (int s = 0; s < img.n_sections; s++) {
            const lr_section_t* sec = &img.sections[s];
            if (sec->is_code) continue;
            if (sec->size < 16 || sec->size > (64u << 20)) continue;
            for (uintptr_t a = sec->vmaddr; a + 16 <= sec->vmaddr + sec->size; a += 8) {
                uint64_t f = 0;
                if (!lr_read(&img, a + 8, &f, 8)) break;
                if ((uintptr_t)f != fn) continue;
                uint64_t nm = 0;
                if (!lr_read(&img, a, &nm, 8)) continue;
                if (!lr_section_for(&img, (uintptr_t)nm, 0)) continue;
                out->name_addr = (uintptr_t)nm;
                out->fn = fn;
                return 1;
            }
        }
        return 0;
    };
    (void)pair_by_fn;

    /* lua_newthread: three gates */
    {
        lr_newthread_result_t nt;
        int rc = lr_derive_newthread(&img, &nt);
        derived_want++;
        if (rc == LR_OK) {
            derived_ok++;
            printf("lua_newthread     OK   fn=%#lx  gates: iy_slots=%d create_pairs=%d bl+movz#%d\n",
                   (unsigned long)nt.fn, nt.slot_copies, nt.create_pairs, LR_LUA_TTHREAD);
        } else {
            printf("lua_newthread     FAIL (%s)\n", rc == LR_ERR_NO_STRING ? "isyieldable pair not found" :
                                                         rc == LR_ERR_NO_XREF ? "slot arithmetic failed" :
                                                         rc == LR_ERR_NO_PATTERN ? "gates disagree" : "failed");
        }
    }

    /* resume split: the anchor-resolved fn must look public (BLs a
     * stack-alloc prologue callee — rawrunprotected shape) */
    for (int i = 0; i < n; i++) {
        if (strcmp(results[i].name, "lua_resume") != 0 || results[i].status != LR_OK) continue;
        int pub = lr_resume_looks_public(&img, results[i].res.fn);
        printf("lua_resume split  %s   fn=%#lx  bl-to-stackalloc-callee=%d\n",
               pub ? "OK  " : "WARN", (unsigned long)results[i].res.fn, pub);
        if (!pub) hard_fail++;
    }

    /* lua_pcall: registration-code derivation via the unique xpcall cstring */
    {
        uintptr_t pcall_fn = 0, xpcall_fn = 0;
        int rc = lr_derive_pcall(&img, &pcall_fn, &xpcall_fn);
        derived_want++;
        if (rc == LR_OK) {
            derived_ok++;
            printf("lua_pcall         OK   fn=%#lx  (xpcall fn=%#lx, code-adjacent)\n",
                   (unsigned long)pcall_fn, (unsigned long)xpcall_fn);
        } else {
            printf("lua_pcall         FAIL (%s)\n", rc == LR_ERR_NO_STRING ? "xpcall string unresolved" :
                                                         rc == LR_ERR_NO_XREF ? "pcall string not in registering fn" :
                                                         "pattern gates failed");
        }
    }

    /* rawload: luau_load caller ∩ loadstring-wrapper callee */
    {
        uintptr_t load_fn = 0;
        for (int i = 0; i < n; i++)
            if (strcmp(results[i].name, "luau_load") == 0 && results[i].status == LR_OK)
                load_fn = results[i].res.fn;
        uintptr_t ls_wrap = 0;
        {
            /* the wrapper raises the loadstring-family string; resolve it the
             * same way the resolver does, then take its fn */
            lr_result_t tmp;
            if (lr_resolve_anchor(&img, "loadstring() is not available", &tmp) == LR_OK)
                ls_wrap = tmp.fn;
        }
        uintptr_t raw = lr_derive_rawload(&img, load_fn, ls_wrap);
        derived_want++;
        if (raw) {
            derived_ok++;
            printf("rawload           OK   fn=%#lx  (luau_load caller ∩ loadstring-wrapper callee)\n",
                   (unsigned long)raw);
        } else {
            printf("rawload           FAIL (no caller of luau_load is also a loadstring-wrapper callee)\n");
        }

        /* compile: the BL target called by the loadstring wrapper right
         * before its rawload call — on 0.741 that is compile_entry, the
         * (sret-container, src-string) function the exec pipeline needs. */
        {
            uintptr_t comp = lr_derive_compile(&img, ls_wrap, raw);
            derived_want++;
            if (comp) {
                derived_ok++;
                printf("compile           OK   fn=%#lx  (loadstring BL right before rawload)\n",
                       (unsigned long)comp);
            } else {
                printf("compile           FAIL (no BL target precedes rawload in the wrapper)\n");
            }
        }
    }

    printf("\n-- verdict --\nanchored resolved: %d/%d\n", ok_anchored, total_anchored);
    printf("derived resolved:  %d/%d\n", derived_ok, derived_want);
    printf("required symbols without an anchor (known work): %d%s%s\n",
           req_gaps, req_gaps ? " — " : "", req_gaps ? req_gap_names : "");
    if (warn) printf("auxiliary anchors unresolved: %d (reported, not fatal)\n", warn);
    int rc = (hard_fail == 0) ? 0 : 1;
    printf("result: %s\n", rc == 0 ? "PASS" : "FAIL");
    free(scratch);
    munmap(base, flen);
    close(fd);
    return rc;
}

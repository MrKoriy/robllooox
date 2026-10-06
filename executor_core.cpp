/*
 * executor_core.cpp — Native Roblox Luau Executor Core for macOS ARM64
 *
 * Stage 2 (rewritten by ENI after audit):
 *   Game-state acquisition via RTTI -> vtable -> instance hunting.
 */

#include "executor_core.h"
#include "luau_signatures.h"
#include "luau_resolver.h"
#include <stdio.h>
#include <ctype.h>
#include <fcntl.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <unistd.h>
#include <dlfcn.h>
#include <pthread.h>
#include <mach/mach.h>
#include <mach/mach_time.h>
#include <mach/mach_vm.h>
#include <libkern/OSCacheControl.h>
#include <mach-o/dyld.h>
#include <mach-o/getsect.h>
#include <mach-o/ldsyms.h>
#include <mach-o/loader.h>
#include <sys/mman.h>
#include <errno.h>

extern "C" void log_msg(const char* fmt, ...);

static void LOG_CORE(const char* fmt, ...) {
    char buf[1024];
    va_list args;
    va_start(args, fmt);
    vsnprintf(buf, sizeof(buf), fmt, args);
    va_end(args);

    printf("[executor-core] %s\n", buf);
    fflush(stdout);

    log_msg("[executor-core] %s", buf);
}

static lua_State*      g_game_lua_state   = NULL;
static void*           g_script_context   = NULL;
#define _XOPEN_SOURCE
#include <signal.h>
#include <setjmp.h>
#include <ucontext.h>
#include <stdexcept>

static sigjmp_buf g_exec_jmp;
static volatile sig_atomic_t g_exec_segv = 0;
static volatile sig_atomic_t g_exec_timeout = 0;

static void exec_segv_handler(int sig, siginfo_t* si, void* ctx) {
    (void)ctx;
    g_exec_segv = 1;
    uintptr_t pc = 0, lr = 0;
    uintptr_t x8 = 0, x25 = 0, x26 = 0, x27 = 0, x20 = 0;
    if (ctx) {
#if defined(__aarch64__)
        /* the executor only ever runs against Apple Silicon Roblox; the
         * x86_64 slice exists so the universal build links */
        ucontext_t* uc = (ucontext_t*)ctx;
        pc = uc->uc_mcontext->__ss.__pc;
        lr = uc->uc_mcontext->__ss.__lr;
        x8  = uc->uc_mcontext->__ss.__x[8];
        x20 = uc->uc_mcontext->__ss.__x[20];
        x25 = uc->uc_mcontext->__ss.__x[25];
        x26 = uc->uc_mcontext->__ss.__x[26];
        x27 = uc->uc_mcontext->__ss.__x[27];
#else
        (void)ctx;
#endif
    }
    LOG_CORE("EXEC: %s at %p pc=%p lr=%p", sig == SIGBUS ? "SIGBUS" : "SIGSEGV",
             si->si_addr, (void*)pc, (void*)lr);
    LOG_CORE("EXEC: regs x8=%#llx x20=%#llx x25=%#llx x26=%#llx x27=%#llx",
             (unsigned long long)x8, (unsigned long long)x20,
             (unsigned long long)x25, (unsigned long long)x26,
             (unsigned long long)x27);
    if (pc == 0 && x25 != 0) {
        /* VM dispatch: br through [table + op*8]. Recover op index. */
        uintptr_t tab_lo = x25;             /* candidate table base (page+0x6c0 set by caller) */
        long opidx = -1;
        if (x8 >= tab_lo && x8 < tab_lo + 0x800)
            opidx = (long)((x8 - tab_lo) >> 3);
        LOG_CORE("EXEC: dispatch-candidate base=%#llx slotptr=%#llx opidx=%ld",
                 (unsigned long long)tab_lo, (unsigned long long)x8, opidx);
    }
    siglongjmp(g_exec_jmp, 1);
}

static void exec_alrm_handler(int sig) {
    (void)sig;
    g_exec_timeout = 1;
    LOG_CORE("EXEC: watchdog timeout");
    siglongjmp(g_exec_jmp, 2);
}

static void install_segv_guard(struct sigaction* sa, struct sigaction* old_sa) {
    memset(sa, 0, sizeof(*sa));
    sa->sa_sigaction = exec_segv_handler;
    sa->sa_flags = SA_SIGINFO;
    sigemptyset(&sa->sa_mask);
    sigaction(SIGSEGV, sa, old_sa);
    sigaction(SIGBUS, sa, old_sa + 1);
    g_exec_segv = 0;
}

static void remove_segv_guard(struct sigaction* sa, struct sigaction* old_sa) {
    (void)sa;
    /* install_segv_guard saved SIGSEGV into old_sa[0] and SIGBUS into
     * old_sa[1] — restore each from its own slot (they were restored
     * crosswise before, which corrupted the game's crash-handler pair
     * after every guarded call) */
    sigaction(SIGSEGV, &old_sa[0], NULL);
    sigaction(SIGBUS, &old_sa[1], NULL);
}

static void install_alrm_guard(struct sigaction* sa, struct sigaction* old_sa) {
    memset(sa, 0, sizeof(*sa));
    sa->sa_handler = exec_alrm_handler;
    sigemptyset(&sa->sa_mask);
    sigaction(SIGALRM, sa, old_sa);
    g_exec_timeout = 0;
}

static void remove_alrm_guard(struct sigaction* old_sa) {
    alarm(0);
    sigaction(SIGALRM, old_sa, NULL);
}

static pthread_mutex_t g_exec_mutex       = PTHREAD_MUTEX_INITIALIZER;
static bool            g_initialized      = false;
static bool            g_scan_done        = false;
static uintptr_t       g_text_base        = 0;  /* RobloxPlayer __TEXT range */
static uintptr_t       g_text_end         = 0;

static uintptr_t       g_vtable_data      = 0;
static uintptr_t       g_vtable_orig[512] = {0};
static int             g_vtable_nslots    = 0;
static uintptr_t       g_script_cands[16] = {0};
static int             g_script_ncands    = 0;
static uintptr_t       g_tramp_area       = 0;
static int             g_tramp_area_size  = 0;
static volatile int    g_hook_active      = 0;
static volatile int    g_hook_captured    = 0;

static bool is_memory_readable(uintptr_t addr) {
    mach_msg_type_number_t count = VM_REGION_BASIC_INFO_COUNT_64;
    mach_vm_size_t region_size = 0;
    vm_region_basic_info_data_64_t info;
    mach_port_t object_name = MACH_PORT_NULL;
    mach_vm_address_t region_addr = (mach_vm_address_t)addr;

    kern_return_t kr = mach_vm_region(mach_task_self(), &region_addr, &region_size,
                                      VM_REGION_BASIC_INFO_64,
                                      (vm_region_info_t)&info, &count, &object_name);
    if (kr != KERN_SUCCESS) return false;
    return (info.protection & VM_PROT_READ) != 0;
}

static bool is_memory_writable(uintptr_t addr) {
    mach_msg_type_number_t count = VM_REGION_BASIC_INFO_COUNT_64;
    mach_vm_size_t region_size = 0;
    vm_region_basic_info_data_64_t info;
    mach_port_t object_name = MACH_PORT_NULL;
    mach_vm_address_t region_addr = (mach_vm_address_t)addr;

    kern_return_t kr = mach_vm_region(mach_task_self(), &region_addr, &region_size,
                                      VM_REGION_BASIC_INFO_64,
                                      (vm_region_info_t)&info, &count, &object_name);
    if (kr != KERN_SUCCESS) return false;
    return (info.protection & VM_PROT_WRITE) != 0;
}

__attribute__((unused))
static bool read_ptr(uintptr_t addr, uintptr_t* out) {
    if (!is_memory_readable(addr)) return false;
    *out = *(uintptr_t*)addr;
    return true;
}

/* Kernel-mediated copy: faults become errors, never SIGSEGV the process.
 * Used for all reads of game heap that may be unmapped mid-scan. */
static bool safe_read(uintptr_t addr, void* dst, size_t len) {
    mach_vm_size_t got = 0;
    kern_return_t kr = mach_vm_read_overwrite(mach_task_self(),
        (mach_vm_address_t)addr, (mach_vm_size_t)len,
        (mach_vm_address_t)dst, &got);
    return (kr == KERN_SUCCESS && got == len);
}

static const struct mach_header_64* find_roblox_header(void) {
    uint32_t count = _dyld_image_count();
    for (uint32_t i = 0; i < count; i++) {
        const char* name = _dyld_get_image_name(i);
        if (name && strstr(name, "RobloxPlayer")) {
            return (const struct mach_header_64*)_dyld_get_image_header(i);
        }
    }
    return (const struct mach_header_64*)_dyld_get_image_header(0);
}

typedef struct {
    uintptr_t addr;
    uintptr_t size;
} section_range;

static bool get_section(const struct mach_header_64* hdr,
                        const char* seg, const char* sect,
                        section_range* out) {
    unsigned long size = 0;
    uint8_t* data = getsectiondata(hdr, seg, sect, &size);
    if (!data || size == 0) return false;
    out->addr = (uintptr_t)data;
    out->size = (uintptr_t)size;
    return true;
}

__attribute__((unused))
static uintptr_t find_bytes(uintptr_t hay, uintptr_t hay_len,
                            const char* needle, size_t needle_len) {
    const uint8_t* h = (const uint8_t*)hay;
    for (uintptr_t i = 0; i + needle_len <= hay_len; i++) {
        if (memcmp(h + i, needle, needle_len) == 0)
            return hay + i;
    }
    return 0;
}

/* arm64e: pointers in const data may carry chained-fixup metadata / PAC
 * signature in the high bits. Compare by low 36 bits only (all observed
 * addresses here fit in ~34 bits; verification stages filter collisions). */
#define PTR_MASK 0x0000000FFFFFFFFFULL

__attribute__((unused))
static uintptr_t find_pointer_in_range(uintptr_t start, uintptr_t size, uintptr_t target) {
    uintptr_t* p = (uintptr_t*)start;
    size_t n = size / sizeof(uintptr_t);
    uintptr_t masked_target = target & PTR_MASK;
    for (size_t i = 0; i < n; i++) {
        if ((p[i] & PTR_MASK) == masked_target)
            return start + i * sizeof(uintptr_t);
    }
    return 0;
}

/* Collect every file-backed, non-code, non-zerofill section of the image.
 * Section ranges are stable for the process lifetime — blind region scanning
 * faults on guard pages / unmapping races. */
static int collect_sections(const struct mach_header_64* hdr,
                            section_range* out, int max_out) {
    /* ASLR slide from __TEXT segment's link-time vmaddr */
    uintptr_t slide = 0;
    const struct load_command* lc = (const struct load_command*)(hdr + 1);
    for (uint32_t i = 0; i < hdr->ncmds; i++) {
        if (lc->cmd == LC_SEGMENT_64) {
            const struct segment_command_64* seg = (const struct segment_command_64*)lc;
            if (strncmp(seg->segname, "__TEXT", 16) == 0 ||
                strncmp(seg->segname, SEG_TEXT, 16) == 0) {
                slide = (uintptr_t)hdr - seg->vmaddr;
                break;
            }
        }
        lc = (const struct load_command*)((const uint8_t*)lc + lc->cmdsize);
    }

    int n = 0;
    lc = (const struct load_command*)(hdr + 1);
    for (uint32_t i = 0; i < hdr->ncmds; i++) {
        if (lc->cmd == LC_SEGMENT_64) {
            const struct segment_command_64* seg = (const struct segment_command_64*)lc;
            const struct section_64* sects = (const struct section_64*)(seg + 1);
            for (uint32_t s = 0; s < seg->nsects && n < max_out; s++) {
                const struct section_64* sec = &sects[s];
                uint32_t type = sec->flags & SECTION_TYPE;
                if (type == S_ZEROFILL || type == S_THREAD_LOCAL_ZEROFILL) continue;
                if (sec->flags & (S_ATTR_PURE_INSTRUCTIONS | S_ATTR_SOME_INSTRUCTIONS)) continue;
                uintptr_t addr = sec->addr + slide;
                uintptr_t size = sec->size;
                if (size < 8 || size > 0x8000000ULL) continue;
                if (!is_memory_readable(addr) || !is_memory_readable(addr + size - 8)) continue;
                out[n].addr = addr;
                out[n].size = size;
                n++;
            }
        }
        lc = (const struct load_command*)((const uint8_t*)lc + lc->cmdsize);
    }
    return n;
}

static int find_bytes_all(const section_range* secs, int nsecs,
                          const char* needle, size_t needle_len,
                          uintptr_t* out, int max_out) {
    int found = 0;
    for (int s = 0; s < nsecs && found < max_out; s++) {
        uintptr_t base = secs[s].addr, sz = secs[s].size;
        const uint8_t* h = (const uint8_t*)base;
        for (uintptr_t i = 0; i + needle_len <= sz && found < max_out; i++) {
            if (memcmp(h + i, needle, needle_len) == 0)
                out[found++] = base + i;
        }
    }
    return found;
}

static uintptr_t find_ptr_in_sections(const section_range* secs, int nsecs,
                                      uintptr_t target) {
    uintptr_t masked = target & PTR_MASK;
    for (int s = 0; s < nsecs; s++) {
        uintptr_t* p = (uintptr_t*)secs[s].addr;
        size_t n = secs[s].size / sizeof(uintptr_t);
        for (size_t k = 0; k < n; k++) {
            if ((p[k] & PTR_MASK) == masked)
                return secs[s].addr + k * sizeof(uintptr_t);
        }
    }
    return 0;
}

/* Strict, FULLY SAFE lua_State validator — every external read goes through
 * the kernel (mach_vm_read_overwrite). No direct derefs of game heap.
 *
 * Gold-standard invariant: a main lua_State holds a pointer to its
 * global_State, and global_State holds a pointer (mainthread) BACK to L.
 * We discover both offsets empirically — version-agnostic, no hardcoding. */
/* Validate a global_State pointer by locating its string table
 * {hash*, size, nuse} with TString-shaped entries. Offset-agnostic. */
/* heap pointer validity: the client maps the lua heap either in the
 * 0x10-0x15x range OR in the 0x71x range depending on launch; the game
 * universe's heap specifically lands high (0x70-0x73x). */
static inline bool heap_ptr_ok(uint64_t p) {
    return p >= 0x100000000ULL && p < 0x74000000000ULL;
}

static int g_strt_ok(uintptr_t g) {
    static uintptr_t ok_cache[64];
    static uint8_t   ok_val[64];
    static int ok_n = 0;
    for (int k = 0; k < ok_n; k++)
        if (ok_cache[k] == g) return ok_val[k];
    int ok = 0;
    uint8_t gb[0x440];
    if (safe_read(g, gb, sizeof(gb))) {
        for (int off = 0; off + 16 <= 0x440 && !ok; off += 8) {
            uintptr_t bucket = *(uintptr_t*)(gb + off) & PTR_MASK;
            if (bucket < 0x100000000ULL || bucket > 0x74000000000ULL || (bucket & 7))
                continue;
            uint64_t size = *(uint32_t*)(gb + off + 8);
            uint64_t nuse = *(uint32_t*)(gb + off + 12);
            if (size < 16 || size > 0x100000ULL || nuse > size * 2) continue;
            uint64_t bs[16];
            memset(bs, 0, sizeof(bs));
            if (!safe_read(bucket, bs, sizeof(bs))) continue;
            int good = 0, bad = 0;
            for (int k = 0; k < 16; k++) {
                if (bs[k] == 0) continue;
                uintptr_t s = bs[k] & PTR_MASK;
                if (s < 0x100000000ULL || s > 0x74000000000ULL || (s & 7)) { bad = 1; break; }
                uint8_t sb[0x18];
                if (!safe_read(s, sb, sizeof(sb))) { bad = 1; break; }
                uint32_t slen = *(uint32_t*)(sb + 0x14);
                if (slen == 0 || slen > 0x100000) { bad = 1; break; }
                good++;
            }
            if (!bad && good >= 2) ok = 1;
        }
    }
    if (ok_n < 64) { ok_cache[ok_n] = g; ok_val[ok_n] = (uint8_t)ok; ok_n++; }
    return ok;
}

/* ---- 0.741 lua_State layout ---------------------------------------- */
/* Derived from disasm of luaE_newthread (0x1026f3494), stack_init
 * (0x1026f3570), lua_newthread (0x1026d6f1c), tothread (0x1026d8544),
 * index2adr (0x1026dc1d4), lua_resume (0x1026e5a54) on 0.741.0.7411056.
 * The API-visible lua_State is the 0x88-byte GC wrapper: tt byte at +1
 * (LUA_TTHREAD = 0xA), status at +3, base@+0x60, G@+0x68, top@+0x70,
 * value stack@+0x78, stack_last@+0x80. Every thread carries an
 * anti-forgery magic at +0x18: u32 = low32(field address) ^ 0x2d. */
#define LUA_TT_OFF      0x01
#define LUA_STATUS_OFF  0x03
#define LUA_MAGIC_OFF   0x18   /* u32: low32(L + 0x18) ^ 0x2d          */
#define LUA_NUM8_OFF    0x1c   /* u32 == 8 right after init           */
#define LUA_G_OFF       0x68
#define LUA_BASE_OFF    0x60
#define LUA_TOP_OFF     0x70
#define LUA_STACK_OFF   0x78
#define LUA_SLAST_OFF   0x80
#define LUA_INNER_OFF   0x50   /* fresh: [+0x50] == [+0x58]            */

static bool lua_thread_magic_ok(uintptr_t L) {
    uint32_t m = 0;
    if (!safe_read(L + LUA_MAGIC_OFF, &m, 4)) return false;
    return m == ((uint32_t)((L + LUA_MAGIC_OFF) & 0xffffffffULL) ^ 0x2du);
}

static bool looks_like_lua_state_safe(uintptr_t candidate) {
    if (candidate == 0 || (candidate % 8) != 0) return false;
    if (candidate < 0x100000000ULL || candidate > 0x74000000000ULL) return false;

    uint8_t buf[0x88];
    if (!safe_read(candidate, buf, sizeof(buf))) return false;

    /* 0.741: tt byte at +1, G at +0x68, anti-forgery magic at +0x18. */
    if (buf[LUA_TT_OFF] != 0xA) return false;

    uintptr_t cand_masked = candidate & PTR_MASK;
    uintptr_t g = *(uintptr_t*)(buf + LUA_G_OFF) & PTR_MASK;
    if (g < 0x100000000ULL || g > 0x74000000000ULL || (g & 0xF) != 0) return false;
    uintptr_t dist = (g > cand_masked) ? (g - cand_masked) : (cand_masked - g);
    if (dist < 0x60) return false;
    if (!lua_thread_magic_ok(candidate)) return false;
    if (!g_strt_ok(g)) return false;

    /* the main thread is referenced back from global_State */
    uint8_t gbuf[0x440];
    if (!safe_read(g, gbuf, sizeof(gbuf))) return false;
    for (int boff = 0; boff + 8 <= (int)sizeof(gbuf); boff += 8) {
        uintptr_t back = *(uintptr_t*)(gbuf + boff) & PTR_MASK;
        if (back != cand_masked) continue;
        uint8_t b2[0x88];
        if (!safe_read(cand_masked, b2, sizeof(b2))) continue;
        if (b2[LUA_TT_OFF] != 0xA) continue;
        if ((*(uintptr_t*)(b2 + LUA_G_OFF) & PTR_MASK) != g) continue;
        LOG_CORE("CONFIRMED lua_State @ %p: G=%p strt-ok, mainthread@+0x%x",
                 (void*)candidate, (void*)g, boff);
        return true;
    }
    return false;
}

static int scan_rw_for_vtable(uintptr_t vtable_data_addr,
                              void** out_instances, int max_instances) {
    mach_vm_address_t address = 0x100000000ULL;
    mach_vm_size_t size = 0;
    mach_msg_type_number_t count = VM_REGION_BASIC_INFO_COUNT_64;
    vm_region_basic_info_data_64_t info;
    mach_port_t object_name = MACH_PORT_NULL;

    /* read via the kernel: a region the game unmaps mid-scan must error
     * the read, not SIGSEGV the process */
    const mach_vm_size_t CHUNK = 0x40000; /* 256KB */
    uint8_t* buf = (uint8_t*)malloc(CHUNK);
    if (!buf) return 0;

    uintptr_t masked_vt = vtable_data_addr & PTR_MASK;
    int found = 0;
    int regions = 0;
    while (regions < 4000 && found < max_instances &&
           mach_vm_region(mach_task_self(), &address, &size, VM_REGION_BASIC_INFO_64,
                          (vm_region_info_t)&info, &count, &object_name) == KERN_SUCCESS) {
        regions++;
        if ((info.protection & VM_PROT_READ) && (info.protection & VM_PROT_WRITE)
            && size >= 8 && size < 0x80000000ULL) {
            for (mach_vm_address_t off = 0; off + 8 <= size && found < max_instances; off += CHUNK) {
                mach_vm_size_t want = (size - off < CHUNK) ? (size - off) : CHUNK;
                mach_vm_size_t got = 0;
                kern_return_t kr = mach_vm_read_overwrite(mach_task_self(), address + off,
                                                          want, (mach_vm_address_t)buf, &got);
                if (kr != KERN_SUCCESS || got < 8) continue;
                uintptr_t* p = (uintptr_t*)buf;
                size_t n = got / sizeof(uintptr_t);
                for (size_t i = 0; i < n; i++) {
                    if ((p[i] & PTR_MASK) == masked_vt) {
                        out_instances[found++] = (void*)(address + off + i * sizeof(uintptr_t));
                        if (found >= max_instances) break;
                    }
                }
            }
        }
        address += size;
        size = 0;
    }
    free(buf);
    return found;
}

/* Scan an entire VM region (bulk-read in chunks) and COLLECT every
 * backref-consistent lua_State candidate. We collect instead of stopping at
 * the first so we can eyeball the real Luau layout of this build. */
typedef struct {
    uintptr_t addr;   /* candidate lua_State */
    uintptr_t ptrs[4];/* heap pointers found in [0x10..0x48] */
    int nptrs;
} lua_cand_t;

static int collect_lua_candidates(uintptr_t region_addr, mach_vm_size_t region_size,
                                  lua_cand_t* out, int max_out, int* out_n) {
    const mach_vm_size_t CHUNK = 0x40000; /* 256KB */
    uint8_t* buf = (uint8_t*)malloc(CHUNK);
    if (!buf) return 0;

    int n = *out_n;
    for (mach_vm_size_t off = 0; off < region_size && n < max_out; off += CHUNK) {
        mach_vm_size_t want = (region_size - off < CHUNK) ? (region_size - off) : CHUNK;
        mach_vm_size_t got = 0;
        kern_return_t kr = mach_vm_read_overwrite(mach_task_self(),
            region_addr + off, want, (mach_vm_address_t)buf, &got);
        if (kr != KERN_SUCCESS || got < 0x50) continue;
        /* cheap LOCAL pre-filters for Luau threads:
         *   [8]  == 9 (LUA_TTHREAD in Luau; 8 is userdata!)
         *   [9]  < 16 (marked)
         *   qword[1] >> 32 == 0xfffffffc  (GC epoch/fflags constant seen on
         *   all real threads) — kills chunk headers and ObjC objects. */
        for (mach_vm_size_t i = 0; i + 0x88 <= got && n < max_out; i += 8) {
            if (buf[i + LUA_TT_OFF] != 0xA) continue;   /* tt @ +1 (0.741) */
            if (buf[i + 2] >= 16) continue;             /* marked */
            uint32_t magic = *(uint32_t*)(buf + i + LUA_MAGIC_OFF);
            uintptr_t cand = region_addr + off + i;
            if (magic != ((uint32_t)((cand + LUA_MAGIC_OFF) & 0xffffffffULL) ^ 0x2du))
                continue;                                /* anti-forgery */
            uintptr_t gg = *(uintptr_t*)(buf + i + LUA_G_OFF) & PTR_MASK;
            if (gg < 0x100000000ULL || gg > 0x74000000000ULL || (gg & 0xF)) continue;
            uintptr_t candidate = region_addr + off + i;
            out[n].addr = candidate;
            out[n].nptrs = 0;
            for (uintptr_t goff = 0x10; goff <= 0x48 && out[n].nptrs < 4; goff += 8) {
                uintptr_t p = *(uintptr_t*)(buf + i + goff) & PTR_MASK;
                if (p < 0x100000000ULL || p > 0x74000000000ULL) continue;
                if (p == (candidate & PTR_MASK)) continue;
                out[n].ptrs[out[n].nptrs++] = p;
            }
            if (out[n].nptrs > 0) n++;
        }
    }
    free(buf);
    *out_n = n;
    return n;
}

extern "C" int executor_dump(uintptr_t addr, char* buf, size_t len) {
    uint8_t raw[64 * 8];
    mach_vm_size_t got = 0;
    kern_return_t kr = mach_vm_read_overwrite(mach_task_self(), (mach_vm_address_t)addr,
                                              64 * 8, (mach_vm_address_t)raw, &got);
    if (kr != KERN_SUCCESS) {
        snprintf(buf, len, "ERR: read failed kr=%d", kr);
        return -1;
    }
    size_t off = 0;
    for (int i = 0; i < 64 && off + 32 < len; i++) {
        uint64_t w = *(uint64_t*)(raw + i * 8);
        int n = snprintf(buf + off, len - off, "+0x%02x: %016llx\n", i * 8,
                         (unsigned long long)w);
        if (n > 0) off += (size_t)n;
    }
    return 0;
}

/* Dump ScriptContext instances with per-pointer annotation: for every
 * heap-like pointer we print the pointed-to object's 32-bit tag word
 * (LuauForgeChunks layout) so the lua_State field can be spotted. */
extern "C" int executor_sc_dump(char* buf, size_t len) {
    size_t off = 0;
    void* instances[8];
    int n = 0;
    if (g_vtable_data)
        n = scan_rw_for_vtable(g_vtable_data, instances, 8);
    if (n == 0 && g_script_context) {
        instances[0] = g_script_context;
        n = 1;
    }
    if (n == 0) {
        snprintf(buf, len, "ERR: no ScriptContext instances (vtable=%p)",
                 (void*)g_vtable_data);
        return -1;
    }
    for (int i = 0; i < n; i++) {
        uintptr_t sc = (uintptr_t)instances[i];
        off += (size_t)snprintf(buf + off, len - off, "== SC %d @ %p ==\n", i, (void*)sc);
        uint8_t chunk[0x400];
        if (!safe_read(sc, chunk, sizeof(chunk))) continue;
        for (uintptr_t o = 0; o + 8 <= sizeof(chunk) && off + 128 < len; o += 8) {
            uintptr_t v = *(uintptr_t*)(chunk + o);
            bool heap = v >= 0x100000000ULL && v <= 0x74000000000ULL && v % 8 == 0;
            if (!heap) continue; /* skip scalars, print pointer fields only */
            uint8_t hdr[0x18];
            safe_read(v, hdr, sizeof(hdr));
            uint32_t tag = *(uint32_t*)(hdr + 8);
            off += (size_t)snprintf(buf + off, len - off,
                "+0x%03lx: %010lx tag=%08x\n",
                (unsigned long)o, (unsigned long)v, tag);
        }
    }
    return 0;
}

/* Code xref scanner: find adrp+add/ldr pairs pointing at `target`.
 * Returns up to 16 code addresses. */
extern "C" int executor_xref(uintptr_t target, char* buf, size_t len) {
    size_t off = 0;
    uintptr_t base = g_text_base;
    uintptr_t end  = g_text_end;
    if (!base || end <= base) {
        snprintf(buf, len, "ERR: no TEXT range");
        return -1;
    }
    uint32_t* code = (uint32_t*)base;
    size_t nwords = (end - base) / 4;
    int hits = 0;
    for (size_t i = 0; i + 16 < nwords && hits < 16; i++) {
        uint32_t insn = code[i];
        if ((insn & 0x9F000000u) != 0x90000000u) continue; /* adrp */
        int rd = (int)(insn & 0x1F);
        int64_t imm = ((int64_t)((insn >> 5) & 0x7FFFF) << 2)
                    | (int64_t)((insn >> 29) & 0x3);
        imm = (imm << 12) >> 12; /* sign-extend 21-bit << 12 */
        uintptr_t page = (base + i * 4) & ~0xFFFULL;
        uintptr_t abase = page + (uintptr_t)(imm << 12);
        for (size_t j = i + 1; j <= i + 8 && j < nwords; j++) {
            uint32_t w = code[j];
            uintptr_t addr = 0;
            int rn = 0;
            if ((w & 0xFFC00000u) == 0xF9400000u) { /* ldr [rn, #imm<<3] */
                rn = (int)((w >> 5) & 0x1F);
                addr = abase + (uintptr_t)(((w >> 10) & 0xFFF) << 3);
            } else if ((w & 0xFF000000u) == 0x91000000u) { /* add rd, rn, #imm12 */
                rn = (int)((w >> 5) & 0x1F);
                addr = abase + (uintptr_t)((w >> 10) & 0xFFF);
                if ((w >> 22) & 1) addr = abase + (uintptr_t)(((w >> 10) & 0xFFF) << 12);
            }
            if (rn == rd && addr == target) {
                off += (size_t)snprintf(buf + off, len - off, "xref @ %p (insn[+%ld])\n",
                                        (void*)(base + i * 4), (long)(j - i));
                hits++;
                break;
            }
        }
    }
    if (hits == 0) snprintf(buf, len, "no xrefs to %p in TEXT", (void*)target);
    return hits;
}

extern "C" int executor_backref(uintptr_t target, char* buf, size_t len) {
    size_t off = 0;
    mach_vm_address_t address = 0x100000000ULL;
    mach_vm_size_t size = 0;
    mach_msg_type_number_t count = VM_REGION_BASIC_INFO_COUNT_64;
    vm_region_basic_info_data_64_t info;
    mach_port_t object_name = MACH_PORT_NULL;
    uint64_t want = (uint64_t)target & PTR_MASK;
    int hits = 0;
    while (hits < 40 && mach_vm_region(mach_task_self(), &address, &size,
                                       VM_REGION_BASIC_INFO_64,
                                       (vm_region_info_t)&info, &count,
                                       &object_name) == KERN_SUCCESS) {
        if ((info.protection & VM_PROT_READ) && (info.protection & VM_PROT_WRITE)
            && size >= 0x100 && size < 0x80000000ULL) {
            uint8_t* chunk = (uint8_t*)malloc(1 << 20);
            if (!chunk) break;
            mach_vm_size_t done = 0;
            while (done + (1 << 20) <= size && hits < 40) {
                mach_vm_size_t got = 0;
                if (mach_vm_read_overwrite(mach_task_self(), address + done,
                                           (1 << 20), (mach_vm_address_t)chunk,
                                           &got) != KERN_SUCCESS) { break; }
                for (mach_vm_size_t i = 0; i + 8 <= got; i += 8) {
                    uint64_t v = *(uint64_t*)(chunk + i);
                    if ((v & PTR_MASK) != want) continue;
                    uintptr_t owner = (uintptr_t)(address + done + i);
                    uintptr_t ctx[4];
                    safe_read(owner - 0x20, ctx, sizeof(ctx));
                    off += (size_t)snprintf(buf + off, len - off,
                            "backref @ %p  (ctx: %016llx %016llx | %016llx | %016llx %016llx)\n",
                            (void*)owner,
                            (unsigned long long)ctx[0], (unsigned long long)ctx[1],
                            (unsigned long long)ctx[2],
                            (unsigned long long)ctx[3], v);
                    hits++;
                }
                done += got;
            }
            free(chunk);
        }
        address += size;
        size = 0;
    }
    if (hits == 0) snprintf(buf, len, "no backrefs to %p in writable memory", (void*)target);
    return hits;
}

extern "C" int executor_scan_heap(char* buf, size_t len) {
    if (executor_get_game_state()) {
        snprintf(buf, len, "OK: already have L=%p", (void*)executor_get_game_state());
        return 0;
    }
    mach_vm_address_t address = 0x100000000ULL;
    mach_vm_size_t size = 0;
    mach_msg_type_number_t count = VM_REGION_BASIC_INFO_COUNT_64;
    vm_region_basic_info_data_64_t info;
    mach_port_t object_name = MACH_PORT_NULL;
    int regions = 0, scanned = 0;
    lua_cand_t cands[512];
    int ncand = 0;
    while (regions < 4000 && ncand < 512 &&
           mach_vm_region(mach_task_self(), &address, &size, VM_REGION_BASIC_INFO_64,
                          (vm_region_info_t)&info, &count, &object_name) == KERN_SUCCESS) {
        regions++;
        if ((info.protection & VM_PROT_READ) && (info.protection & VM_PROT_WRITE)
            && size >= 0x50 && size < 0x80000000ULL) {
            scanned++;
            collect_lua_candidates(address, size, cands, 512, &ncand);
            if (scanned <= 3 || ncand > 0)
                LOG_CORE("scan region %3d: %p size=0x%llx (cands=%d)", scanned,
                         (void*)address, (unsigned long long)size, ncand);
        }
        address += size;
        size = 0;
    }

    LOG_CORE("=== heap scan done: %d regions, %d candidates ===", regions, ncand);
    for (int i = 0; i < ncand; i++) {
        uint8_t q[0x50];
        safe_read(cands[i].addr, q, sizeof(q));
        LOG_CORE("CAND[%3d] L=%p %016llx %016llx %016llx %016llx %016llx %016llx",
                 i, (void*)cands[i].addr,
                 (unsigned long long)*(uint64_t*)(q + 0x00),
                 (unsigned long long)*(uint64_t*)(q + 0x08),
                 (unsigned long long)*(uint64_t*)(q + 0x10),
                 (unsigned long long)*(uint64_t*)(q + 0x18),
                 (unsigned long long)*(uint64_t*)(q + 0x20),
                 (unsigned long long)*(uint64_t*)(q + 0x28));
    }

    /* The global_State is pointed to by MANY threads — find the pointer
     * value shared by the most candidates (must be a real mapped address). */
    uintptr_t gbest = 0;
    int gcount = 0;
    for (int i = 0; i < ncand; i++) {
        for (int p = 0; p < cands[i].nptrs; p++) {
            uintptr_t val = cands[i].ptrs[p];
            if (!is_memory_readable(val)) continue;
            int c = 0;
            for (int j = 0; j < ncand; j++) {
                for (int q2 = 0; q2 < cands[j].nptrs; q2++) {
                    if (cands[j].ptrs[q2] == val) { c++; break; }
                }
            }
            if (c > gcount) { gcount = c; gbest = val; }
        }
    }
    LOG_CORE("most-shared ptr: %p (shared by %d candidates)", (void*)gbest, gcount);

    lua_State* best = NULL;
    if (gcount >= 3) {
        uint8_t gbuf[0x800];
        if (safe_read(gbest, gbuf, sizeof(gbuf))) {
            uintptr_t frealloc = *(uintptr_t*)(gbuf + 0) & PTR_MASK;
            LOG_CORE("global_State @ %p: [0]=%p (in TEXT: %s)", (void*)gbest,
                     (void*)frealloc,
                     (frealloc >= g_text_base && frealloc < g_text_end) ? "yes" : "no");
            /* main L = candidate that global_State points back to */
            for (int i = 0; i < ncand && !best; i++) {
                for (uintptr_t boff = 0; boff + 8 <= sizeof(gbuf); boff += 8) {
                    uintptr_t back = *(uintptr_t*)(gbuf + boff) & PTR_MASK;
                    if (back == (cands[i].addr & PTR_MASK)) {
                        /* candidate must ALSO have gbest among its ptrs */
                        for (int p = 0; p < cands[i].nptrs; p++) {
                            if (cands[i].ptrs[p] == gbest) {
                                best = (lua_State*)cands[i].addr;
                                LOG_CORE("BEST PICK: L=%p (global backref @+0x%lx)",
                                         (void*)best, (unsigned long)boff);
                                break;
                            }
                        }
                        break;
                    }
                }
            }
        }
    }

    if (best) {
        pthread_mutex_lock(&g_exec_mutex);
        if (!g_game_lua_state) g_game_lua_state = best;
        g_hook_captured = 1;
        pthread_mutex_unlock(&g_exec_mutex);
        LOG_CORE("CAPTURED lua_State @ %p via heap scan (%d regions)", (void*)best, regions);
        snprintf(buf, len, "OK: lua_State @ %p (regions: %d, candidates: %d)",
                 (void*)best, regions, ncand);
        return 0;
    }
    snprintf(buf, len, "ERR: no verified lua_State (%d regions, %d scanned, %d candidates)",
             regions, scanned, ncand);
    return -1;
}

static bool lua_state_usable(uintptr_t L);
static void* hunter_thread(void* arg);
static void* hook_reporter_thread(void* arg);
static void* main_watchdog_thread(void* arg);

static void* hunter_thread(void* arg) {
    (void)arg;
    LOG_CORE("Hunter thread started, waiting for DataModel boot...");
    for (int i = 0; i < 15 && !g_script_context; i++) sleep(1);

    const struct mach_header_64* hdr = find_roblox_header();
    if (!hdr) {
        LOG_CORE("FATAL: RobloxPlayer image not found");
        g_scan_done = true;
        return NULL;
    }
    LOG_CORE("RobloxPlayer image @ %p", (void*)hdr);

    section_range cstrings = {0, 0}, text_const = {0, 0}, data_const = {0, 0};
    bool have_cs  = get_section(hdr, "__TEXT", "__cstring", &cstrings);
    bool have_tc  = get_section(hdr, "__TEXT", "__const", &text_const);
    bool have_dc  = get_section(hdr, "__DATA_CONST", "__const", &data_const);
    if (!have_cs) {
        LOG_CORE("FATAL: __TEXT,__cstring not found");
        g_scan_done = true;
        return NULL;
    }
    LOG_CORE("__cstring: %p (%lu KB)  __TEXT,__const: %s  __DATA_CONST,__const: %s",
             (void*)cstrings.addr, cstrings.size / 1024,
             have_tc ? "yes" : "no", have_dc ? "yes" : "no");

    section_range secs[96];
    int nsecs = collect_sections(hdr, secs, 96);
    LOG_CORE("collected %d scannable sections", nsecs);

    const char* rtti_name = "N3RBX13ScriptContextE";
    size_t rtti_len = strlen(rtti_name);
    uintptr_t occ[16];
    int nocc = find_bytes_all(secs, nsecs, rtti_name, rtti_len, occ, 16);
    LOG_CORE("RTTI name '%s' occurrences: %d", rtti_name, nocc);
    if (nocc == 0) {
        LOG_CORE("FATAL: RTTI name not found");
        g_scan_done = true;
        return NULL;
    }
    for (int o = 0; o < nocc; o++)
        LOG_CORE("  occ[%d] @ %p", o, (void*)occ[o]);

    uintptr_t typeinfo_ref = 0, typeinfo_addr = 0, name_addr = 0;
    for (int o = 0; o < nocc; o++) {
        uintptr_t ref = find_ptr_in_sections(secs, nsecs, occ[o]);
        if (ref) {
            name_addr      = occ[o];
            typeinfo_ref   = ref;
            typeinfo_addr  = ref - 8; /* name ptr is 2nd field of typeinfo */
            LOG_CORE("typeinfo xref -> name @ %p, typeinfo @ %p", (void*)name_addr, (void*)typeinfo_addr);
            break;
        }
    }
    if (!typeinfo_ref) {
        LOG_CORE("FATAL: typeinfo xref not found for any occurrence");
        g_scan_done = true;
        return NULL;
    }

    uintptr_t vtable_ti_slot = find_ptr_in_sections(secs, nsecs, typeinfo_addr);
    if (!vtable_ti_slot) {
        LOG_CORE("FATAL: vtable not found");
        g_scan_done = true;
        return NULL;
    }
    uintptr_t vtable_data = vtable_ti_slot + 8;
    g_vtable_data = vtable_data;
    LOG_CORE("vtable data addr = %p", (void*)vtable_data);

    /* Verify Luau signatures from luau_signatures.h in host process memory */
    section_range text_sec = {0, 0};
    if (get_section(hdr, "__TEXT", "__text", &text_sec)) {
        uintptr_t slide = (uintptr_t)hdr - 0x100000000ULL;
        LOG_CORE("Checking extracted Luau signatures with ASLR slide %p...", (void*)slide);

        uintptr_t target_fn = LUAU_SIG_STACK_OVERFLOW_VMADDR + slide;
        uint8_t cur_bytes[16] = {0};
        if (safe_read(target_fn, cur_bytes, 16)) {
            if (memcmp(cur_bytes, LUAU_SIG_STACK_OVERFLOW_BYTES, 16) == 0) {
                LOG_CORE("  [+] Verified luaD_growstack @ %p", (void*)target_fn);
            } else {
                LOG_CORE("  [-] Signature mismatch @ %p", (void*)target_fn);
            }
        }

        uintptr_t argerr_fn = LUAU_SIG_BAD_ARGUMENT_VMADDR + slide;
        if (safe_read(argerr_fn, cur_bytes, 16)) {
            if (memcmp(cur_bytes, LUAU_SIG_BAD_ARGUMENT_BYTES, 16) == 0) {
                LOG_CORE("  [+] Verified luaL_argerror @ %p", (void*)argerr_fn);
            }
        }
    }

    void* instances[16];
    int n = scan_rw_for_vtable(vtable_data, instances, 16);
    g_script_ncands = n < 16 ? n : 16;
    for (int i = 0; i < g_script_ncands; i++) g_script_cands[i] = (uintptr_t)instances[i];
    LOG_CORE("ScriptContext instance candidates: %d", n);
    if (n == 0) {
        LOG_CORE("not found — game may still be booting; rerun later");
        g_scan_done = true;
        return NULL;
    }

    for (int i = 0; i < n; i++) {
        uintptr_t sc = (uintptr_t)instances[i];
        uintptr_t sc_vptr = 0;
        safe_read(sc, &sc_vptr, 8);
        LOG_CORE("probing instance %d @ %p vptr=%p %s", i, (void*)sc,
                 (void*)(sc_vptr & PTR_MASK),
                 (sc_vptr & PTR_MASK) == vtable_data ? "(REAL)" : "");

        uint8_t chunk[0x2008];   /* 0.739: L may sit beyond 0x800 in SC */
        if (!safe_read(sc, chunk, sizeof(chunk))) {
            /* 0x2000 may cross into an unmapped page — fall back to 0x808 */
            if (!safe_read(sc, chunk, 0x808)) {
                LOG_CORE("instance %d: unreadable, skipping", i);
                continue;
            }
        }
        bool verified = false;
        for (uintptr_t off = 0; off + 8 <= sizeof(chunk); off += 8) {
            uintptr_t v = *(uintptr_t*)(chunk + off);
            if (v < 0x100000000ULL || v > 0x74000000000ULL) continue;
            /* log every in-range pointer candidate with its g/stack/top fields */
            {
                uint8_t q[0x88];
                if (safe_read(v, q, sizeof(q))) {
                    uintptr_t vg = *(uintptr_t*)(q + LUA_G_OFF);    /* 0.741: L->G */
                    uintptr_t vstk = *(uintptr_t*)(q + LUA_STACK_OFF);
                    uintptr_t vtop = *(uintptr_t*)(q + LUA_TOP_OFF);
                    static int dbg_probe = 0;
                    if (vg >= 0x100000000ULL && vg <= 0x74000000000ULL && dbg_probe < 60) {
                        dbg_probe++;
                        LOG_CORE("  +0x%03lx -> %p b1=%02x g=%#llx stk=%#llx top=%#llx",
                                 (unsigned long)off, (void*)v, q[LUA_TT_OFF],
                                 (unsigned long long)vg,
                                 (unsigned long long)vstk,
                                 (unsigned long long)vtop);
                    }
                }
            }
            if (lua_state_usable(v)) {
                pthread_mutex_lock(&g_exec_mutex);
                g_script_context = (void*)sc;
                g_game_lua_state  = (lua_State*)v;
                pthread_mutex_unlock(&g_exec_mutex);
                LOG_CORE("VERIFIED lua_State @ %p (ScriptContext+0x%lx)",
                         (void*)v, (unsigned long)off);
                g_scan_done = true;
                return NULL;
            }
        }
        if (!verified)
            LOG_CORE("instance %d: no verified lua_State in scanned window", i);
    }

    g_scan_done = true;
    return NULL;
}

static void init_text_range(void) {
    const struct mach_header_64* hdr = find_roblox_header();
    if (!hdr) return;
    const struct load_command* lc = (const struct load_command*)(hdr + 1);
    for (uint32_t i = 0; i < hdr->ncmds; i++) {
        if (lc->cmd == LC_SEGMENT_64) {
            const struct segment_command_64* seg = (const struct segment_command_64*)lc;
            if (strncmp(seg->segname, "__TEXT", 16) == 0 ||
                strncmp(seg->segname, SEG_TEXT, 16) == 0) {
                uintptr_t slide = (uintptr_t)hdr - seg->vmaddr;
                g_text_base = seg->vmaddr + slide;
                g_text_end  = g_text_base + seg->vmsize;
                return;
            }
        }
        lc = (const struct load_command*)((const uint8_t*)lc + lc->cmdsize);
    }
}

extern "C" bool executor_init(void) {
    if (g_initialized) return true;
    g_initialized = true;

    const char* prog = getprogname();
    if (prog && strcasestr(prog, "Roblox") == NULL) {
        return true;
    }

    pthread_t tid;
    init_text_range();
    LOG_CORE("Roblox __TEXT: %p - %p", (void*)g_text_base, (void*)g_text_end);
    /* hunter thread disabled: its vtable-instance probing spins for minutes
     * with the game heap and its alarm/signal interplay wedges the exec
     * path; the G-preference main discovery replaces it entirely */
    pthread_t rid;
    if (pthread_create(&rid, NULL, hook_reporter_thread, NULL) == 0) {
        pthread_detach(rid);
    }
    /* watchdog disabled entirely: with the game joined its full rescans
     * wedge the single IPC thread and destabilize the client; the exec
     * path handles a stale main itself (G-preference pick, no scan) */
    return true;
}

extern "C" lua_State* executor_get_game_state(void) {
    pthread_mutex_lock(&g_exec_mutex);
    lua_State* L = g_game_lua_state;
    pthread_mutex_unlock(&g_exec_mutex);
    return L;
}

extern "C" bool executor_is_ready(void) {
    return executor_get_game_state() != NULL;
}

struct RobloxExtraSpaceShared {
    int script_context;
    uint64_t capabilities;
    int identity;
};

struct RobloxExtraSpace {
    RobloxExtraSpaceShared* shared;
    int identity;
    uint64_t capabilities;
};

extern "C" void executor_set_identity(lua_State* L, int identity, uint64_t capabilities) {
    if (!L) return;
    uintptr_t extraspace_addr = (uintptr_t)L - sizeof(RobloxExtraSpace);
    uint64_t probe = 0;
    if (!safe_read(extraspace_addr, &probe, sizeof(probe))) {
        LOG_CORE("set_identity: ExtraSpace memory unreadable at %p", (void*)extraspace_addr);
        return;
    }

    RobloxExtraSpace* es = (RobloxExtraSpace*)((uintptr_t)L - sizeof(RobloxExtraSpace));
    es->identity = identity;
    es->capabilities = capabilities;

    if (es->shared && is_memory_readable((uintptr_t)es->shared) &&
        is_memory_writable((uintptr_t)es->shared)) {
        es->shared->identity = identity;
        es->shared->capabilities = capabilities;
    }
    LOG_CORE("Set thread identity=%d capabilities=0x%llx @ ExtraSpace %p",
             identity, (unsigned long long)capabilities, (void*)es);
}

extern "C" char* executor_compile_luau(const char* source, size_t* out_len,
                                       char* err_buf, size_t err_buf_len) {
    (void)source; (void)out_len;
    if (err_buf) {
        snprintf(err_buf, err_buf_len,
                 "bytecode compile: uses Luau native load or custom bytecode pipeline");
    }
    return NULL;
}

extern "C" int executor_execute(const char* code, char* response_buf, size_t response_buf_len) {
    lua_State* L = executor_get_game_state();
    if (!L) {
        if (response_buf) {
            snprintf(response_buf, response_buf_len,
                     "ERR: game lua_State not acquired (scan %s). No execution attempted.",
                     g_scan_done ? "finished, no candidate" : "still running");
        }
        return -1;
    }

    /* Elevate identity to level 7 (Executor identity) on the captured state */
    executor_set_identity(L, 7, 0x3FFFFFFULL);

    /* Real pipeline: main thread -> coroutine -> rawload(source) -> resume */
    return executor_exec_gamestate(code, response_buf, response_buf_len);
}

/* ------------------------------------------------------------------ */
/* Vtable hook lab: capture the game's lua_State via live call sites.  */
/* Trampolines are generated in an executable mmap region; each slot's */
/* method entry is redirected to a per-slot stub that probes x0/x1 for */
/* a Lua thread, then branches to the original function.               */
/* ------------------------------------------------------------------ */

#define TRAMP_SIZE 0x68
#define HOOKPAD_SIZE 0x4000
/* Slot index the pcall trampoline reports with (outside the 512-slot
 * vtable range so hook_check routes it to the deferred-exec path) */
#define PCALL_HOOK_SLOT 999
/* Dedicated region inside hook_pad for the pcall trampoline — kept
 * independent of g_tramp_area so it never clobbers vtable-lab stubs */
#define PCALL_TRAMP_OFF  0x2000
#define PCALL_TRAMP_SIZE 0x80

/* Executable scratch space inside our own __TEXT (arm64e forbids fresh
 * executable mmap without a JIT entitlement). Trampolines are written
 * here via RW->RX page flip. */
extern "C" unsigned char hook_pad[HOOKPAD_SIZE];
__asm__(".section __TEXT,__hookpad,regular\n"
        ".align 12\n"
        ".globl _hook_pad\n"
        "_hook_pad:\n"
        ".space 0x4000\n"
        ".subsections_via_symbols\n");

static uint32_t insn_stp_pre(int rt, int rt2, int rn, int imm) {
    int imm7 = (imm >> 3) & 0x7F;
    return 0xA9800000u | (uint32_t)(imm7 << 15) | (uint32_t)(rt2 << 10)
         | (uint32_t)(rn << 5) | (uint32_t)rt;
}

static uint32_t insn_str_pre(int rt, int rn, int imm) {
    return 0xF8000000u | (uint32_t)((imm & 0x1FF) << 12) | 0x400u
         | (uint32_t)(rn << 5) | (uint32_t)rt;
}

static uint32_t insn_ldp_post(int rt, int rt2, int rn, int imm) {
    int imm7 = (imm >> 3) & 0x7F;
    return 0xA8C00000u | (uint32_t)(imm7 << 15) | (uint32_t)(rt2 << 10)
         | (uint32_t)(rn << 5) | (uint32_t)rt;
}

static uint32_t insn_ldr_literal(int rt, uintptr_t pc, uintptr_t target) {
    int64_t imm19 = ((int64_t)target - (int64_t)pc) >> 2;
    return 0x58000000u | (uint32_t)((imm19 & 0x7FFFF) << 5) | (uint32_t)rt;
}

static uint32_t insn_blr(int rn)  { return 0xD63F0000u | (uint32_t)(rn << 5); }
static uint32_t insn_br(int rn)   { return 0xD61F0000u | (uint32_t)(rn << 5); }
static uint32_t insn_nop(void)    { return 0xD503201Fu; }

static void put_u32(uint8_t* p, uint32_t v) {
    memcpy(p, &v, 4);
}

static void put_quad(uint8_t* p, uint64_t v) {
    memcpy(p, &v, 8);
}

/* Hot-path hook callback. Runs inside the game's threads — must NOT do any
 * heavy work (no fprintf, no mutexes, no syscalls beyond the tt probe).
 * Results are parked in atomic mailboxes drained by hook_reporter_thread. */
static volatile uint64_t g_tramp_calls[512];
static volatile uint64_t g_tramp_total;
static volatile int g_tramp_dirty;
static volatile uintptr_t g_last_tramp_slot, g_last_tramp_x0, g_last_tramp_x1;
static volatile int g_vhook_dirty;
static volatile uintptr_t g_vhook_slot, g_vhook_addr;
static volatile int g_vhook_which, g_vhook_strict;

static void pcall_hook_entry(uintptr_t L);   /* defined with the arm machinery */

extern "C" void hook_check(uintptr_t x0, uintptr_t x1, uintptr_t slot_idx) {
    if (slot_idx == PCALL_HOOK_SLOT) {
        /* entry patch on the game's lua_pcall: x0 = the calling thread L.
         * Deferred-exec path — runs the staged chunk inline when armed. */
        pcall_hook_entry(x0);
        return;
    }
    if (slot_idx < 512) {
        uint64_t n = ++g_tramp_calls[slot_idx];
        if (n == 1) {
            g_last_tramp_slot = slot_idx;
            g_last_tramp_x0   = x0;
            g_last_tramp_x1   = x1;
            __atomic_store_n(&g_tramp_dirty, 1, __ATOMIC_RELEASE);
        }
    }
    if (g_hook_captured) return;

    uintptr_t cands[2] = { x1, x0 }; /* arg first, then this */
    for (int i = 0; i < 2; i++) {
        uintptr_t c = cands[i];
        if (c < 0x100000000ULL || c > 0x74000000000ULL) continue;
        if ((c % 8) != 0) continue;

        uint8_t buf[0x50];
        if (!safe_read(c, buf, sizeof(buf))) continue;
        if (buf[0] != 0xA) continue;   /* tt @ +0 (0.740) */

        bool strict = looks_like_lua_state_safe(c);
        g_vhook_slot   = slot_idx;
        g_vhook_addr   = c;
        g_vhook_which  = i;
        g_vhook_strict = strict ? 1 : 0;
        __atomic_store_n(&g_vhook_dirty, 1, __ATOMIC_RELEASE);

        if (strict) {
            pthread_mutex_lock(&g_exec_mutex);
            if (!g_game_lua_state) {
                g_game_lua_state = (lua_State*)c;
                g_hook_captured = 1;
                LOG_CORE("CAPTURED game lua_State @ %p via vtable slot %lu",
                         (void*)c, (unsigned long)slot_idx);
            }
            pthread_mutex_unlock(&g_exec_mutex);
            return;
        }
    }
}

static void* hook_reporter_thread(void* arg) {
    (void)arg;
    uint64_t ticks = 0;
    for (;;) {
        if (__atomic_exchange_n(&g_tramp_dirty, 0, __ATOMIC_ACQUIRE)) {
            LOG_CORE("TRAMP call slot=%lu x0=%p x1=%p",
                     (unsigned long)g_last_tramp_slot,
                     (void*)g_last_tramp_x0, (void*)g_last_tramp_x1);
        }
        if (__atomic_exchange_n(&g_vhook_dirty, 0, __ATOMIC_ACQUIRE)) {
            LOG_CORE("VHOOK slot=%-4lu %s candidate lua_State @ %p tt=9 strict=%s",
                     (unsigned long)g_vhook_slot, g_vhook_which == 0 ? "x1" : "x0",
                     (void*)g_vhook_addr, g_vhook_strict ? "YES" : "no");
        }
        if ((ticks++ % 60) == 0) {
            pthread_mutex_lock(&g_exec_mutex);
            lua_State* L = g_game_lua_state;
            pthread_mutex_unlock(&g_exec_mutex);
            if (L && !looks_like_lua_state_safe((uintptr_t)L)) {
                pthread_mutex_lock(&g_exec_mutex);
                if (g_game_lua_state == L) {
                    g_game_lua_state = NULL;
                    g_hook_captured = 0;
                    LOG_CORE("REVALIDATE FAIL: lua_State @ %p no longer valid — cleared",
                             (void*)L);
                }
                pthread_mutex_unlock(&g_exec_mutex);
            }
        }
        usleep(50000);
    }
    return NULL;
}

static bool make_vtable_writable(uintptr_t page) {
    kern_return_t kr = mach_vm_protect(mach_task_self(), (mach_vm_address_t)page,
                                       0x4000, false,
                                       VM_PROT_READ | VM_PROT_WRITE);
    if (kr != KERN_SUCCESS) {
        LOG_CORE("mprotect vtable page failed (kr=%d), trying VM_PROT_COPY", kr);
        kr = mach_vm_protect(mach_task_self(), (mach_vm_address_t)page,
                             0x4000, false,
                             VM_PROT_READ | VM_PROT_WRITE | VM_PROT_COPY);
        if (kr != KERN_SUCCESS) {
            LOG_CORE("mprotect VM_PROT_COPY failed too (kr=%d)", kr);
            return false;
        }
    }
    LOG_CORE("vtable page %p now writable", (void*)page);
    return true;
}

/* Dump live vtable slots (masked + raw, to spot PAC signatures) and
 * verify the page can be made writable. Returns number of slots. */
extern "C" int executor_vtable_lab(char* buf, size_t len) {
    size_t off = 0;
#define LAB_PRINT(...) \
    do { int n = snprintf(buf + off, len - off, __VA_ARGS__); \
         if (n > 0) off += (size_t)n; } while (0)

    if (!g_vtable_data) {
        snprintf(buf, len, "vtable not located yet (hunter still running or failed)");
        return -1;
    }

    uintptr_t page = g_vtable_data & ~0xFFFULL;
    bool writable = make_vtable_writable(page);

    int nslots = 0;
    for (int i = 0; i < 256; i++) {
        uintptr_t slot = g_vtable_data + (uintptr_t)i * 8;
        uintptr_t v = 0;
        if (!safe_read(slot, &v, 8)) break;
        uintptr_t masked = v & PTR_MASK;
        if (masked < 0x100000000ULL || masked > 0x74000000000ULL) {
            if (nslots > 0) break; /* data after code slots */
            continue;
        }
        g_vtable_orig[nslots] = v;
        nslots++;
    }
    g_vtable_nslots = nslots;
    LAB_PRINT("vtable=%p writable=%s nslots=%d\n", (void*)g_vtable_data,
              writable ? "yes" : "no", nslots);
    for (int i = 0; i < nslots && i < 16; i++) {
        LAB_PRINT("  slot %3d raw=%016llx mask=%010llx\n", i,
                  (unsigned long long)g_vtable_orig[i],
                  (unsigned long long)(g_vtable_orig[i] & PTR_MASK));
    }
    return nslots;
#undef LAB_PRINT
}

static uintptr_t build_trampoline(uint8_t* area, uintptr_t slot_idx,
                                  uintptr_t orig_addr, uintptr_t check_addr) {
    uint8_t* t = area;
    uintptr_t taddr = (uintptr_t)t;
    put_u32(t + 0x00, insn_stp_pre(0, 1, 31, -16));
    put_u32(t + 0x04, insn_stp_pre(2, 3, 31, -16));
    put_u32(t + 0x08, insn_stp_pre(4, 5, 31, -16));
    put_u32(t + 0x0c, insn_stp_pre(6, 7, 31, -16));
    put_u32(t + 0x10, insn_str_pre(30, 31, -16)); /* save x30 (blr clobbers it) */
    put_u32(t + 0x14, insn_ldr_literal(17, taddr + 0x14, taddr + 0x60)); /* check */
    put_u32(t + 0x18, insn_ldr_literal(2, taddr + 0x18, taddr + 0x50));  /* slot */
    put_u32(t + 0x1c, insn_blr(17));
    put_u32(t + 0x20, insn_ldp_post(30, 31, 31, 16)); /* restore x30 */
    put_u32(t + 0x24, insn_ldp_post(6, 7, 31, 16));
    put_u32(t + 0x28, insn_ldp_post(4, 5, 31, 16));
    put_u32(t + 0x2c, insn_ldp_post(2, 3, 31, 16));
    put_u32(t + 0x30, insn_ldp_post(0, 1, 31, 16));
    put_u32(t + 0x34, insn_ldr_literal(16, taddr + 0x34, taddr + 0x58)); /* orig */
    put_u32(t + 0x38, insn_br(16));
    put_u32(t + 0x3c, insn_nop());
    put_u32(t + 0x40, insn_nop());
    put_u32(t + 0x44, insn_nop());
    put_u32(t + 0x48, insn_nop());
    put_u32(t + 0x4c, insn_nop());
    put_quad(t + 0x50, slot_idx);
    put_quad(t + 0x58, orig_addr);
    put_quad(t + 0x60, check_addr);
    __builtin___clear_cache((char*)t, (char*)t + TRAMP_SIZE);
    return taddr;
}

extern "C" int executor_hook_vtable(int first, int last, char* buf, size_t len) {
    if (!g_vtable_data) {
        snprintf(buf, len, "ERR: vtable not located");
        return -1;
    }
    if (g_hook_active) {
        snprintf(buf, len, "ERR: hooks already active");
        return -1;
    }
    uintptr_t page = g_vtable_data & ~0xFFFULL;
    if (!make_vtable_writable(page)) {
        snprintf(buf, len, "ERR: cannot make vtable page writable");
        return -1;
    }
    if (first < 0) first = 0;
    if (last < 0 || last >= 512) last = 511;
    if (g_vtable_nslots == 0) {
        for (int i = 0; i < 512; i++) {
            uintptr_t v = 0;
            if (!safe_read(g_vtable_data + (uintptr_t)i * 8, &v, 8)) break;
            g_vtable_orig[i] = v;
            g_vtable_nslots = i + 1;
        }
    }
    if (last >= g_vtable_nslots) last = g_vtable_nslots - 1;

    int count = last - first + 1;
    int need = count * TRAMP_SIZE;
    if (need > HOOKPAD_SIZE) {
        snprintf(buf, len, "ERR: %d slots need %d bytes > hookpad %d", count, need, HOOKPAD_SIZE);
        return -1;
    }
    if (!g_tramp_area) {
        g_tramp_area = (uintptr_t)hook_pad;
        g_tramp_area_size = HOOKPAD_SIZE;
    }
    {
        /* hookpad may still be RX from a previous hook cycle — always flip to RW */
        uintptr_t p = g_tramp_area & ~0xFFFULL;
        kern_return_t kr = mach_vm_protect(mach_task_self(), (mach_vm_address_t)p,
                                           HOOKPAD_SIZE + 0xFFF, false,
                                           VM_PROT_READ | VM_PROT_WRITE);
        if (kr != KERN_SUCCESS) {
            snprintf(buf, len, "ERR: mprotect hookpad RW failed (kr=%d)", kr);
            return -1;
        }
        LOG_CORE("hookpad %p -> RW", (void*)g_tramp_area);
    }

    uintptr_t check_addr = (uintptr_t)&hook_check;
    uint8_t* area = (uint8_t*)g_tramp_area;
    for (int i = first; i <= last; i++) {
        uintptr_t orig = g_vtable_orig[i] & PTR_MASK;
        uintptr_t tramp = build_trampoline(area + (uintptr_t)(i - first) * TRAMP_SIZE,
                                           (uintptr_t)i, orig, check_addr);
        uintptr_t slot = g_vtable_data + (uintptr_t)i * 8;
        uintptr_t stored = *(volatile uintptr_t*)slot;
        *(volatile uintptr_t*)slot = tramp;
        uintptr_t readback = *(volatile uintptr_t*)slot;
        LOG_CORE("HOOK slot %3d: %010lx -> %010lx (stored=%010lx rb=%010lx)",
                 i, orig, tramp, stored & PTR_MASK, readback & PTR_MASK);
    }
    {
        uintptr_t p = g_tramp_area & ~0xFFFULL;
        kern_return_t kr = mach_vm_protect(mach_task_self(), (mach_vm_address_t)p,
                                           HOOKPAD_SIZE + 0xFFF, false,
                                           VM_PROT_READ | VM_PROT_EXECUTE);
        if (kr != KERN_SUCCESS) {
            snprintf(buf, len, "ERR: mprotect hookpad back to RX failed (kr=%d)", kr);
            return -1;
        }
        LOG_CORE("hookpad -> RX");
    }
    g_hook_active = 1;
    g_hook_captured = 0;
    int n = snprintf(buf, len, "OK: hooked %d slots (%d..%d), check=%p, tramp_area=%p",
                     count, first, last, (void*)check_addr, (void*)g_tramp_area);
    return n;
}

extern "C" uintptr_t executor_image_slide(void) {
    return g_text_base ? (g_text_base - 0x100000000ULL) : 0;
}

/* ==================================================================== */
/* Version-agnostic symbol resolution + version guard.                  */
/*                                                                      */
/* Every link-time address in this file was captured from one client    */
/* build. Roblox re-links on every update, so a stale constant silently */
/* points into whatever now lives at that offset — the failure mode is  */
/* a crash in the middle of a resume, indistinguishable from a real     */
/* bug. `LEGACY_CLIENT_VERSION` pins the only build the constants are   */
/* valid for; on anything else a symbol must come from the resolver     */
/* (luau_resolver.h) or the call is refused with the exact name of what */
/* could not be resolved.                                              */
/* ==================================================================== */

#define LEGACY_CLIENT_VERSION "0.735.0.7351131"

enum {
    EXEC_FN_NEWTHREAD = 0,
    EXEC_FN_RESUME,
    EXEC_FN_BUfload,
    EXEC_FN_PCALL,
    EXEC_FN_RAWLOAD,
    EXEC_FN_COMPILE,
    EXEC_FN_INTERN,
    EXEC_FN_LOADSTRING,
    EXEC_FN_COUNT
};

typedef struct {
    const char* name;      /* how the exec pipeline refers to it */
    const char* sym;       /* name in lr_symbol_table, NULL = no anchor */
    uintptr_t   legacy;    /* link-time address valid only for the legacy build */
    uintptr_t   resolved;  /* runtime address from the resolver */
    int         tried;     /* resolution is a full code scan — run it once */
} exec_fn_t;

static exec_fn_t g_exec_fn[EXEC_FN_COUNT] = {
    { "lua_newthread", "lua_newthread", 0, 0, 0 },
    { "lua_resume",    "lua_resume",    0, 0, 0 },
    { "luau_load",     "luau_load",     0, 0, 0 },
    { "lua_pcall",     "lua_pcall",     0, 0, 0 },
    { "rawload",       "rawload",       0, 0, 0 },
    { "compile",       "compile",       0, 0, 0 },
    { "luaS_newlstr",  NULL,            0, 0, 0 },
    { "loadstring",    "loadstring",    0, 0, 0 },
};

static char    g_client_version[64];
static uint8_t g_image_uuid[16];
static int     g_version_state = 0;   /* 0 = not tried, 1 = ok, -1 = failed */

/* /Applications/Roblox.app/Contents/MacOS/RobloxPlayer -> .../Contents/Info.plist
 * Both XML and binary plists keep the version as plain ASCII digits, so a
 * scan for the first N.N.N.N token after CFBundleVersion works for either. */
static void read_client_version(void) {
    if (g_version_state) return;
    g_version_state = -1;
    char exe[1024];
    uint32_t exe_len = sizeof(exe);
    if (_NSGetExecutablePath(exe, &exe_len) != 0) return;
    char* p = strrchr(exe, '/');
    if (!p) return;
    *p = 0;
    p = strrchr(exe, '/');
    if (!p) return;
    snprintf(p, sizeof(exe) - (size_t)(p - exe), "/Info.plist");

    int fd = open(exe, O_RDONLY);
    if (fd < 0) {
        LOG_CORE("VER: cannot open %s", exe);
        return;
    }
    static char buf[256 * 1024];   /* too big for a payload thread's stack */
    ssize_t got = read(fd, buf, sizeof(buf) - 1);
    close(fd);
    if (got <= 0) return;
    buf[got] = 0;

    const char* hay = strstr(buf, "CFBundleVersion");
    if (!hay) hay = buf;
    for (const char* q = hay; *q; q++) {
        if (!isdigit((unsigned char)*q)) continue;
        if (q != hay && (isdigit((unsigned char)q[-1]) || q[-1] == '.')) continue;
        const char* scan = q;
        int parts = 0;
        while (parts < 4) {
            int digits = 0;
            while (isdigit((unsigned char)*scan)) { scan++; digits++; }
            if (digits < 1 || digits > 5) break;
            parts++;
            if (parts < 4) {
                if (*scan != '.') break;
                scan++;
            }
        }
        if (parts == 4) {
            size_t len = (size_t)(scan - q);
            if (len < sizeof(g_client_version)) {
                memcpy(g_client_version, q, len);
                g_client_version[len] = 0;
                g_version_state = 1;
                return;
            }
        }
    }
}

extern "C" const char* executor_client_version(void) {
    read_client_version();
    return g_client_version[0] ? g_client_version : "unknown";
}

static void read_image_uuid(void) {
    static int done = 0;
    if (done) return;
    done = 1;
    const struct mach_header_64* hdr = find_roblox_header();
    if (!hdr) return;
    const struct load_command* lc = (const struct load_command*)(hdr + 1);
    for (uint32_t i = 0; i < hdr->ncmds; i++) {
        if (lc->cmd == LC_UUID) {
            memcpy(g_image_uuid, ((const struct uuid_command*)lc)->uuid, 16);
            return;
        }
        lc = (const struct load_command*)((const uint8_t*)lc + lc->cmdsize);
    }
}

/* One lr_image_t over the live RobloxPlayer image: runtime addresses, reads
 * through the kernel, chunk buffer for the scans. */
static lr_section_t g_img_sections[LR_MAX_SECTIONS];
static int          g_img_nsections = 0;
static uint8_t*     g_img_scratch = NULL;
static lr_image_t   g_img;
static int          g_img_state = 0;  /* 0 = not built, 1 = ok, -1 = failed */

static int img_reader(void* ctx, uintptr_t addr, void* dst, size_t len) {
    (void)ctx;
    return safe_read(addr, dst, len) ? 1 : 0;
}

static int build_self_image(void) {
    if (g_img_state) return g_img_state > 0;
    g_img_state = -1;
    const struct mach_header_64* hdr = find_roblox_header();
    if (!hdr) return 0;

    uintptr_t slide = 0;
    const struct load_command* lc = (const struct load_command*)(hdr + 1);
    for (uint32_t i = 0; i < hdr->ncmds; i++) {
        if (lc->cmd == LC_SEGMENT_64) {
            const struct segment_command_64* seg = (const struct segment_command_64*)lc;
            if (strncmp(seg->segname, "__TEXT", 16) == 0) {
                slide = (uintptr_t)hdr - seg->vmaddr;
                break;
            }
        }
        lc = (const struct load_command*)((const uint8_t*)lc + lc->cmdsize);
    }

    int n = 0;
    lc = (const struct load_command*)(hdr + 1);
    for (uint32_t i = 0; i < hdr->ncmds && n < LR_MAX_SECTIONS; i++) {
        if (lc->cmd == LC_SEGMENT_64) {
            const struct segment_command_64* seg = (const struct segment_command_64*)lc;
            const struct section_64* sects = (const struct section_64*)(seg + 1);
            for (uint32_t s = 0; s < seg->nsects && n < LR_MAX_SECTIONS; s++) {
                const struct section_64* sec = &sects[s];
                uint32_t type = sec->flags & SECTION_TYPE;
                if (type == S_ZEROFILL || type == S_THREAD_LOCAL_ZEROFILL) continue;
                if (sec->size < 4) continue;
                uintptr_t addr = sec->addr + slide;
                if (!is_memory_readable(addr) ||
                    !is_memory_readable(addr + sec->size - 4)) continue;
                g_img_sections[n].vmaddr = addr;
                g_img_sections[n].size   = sec->size;
                g_img_sections[n].is_code =
                    (sec->flags & (S_ATTR_PURE_INSTRUCTIONS | S_ATTR_SOME_INSTRUCTIONS)) != 0;
                g_img_sections[n].label  = NULL;
                n++;
            }
        }
        lc = (const struct load_command*)((const uint8_t*)lc + lc->cmdsize);
    }
    if (!n) {
        LOG_CORE("RESOLVE: no usable sections in the image");
        return 0;
    }
    if (!g_img_scratch) g_img_scratch = (uint8_t*)malloc(1 << 20);
    if (!g_img_scratch) return 0;

    g_img_nsections  = n;
    g_img.sections   = g_img_sections;
    g_img.n_sections = n;
    g_img.read       = img_reader;
    g_img.ctx        = NULL;
    g_img.scratch    = g_img_scratch;
    g_img.scratch_len = 1 << 20;
    g_img_state = 1;
    return 1;
}

static int legacy_client(void) {
    read_client_version();
    return g_client_version[0] &&
           strcmp(g_client_version, LEGACY_CLIENT_VERSION) == 0;
}

static uintptr_t resolve_one(const char* sym_name, int* status_out) {
    if (status_out) *status_out = LR_ERR_NO_IMAGE;
    if (!sym_name || !build_self_image()) return 0;
    const lr_symbol_t* sym = lr_symbol_by_name(sym_name);
    if (!sym) return 0;
    lr_sym_result_t r;
    int rc = lr_resolve_symbol(&g_img, sym, &r);
    if (status_out) *status_out = rc;
    if (rc != LR_OK || !r.res.fn) return 0;
    if (!lr_section_for(&g_img, r.res.fn, 1)) return 0;
    return r.res.fn;
}

static uintptr_t resolve_pipeline_symbol(int which) {
    if (which < 0 || which >= EXEC_FN_COUNT) return 0;
    exec_fn_t* f = &g_exec_fn[which];
    if (f->resolved) return f->resolved;
    if (f->sym) {
        f->resolved = resolve_one(f->sym, NULL);
    }
    if (!f->resolved) {
        if (!build_self_image()) return 0;
        if (strcmp(f->name, "lua_newthread") == 0) {
            lr_newthread_result_t nt;
            if (lr_derive_newthread(&g_img, &nt) == LR_OK && nt.fn) f->resolved = nt.fn;
        } else if (strcmp(f->name, "lua_pcall") == 0) {
            uintptr_t pcall_fn = 0, xpcall_fn = 0;
            if (lr_derive_pcall(&g_img, &pcall_fn, &xpcall_fn) == LR_OK) f->resolved = pcall_fn;
        } else if (strcmp(f->name, "rawload") == 0 || strcmp(f->name, "compile") == 0) {
            uintptr_t ls_wrapper = 0, luau_load_fn = 0;
            const lr_symbol_t* s_ls  = lr_symbol_by_name("loadstring");
            const lr_symbol_t* s_lld = lr_symbol_by_name("luau_load");
            if (s_ls) {
                lr_sym_result_t r;
                if (lr_resolve_symbol(&g_img, s_ls, &r) == LR_OK) ls_wrapper = r.res.fn;
            }
            if (s_lld) {
                lr_sym_result_t r;
                if (lr_resolve_symbol(&g_img, s_lld, &r) == LR_OK) luau_load_fn = r.res.fn;
            }
            uintptr_t rawload = lr_derive_rawload(&g_img, luau_load_fn, ls_wrapper);
            uintptr_t comp = lr_derive_compile(&g_img, ls_wrapper, rawload);
            g_exec_fn[EXEC_FN_RAWLOAD].resolved = rawload;
            g_exec_fn[EXEC_FN_COMPILE].resolved = comp;
        } else if (strcmp(f->name, "lua_resume") == 0) {
            uintptr_t res = lr_derive_resume(&g_img);
            if (res) f->resolved = res;
        }
    }
    return f->resolved;
}

/* Runtime address of a symbol the exec pipeline needs, or 0 when it cannot be
 * resolved on this client build. The legacy constant is only ever used when
 * the client really is the build it came from. */
static uintptr_t exec_fn_addr(int which) {
    if (which < 0 || which >= EXEC_FN_COUNT) return 0;
    exec_fn_t* f = &g_exec_fn[which];
    if (!f->tried) {
        f->tried = 1;
        resolve_pipeline_symbol(which);
    }
    if (f->resolved) return f->resolved;
    if (f->legacy && legacy_client()) {
        LOG_CORE("RESOLVE: %s via legacy %s constant (client matches)",
                 f->name, LEGACY_CLIENT_VERSION);
        return f->legacy + executor_image_slide();
    }
    if (f->legacy && !legacy_client())
        LOG_CORE("RESOLVE: %s unresolved on client %s — legacy constant %#llx is "
                 "NOT valid here and was refused",
                 f->name, executor_client_version(),
                 (unsigned long long)(f->legacy + executor_image_slide()));
    return 0;
}

extern "C" int executor_resolve(char* buf, size_t len) {
    int n = 0;
    read_client_version();
    read_image_uuid();
    if (!build_self_image()) {
        return snprintf(buf, len, "ERR: cannot build an image view of RobloxPlayer\n");
    }
    uintptr_t text_lo = 0, text_hi = 0;
    for (int i = 0; i < g_img_nsections; i++) {
        if (!g_img_sections[i].is_code) continue;
        if (!text_lo || g_img_sections[i].vmaddr < text_lo) text_lo = g_img_sections[i].vmaddr;
        uintptr_t end = g_img_sections[i].vmaddr + g_img_sections[i].size;
        if (end > text_hi) text_hi = end;
    }
    n += snprintf(buf + n, len - n,
                  "client=%s  uuid=%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x\n"
                  "slide=%#lx  sections=%d  code=%#lx-%#lx\n"
                  "legacy constants valid for: %s (%s)\n\n",
                  executor_client_version(),
                  g_image_uuid[0], g_image_uuid[1], g_image_uuid[2], g_image_uuid[3],
                  g_image_uuid[4], g_image_uuid[5], g_image_uuid[6], g_image_uuid[7],
                  g_image_uuid[8], g_image_uuid[9], g_image_uuid[10], g_image_uuid[11],
                  g_image_uuid[12], g_image_uuid[13], g_image_uuid[14], g_image_uuid[15],
                  (unsigned long)executor_image_slide(), g_img_nsections,
                  (unsigned long)text_lo, (unsigned long)text_hi,
                  LEGACY_CLIENT_VERSION,
                  legacy_client() ? "MATCHES running client" : "does NOT match running client");

    n += snprintf(buf + n, len - n, "-- anchor resolution --\n");
    for (int i = 0; i < LR_SYMBOL_COUNT && n < (int)len - 256; i++) {
        lr_sym_result_t r;
        int rc = lr_resolve_symbol(&g_img, &lr_symbol_table[i], &r);
        if (rc == LR_OK && r.res.fn) {
            n += snprintf(buf + n, len - n,
                          "%-15s @ %#lx  exact=%d/%d  fns=%d  verified=%d%s\n",
                          r.name, (unsigned long)r.res.fn, r.res.xrefs,
                          r.res.occurrences, r.res.distinct_fn, r.verified_extra,
                          r.res.boundary_proven ? "" : " [entry unproven]");
        } else {
            const char* why = rc == LR_ERR_NO_ANCHOR ? "no anchor for this symbol" :
                              rc == LR_ERR_NO_STRING ? "anchor string absent" :
                              rc == LR_ERR_NO_XREF   ? "no confirmed code xref" :
                              rc == LR_ERR_NO_PROLOGUE ? "no function entry found" :
                                                        "unresolved";
            n += snprintf(buf + n, len - n, "%-15s -- %s\n", r.name, why);
        }
    }

    n += snprintf(buf + n, len - n, "\n-- exec pipeline --\n");
    int missing = 0;
    for (int i = 0; i < EXEC_FN_COUNT; i++) {
        exec_fn_t* f = &g_exec_fn[i];
        f->tried = 1;
        resolve_pipeline_symbol(i);
        if (f->resolved) {
            n += snprintf(buf + n, len - n, "%-15s OK    %#lx%s\n",
                          f->name, (unsigned long)f->resolved,
                          f->sym ? "" : " (derived)");
        } else if (!legacy_client() && f->legacy) {
            missing++;
            n += snprintf(buf + n, len - n,
                          "%-15s MISSING (legacy %#llx refused: client %s)\n",
                          f->name, (unsigned long long)f->legacy,
                          executor_client_version());
        } else {
            n += snprintf(buf + n, len - n, "%-15s (no legacy constant)\n", f->name);
        }
    }
    n += snprintf(buf + n, len - n,
                  "\nverdict: %s\n",
                  missing == 0 ? "execution symbols available" :
                                 "execution blocked until the missing symbols are derived "
                                 "(no legacy constant will be substituted)");
    return n;
}

/* First pass over RW regions looking for a tt==9 thread object.
 * Mutual-reference invariant 0.739: [L+0x48] == G and [G+0x90] == L
 * (proved offline: lua_pushthread tail reads [x0+0x48] then [x8+0x90]).
 * Chunk-local reads only. */
static uintptr_t g_tt9_cands[24];
static int g_tt9_count = 0;
/* known real threads (validated layout) and cross-references to them */
static uintptr_t g_thr[64];
static int g_thr_n = 0;
static uintptr_t g_thr_min = 0xffffffffffffffffULL, g_thr_max = 0;
static uintptr_t g_ref_addr[128];
static uintptr_t g_harvested_cont = 0;
static uintptr_t g_ref_thr[128];
static int g_ref_n = 0;

static void thr_register(uintptr_t L) {
    for (int q = 0; q < g_thr_n; q++)
        if (g_thr[q] == L) return;
    if (g_thr_n >= 64) return;
    g_thr[g_thr_n++] = L;
    if (L < g_thr_min) g_thr_min = L;
    if (L > g_thr_max) g_thr_max = L;
}

#define MAX_LIVE_CANDS 512
static uintptr_t g_live_L[MAX_LIVE_CANDS];
static uintptr_t g_live_ss[MAX_LIVE_CANDS];
static uintptr_t g_live_stack[MAX_LIVE_CANDS];
static uintptr_t g_live_top[MAX_LIVE_CANDS];
static uint64_t  g_live_tp[MAX_LIVE_CANDS];
static int       g_live_pri[MAX_LIVE_CANDS];
static int g_live_n = 0;

static void find_live_thread(void) {
    g_live_n = 0;
    int dbg_str = 0;
    int dbg_g2 = 0;
    int dbg_bs = 0;
    int dbg_far = 0;
    static uintptr_t g_coro_G[16];
    static uint32_t g_coro_cnt[16];
    int g_coro_n = 0;
    int coro_stored = 0;
    uintptr_t gbest = 0;
    int bestn = 0;
    /* scan wall-clock baseline shared by the pass and region-loop checks */
    static mach_timebase_info_data_t tb_s;
    static int tb_s_init = 0;
    if (!tb_s_init) { mach_timebase_info(&tb_s); tb_s_init = 1; }
    uint64_t scan_t0 = mach_absolute_time();
    for (int pass = 0; pass < 8; pass++) {
        LOG_CORE("EXEC: scan pass %d", pass);
        {
            uint64_t now = mach_absolute_time();
            double elapsed = (double)(now - scan_t0) * (double)tb_s.numer /
                             ((double)tb_s.denom * 1e9);
            if (elapsed > 150.0) {
                LOG_CORE("EXEC: scan deadline hit (%.1fs) — stopping", elapsed);
                break;
            }
        }
        /* pick the most frequent G seen among fresh coroutines */
        for (int q = 0; q < g_coro_n; q++)
            if (g_coro_cnt[q] > bestn) { bestn = g_coro_cnt[q]; gbest = g_coro_G[q]; }
        /* direct deterministic mainthreads of ALL lua universes:
         * every distinct G seen among fresh coroutines contributes its
         * [G+0x90] mainthread (0.739 offset; 0.735 used 0x88); loadstring
         * availability differs per universe */
        {
            int stored_mains = 0;
            for (int q = 0; q < g_coro_n && stored_mains < 8; q++) {
                uintptr_t gb2 = g_coro_G[q];
                if (gb2 < 0x100000000ULL || gb2 > 0x74000000000ULL || (gb2 & 0xF) != 0)
                    continue;
                uintptr_t mt = 0;
                safe_read(gb2 + 0x90, &mt, 8);
                if (mt < 0x100000000ULL || mt > 0x74000000000ULL || (mt & 0xF) != 0) {
                    LOG_CORE("EXEC: u=%d g=%p bad mt=%#llx", q, (void*)gb2,
                             (unsigned long long)mt);
                    continue;
                }
                uintptr_t mg = 0;
                safe_read(mt + 0x48, &mg, 8);
                if (mg != gb2) {
                    LOG_CORE("EXEC: u=%d mt=%p backref=%#llx != g", q, (void*)mt,
                             (unsigned long long)mg);
                    continue;
                }
                /* prefer the majority universe first */
                int pri_m = 200 - q * 5 + (gb2 == gbest ? 50 : 0);
                int dupm = -1;
                for (int z = 0; z < g_live_n; z++)
                    if (g_live_L[z] == mt) { dupm = z; break; }
                if (dupm >= 0) {
                    /* already stored by Phase B — just promote it */
                    g_live_pri[dupm] = pri_m;
                    LOG_CORE("EXEC: EXECMAIN u=%d PROMOTED idx=%d mt=%p pri=%d",
                             q, dupm, (void*)mt, pri_m);
                    stored_mains++;
                    continue;
                }
                if (g_live_n < MAX_LIVE_CANDS) {
                    uintptr_t mstk = 0, mtop = 0, mci = 0;
                    safe_read(mt + 0x38, &mstk, 8);
                    safe_read(mt + 0x58, &mtop, 8);
                    safe_read(mt + 0x50, &mci, 8);
                    if ((mtop >> 56) == 0xca)
                        mtop = ((mtop >> 32) & 0xffffff) << 32 | (mtop & 0xffffffff);
                    if (mstk >= 0x100000000ULL && mstk <= 0x74000000000ULL &&
                        mtop >= mstk && mtop <= 0x74000000000ULL &&
                        (mtop - mstk) <= 0x400000ULL) {
                        g_live_L[g_live_n] = mt;
                        g_live_ss[g_live_n] = mci;
                        g_live_stack[g_live_n] = mstk;
                        g_live_top[g_live_n] = mtop;
                        g_live_tp[g_live_n] = mtop;
                        g_live_pri[g_live_n] = pri_m;
                        LOG_CORE("EXEC: EXECMAIN u=%d mt=%p g=%p stk=%#llx top=%#llx pri=%d",
                                 q, (void*)mt, (void*)gb2,
                                 (unsigned long long)mstk,
                                 (unsigned long long)mtop, pri_m);
                        g_live_n++;
                        stored_mains++;
                    }
                }
            }
        }
        uint32_t c_tt9 = 0, c_g = 0;
        uint32_t c_ptr = 0, c_d = 0, c_span = 0, c_gread = 0, c_gsize = 0, c_final = 0;
        /* ascending walk (descending probes never reach the malloc heap
         * through the read-only mappings at the top of the space).
         * Each pass covers a DIFFERENT slice of the address space so the
         * 8 passes together cover the whole heap within the deadline. */
        const uint64_t span_lo = 0x100000000ULL;
        const uint64_t span_hi = 0x74000000000ULL;
        const uint64_t step = (span_hi - span_lo) / 8;
        mach_vm_address_t addr = span_lo + (uint64_t)pass * step;
        mach_vm_address_t addr_hi = (pass < 7) ? (addr + step) : span_hi;
        mach_vm_size_t size = 0;
        while (1) {
            mach_msg_type_number_t cnt = VM_REGION_BASIC_INFO_COUNT_64;
            vm_region_basic_info_data_64_t info;
            mach_port_t object_name = 0;
            kern_return_t kr = mach_vm_region(mach_task_self(), &addr, &size,
                                              VM_REGION_BASIC_INFO_64,
                                              (vm_region_info_t)&info, &cnt, &object_name);
            if (kr != KERN_SUCCESS) break;
            if (!(info.protection & VM_PROT_READ) || !(info.protection & VM_PROT_WRITE) ||
                addr < 0x100000000ULL || addr >= 0x74000000000ULL ||
                size < 0x4000 || size >= 0x80000000ULL) {
                addr += size;
                continue;
            }
                uint8_t* chunk = (uint8_t*)malloc(1 << 20);
                if (!chunk) break;
                mach_vm_size_t done = 0;
                while (done + (1 << 20) <= size) {
                    /* region-loop deadline: a single huge region must not
                     * wedge the IPC thread either */
                    {
                        uint64_t now2 = mach_absolute_time();
                        double el2 = (double)(now2 - scan_t0) * (double)tb_s.numer /
                                     ((double)tb_s.denom * 1e9);
                        if (el2 > 155.0) {
                            LOG_CORE("EXEC: region-loop deadline (%.1fs) — aborting scan", el2);
                            free(chunk);
                            goto scan_done;
                        }
                    }
                    mach_vm_size_t got = 0;
                    uintptr_t cbase = addr + done;
                    if (mach_vm_read_overwrite(mach_task_self(), cbase,
                                               (1 << 20), (mach_vm_address_t)chunk,
                                               &got) != KERN_SUCCESS) break;
                    for (mach_vm_size_t i = 0; i + 0x88 <= got; i += 8) {
                        uintptr_t L = cbase + i;
                        if ((L & 0xF) != 0) continue;
                        if (chunk[i + LUA_TT_OFF] != 0xA) continue;   /* tt @ +1 (0.741) */
                        c_tt9++;
                        /* 0.741 layout (luaE_newthread + stack_init + tothread):
                         * tt@+1, status@+3, magic(u32)^0x2d@+0x18, G@+0x68,
                         * base@+0x60, top@+0x70, stack@+0x78, last@+0x80.
                         * The old 8-vs-9 tt contradiction here made this
                         * function return false unconditionally. */
                        uintptr_t g   = *(uintptr_t*)(chunk + i + LUA_G_OFF);
                        uintptr_t stk = *(uintptr_t*)(chunk + i + LUA_STACK_OFF);
                        uintptr_t lci = *(uintptr_t*)(chunk + i + LUA_INNER_OFF);
                        uintptr_t top = *(uintptr_t*)(chunk + i + LUA_TOP_OFF);
                        if ((top >> 56) == 0xca)
                            top = ((top >> 32) & 0xffffff) << 32 | (top & 0xffffffff);
                        if (g < 0x100000000ULL || g > 0x74000000000ULL) continue;
                        if (stk < 0x100000000ULL || stk > 0x74000000000ULL) continue;
                        if (lci < 0x100000000ULL || lci > 0x74000000000ULL) continue;
                        if (top < 0x100000000ULL || top > 0x74000000000ULL) continue;
                        if ((g & 0xF) != 0) continue;
                        c_ptr++;
                        /* reference scan: qwords pointing at known threads;
                         * the main thread is referenced from binary __DATA */
                        if (g_thr_n > 0) {
                            uint64_t v0 = *(uint64_t*)(chunk + i);
                            if (v0 >= g_thr_min && v0 <= g_thr_max) {
                                for (int q = 0; q < g_thr_n; q++) {
                                    if (g_thr[q] != v0) continue;
                                    if (g_ref_n < 128) {
                                        g_ref_addr[g_ref_n] = cbase + i;
                                        g_ref_thr[g_ref_n] = v0;
                                        g_ref_n++;
                                        LOG_CORE("EXEC: THRREF at=%p thr=%p",
                                                 (void*)(cbase + i), (void*)v0);
                                    }
                                    break;
                                }
                            }
                        }
                         /* ---- fast path (0.741): magic + structure + G-strt ---- */
                        {
                            int pri = 8;
                            uint32_t magic = *(uint32_t*)(chunk + i + LUA_MAGIC_OFF);
                            if (magic == ((uint32_t)((L + LUA_MAGIC_OFF) & 0xffffffffULL) ^ 0x2du))
                                pri += 16;
                            uintptr_t blk = *(uintptr_t*)(chunk + i + LUA_STACK_OFF);
                            uintptr_t lim = *(uintptr_t*)(chunk + i + LUA_SLAST_OFF);
                            if (blk >= 0x100000000ULL && blk <= 0x74000000000ULL &&
                                lim > blk && lim - blk <= 0x100000ULL) {
                                pri += 8;
                                if (*(uintptr_t*)(chunk + i + LUA_INNER_OFF) ==
                                    *(uintptr_t*)(chunk + i + LUA_INNER_OFF + 8)) pri += 4;
                            }
                            /* mandatory: top lives in the stack block (a
                             * parked main can sit slightly below base) — this
                             * alone kills the tag-array false positives */
                            int top_ok = top >= stk - 0x1000ULL &&
                                         top - stk <= 0x400000ULL &&
                                         ((top - stk) & 0xF) == 0 &&
                                         blk >= 0x100000000ULL &&
                                         blk <= 0x74000000000ULL;
                            if (top_ok) {
                                if (g_strt_ok(g)) pri += 20;
                                c_final++;
                                int dup = 0;
                                for (int q = 0; q < g_live_n; q++)
                                    if (g_live_L[q] == L) { dup = 1; break; }
                                /* G-diversification: once a G dominates the
                                 * candidate list (e.g. the menu universe's
                                 * hundreds of threads), stop adding more of
                                 * it so later heap regions (the GAME
                                 * universe, allocated at join time) still
                                 * get represented. */
                                if (!dup && g_live_n < MAX_LIVE_CANDS) {
                                    int gcount = 0;
                                    for (int q = 0; q < g_live_n; q++) {
                                        uintptr_t qg = 0;
                                        safe_read(g_live_L[q] + LUA_G_OFF, &qg, 8);
                                        if (qg == g) gcount++;
                                    }
                                    if (gcount >= 200) dup = 1;
                                }
                                if (!dup && g_live_n < MAX_LIVE_CANDS) {
                                    thr_register(L);
                                    g_live_L[g_live_n] = L;
                                    g_live_ss[g_live_n] = lci;
                                    g_live_stack[g_live_n] = stk;
                                    g_live_top[g_live_n] = top;
                                    g_live_tp[g_live_n] = top;
                                    g_live_pri[g_live_n] = pri;
                                    LOG_CORE("EXEC: L741 L=%p g=%p stk=%#llx top=%#llx pri=%d",
                                             (void*)L, (void*)g,
                                             (unsigned long long)stk,
                                             (unsigned long long)top, pri);
                                    g_live_n++;
                                }
                                continue;
                            }
                        }
                        /* ---- Phase A: fresh-coroutine signature, exact
                         * postconditions of stack_init (0x1026f3570):
                         * [L+1]=0xA, [L+0x18]=low32(L+0x18)^0x2d, [L+0x1c]=8,
                         * B(stack)=[L+0x78], base=[L+0x60]=B+0x10,
                         * top=[L+0x70]=B+0x10, last=[L+0x80]=B+0x280,
                         * inner A=[L+0x50]=[L+0x58].
                         * All coroutines share one G -> reveals the real global_State */
                        if (chunk[i + LUA_TT_OFF] == 0xA &&
                            *(uint32_t*)(chunk + i + LUA_MAGIC_OFF) ==
                                ((uint32_t)((L + LUA_MAGIC_OFF) & 0xffffffffULL) ^ 0x2d) &&
                            *(uint32_t*)(chunk + i + LUA_NUM8_OFF) == 8) {
                            uintptr_t c_sa  = *(uintptr_t*)(chunk + i + LUA_STACK_OFF);
                            uintptr_t c_stk = stk;
                            uintptr_t c_sl  = *(uintptr_t*)(chunk + i + LUA_SLAST_OFF);
                            uintptr_t c_cil = *(uintptr_t*)(chunk + i + LUA_TOP_OFF);
                            uintptr_t c_cib = *(uintptr_t*)(chunk + i + LUA_BASE_OFF);
                            uintptr_t c_ina = *(uintptr_t*)(chunk + i + LUA_INNER_OFF);
                            if (c_sa >= 0x100000000ULL && c_sa <= 0x74000000000ULL &&
                                c_stk == c_sa && c_sl == c_sa + 0x280 &&
                                top == c_sa + 0x10 && c_cil == c_sa + 0x10 &&
                                c_cib == c_sa + 0x10 && c_ina == lci &&
                                lci >= 0x100000000ULL && lci <= 0x74000000000ULL) {
                                int seen = -1;
                                for (int q = 0; q < g_coro_n; q++)
                                    if (g_coro_G[q] == g) { seen = q; break; }
                                if (seen >= 0) g_coro_cnt[seen]++;
                                else if (g_coro_n < 16) {
                                    g_coro_G[g_coro_n] = g;
                                    g_coro_cnt[g_coro_n] = 1;
                                    g_coro_n++;
                                }
                                if (g_coro_cnt[seen < 0 ? g_coro_n - 1 : seen] > bestn &&
                                    g_coro_cnt[seen < 0 ? g_coro_n - 1 : seen] >= 3) {
                                    bestn = g_coro_cnt[seen < 0 ? g_coro_n - 1 : seen];
                                    gbest = g;
                                    /* log only when the winner changes — this fires
                                     * thousands of times per scan otherwise */
                                    static uintptr_t last_gbest_log = 1;
                                    if (last_gbest_log != gbest) {
                                        last_gbest_log = gbest;
                                        LOG_CORE("EXEC: GBEST g=%p cnt=%d", (void*)gbest, bestn);
                                    }
                                }
                                /* store only a few coroutines — they are all
                                 * equivalent and loadstring on them is risky */
                                if (coro_stored < 8) {
                                    int dupc = 0;
                                    for (int q = 0; q < g_live_n; q++)
                                        if (g_live_L[q] == L) { dupc = 1; break; }
                                    if (!dupc && g_live_n < MAX_LIVE_CANDS) {
                                        coro_stored++;
                                        thr_register(L);
                                        g_live_L[g_live_n] = L;
                                        g_live_ss[g_live_n] = lci;
                                        g_live_stack[g_live_n] = stk;
                                        g_live_top[g_live_n] = top;
                                        g_live_tp[g_live_n] = top;
                                        g_live_pri[g_live_n] = 1;
                                        LOG_CORE("EXEC: CORO L=%p g=%p stk=%#llx pri=1",
                                                 (void*)L, (void*)g,
                                                 (unsigned long long)stk);
                                        g_live_n++;
                                    }
                                }
                                continue;
                            }
                        }
                        /* ---- Phase B: once the real G is known, every object with
                         * [obj+0x30]==G is a thread (main or coroutine). The main
                         * thread may sit far from G, so no distance filter here. */
                        if (gbest != 0 && g == gbest) {
                            if (top >= stk && (top - stk) <= 0x400000ULL &&
                                ((top - stk) & 0xF) == 0) {
                                int dupb = 0;
                                for (int q = 0; q < g_live_n; q++)
                                    if (g_live_L[q] == L) { dupb = 1; break; }
                                if (!dupb && g_live_n < 400) {
                                    int prib = 8;
                                    if (chunk[i + 8] == 9) prib += 24; /* 47061 marker */
                                    if (chunk[i] == 0xA) prib += 4;
                                    uintptr_t sab = *(uintptr_t*)(chunk + i + 0x40);
                                    if (sab == 0) prib += 50; /* newstate-created main thread */
                                    if (g == gbest) prib += 20;
                                    thr_register(L);
                                    g_live_L[g_live_n] = L;
                                    g_live_ss[g_live_n] = lci;
                                    g_live_stack[g_live_n] = stk;
                                    g_live_top[g_live_n] = top;
                                    g_live_tp[g_live_n] = top;
                                    g_live_pri[g_live_n] = prib;
                                    LOG_CORE("EXEC: GMAIN L=%p b0=%02x b8=%02x stk=%#llx top=%#llx pri=%d",
                                             (void*)L, chunk[i], chunk[i + 8],
                                             (unsigned long long)stk,
                                             (unsigned long long)top, prib);
                                    g_live_n++;
                                }
                                continue;
                            }
                        }
                        uintptr_t d = (g > L) ? (g - L) : (L - g);
                        if (d <= 0x100 || d > 0x40000ULL) continue;
                        if (top < stk || (top - stk) > 0x400000ULL || ((top - stk) & 0xF) != 0)
                            continue;
                        c_d++;
                        /* init(0x102c52a88)-derived ordering: stack_alloc<=stack,
                         * stack_last>=top, ci_base<=ci<=ci_last (zero fields allowed) */
                        uintptr_t sa  = *(uintptr_t*)(chunk + i + 0x40);
                        uintptr_t sl  = *(uintptr_t*)(chunk + i + 0x48);
                        uintptr_t cil = *(uintptr_t*)(chunk + i + 0x60);
                        uintptr_t cib = *(uintptr_t*)(chunk + i + 0x68);
                        if (sa != 0) {
                            if (sa < 0x100000000ULL || sa > 0x74000000000ULL) continue;
                            if (sa > stk || stk - sa > 0x100000ULL) continue;
                        }
                        if (sl != 0) {
                            if (sl < 0x100000000ULL || sl > 0x74000000000ULL) continue;
                            /* Luau extra stack space: reference 47061 had top =
                             * stack_last + 0x4d0; allow generous margin */
                            if (top > sl + 0x1000ULL || sl - stk > 0x100000ULL) continue;
                        }
                        if (cil != 0 && cib != 0) {
                            if (cil < 0x100000000ULL || cil > 0x74000000000ULL) continue;
                            if (cib < 0x100000000ULL || cib > 0x74000000000ULL) continue;
                            if (cib > lci || lci > cil || cil - cib > 0x40000ULL) continue;
                        }
                        c_span++;
                        /* deep-log far-heap structural candidates: the 47061
                         * reference lived at L≈0x711da72ab0; most malloc-metadata
                         * noise sits below 0x5_00000000 */
                        if (L >= 0x500000000ULL && dbg_far < 80) {
                            dbg_far++;
                            uint8_t gd[0x40] = {0};
                            safe_read(g, gd, sizeof(gd));
                            LOG_CORE("EXEC: FAR L=%p b0=%02x b8=%02x d=%#lx", (void*)L,
                                     chunk[i], chunk[i + 8], (unsigned long)d);
                            LOG_CORE("EXEC: FARg g=%p stk=%#llx top=%#llx ci=%#llx",
                                     (void*)g, (unsigned long long)stk,
                                     (unsigned long long)top, (unsigned long long)lci);
                            LOG_CORE("EXEC: FARg +0=%#llx +8=%#llx +10=%#llx +18=%#llx",
                                     (unsigned long long)*(uint64_t*)(gd + 0),
                                     (unsigned long long)*(uint64_t*)(gd + 8),
                                     (unsigned long long)*(uint64_t*)(gd + 0x10),
                                     (unsigned long long)*(uint64_t*)(gd + 0x18));
                            LOG_CORE("EXEC: FARg +20=%#llx +28=%#llx +30=%#llx +38=%#llx",
                                     (unsigned long long)*(uint64_t*)(gd + 0x20),
                                     (unsigned long long)*(uint64_t*)(gd + 0x28),
                                     (unsigned long long)*(uint64_t*)(gd + 0x30),
                                     (unsigned long long)*(uint64_t*)(gd + 0x38));
                            LOG_CORE("EXEC: FARg +40=%#llx +48=%#llx sa=%#llx sl=%#llx",
                                     (unsigned long long)*(uint64_t*)(gd + 0x40),
                                     (unsigned long long)*(uint64_t*)(gd + 0x48),
                                     (unsigned long long)sa, (unsigned long long)sl);
                        }
                        {
                            uint64_t gv[2] = {0, 0};
                            if (!safe_read(g, gv, 16)) continue;
                            uintptr_t gb = gv[0];
                            if (gb < 0x100000000ULL || gb > 0x74000000000ULL) continue;
                            uint64_t gsize = gv[1] & 0xffffffffULL;
                            uint64_t gnuse = gv[1] >> 32;
                            c_gread++;
                            if (gsize < 0x20 || gsize > 0x1000000ULL || gnuse > gsize * 2) {
                                if (gsize >= 0x1000 && gsize <= 0x40000000ULL && dbg_g2 < 60) {
                                    dbg_g2++;
                                    LOG_CORE("EXEC: GBAD L=%p g=%p gb=%#llx size=%llu nuse=%llu",
                                             (void*)L, (void*)g, (unsigned long long)gb,
                                             (unsigned long long)gsize, (unsigned long long)gnuse);
                                }
                                continue;
                            }
                            c_gsize++;
                            uint64_t bs[64];
                            memset(bs, 0, sizeof(bs));
                            if (!safe_read(gb, bs, sizeof(bs))) continue;
                            int bad = 0;
                            for (int k = 0; k < 64; k++) {
                                if (bs[k] == 0) continue;
                                if (bs[k] < 0x100000000ULL || bs[k] > 0x74000000000ULL ||
                                    (bs[k] & 7) != 0) {
                                    bad = 1;
                                    break;
                                }
                                uint8_t sbuf[0x18];
                                if (!safe_read(bs[k], sbuf, sizeof(sbuf))) {
                                    bad = 1;
                                    break;
                                }
                                uint64_t snext = *(uint64_t*)(sbuf + 8);
                                uint32_t slen = *(uint32_t*)(sbuf + 0x14);
                                if (slen == 0 || slen > 0x100000) {
                                    bad = 1;
                                    break;
                                }
                                if (snext != 0 && (snext < 0x100000000ULL ||
                                                   snext > 0x74000000000ULL)) {
                                    bad = 1;
                                    break;
                                }
                            }
                            if (bad) {
                                if (dbg_bs < 30) {
                                    dbg_bs++;
                                    LOG_CORE("EXEC: BBAD L=%p g=%p gb=%#llx size=%llu",
                                             (void*)L, (void*)g, (unsigned long long)gb,
                                             (unsigned long long)gsize);
                                }
                                continue;
                            }
                            c_final++;
                        }
                        c_g++;
                        if (dbg_str < 400) {
                            dbg_str++;
                            LOG_CORE("EXEC: STR L=%p g=%p stk=%#llx ci=%#llx top=%#llx b0=%02x b8=%02x d=%#lx",
                                     (void*)L, (void*)g, (unsigned long long)stk,
                                     (unsigned long long)lci, (unsigned long long)top,
                                     chunk[i], chunk[i + 8], (unsigned long)d);
                        }
                        int dup = 0;
                        for (int q = 0; q < g_live_n; q++)
                            if (g_live_L[q] == L) { dup = 1; break; }
                        if (dup) continue;
                        /* status sanity: valid thread statuses are 0..6 and
                         * 0x7f — the st=75/20/16 "threads" are heap garbage
                         * that monopolize the candidate list */
                        {
                            uint8_t stt = chunk[i + LUA_STATUS_OFF];
                            if (stt > 6 && stt != 0x7f) continue;
                        }
                        if (g_live_n < MAX_LIVE_CANDS) {
                            int cand_pri = 0;
                            if (chunk[i] == 0xA) cand_pri += 4;   /* LUA_TTHREAD per newthread */
                            if (chunk[i + 8] == 9) cand_pri += 2; /* 47061 empirical marker */
                            if (d <= 0x4000) cand_pri += 1;       /* G adjacent like 47061 */
                            g_live_L[g_live_n] = L;
                            g_live_ss[g_live_n] = lci;
                            g_live_stack[g_live_n] = stk;
                            g_live_top[g_live_n] = top;
                            g_live_tp[g_live_n] = *(uint64_t*)(chunk + i + 0x58);
                            g_live_pri[g_live_n] = cand_pri;
                            LOG_CORE("EXEC: pass %d CAND+ L=%p g=%p ci=%p stack=%p top=%p pri=%d",
                                     pass, (void*)L, (void*)g, (void*)lci,
                                     (void*)stk, (void*)top, cand_pri);
                            if (g_live_n < 24) g_tt9_cands[g_live_n] = L;
                            g_live_n++;
                        }
                    }
                    done += got;
                }
                free(chunk);
            addr += size;
            if (addr >= addr_hi) break; /* this pass's slice done */
        }
        LOG_CORE("EXEC: pass %d done tt9=%u ptr=%u d=%u span=%u gread=%u gsize=%u final=%u stored=%d",
                 pass, c_tt9, c_ptr, c_d, c_span, c_gread, c_gsize, c_final, g_live_n);
        g_tt9_count = g_live_n < 24 ? g_live_n : 24;
        usleep(300000);
    }
    /* the main thread is referenced from the binary's data segment */
    if (g_text_base != 0 && g_ref_n > 0) {
        uintptr_t dlo = g_text_base, dhi = g_text_base + 0xb600000ULL;
        for (int a = 0; a < g_live_n; a++) {
            for (int r = 0; r < g_ref_n; r++) {
                if (g_ref_thr[r] != g_live_L[a]) continue;
                if (g_ref_addr[r] >= dlo && g_ref_addr[r] < dhi) {
                    g_live_pri[a] += 100;
                    LOG_CORE("EXEC: MAINREF L=%p ref=%p", (void*)g_live_L[a],
                             (void*)g_ref_addr[r]);
                }
            }
        }
    }
    return;
scan_done:
    LOG_CORE("EXEC: scan aborted by deadline (live=%d)", g_live_n);
}

/* ------------------------------------------------------------------ */
/* lua_pcall inline hook (write-barrier route 1)                       */
/*                                                                     */
/* Patches the entry of the game's lua_pcall so every protected call  */
/* in the process flows through hook_check(PCALL_HOOK_SLOT). When the */
/* deferred-exec machinery is armed, the staged chunk runs INLINE on  */
/* the calling game thread — full script identity and the live native */
/* dispatch environment of a real game call frame (the exact context  */
/* the write/physics natives NULL-deref without).                     */
/* ------------------------------------------------------------------ */

static uint32_t  g_pcall_orig_insn[4];
static int       g_pcall_orig_n;
static uintptr_t g_pcall_fn;
static int       g_pcall_hooked;
static int       g_pcall_wide;      /* 0 = 4-byte BL patch, 1 = 16-byte BR patch */

/* Trampoline: fixed 96-byte frame (sub sp / absolute-offset slots — the
 * pre-index stp/str variant mis-restored x30 empirically), call
 * check(x0, x1, PCALL_HOOK_SLOT), restore, replay the orig_n stolen entry
 * insns, branch back into orig_fn + orig_n*4.
 * Literal pool: +0x68 = slot, +0x70 = continuation, +0x78 = check.
 * Fits PCALL_TRAMP_SIZE (0x80). Verified end-to-end offline
 * (tools/tramp harness: hooked fn runs, check fires, return intact). */
static uintptr_t build_pcall_trampoline(uint8_t* area, uintptr_t orig_fn,
                                        uintptr_t check_addr, int orig_n) {
    uint8_t* t = area;
    uintptr_t ta = (uintptr_t)t;
    put_u32(t + 0x00, 0xD10183FFu);                    /* sub sp, sp, #96   */
    put_u32(t + 0x04, 0xA90007E0u);                    /* stp x0,x1,[sp]    */
    put_u32(t + 0x08, 0xA9010FE2u);                    /* stp x2,x3,[sp,#16]*/
    put_u32(t + 0x0c, 0xA90217E4u);                    /* stp x4,x5,[sp,#32]*/
    put_u32(t + 0x10, 0xA9031FE6u);                    /* stp x6,x7,[sp,#48]*/
    put_u32(t + 0x14, 0xF90023FEu);                    /* str x30,[sp,#64]  */
    put_u32(t + 0x18, insn_ldr_literal(17, ta + 0x18, ta + 0x78)); /* check */
    put_u32(t + 0x1c, insn_ldr_literal(2,  ta + 0x1c, ta + 0x68)); /* slot  */
    put_u32(t + 0x20, insn_blr(17));
    put_u32(t + 0x24, 0xF94023FEu);                    /* ldr x30,[sp,#64]  */
    put_u32(t + 0x28, 0xA9431FE6u);                    /* ldp x6,x7,[sp,#48]*/
    put_u32(t + 0x2c, 0xA94217E4u);                    /* ldp x4,x5,[sp,#32]*/
    put_u32(t + 0x30, 0xA9410FE2u);                    /* ldp x2,x3,[sp,#16]*/
    put_u32(t + 0x34, 0xA94007E0u);                    /* ldp x0,x1,[sp]    */
    put_u32(t + 0x38, 0x910183FFu);                    /* add sp, sp, #96   */
    size_t cur = 0x3c;
    memcpy(t + cur, g_pcall_orig_insn, (size_t)orig_n * 4);
    cur += (size_t)orig_n * 4;
    put_u32(t + cur, insn_ldr_literal(16, ta + cur, ta + 0x70));   /* cont */
    cur += 4;
    put_u32(t + cur, insn_br(16));
    cur += 4;
    while (cur < 0x68) { put_u32(t + cur, insn_nop()); cur += 4; }
    put_quad(t + 0x68, PCALL_HOOK_SLOT);
    put_quad(t + 0x70, orig_fn + (uintptr_t)orig_n * 4);
    put_quad(t + 0x78, check_addr);
    __builtin___clear_cache((char*)t, (char*)t + PCALL_TRAMP_SIZE);
    return ta;
}

static int executor_hook_pcall(uintptr_t fn) {
    if (g_pcall_hooked) return 0;
    uintptr_t area = (uintptr_t)hook_pad + PCALL_TRAMP_OFF;
    uintptr_t page = (uintptr_t)hook_pad & ~0xFFFULL;
    kern_return_t kr = mach_vm_protect(mach_task_self(), (mach_vm_address_t)page,
                                       HOOKPAD_SIZE, false,
                                       VM_PROT_READ | VM_PROT_WRITE);
    if (kr != KERN_SUCCESS) {
        LOG_CORE("HOOK_PCALL: hookpad mprotect RW failed kr=%d", kr);
        return -1;
    }

    uint8_t probe[16] = {0};
    if (!safe_read(fn, probe, sizeof(probe))) {
        LOG_CORE("HOOK_PCALL: cannot read fn %p", (void*)fn);
        return -1;
    }
    LOG_CORE("HOOK_PCALL: fn=%p first16=%02x%02x%02x%02x %02x%02x%02x%02x %02x%02x%02x%02x %02x%02x%02x%02x",
             (void*)fn, probe[0], probe[1], probe[2], probe[3],
             probe[4], probe[5], probe[6], probe[7],
             probe[8], probe[9], probe[10], probe[11],
             probe[12], probe[13], probe[14], probe[15]);
    uint32_t w0 = *(uint32_t*)probe;
    uint32_t w1 = *(uint32_t*)(probe + 4);

    /* Stale-hook recovery: a previous payload copy leaves its patch behind
     * (dlopen of a fresh path loads a new image, but the OLD patch stays in
     * the game code). Stacking a second patch on top corrupts the replay.
     * The old trampoline's replay area holds the TRUE original insns —
     * recover them and re-point the existing patch at OUR trampoline. */
    int stale_wide = (w0 == 0x58000050u && w1 == 0xD61F0200u);   /* ldr x16,#8; br x16 */
    int stale_bl   = ((w0 & 0xFC000000u) == 0x94000000u);        /* BL */
    if (stale_bl) {
        /* a genuine BL first-insn is possible in principle — only trust it
         * as a stale patch when the target lands OUTSIDE the game __TEXT
         * (i.e. in a dylib hookpad region) */
        int64_t off0 = (int64_t)(w0 & 0x3FFFFFF);
        if (off0 & (1 << 25)) off0 -= (1 << 26);
        uintptr_t t0 = fn + (off0 << 2);
        if (g_text_base && t0 >= g_text_base && t0 < g_text_end) stale_bl = 0;
    }
    if (stale_wide || stale_bl) {
        uintptr_t old_tramp = 0;
        if (stale_wide) {
            old_tramp = *(uint64_t*)(probe + 8);
        } else {
            int64_t off = (int64_t)(w0 & 0x3FFFFFF);
            if (off & (1 << 25)) off -= (1 << 26);
            old_tramp = fn + (off << 2);
        }
        if (old_tramp < 0x100000000ULL || old_tramp > 0x74000000000ULL ||
            !safe_read(old_tramp + 0x34, g_pcall_orig_insn, 16) ||
            g_pcall_orig_insn[0] == 0) {
            LOG_CORE("HOOK_PCALL: stale patch present but old tramp %p unreadable",
                     (void*)old_tramp);
            return -1;
        }
        g_pcall_wide = 1;
        g_pcall_orig_n = 4;
        uintptr_t tramp = build_pcall_trampoline((uint8_t*)area, fn,
                                                 (uintptr_t)&hook_check, 4);
        /* re-point ONLY the patch's .quad at our trampoline; fn+0/4 stay */
        uintptr_t fpage = fn & ~0xFFFULL;
        kr = mach_vm_protect(mach_task_self(), (mach_vm_address_t)fpage, 0x4000,
                             false, VM_PROT_READ | VM_PROT_WRITE);
        if (kr != KERN_SUCCESS) {
            kr = mach_vm_protect(mach_task_self(), (mach_vm_address_t)fpage,
                                 0x4000, false,
                                 VM_PROT_READ | VM_PROT_WRITE | VM_PROT_COPY);
        }
        if (kr != KERN_SUCCESS) {
            LOG_CORE("HOOK_PCALL: stale re-point mprotect failed kr=%d", kr);
            return -1;
        }
        volatile uint32_t* p = (volatile uint32_t*)fn;
        p[2] = (uint32_t)(tramp & 0xFFFFFFFFu);
        p[3] = (uint32_t)(tramp >> 32);
        __builtin___clear_cache((char*)fn, (char*)fn + 16);
        mach_vm_protect(mach_task_self(), (mach_vm_address_t)page,
                        HOOKPAD_SIZE, false, VM_PROT_READ | VM_PROT_EXECUTE);
        mach_vm_protect(mach_task_self(), (mach_vm_address_t)fpage, 0x4000,
                        false, VM_PROT_READ | VM_PROT_EXECUTE);
        g_pcall_fn = fn;
        g_pcall_hooked = 1;
        LOG_CORE("HOOK_PCALL: re-pointed stale patch @%p -> new tramp %p "
                 "(recovered orig insns from %p)",
                 (void*)fn, (void*)tramp, (void*)old_tramp);
        return 0;
    }

    if (w0 == 0) {
        LOG_CORE("HOOK_PCALL: first insn is 0 — stale address?");
        return -1;
    }
    memcpy(g_pcall_orig_insn, probe, 16);

    /* BL patch (single atomic 4-byte store) when the trampoline is within
     * ±128MB; otherwise a 16-byte absolute BR sequence (works across any
     * image distance, at the cost of a nanosecond-scale torn-patch window
     * during the 4 stores). */
    uintptr_t tramp;
    int64_t diff = (int64_t)area - (int64_t)fn;
    g_pcall_wide = (diff < -0x8000000LL || diff > 0x7FFFFFFLL);
    g_pcall_orig_n = g_pcall_wide ? 4 : 1;
    tramp = build_pcall_trampoline((uint8_t*)area, fn, (uintptr_t)&hook_check,
                                   g_pcall_orig_n);

    uintptr_t fpage = fn & ~0xFFFULL;
    kr = mach_vm_protect(mach_task_self(), (mach_vm_address_t)fpage, 0x4000, false,
                         VM_PROT_READ | VM_PROT_WRITE);
    if (kr != KERN_SUCCESS) {
        /* arm64e refuses plain RW on code pages even for adhoc-resigned
         * binaries — COW the page instead: a private writable copy at the
         * same address (same pattern as the vtable lab) */
        LOG_CORE("HOOK_PCALL: fn page RW refused (kr=%d), trying VM_PROT_COPY", kr);
        kr = mach_vm_protect(mach_task_self(), (mach_vm_address_t)fpage, 0x4000, false,
                             VM_PROT_READ | VM_PROT_WRITE | VM_PROT_COPY);
    }
    if (kr != KERN_SUCCESS) {
        LOG_CORE("HOOK_PCALL: fn page mprotect RW failed kr=%d (page=%p)", kr, (void*)fpage);
        return -1;
    }
    volatile uint32_t* p = (volatile uint32_t*)fn;
    if (!g_pcall_wide) {
        int64_t bd = (int64_t)tramp - (int64_t)fn;
        p[0] = 0x94000000u | (uint32_t)((bd >> 2) & 0x3FFFFFF);
    } else {
        /* ldr x16, #8 ; br x16 ; .quad tramp — entry insn written LAST */
        p[1] = insn_br(16);
        p[2] = (uint32_t)(tramp & 0xFFFFFFFFu);
        p[3] = (uint32_t)(tramp >> 32);
        __builtin___clear_cache((char*)fn, (char*)fn + 16);
        p[0] = insn_ldr_literal(16, fn, fn + 8);
    }
    __builtin___clear_cache((char*)fn, (char*)fn + 16);

    kr = mach_vm_protect(mach_task_self(), (mach_vm_address_t)page,
                         HOOKPAD_SIZE, false,
                         VM_PROT_READ | VM_PROT_EXECUTE);
    if (kr != KERN_SUCCESS) return -1;
    kr = mach_vm_protect(mach_task_self(), (mach_vm_address_t)fpage, 0x4000, false,
                         VM_PROT_READ | VM_PROT_EXECUTE);
    if (kr != KERN_SUCCESS) return -1;
    g_pcall_fn = fn;
    g_pcall_hooked = 1;
    LOG_CORE("HOOK_PCALL: fn=%p tramp=%p wide=%d orig_n=%d",
             (void*)fn, (void*)tramp, g_pcall_wide, g_pcall_orig_n);
    return 0;
}

static int executor_unhook_pcall(void) {
    if (!g_pcall_hooked || !g_pcall_fn) return -1;
    uintptr_t fpage = g_pcall_fn & ~0xFFFULL;
    kern_return_t kr = mach_vm_protect(mach_task_self(), (mach_vm_address_t)fpage,
                                       0x4000, false,
                                       VM_PROT_READ | VM_PROT_WRITE);
    if (kr != KERN_SUCCESS) {
        kr = mach_vm_protect(mach_task_self(), (mach_vm_address_t)fpage,
                             0x4000, false,
                             VM_PROT_READ | VM_PROT_WRITE | VM_PROT_COPY);
    }
    if (kr != KERN_SUCCESS) {
        LOG_CORE("UNHOOK_PCALL: fn page mprotect RW failed kr=%d", kr);
        return -1;
    }
    /* the saved 16 original bytes cover both patch widths */
    memcpy((void*)g_pcall_fn, g_pcall_orig_insn, 16);
    __builtin___clear_cache((char*)g_pcall_fn, (char*)g_pcall_fn + 16);
    mach_vm_protect(mach_task_self(), (mach_vm_address_t)fpage, 0x4000, false,
                    VM_PROT_READ | VM_PROT_EXECUTE);
    g_pcall_hooked = 0;
    LOG_CORE("UNHOOK_PCALL: restored 16 bytes @%p", (void*)g_pcall_fn);
    return 0;
}

static bool lua_state_usable(uintptr_t L) {
    if (L < 0x100000000ULL || L > 0x74000000000ULL) return false;
    if ((L & 0xF) != 0) return false;
    uint8_t lh[0x88];
    if (!safe_read(L, lh, sizeof(lh))) return false;
    if (lh[LUA_TT_OFF] != 0xA) return false;   /* tt @ +1 (0.741) */
    uintptr_t g = *(uintptr_t*)(lh + LUA_G_OFF);
    if (g < 0x100000000ULL || g > 0x74000000000ULL) return false;
    if ((g & 0xF) != 0) return false;
    if (!g_strt_ok(g)) return false;
    uintptr_t stack = *(uintptr_t*)(lh + LUA_STACK_OFF);
    uintptr_t top = *(uintptr_t*)(lh + LUA_TOP_OFF);
    if (stack < 0x100000000ULL || stack > 0x74000000000ULL) return false;
    if ((top >> 56) == 0xca)
        top = ((top >> 32) & 0xffffff) << 32 | (top & 0xffffffff);
    if (top < stack || top > 0x74000000000ULL) return false;
    if ((top - stack) > 0x400000ULL || ((top - stack) & 0xF) != 0) return false;
    return true;
}

static volatile int g_intern_done = 0;
static volatile uintptr_t g_intern_ret = 0;
static uintptr_t g_intern_fn = 0;

static uintptr_t lua_pack_ptr(uintptr_t a) {
    return 0xca00000000000000ULL | (((a >> 32) & 0xffffff) << 32) | (a & 0xffffffff);
}

/* disable the "loadstring() is not available" permission gate inside the
 * Roblox wrapper (0x101541310 cbz / 0x10154131c b.ne -> throw) */
static bool patch_insn_remapped(uintptr_t addr, uint32_t insn) {
    /* kernel-mediated write through the task port: ignores page W^X
     * (hardened runtime denies mprotect RW on signed __TEXT with kr=2) */
    kern_return_t kr = mach_vm_write(mach_task_self(), (mach_vm_address_t)addr,
                                     (vm_offset_t)&insn, 4);
    if (kr != KERN_SUCCESS) {
        LOG_CORE("PATCH: mach_vm_write kr=%d addr=%p", kr, (void*)addr);
        return false;
    }
    __builtin___clear_cache((char*)addr, (char*)(addr + 4));
    uint32_t v = 0;
    safe_read(addr, &v, 4);
    return v == insn;
}

static int patch_loadstring_gate(uintptr_t slide) {
    static int done = 0;
    if (done) return 0;
    if (!legacy_client()) {
        LOG_CORE("PATCH: refused — gate offsets belong to %s, running client is %s",
                 LEGACY_CLIENT_VERSION, executor_client_version());
        done = -1;
        return -1;
    }
    uintptr_t a1 = 0x101541310ULL + slide;
    uintptr_t a2 = 0x10154131cULL + slide;
    uintptr_t a3 = 0x10153530cULL + slide; /* "loadstring enabled" getter */
    uint32_t i1 = 0, i2 = 0, i3 = 0;
    if (!safe_read(a1, &i1, 4) || !safe_read(a2, &i2, 4) || !safe_read(a3, &i3, 4)) {
        LOG_CORE("PATCH: insn read failed a1=%p a2=%p", (void*)a1, (void*)a2);
        return -1;
    }
    LOG_CORE("PATCH: a1=%p insn=%#x a2=%p insn=%#x a3=%p insn=%#x",
             (void*)a1, i1, (void*)a2, i2, (void*)a3, i3);
    if ((i1 & 0xff000000ULL) != 0xb4000000ULL) {  /* cbz x8, ... */
        LOG_CORE("PATCH: unexpected insn1");
        return -1;
    }
    if ((i2 & 0xff000010ULL) != 0x54000000ULL) {  /* b.ne ... */
        LOG_CORE("PATCH: unexpected insn2");
        return -1;
    }
    /* the getter is compile-time-inlined FALSE in live clients:
     * mov w0,#0 (0x52800000) -> mov w0,#1 (0x52800020) */
    if (i3 == 0x52800000u) {
        bool ok3 = patch_insn_remapped(a3, 0x52800020u);
        LOG_CORE("PATCH: getter flip ok=%d", (int)ok3);
    }
    uint32_t nop = 0xd503201f;
    bool ok1 = patch_insn_remapped(a1, nop);
    bool ok2 = ok1 ? patch_insn_remapped(a2, nop) : false;
    uint32_t v1 = 0, v2 = 0, v3 = 0;
    safe_read(a1, &v1, 4);
    safe_read(a2, &v2, 4);
    safe_read(a3, &v3, 4);
    LOG_CORE("PATCH: result ok1=%d ok2=%d verify1=%#x verify2=%#x verify3=%#x",
             ok1, ok2, v1, v2, v3);
    done = (ok1 && ok2 && v1 == nop && v2 == nop) ? 1 : -1;
    return done == 1 ? 0 : -1;
}

/* Legacy path kept for reference: intern + rawload + pcall directly on the
 * main thread. Superseded by the coroutine+resume pipeline below — pcall on
 * the main thread from a foreign thread is the risky variant. */
__attribute__((unused))
static int exec_gamestate_legacy(const char* code, char* out, size_t out_len) {
    size_t len = strlen(code);
    uintptr_t slide = executor_image_slide();
    uintptr_t fn_intern = 0x102c535b8ULL + slide;
    uintptr_t fn_loadstr = 0x1015412a8ULL + slide;
    uintptr_t fn_pcall = 0x102c3b1ccULL + slide;
    uintptr_t fn_rawload = 0x101533becULL + slide;
    int n = 0;

    find_live_thread();
    if (g_live_n == 0) {
        int m = snprintf(out, out_len, "ERR: no live thread (slide=%#lx, tt9=%d)\n", slide, g_tt9_count);
        for (int i = 0; i < g_tt9_count && m < (int)out_len - 200; i += 2) {
            uintptr_t c = g_tt9_cands[i];
            uint8_t q[0x60];
            if (!safe_read(c, q, 0x60)) continue;
            m += snprintf(out + m, out_len - m,
                          "c[%d] L=%p w8=%#llx w30=%#llx st=%#llx tp=%#llx\n",
                          i, (void*)c,
                          (unsigned long long)*(uint64_t*)(q + 8),
                          (unsigned long long)*(uint64_t*)(q + 0x30),
                          (unsigned long long)*(uint64_t*)(q + 0x38),
                          (unsigned long long)*(uint64_t*)(q + 0x58));
        }
        return -1;
    }
    LOG_CORE("EXEC: %d live candidates", g_live_n);
    int try_n = g_live_n < 48 ? g_live_n : 48;
    for (int a = 0; a < try_n; a++) {
        for (int b = a + 1; b < g_live_n; b++) {
            if (g_live_pri[b] > g_live_pri[a]) {
                uintptr_t tL = g_live_L[a]; g_live_L[a] = g_live_L[b]; g_live_L[b] = tL;
                uintptr_t ts = g_live_ss[a]; g_live_ss[a] = g_live_ss[b]; g_live_ss[b] = ts;
                uintptr_t tk = g_live_stack[a]; g_live_stack[a] = g_live_stack[b]; g_live_stack[b] = tk;
                uintptr_t tp = g_live_top[a]; g_live_top[a] = g_live_top[b]; g_live_top[b] = tp;
                uint64_t  tv = g_live_tp[a]; g_live_tp[a] = g_live_tp[b]; g_live_tp[b] = tv;
                int       tg = g_live_pri[a]; g_live_pri[a] = g_live_pri[b]; g_live_pri[b] = tg;
            }
        }
    }

    for (int ci = 0; ci < try_n; ci++) {
    next_cand:
        uintptr_t L = g_live_L[ci];
        uintptr_t ss = g_live_ss[ci];
        uintptr_t stack = g_live_stack[ci];
        uintptr_t top_abs = g_live_top[ci];
        uintptr_t tp = g_live_tp[ci];
        int cand_pri = g_live_pri[ci];
        n = 0;
        n += snprintf(out + n, out_len - n, "L=%p slide=%#lx (cand %d/%d)\n", (void*)L, slide, ci + 1, g_live_n);

        uintptr_t Lg = *(uintptr_t*)(L + 0x48);   /* 0.739: L->G */
        uint64_t gchk[2] = {0, 0};
        uint8_t* gbuf = (uint8_t*)&gchk;
        if (Lg >= 0x100000000ULL && Lg < 0x74000000000ULL && safe_read(Lg, gbuf, 16)) {
            uintptr_t gbucket = gchk[0];
            uint32_t gbsize = (uint32_t)(gchk[1] & 0xffffffffULL);
            uint32_t gcnt = (uint32_t)(gchk[1] >> 32);
            LOG_CORE("EXEC: G=%p bucket=%p bsize=%u cnt=%u", (void*)Lg, (void*)gbucket,
                     gbsize, gcnt);
            if (gbucket < 0x100000000ULL || gbucket > 0x74000000000ULL) {
                snprintf(out + n, out_len - n, "ERR: bad bucket at G (cand skip)\n");
                continue;
            }
        } else {
            snprintf(out + n, out_len - n, "ERR: G unreadable (cand skip)\n");
            continue;
        }
    uintptr_t v8 = *(uintptr_t*)(L + 8);
    uintptr_t v10 = *(uintptr_t*)(L + 0x10);
    uintptr_t v18 = *(uintptr_t*)(L + 0x18);
    uintptr_t v20 = *(uintptr_t*)(L + 0x20);
    uintptr_t v28 = *(uintptr_t*)(L + 0x28);
    uintptr_t v38 = *(uintptr_t*)(L + 0x38);
    uintptr_t v40 = *(uintptr_t*)(L + 0x40);
    uintptr_t v48 = *(uintptr_t*)(L + 0x48);
    LOG_CORE("EXEC: fields L=%p 8=%#llx 10=%#llx 18=%#llx 20=%#llx 28=%#llx 30=%#llx 38=%#llx 40=%#llx 48=%#llx 50=%#llx 58=%#llx bit2=%u",
             (void*)L, (unsigned long long)v8, (unsigned long long)v10, (unsigned long long)v18,
             (unsigned long long)v20, (unsigned long long)v28, (unsigned long long)Lg,
             (unsigned long long)v38, (unsigned long long)v40, (unsigned long long)v48,
             (unsigned long long)ss, (unsigned long long)tp, ((uint8_t*)L)[2] & 4);
    n += snprintf(out + n, out_len - n, "fields: 8=%#llx 38=%#llx 50=%#llx 58=%#llx\n",
                  (unsigned long long)v8, (unsigned long long)v38,
                  (unsigned long long)ss, (unsigned long long)tp);

    if ((tp >> 56) == 0xca) {
        top_abs = ((tp >> 32) & 0xffffff) << 32 | (tp & 0xffffffff);
        n += snprintf(out + n, out_len - n, "top unpacked: %#lx\n", top_abs);
    } else if (tp >= 0x100000000ULL && tp < 0x74000000000ULL && (tp & 7) == 0) {
        top_abs = tp;
    }
    if (!top_abs || (stack && (top_abs < stack || top_abs - stack > 0x400000ULL))) {
        if (stack && stack >= 0x100000000ULL && stack < 0x74000000000ULL && is_memory_writable(stack)) {
            tp = stack;
            top_abs = stack;
            LOG_CORE("EXEC: empty stack, using top=stack %#lx", stack);
        } else {
            snprintf(out + n, out_len - n, "ERR: cannot determine top (stack=%#lx tp=%#llx)\n",
                     stack, (unsigned long long)tp);
            continue;
        }
    }

    uintptr_t old_t0v = 0, old_t0t = 0;
    int top_ok = 0;
    uint8_t tsv[0x40];
    if (top_abs && is_memory_readable(top_abs) && safe_read(top_abs, tsv, 0x20)) {
        old_t0v = *(uintptr_t*)(tsv + 0x00);
        old_t0t = *(uintptr_t*)(tsv + 0x08);
        top_ok = 1;
    }
    uintptr_t old_s0v = 0, old_s0t = 0, old_s1v = 0, old_s1t = 0;
    int saved_stack = 0;
    if (stack && stack != top_abs && is_memory_readable(stack) && safe_read(stack, tsv, 0x20)) {
        old_s0v = *(uintptr_t*)(tsv + 0x00);
        old_s0t = *(uintptr_t*)(tsv + 0x08);
        old_s1v = *(uintptr_t*)(tsv + 0x10);
        old_s1t = *(uintptr_t*)(tsv + 0x18);
        saved_stack = 1;
    }
    if (!top_ok) {
        snprintf(out + n, out_len - n, "ERR: top slot unreadable (stack=%#lx tp=%#llx)\n",
                 stack, (unsigned long long)tp);
        continue;
    }
    if (!is_memory_writable(top_abs) || (saved_stack && !is_memory_writable(stack))) {
        snprintf(out + n, out_len - n, "ERR: slots not writable\n");
        continue;
    }

    g_intern_fn = fn_intern;
    patch_loadstring_gate(slide);
    LOG_CORE("EXEC: intern(%p, %zu bytes) under guard...", (void*)L, len);
    uintptr_t str_obj = 0;
    struct sigaction old_sa[2], old_alrm, sa;
    install_segv_guard(&sa, old_sa);
    install_alrm_guard(&sa, &old_alrm);
    alarm(3);
    if (sigsetjmp(g_exec_jmp, 1) == 0) {
        uintptr_t (*intern)(uintptr_t, const char*, uintptr_t) =
            (uintptr_t(*)(uintptr_t, const char*, uintptr_t))fn_intern;
        try {
            str_obj = intern(L, code, len);
        } catch (...) {
            str_obj = 0;
            LOG_CORE("EXEC: intern C++ exception");
        }
    } else {
        str_obj = 0;
    }
    remove_alrm_guard(&old_alrm);
    remove_segv_guard(&sa, old_sa);
    if (g_exec_timeout) {
        LOG_CORE("EXEC: intern TIMEOUT on L=%p", (void*)L);
        snprintf(out + n, out_len - n, "ERR: intern timeout (L fake or stale)\n");
        continue;
    }
    if (g_exec_segv) {
        LOG_CORE("EXEC: intern SEGV on L=%p", (void*)L);
        snprintf(out + n, out_len - n, "ERR: intern SEGV (L fake or stale)\n");
        continue;
    }
    LOG_CORE("EXEC: intern -> %p", (void*)str_obj);
    n += snprintf(out + n, out_len - n, "intern=%#lx len=%zu\n", str_obj, len);
    if (!str_obj || str_obj < 0x100000000ULL || str_obj > 0x74000000000ULL) {
        snprintf(out + n, out_len - n, "ERR: intern failed");
        continue;
    }
    uint32_t rlen = 0;
    char rbuf[64];
    if (safe_read(str_obj + 0x14, &rlen, 4) && rlen == len && len < 64 &&
        safe_read(str_obj + 0x18, rbuf, len)) {
        rbuf[len] = 0;
        n += snprintf(out + n, out_len - n, "str_ok len=%u data=\"%.48s\"\n", rlen, rbuf);
    } else {
        snprintf(out + n, out_len - n, "ERR: intern string mismatch (len=%u)\n", rlen);
        continue;
    }

    /* G validated by intern. loadstring/pcall are only safe on the main
     * thread — running them on a coroutine killed the process twice.
     * Main-thread marker (empirical, 47061): byte at [L+8] == 9 */
    /* loadstring's handler dereferences [L+0x78] then [[L+0x78]+0x40]
     * (see 0x1015b2d20); bare coroutines have [L+0x78]==0 -> hard crash.
     * A non-null, readable glue object is the requirement for exec;
     * byte9/binary-ref only boost priority */
    uintptr_t glue = 0;
    safe_read(L + 0x78, &glue, 8);
    /* deterministic main-thread identity: G->mainthread at [G+0x90]
     * (0.739 offsets; proved offline via lua_pushthread tail:
     *  G=[L+0x48], mainthread=[G+0x90]) */
    uintptr_t mt = 0;
    safe_read(Lg + 0x90, &mt, 8);
    int is_main = (mt == L);
    if (!is_main || glue < 0x100000000ULL || glue > 0x74000000000ULL) {
        LOG_CORE("EXEC: SKIP L=%p glue=%#llx mt=%#llx pri=%d", (void*)L,
                 (unsigned long long)glue, (unsigned long long)mt, cand_pri);
        n += snprintf(out + n, out_len - n, "skip (glue=%#llx mt=%#llx)\n",
                      (unsigned long long)glue, (unsigned long long)mt);
        continue;
    }
    LOG_CORE("EXEC: MAIN THREAD CONFIRMED L=%p glue=%#llx", (void*)L,
             (unsigned long long)glue);
    /* Bypass the Roblox loadstring wrapper entirely: call the raw
     * compile+load helper 0x101533bec(L, std::string*, chunkname, 0).
     * libc++ SSO short string: data[0..22], size byte at +0x17 (bit7=0) */
    int rr = -9;
    int r2 = -9;
    {
        size_t clen = strlen(code);
        char sso[32];
        memset(sso, 0, sizeof(sso));
        int raw_ok = 0;
        if (clen <= 21) {
            memcpy(sso, code, clen);
            sso[0x17] = (char)(clen & 0x7f);
            raw_ok = 1;
        } else {
            /* long-form libc++ string: {data,size,cap|1} best-effort */
            char* heapbuf = (char*)malloc(clen + 1);
            if (heapbuf) {
                memcpy(heapbuf, code, clen + 1);
                *(uint64_t*)(sso + 0) = (uint64_t)heapbuf;
                *(uint64_t*)(sso + 8) = clen;
                *(uint64_t*)(sso + 16) = (clen + 1) | 1;
                sso[0x17] = (char)(0x80 | (clen & 0x7f));
                raw_ok = 1;
            }
        }
        if (!raw_ok) {
            n += snprintf(out + n, out_len - n, "ERR: cannot build source string\n");
            continue;
        }
        LOG_CORE("EXEC: rawload(%p, %zu bytes) ...", (void*)L, clen);
        install_segv_guard(&sa, old_sa);
        install_alrm_guard(&sa, &old_alrm);
        alarm(10);
        rr = -9;
        g_exec_segv = 0;
        g_exec_timeout = 0;
        int jv = sigsetjmp(g_exec_jmp, 1);
        if (jv == 0) {
            try {
                int (*rawload)(uintptr_t, void*, const char*, uintptr_t) =
                    (int(*)(uintptr_t, void*, const char*, uintptr_t))fn_rawload;
                rr = rawload(L, sso, "INJ", 0);
            } catch (const std::exception& e) {
                rr = -3;
                LOG_CORE("EXEC: rawload exc: %s", e.what());
            } catch (...) {
                rr = -3;
                LOG_CORE("EXEC: rawload exc unknown");
            }
        }
        remove_alrm_guard(&old_alrm);
        remove_segv_guard(&sa, old_sa);
        LOG_CORE("EXEC: rawload -> rr=%d jv=%d segv=%d to=%d", rr, jv,
                 (int)g_exec_segv, (int)g_exec_timeout);
        if (jv == 2 || g_exec_timeout) rr = -2;
        else if (jv == 1 || g_exec_segv) rr = -4;
        if (rr != 0) {
            n += snprintf(out + n, out_len - n, "ERR: rawload ret=%d\n", rr);
            continue;
        }
        /* closure should now be pushed on the stack; run it */
        uintptr_t tp3 = 0;
        safe_read(L + 0x58, &tp3, 8);
        uintptr_t t3 = ((tp3 >> 56) == 0xca) ?
            ((tp3 >> 32) & 0xffffff) << 32 | (tp3 & 0xffffffff) : tp3;
        uint64_t fv = 0, ft = 0;
        if (t3 >= 0x100000000ULL && t3 > stack && is_memory_readable(t3 - 0x10)) {
            fv = *(uint64_t*)(t3 - 0x10);
            ft = *(uint64_t*)(t3 - 0x08);
        }
        LOG_CORE("EXEC: closure at top: val=%#llx tag=%#llx",
                 (unsigned long long)fv, (unsigned long long)ft);
        /* Roblox closures carry a continuation pointer at +0x28 */
        if (fv >= 0x100000000ULL && fv <= 0x74000000000ULL) {
            uint64_t c00 = 0, c08 = 0, c28 = 0, c30 = 0;
            safe_read(fv + 0x00, &c00, 8);
            safe_read(fv + 0x08, &c08, 8);
            safe_read(fv + 0x28, &c28, 8);
            safe_read(fv + 0x30, &c30, 8);
            LOG_CORE("EXEC: closure %llx: +0=%llx +8=%llx +28=%llx +30=%llx",
                     (unsigned long long)fv, (unsigned long long)c00,
                     (unsigned long long)c08, (unsigned long long)c28,
                     (unsigned long long)c30);
        }
        n += snprintf(out + n, out_len - n, "rawload ok, closure tag=%#llx\n",
                      (unsigned long long)ft);

        int (*pcall)(uintptr_t, int, int, int) = (int(*)(uintptr_t, int, int, int))fn_pcall;
        LOG_CORE("EXEC: pcall(%p,0,-1,0) ...", (void*)L);
        r2 = 0;
        install_segv_guard(&sa, old_sa);
        install_alrm_guard(&sa, &old_alrm);
        alarm(10);
        if (sigsetjmp(g_exec_jmp, 1) == 0) {
            try {
                r2 = pcall(L, 0, -1, 0);
            } catch (const std::exception& e) {
                r2 = -3;
                LOG_CORE("EXEC: pcall exc: %s", e.what());
            } catch (...) {
                r2 = -3;
                LOG_CORE("EXEC: pcall exc unknown");
            }
        } else {
            r2 = -2;
        }
        remove_alrm_guard(&old_alrm);
        remove_segv_guard(&sa, old_sa);
        LOG_CORE("EXEC: pcall -> %d (segv=%d to=%d)", r2, (int)g_exec_segv, (int)g_exec_timeout);
    }

    /* results: read slots below top (print output lands there) */
    {
        uintptr_t tp2 = 0;
        safe_read(L + 0x58, &tp2, 8);
        uintptr_t t2 = ((tp2 >> 56) == 0xca) ? ((tp2 >> 32) & 0xffffff) << 32 | (tp2 & 0xffffffff) : tp2;
        for (int i = -2; i < 0; i++) {
            uintptr_t slot = t2 + (uintptr_t)i * 0x10;
            uint64_t v = 0, t = 0;
            if (slot >= 0x100000000ULL && is_memory_readable(slot)) {
                v = *(uint64_t*)slot;
                t = *(uint32_t*)(slot + 0xc);
            }
            n += snprintf(out + n, out_len - n, "  [%d] @%#lx = %#llx tag=%#llx\n", i, slot,
                          (unsigned long long)v, (unsigned long long)t);
            if (i == -1 && t == 6 && v >= 0x100000000ULL && v < 0x74000000000ULL) {
                uint32_t slen = 0;
                char sbuf[1025];
                sbuf[0] = 0;
                if (safe_read(v + 0x14, &slen, 4) && slen > 0 && slen < 1024 &&
                    safe_read(v + 0x18, sbuf, slen)) {
                    sbuf[slen] = 0;
                    n += snprintf(out + n, out_len - n, "  str: \"%.512s\"\n", sbuf);
                }
            }
        }
    }

    *(uintptr_t*)(L + 0x58) = tp;
    *(uintptr_t*)(top_abs + 0x00) = old_t0v;
    *(uintptr_t*)(top_abs + 0x08) = old_t0t;
    if (saved_stack) {
        *(uintptr_t*)(stack + 0x00) = old_s0v;
        *(uintptr_t*)(stack + 0x08) = old_s0t;
        *(uintptr_t*)(stack + 0x10) = old_s1v;
        *(uintptr_t*)(stack + 0x18) = old_s1t;
    }
    n += snprintf(out + n, out_len - n, "restored, ss=%#lx\n", ss);
    if (rr == 0) return r2;
    continue;
    }
    {
        int m = snprintf(out, out_len, "ERR: all %d candidates failed\n", g_live_n);
        return -1;
    }
}

/* ==================================================================== */
/* Stage-4 exec engine: cached main thread -> fresh coroutine ->        */
/* rawload(source) -> lua_resume(co, main, 0).                          */
/*                                                                      */
/* Disassembly-verified for 0.735.0.7351131:                            */
/*   lua_newthread   0x102c529f0  (L)              -> lua_State*        */
/*   raw compile+load 0x101533bec (L, str*, name, 0) -> int, pushes     */
/*   lua_resume      0x102c48ab0  (L, from, nargs) -> int               */
/*   TValue tag of a function = 8 ([slot+0xc]), string = 6              */
/* ==================================================================== */

static uintptr_t g_main_L = 0;
static uintptr_t g_main_G = 0;

static uintptr_t unpack_top(uintptr_t tp) {
    if ((tp >> 56) == 0xca)
        return ((tp >> 32) & 0xffffff) << 32 | (tp & 0xffffffff);
    return tp;
}

/* Deterministic main-thread check (0.741): tt@+1, G=[L+0x68], anti-forgery
 * magic at +0x18, G references its main thread somewhere in its first
 * 0x2c0 bytes. The compile->loader->resume pipeline never dereferences
 * the parent's glue (on 0.741 the old +0x78 glue slot is the value
 * stack — it must not be touched). */
static bool validate_main_thread(uintptr_t L) {
    if (L < 0x100000000ULL || L > 0x74000000000ULL || (L & 0xF) != 0) return false;
    uint8_t lh[0x88];
    if (!safe_read(L, lh, sizeof(lh))) return false;
    if (lh[LUA_TT_OFF] != 0xA) return false; /* tt @ +1 (0.741) */
    uintptr_t G = *(uintptr_t*)(lh + LUA_G_OFF);
    if (G < 0x100000000ULL || G > 0x74000000000ULL || (G & 0xF) != 0) return false;
    uintptr_t stack = *(uintptr_t*)(lh + LUA_STACK_OFF);
    if (stack < 0x100000000ULL || stack > 0x74000000000ULL) return false;
    /* anti-forgery magic written by stack_init on every thread */
    if (!lua_thread_magic_ok(L)) return false;
    /* G references its main thread; the slot moved between versions (0.739
     * was [G+0x90]) — locate the backref by content, not a fixed offset */
    uint8_t gb[0x2c0];
    if (!safe_read(G, gb, sizeof(gb))) return false;
    for (int off = 0x20; off + 8 <= (int)sizeof(gb); off += 8)
        if (*(uintptr_t*)(gb + off) == L) return true;
    return false;
}

/* Returns the live game main thread, running the full heap hunt only when
 * the cached pointer is missing or stale.why gets the failure reason. */
static bool validate_usable_thread(uintptr_t L) {
    if (L < 0x100000000ULL || L > 0x74000000000ULL || (L & 0xF) != 0) return false;
    uint8_t lh[0x88];
    if (!safe_read(L, lh, sizeof(lh))) return false;
    if (lh[LUA_TT_OFF] != 0xA) return false;
    uintptr_t G = *(uintptr_t*)(lh + LUA_G_OFF);
    if (G < 0x100000000ULL || G > 0x74000000000ULL || (G & 0xF) != 0) return false;
    uintptr_t stack = *(uintptr_t*)(lh + LUA_STACK_OFF);
    if (stack < 0x100000000ULL || stack > 0x74000000000ULL) return false;
    if (!lua_thread_magic_ok(L)) return false;
    return true;
}

static uintptr_t confirmed_main_thread(char* why, size_t why_len) {
    /* The cached main does not have to be THE mainthread: any live thread
     * carrying the right G works as the lua_newthread parent (identity +
     * env come from G). This keeps the lock on the GAME universe even when
     * the parked coroutine we captured gets recycled by the scheduler. */
    if (g_main_L && validate_usable_thread(g_main_L)) {
        uintptr_t G = 0;
        safe_read(g_main_L + LUA_G_OFF, &G, 8);
        if (!g_main_G || G == g_main_G) { g_main_G = G; return g_main_L; }
    }
    g_main_L = 0;
    find_live_thread();
    int best = -1;
    /* prefer candidates carrying the remembered game G */
    if (g_main_G) {
        for (int i = 0; i < g_live_n; i++) {
            uintptr_t G = 0;
            safe_read(g_live_L[i] + LUA_G_OFF, &G, 8);
            if (G != g_main_G) continue;
            if (!validate_usable_thread(g_live_L[i])) continue;
            if (best < 0 || g_live_pri[i] > g_live_pri[best]) best = i;
        }
        if (best >= 0) { g_main_L = g_live_L[best]; return g_main_L; }
    }
    for (int i = 0; i < g_live_n; i++) {
        if (!validate_main_thread(g_live_L[i])) continue;
        if (best < 0 || g_live_pri[i] > g_live_pri[best]) best = i;
    }
    if (best < 0) {
        /* accept a game coroutine directly: find the most popular G among
         * the candidates (the game universe) and take the highest-priority
         * candidate with that G — scheduler coroutines carry the game
         * identity and the runner works on them like on the main. */
        uintptr_t gc_g[256]; int gc_n[256]; int ngc = 0;
        for (int i = 0; i < g_live_n; i++) {
            uintptr_t G = 0;
            if (!safe_read(g_live_L[i] + LUA_G_OFF, &G, 8)) continue;
            if (G < 0x100000000ULL || G > 0x74000000000ULL || (G & 0xF) != 0) continue;
            int found = -1;
            for (int q = 0; q < ngc; q++) if (gc_g[q] == G) { found = q; break; }
            if (found >= 0) gc_n[found]++;
            else if (ngc < 256) { gc_g[ngc] = G; gc_n[ngc] = 1; ngc++; }
        }
        uintptr_t gameG = 0; int gameGn = 0;
        for (int q = 0; q < ngc; q++)
            if (gc_n[q] > gameGn) { gameG = gc_g[q]; gameGn = gc_n[q]; }
        LOG_CORE("MAIN: gameG=%p count=%d (ngc=%d)", (void*)gameG, gameGn, ngc);
        if (gameG && gameGn >= 3) {
            for (int i = 0; i < g_live_n; i++) {
                uintptr_t G = 0;
                safe_read(g_live_L[i] + LUA_G_OFF, &G, 8);
                if (G != gameG) continue;
                /* relaxed: parked coroutines have top <= stack — accept them */
                {
                    uintptr_t stk = 0, tp = 0;
                    safe_read(g_live_L[i] + LUA_STACK_OFF, &stk, 8);
                    safe_read(g_live_L[i] + LUA_TOP_OFF, &tp, 8);
                    if (tp < stk - 0x1000ULL || tp > stk + 0x400000ULL) continue;
                }
                /* status byte @+3: 0=OK, 1=YIELD(parked), 2+=dead — skip dead.
                 * For the lua_newthread parent we only need the GAME G (so
                 * the fresh co inherits the game universe's globals/env);
                 * status 0 or 1 both work. */
                {
                    uint8_t st = 0xff;
                    safe_read(g_live_L[i] + LUA_STATUS_OFF, &st, 1);
                    if (st != 0 && st != 1) continue;
                }
                if (best < 0 || g_live_pri[i] > g_live_pri[best]) best = i;
            }
            /* re-check status NOW (the game may have killed the
             * coroutine between the scan and this call) */
            for (int tries = 0; tries < 5; tries++) {
                uint8_t st = 0xff;
                safe_read(g_live_L[best] + LUA_STATUS_OFF, &st, 1);
                if (st == 0 || st == 1) break;
                best = -1;
                for (int i2 = 0; i2 < g_live_n; i2++) {
                    uintptr_t G2 = 0;
                    safe_read(g_live_L[i2] + LUA_G_OFF, &G2, 8);
                    if (G2 != gameG) continue;
                    uint8_t st2 = 0xff;
                    safe_read(g_live_L[i2] + LUA_STATUS_OFF, &st2, 1);
                    if (st2 != 0 && st2 != 1) continue;
                    if (best < 0 || g_live_pri[i2] > g_live_pri[best]) best = i2;
                }
                if (best < 0) break;
            }
            if (best >= 0) {
                g_main_L = g_live_L[best];
                safe_read(g_main_L + LUA_G_OFF, &g_main_G, 8);
                LOG_CORE("MAIN: game-coroutine DIRECT L=%p G=%p (count=%d)",
                         (void*)g_main_L, (void*)gameG, gameGn);
                return g_main_L;
            }
        }
    }
    if (best < 0) {
        LOG_CORE("MAIN: fallback entered (live=%d)", g_live_n);
        /* Fallback: the fresh-coroutine signature hunt misses long-running
         * game VMs (their coroutines are scheduler-recycled and never match
         * the init shape). Discover universes by shape-scanning the whole
         * heap for lua_State-like objects, then take G->mainthread of each. */
        uintptr_t gseen[32];
        int ngseen = 0;
        /* Seed gseen with the Gs of the ALREADY-FOUND candidates: the game
         * coroutines stored in g_live carry the game universe's G — the
         * heap-order shape scan below can miss them (menu universes fill
         * the 32 slots first because they sit lower in the heap). */
        /* Count G popularity across ALL candidates — the game universe has
         * the MOST coroutines, so the most-frequent G = the game G. */
        {
            uintptr_t gcount_g[64]; int gcount_n[64]; int ngc = 0;
            for (int i = 0; i < g_live_n && ngc < 64; i++) {
                uintptr_t G = 0;
                if (!safe_read(g_live_L[i] + LUA_G_OFF, &G, 8)) continue;
                if (G < 0x100000000ULL || G > 0x74000000000ULL || (G & 0xF) != 0) continue;
                int found = -1;
                for (int q = 0; q < ngc; q++)
                    if (gcount_g[q] == G) { found = q; break; }
                if (found >= 0) gcount_n[found]++;
                else if (ngc < 64) { gcount_g[ngc] = G; gcount_n[ngc] = 1; ngc++; }
            }
            /* sort by count desc — the game G first */
            for (int a = 0; a < ngc; a++)
                for (int b = a + 1; b < ngc; b++)
                    if (gcount_n[b] > gcount_n[a]) {
                        uintptr_t tg = gcount_g[a]; int tn = gcount_n[a];
                        gcount_g[a] = gcount_g[b]; gcount_n[a] = gcount_n[b];
                        gcount_g[b] = tg; gcount_n[b] = tn;
                    }
            for (int q = 0; q < ngc && ngseen < 32; q++)
                gseen[ngseen++] = gcount_g[q];
        }
        mach_vm_address_t addr = 0;
        mach_vm_size_t size = 0;
        uint8_t* chunk = (uint8_t*)malloc(1 << 20);
        if (chunk) {
            while (ngseen < 32) {
                mach_msg_type_number_t cnt = VM_REGION_BASIC_INFO_COUNT_64;
                vm_region_basic_info_data_64_t info;
                mach_port_t object_name = 0;
                kern_return_t kr = mach_vm_region(
                    mach_task_self(), &addr, &size, VM_REGION_BASIC_INFO_64,
                    (vm_region_info_t)&info, &cnt, &object_name);
                if (kr != KERN_SUCCESS) break;
                bool scan = (info.protection & VM_PROT_READ) &&
                            (info.protection & VM_PROT_WRITE) &&
                            addr >= 0x100000000ULL &&
                            addr < 0x74000000000ULL &&
                            size >= 0x4000 && size < 0x80000000ULL;
                if (scan) {
                    mach_vm_size_t done = 0;
                    while (done + 0x88 <= size) {
                        mach_vm_size_t want =
                            size - done < (1 << 20) ? size - done : (1 << 20);
                        mach_vm_size_t got = 0;
                        if (mach_vm_read_overwrite(
                                mach_task_self(), addr + done, want,
                                (mach_vm_address_t)chunk, &got) != KERN_SUCCESS)
                            break;
                        for (mach_vm_size_t i = 0;
                             i + 0x88 <= got && ngseen < 32; i += 8) {
                            uintptr_t c = addr + done + i;
                            if ((c & 0xF) != 0) continue;
                            if (chunk[i + LUA_TT_OFF] != 0xA) continue;
                            if (*(uint32_t*)(chunk + i + LUA_MAGIC_OFF) !=
                                ((uint32_t)((c + LUA_MAGIC_OFF) & 0xffffffffULL) ^ 0x2du))
                                continue;
                            uintptr_t G = *(uintptr_t*)(chunk + i + LUA_G_OFF);
                            if (G < 0x100000000ULL || G > 0x74000000000ULL ||
                                (G & 0xF) != 0)
                                continue;
                            int dup = 0;
                            for (int q = 0; q < ngseen; q++)
                                if (gseen[q] == G) { dup = 1; break; }
                            if (dup) continue;
                            /* string-table sanity on the G itself */
                            if (g_strt_ok(G)) {
                                gseen[ngseen++] = G;
                                LOG_CORE("MAIN: shape-universe G=%p", (void*)G);
                            }
                        }
                        done += got;
                    }
                }
                addr += size;
            }
            free(chunk);
        }
        for (int q = 0; q < ngseen; q++) {
            /* 0.740: the mainthread slot moved — find any G backref */
            uintptr_t mt = 0;
            uint8_t gbuf2[0x400];
            if (!safe_read(gseen[q], gbuf2, sizeof(gbuf2))) continue;
            LOG_CORE("MAIN: gseen[%d]=%p (ngseen=%d)", q, (void*)gseen[q], ngseen);
            for (int off = 0x20; off + 8 <= (int)sizeof(gbuf2) && !mt; off += 8) {
                uintptr_t cand = *(uintptr_t*)(gbuf2 + off);
                if (validate_main_thread(cand)) { mt = cand; LOG_CORE("MAIN: backref hit at G+%#x -> %p", off, (void*)mt); }
            }
            if (mt) {
                /* g_live is FULL of coroutines (512) — overwrite the LAST
                 * slot with the real main instead of skipping it */
                if (g_live_n >= MAX_LIVE_CANDS) g_live_n = MAX_LIVE_CANDS - 1;
                int dup = 0;
                for (int z = 0; z < g_live_n; z++)
                    if (g_live_L[z] == mt) { dup = 1; break; }
                if (!dup) {
                    uintptr_t st = 0, tp = 0, ci = 0;
                    safe_read(mt + LUA_STACK_OFF, &st, 8);
                    safe_read(mt + LUA_TOP_OFF, &tp, 8);
                    safe_read(mt + LUA_INNER_OFF, &ci, 8);
                    g_live_L[g_live_n] = mt;
                    g_live_ss[g_live_n] = ci;
                    g_live_stack[g_live_n] = st;
                    g_live_top[g_live_n] = unpack_top(tp);
                    g_live_tp[g_live_n] = tp;
                    g_live_pri[g_live_n] = 150;
                    LOG_CORE("MAIN: shape-main mt=%p G=%p (idx %d)", (void*)mt,
                             (void*)gseen[q], g_live_n);
                    g_live_n++;
                    if (best < 0) best = g_live_n - 1;
                }
            }
        }
    }
    if (best >= 0) {
        g_main_L = g_live_L[best];
        safe_read(g_main_L + 0x18, &g_main_G, 8);
        LOG_CORE("MAIN: confirmed+cached L=%p G=%p (cand %d/%d pri=%d)",
                 (void*)g_main_L, (void*)g_main_G, best + 1, g_live_n,
                 g_live_pri[best]);
        return g_main_L;
    }
    if (why)
        snprintf(why, why_len, "no main thread found (%d candidates, slide=%#lx)",
                 g_live_n, executor_image_slide());
    return 0;
}


/* Snapshot of a lua_State for the log: header bytes, G/stack/ci/top and
 * the two TValues below top (with string extraction). */
static void log_thread_state(const char* tag, uintptr_t L) {
    if (L < 0x100000000ULL || L > 0x74000000000ULL) return;
    uint8_t q[0x88];
    if (!safe_read(L, q, sizeof(q))) {
        LOG_CORE("%s: L=%p UNREADABLE", tag, (void*)L);
        return;
    }
    uintptr_t top = unpack_top(*(uintptr_t*)(q + LUA_TOP_OFF));
    LOG_CORE("%s: L=%p tt=%u status=%u G=%#llx stk=%#llx top=%#llx base=%#llx last=%#llx magic=%#x",
             tag, (void*)L, q[LUA_TT_OFF], q[LUA_STATUS_OFF],
             (unsigned long long)*(uintptr_t*)(q + LUA_G_OFF),
             (unsigned long long)*(uintptr_t*)(q + LUA_STACK_OFF),
             (unsigned long long)top,
             (unsigned long long)*(uintptr_t*)(q + LUA_BASE_OFF),
             (unsigned long long)*(uintptr_t*)(q + LUA_SLAST_OFF),
             *(uint32_t*)(q + LUA_MAGIC_OFF));
    for (int i = -2; i < 0; i++) {
        uintptr_t slot = top + (uintptr_t)i * 0x10;
        if (slot < 0x100000000ULL || !is_memory_readable(slot)) continue;
        uint64_t v = 0;
        uint32_t t = 0;
        safe_read(slot, &v, 8);
        safe_read(slot + 0xc, &t, 4);
        LOG_CORE("%s:   slot[%d]=%#llx tt=%u", tag, i, (unsigned long long)v, t);
        if (t == 6 && v >= 0x100000000ULL && v < 0x74000000000ULL) {
            uint32_t slen = 0;
            char sbuf[160];
            if (safe_read(v + 0x14, &slen, 4) && slen > 0 && slen < 150 &&
                safe_read(v + 0x18, sbuf, slen)) {
                sbuf[slen] = 0;
                LOG_CORE("%s:   str[%d]=\"%s\"", tag, i, sbuf);
            }
        }
    }
}

/* co = lua_newthread(mainL), plus popping the TValue it pushes on main. */
/* Pick a parked (st=1) game-universe coroutine from the live candidates.
 * Running our closure ON such a coroutine gives it the game's script
 * context (identity, capabilities, ScriptContext) — the write/physics
 * natives that segfault on a bare lua_newthread co work there. */
static uintptr_t exec_pick_parked_game_co(void) {
    if (!g_main_G || g_live_n <= 0) return 0;
    /* prefer parked-in-yield (st=1) script coroutines; accept idle (st=0)
     * game coroutines too — they carry the same script identity/context */
    uintptr_t best0 = 0;
    for (int i = 0; i < g_live_n; i++) {
        uintptr_t P = g_live_L[i];
        if (!P || P < 0x100000000ULL || P > 0x74000000000ULL) continue;
        uint8_t st = 0xff;
        if (!safe_read(P + LUA_STATUS_OFF, &st, 1)) continue;
        if (st != 1 && st != 0) continue;
        uintptr_t G = 0;
        if (!safe_read(P + LUA_G_OFF, &G, 8) || G != g_main_G) continue;
        if (!validate_usable_thread(P)) continue;
        if (st == 1) return P;
        if (!best0) {
            /* st=0 heuristic: a real script coroutine has the Roblox
             * ExtraSpace before the lua_State — [P-0x18] = the shared
             * block pointer (a valid heap pointer). Internal coroutines
             * (HTTP/telemetry) have garbage there. */
            uintptr_t es = 0;
            if (safe_read(P - 0x18, &es, 8) && es >= 0x100000000ULL &&
                es <= 0x74000000000ULL && (es & 0xF) == 0)
                best0 = P;
        }
    }
    return best0;
}

static uintptr_t exec_newthread(uintptr_t mainL) {
    uintptr_t fn_newthread = exec_fn_addr(EXEC_FN_NEWTHREAD);
    if (!fn_newthread) {
        LOG_CORE("EXEC: lua_newthread unresolved on client %s — refusing to call "
                 "a stale address", executor_client_version());
        return 0;
    }
    struct sigaction old_sa[2], old_alrm, sa;
    install_segv_guard(&sa, old_sa);
    install_alrm_guard(&sa, &old_alrm);
    alarm(10);
    g_exec_segv = 0;
    g_exec_timeout = 0;
    uintptr_t co = 0;
    int jv = sigsetjmp(g_exec_jmp, 1);
    if (jv == 0) {
        try {
            co = ((uintptr_t(*)(uintptr_t))fn_newthread)(mainL);
        } catch (...) {
            co = 0;
        }
    }
    remove_alrm_guard(&old_alrm);
    remove_segv_guard(&sa, old_sa);
    if (jv != 0 || co < 0x100000000ULL || co > 0x74000000000ULL) return 0;
    /* lua_newthread pushed the thread TValue onto main's stack — restore
     * main's top so the parked main keeps its frame shape. */
    uintptr_t mtp = 0;
    if (safe_read(mainL + LUA_TOP_OFF, &mtp, 8) && mtp >= 0x100000000ULL && mtp <= 0x74000000000ULL) {
        if (is_memory_writable(mainL + LUA_TOP_OFF)) {
            if ((mtp >> 56) != 0xca && mtp >= 0x100000000ULL)
                *(uintptr_t*)(mainL + LUA_TOP_OFF) = mtp - 0x10;
        }
    }
    return co;
}

/* lua_resume(co, from=mainL, nargs=0) under the crash/timeout guard. */
static int exec_resume(uintptr_t co, uintptr_t fromL) {
    uintptr_t fn_resume = exec_fn_addr(EXEC_FN_RESUME);
    if (!fn_resume) {
        LOG_CORE("EXEC: lua_resume unresolved on client %s", executor_client_version());
        return -10;
    }
    struct sigaction old_sa[2], old_alrm, sa;
    install_segv_guard(&sa, old_sa);
    install_alrm_guard(&sa, &old_alrm);
    alarm(15);
    g_exec_segv = 0;
    g_exec_timeout = 0;
    int r = -9;
    int jv = sigsetjmp(g_exec_jmp, 1);
    if (jv == 0) {
        try {
            /* 0.741 lua_resume signature (disasm 0x1026e5a54): arg0 is the
             * coroutine (values are copied onto its stack, its closure at
             * stack slot 0 runs); `from` is arg1. 0.739/0.740 had the
             * reverse order. */
            r = ((int(*)(uintptr_t, uintptr_t, int))fn_resume)(co, fromL, 0);
        } catch (const std::exception& e) {
            r = -3;
            LOG_CORE("EXEC: resume exc: %s", e.what());
        } catch (...) {
            r = -3;
        }
    }
    remove_alrm_guard(&old_alrm);
    remove_segv_guard(&sa, old_sa);
    if (jv == 2 || g_exec_timeout) return -2;
    if (jv == 1 || g_exec_segv) return -4;
    return r;
}

/* The game's own script runner (live backtrace: every server script runs
 * through it): 0x1026e8df0(thread, from_or_0, count) — protected-runs the
 * function at thread.top - count*16 (the run_fn 0x1026e8f54 via
 * rawrunprotected 0x1026e8250, with the G+0x6d0/G+0x678 thread hooks).
 * Frame protocol: closure at top-1 (ci->func = top-16), count = 0 —
 * func slot = top-(count+1)*16 = the closure; status = 0 (FRESH,
 * ci==base_ci passes the pre-check; status=1 would take the
 * yield-continuation path and walk a garbage CallInfo chain). */
static int exec_run(uintptr_t co, uintptr_t from) {
    uintptr_t slide = executor_image_slide();
    uintptr_t fn = 0x1026e8df0ULL + slide;
    uint32_t first = 0;
    if (!safe_read(fn, &first, 4) || first != 0xa9bd57f6u) {
        LOG_CORE("EXEC: runner signature drifted (%#x) on %s",
                 first, executor_client_version());
        return -10;
    }
    struct sigaction old_sa[2], old_alrm, sa;
    install_segv_guard(&sa, old_sa);
    install_alrm_guard(&sa, &old_alrm);
    alarm(15);
    g_exec_segv = 0;
    g_exec_timeout = 0;
    int r = -9;
    int jv = sigsetjmp(g_exec_jmp, 1);
    if (jv == 0) {
        try {
            r = ((int (*)(uintptr_t, uintptr_t, int))fn)(co, 0, 0);
        } catch (const std::exception& e) {
            r = -3;
            LOG_CORE("EXEC: run exc: %s", e.what());
        } catch (...) {
            r = -3;
        }
    }
    remove_alrm_guard(&old_alrm);
    remove_segv_guard(&sa, old_sa);
    if (jv == 2 || g_exec_timeout) return -2;
    if (jv == 1 || g_exec_segv) return -4;
    return r;
}

/* lua_pcall(co, 0, MULTRET, 0) under the crash/timeout guard. The 0.741
 * lua_resume only MOVES values (the actual run happens in the game's
 * scheduler, which does not know about our coroutines) — lua_pcall is the
 * synchronous runner that actually executes the closure. */
static int exec_pcall(uintptr_t co) {
    uintptr_t fn_pcall = exec_fn_addr(EXEC_FN_PCALL);
    if (!fn_pcall) {
        LOG_CORE("EXEC: lua_pcall unresolved on client %s", executor_client_version());
        return -10;
    }
    struct sigaction old_sa[2], old_alrm, sa;
    install_segv_guard(&sa, old_sa);
    install_alrm_guard(&sa, &old_alrm);
    alarm(15);
    g_exec_segv = 0;
    g_exec_timeout = 0;
    int r = -9;
    int jv = sigsetjmp(g_exec_jmp, 1);
    if (jv == 0) {
        try {
            /* closure sits at top-1 (luau_load pushed it) */
            r = ((int (*)(uintptr_t, int, int, int))fn_pcall)(co, 0, -1, 0);
        } catch (const std::exception& e) {
            r = -3;
            LOG_CORE("EXEC: pcall exc: %s", e.what());
        } catch (...) {
            r = -3;
        }
    }
    remove_alrm_guard(&old_alrm);
    remove_segv_guard(&sa, old_sa);
    if (jv == 2 || g_exec_timeout) return -2;
    if (jv == 1 || g_exec_segv) return -4;
    return r;
}

/* If the slot below top is a string (compile/runtime error object), copy it
 * into out. Returns bytes appended, 0 when not a string. */
static int extract_top_string(uintptr_t L, char* out, size_t out_len) {
    uintptr_t tp = 0;
    if (!safe_read(L + LUA_TOP_OFF, &tp, 8)) return 0;   /* 0.741: top @ +0x70 */
    uintptr_t top = unpack_top(tp);
    for (int k = 1; k <= 8; k++) {
        uintptr_t slot = top - (uintptr_t)k * 0x10;
        if (slot < 0x100000000ULL || !is_memory_readable(slot)) return 0;
        uint64_t v = 0;
        uint32_t t = 0;
        safe_read(slot, &v, 8);
        safe_read(slot + 0xc, &t, 4);
        if (t != 6 || v < 0x100000000ULL || v > 0x74000000000ULL) continue;
        uint32_t slen = 0;
        if (!safe_read(v + 0x14, &slen, 4) || slen == 0 || slen > 600) continue;
        char sbuf[608];
        if (!safe_read(v + 0x18, sbuf, slen)) continue;
        sbuf[slen] = 0;
        return snprintf(out, out_len, "%s", sbuf);
    }
    return 0;
}

static const char* resume_status_name(int r) {
    switch (r) {
        case 0: return "OK";
        case 1: return "YIELD (script yielded: wait/task.wait — runs detached)";
        case 2: return "ERRRUN";
        case 3: return "ERRSYNTAX";
        case 4: return "ERRMEM";
        case 5: return "ERRERR";
        case 6: return "BREAK";
        case -2: return "TIMEOUT";
        case -3: return "C++ exception";
        case -4: return "SEGV";
        case -10: return "unresolved symbol (run __RESOLVE__)";
        default: return "?";
    }
}

/* ------------------------------------------------------------------ */
/* Deferred execution: stage bytecode once, fire it inside the game's  */
/* own lua_pcall so the chunk runs on a real game script thread with  */
/* its live identity / ScriptContext / native dispatch tables — the   */
/* context the write/physics natives need (NULL-dispatch barrier).    */
/*                                                                     */
/* Flow: __ARM__ <src|BC:hex> stages + hooks + arms. The next game-   */
/* universe pcall runs the chunk inline and parks the result here;    */
/* __POLL__ reads it, __REARM__ fires the same staged chunk again,    */
/* __DISARM__ unpatches. __ARMG__ <hexG> pins the universe filter.    */
/* ------------------------------------------------------------------ */

enum { ARM_IDLE = 0, ARM_ARMED = 1, ARM_BUSY = 2, ARM_DONE = 3 };

static volatile int       g_arm_state = ARM_IDLE;
static volatile int       g_pcall_in_hook = 0;   /* re-entry guard: our own
                                                  * nested pcall passes through */
static volatile uintptr_t g_arm_g_filter = 0;    /* 0 = follow g_main_G */
static uint8_t            g_arm_bc[65536];
static size_t             g_arm_bc_len;
static int                g_arm_has_bc;
static char               g_arm_result[4096];
static uintptr_t          g_arm_fired_L;
static uintptr_t          g_arm_fired_G;
static int                g_arm_fired_rc = -999;
static volatile uint64_t  g_arm_fire_count;

static void arm_set_result(const char* fmt, ...) {
    va_list args;
    va_start(args, fmt);
    vsnprintf(g_arm_result, sizeof(g_arm_result), fmt, args);
    va_end(args);
}

/* Raw-bytecode staging: "BC:<hex>" goes straight into the staging buffer,
 * same wire format as the exec pipeline's BC: mode. */
static int arm_stage_hex(const char* hex, char* err, size_t err_len) {
    size_t hl = strlen(hex);
    while (hl > 0 && (hex[hl-1] == '\n' || hex[hl-1] == '\r' ||
                      hex[hl-1] == ' '  || hex[hl-1] == '\t')) hl--;
    if (hl < 2 || (hl & 1)) {
        snprintf(err, err_len, "bad hex length");
        return -1;
    }
    size_t bl = hl / 2;
    if (bl > sizeof(g_arm_bc)) {
        snprintf(err, err_len, "blob over staging cap (%zu > %zu)",
                 bl, sizeof(g_arm_bc));
        return -1;
    }
    for (size_t i = 0; i < bl; i++) {
        unsigned v = 0;
        if (sscanf(hex + i * 2, "%2x", &v) != 1) {
            snprintf(err, err_len, "bad hex at byte %zu", i);
            return -1;
        }
        g_arm_bc[i] = (uint8_t)v;
    }
    g_arm_bc_len = bl;
    g_arm_has_bc = 1;
    return 0;
}

/* Source staging: the client's own compiler (the exec pipeline's verified
 * compile stage) — result copied out of the cache-owned module string into
 * the staging buffer so later compiles cannot mutate it under us. */
static int arm_stage_compile(const char* code, char* err, size_t err_len) {
    uintptr_t fn_rawload = exec_fn_addr(EXEC_FN_RAWLOAD);
    uintptr_t fn_compile = exec_fn_addr(EXEC_FN_COMPILE);
    if (!fn_rawload || !fn_compile) {
        snprintf(err, err_len, "compile/rawload unresolved on client %s",
                 executor_client_version());
        return -1;
    }
    uintptr_t slide = executor_image_slide();
    uintptr_t fn_init = 0x10000c75cULL + slide;
    uintptr_t fn_ccompile = 0x10364fdb4ULL + slide;
    uint32_t first = 0;
    if (!safe_read(fn_init, &first, 4) || first != 0xa9bc5ff8u ||
        !safe_read(fn_ccompile, &first, 4) || first != 0xd10103ffu) {
        snprintf(err, err_len, "string/compile signatures drifted on %s",
                 executor_client_version());
        return -1;
    }
    uint8_t srcStr[24];
    memset(srcStr, 0, sizeof(srcStr));
    uint8_t cont[0x18];
    memset(cont, 0, sizeof(cont));
    size_t slen = strlen(code);

    struct sigaction osa[2], oalrm, sa;
    install_segv_guard(&sa, osa);
    install_alrm_guard(&sa, &oalrm);
    alarm(20);
    g_exec_segv = 0;
    g_exec_timeout = 0;
    int rr = -9;
    int jv = sigsetjmp(g_exec_jmp, 1);
    if (jv == 0) {
        try {
            ((void (*)(void*, const char*, size_t))fn_init)(srcStr, code, slen);
#if defined(__aarch64__)
            __asm__ volatile(
                "mov x8, %[dst]\n"
                "mov x0, %[srcp]\n"
                "blr %[f]\n"
                :
                : [dst] "r" ((uintptr_t)cont),
                  [srcp] "r" ((uintptr_t)srcStr),
                  [f] "r" (fn_ccompile)
                : "x0", "x1", "x2", "x3", "x4", "x5", "x6", "x7", "x8",
                  "x9", "x10", "x11", "x12", "x13", "x14", "x18",
                  "memory", "cc");
            rr = 0;
#else
            rr = -7;
#endif
        } catch (...) {
            rr = -5;
        }
    } else {
        rr = (jv == 2) ? -2 : -4;
    }
    remove_alrm_guard(&oalrm);
    remove_segv_guard(&sa, osa);
    if ((srcStr[0x17] & 0x80) && *(void**)srcStr) free(*(void**)srcStr);
    if (rr != 0) {
        snprintf(err, err_len, "compile stage rc=%d", rr);
        return -1;
    }

    uintptr_t module = *(uintptr_t*)cont & PTR_MASK;
    if (module < 0x100000000ULL || module > 0x74000000000ULL) {
        snprintf(err, err_len, "compile container has no module0");
        return -1;
    }
    uint8_t mod[0x48];
    if (!safe_read(module, mod, sizeof(mod))) {
        snprintf(err, err_len, "module unreadable");
        return -1;
    }
    const uint8_t* bcs = mod + 0x18;              /* module string @ +0x18 */
    uintptr_t bc_data;
    size_t bc_len;
    if (bcs[0x17] & 0x80) {                       /* long form */
        bc_data = *(uintptr_t*)(mod + 0x18);
        bc_len = *(size_t*)(mod + 0x20);
    } else {                                      /* short: inline */
        bc_data = (uintptr_t)(mod + 0x18);
        bc_len = bcs[0x17];
    }
    if (bc_data < 0x100000000ULL || bc_data > 0x74000000000ULL ||
        bc_len == 0 || bc_len > sizeof(g_arm_bc)) {
        snprintf(err, err_len, "bad compiled blob (data=%#llx len=%#zx)",
                 (unsigned long long)bc_data, bc_len);
        return -1;
    }
    if (!safe_read(bc_data, g_arm_bc, bc_len)) {
        snprintf(err, err_len, "blob read failed");
        return -1;
    }
    if (bc_len == slen && memcmp(g_arm_bc, code, slen) == 0) {
        snprintf(err, err_len, "compiler is dead on this build (passthrough)");
        g_arm_has_bc = 0;
        return -1;
    }
    g_arm_bc_len = bc_len;
    g_arm_has_bc = 1;
    LOG_CORE("ARM: staged %zu bytes, head=%02x %02x %02x %02x",
             bc_len, g_arm_bc[0], g_arm_bc[1], g_arm_bc[2], g_arm_bc[3]);
    return 0;
}

/* Runs the staged chunk ON the fired game thread, inline at its own
 * lua_pcall call site. The game thread's stack shape and gt are restored
 * afterwards so the pending original pcall proceeds normally. */
static void run_staged_on(uintptr_t L) {
    uintptr_t fn_load  = exec_fn_addr(EXEC_FN_BUfload);
    if (!fn_load) {
        arm_set_result("ERR: luau_load unresolved on client %s",
                       executor_client_version());
        g_arm_fired_rc = -10;
        return;
    }
    /* luaD_call (0.741: 0x10270af04) — runs the closure at top-1.
     * NOTE: the resolver's "lua_pcall" is actually the luaB_pcall BUILTIN
     * (Lua-level pcall semantics — wrong for a direct C-side run; returned
     * 2 without executing). luaD_call is the raw runner — Lua errors would
     * longjmp into the game's nearest protected frame (the very pcall we
     * hooked), which is acceptable; hard faults stay under our guard. */
    uintptr_t fn_dcall = 0x10270af04ULL + executor_image_slide();
    uint32_t first = 0;
    if (!safe_read(fn_dcall, &first, 4) || first == 0) {
        arm_set_result("ERR: luaD_call unreadable");
        g_arm_fired_rc = -10;
        return;
    }
    struct sigaction old_sa[2], old_alrm, sa;
    install_segv_guard(&sa, old_sa);
    install_alrm_guard(&sa, &old_alrm);
    alarm(10);
    g_exec_segv = 0;
    g_exec_timeout = 0;
    int rc = -9;
    /* volatile: written between setjmp and a possible longjmp.
     * The FULL lua frame state must be restorable: a contained fault
     * siglongjmps out of the VM mid-instruction, abandoning the nested
     * CallInfo — leaving L->ci/base pointing at a dead frame would crash
     * the game thread as soon as its own pcall resumes. */
    volatile uintptr_t saved_top_v = 0;
    volatile uintptr_t saved_gt_v = 0;
    volatile uintptr_t saved_ci_v = 0;
    volatile uintptr_t saved_baseci_v = 0;
    volatile uintptr_t saved_base_v = 0;
    int jv = sigsetjmp(g_exec_jmp, 1);
    if (jv == 0) {
        try {
            g_pcall_in_hook = 1;
            /* gt-swap to the raw globals of the cached main: a fired script
             * thread may carry the sandboxed env where `game` resolves to a
             * wrapper function ("Instance expected, got function"). The raw
             * gt resolves the real DataModel; restored below. */
            uintptr_t sgt = 0, mgt = 0;
            if (g_main_L && is_memory_writable(L + 0x40)) {
                safe_read(L + 0x40, &sgt, 8);
                safe_read(g_main_L + 0x40, &mgt, 8);
                if (mgt >= 0x100000000ULL && mgt <= 0x74000000000ULL &&
                    sgt != mgt) {
                    *(uintptr_t*)(L + 0x40) = mgt;
                    saved_gt_v = sgt;
                }
            }
            uintptr_t s5 = 0, s6 = 0, s7 = 0, s8 = 0;
            safe_read(L + 0x50, &s5, 8);   /* ci */
            safe_read(L + 0x58, &s6, 8);   /* base_ci */
            safe_read(L + 0x60, &s7, 8);   /* base */
            safe_read(L + LUA_TOP_OFF, &s8, 8);
            saved_ci_v = s5; saved_baseci_v = s6; saved_base_v = s7;
            saved_top_v = s8;
            int lr = ((int (*)(uintptr_t, const char*, const void*, size_t, int))
                      fn_load)(L, "INJARM", g_arm_bc, g_arm_bc_len, 0);
            if (lr != 0) {
                char eb[512];
                int got = extract_top_string(L, eb, sizeof(eb));
                arm_set_result("load ret=%d%s%s%s", lr,
                               got ? " err=\"" : "", got ? eb : "",
                               got ? "\"" : "");
                rc = -20 - lr;
            } else {
                /* the closure sits at top-1 after luau_load */
                uintptr_t tp = 0;
                safe_read(L + LUA_TOP_OFF, &tp, 8);
                uintptr_t func = tp - 0x10;
                ((void (*)(uintptr_t, uintptr_t, int))fn_dcall)(L, func, -1);
                rc = 0;
                /* result placement probe: dump slots around func (the call
                 * base) AND around top — on this client the result does not
                 * reliably land at top-1 (empirical) */
                for (int k = -2; k <= 4; k++) {
                    uintptr_t slot = func + (uintptr_t)k * 0x10;
                    if (slot < 0x100000000ULL) continue;
                    uint64_t v = 0; uint32_t t = 0;
                    safe_read(slot, &v, 8);
                    safe_read(slot + 0xc, &t, 4);
                    LOG_CORE("ARM: fslot[%+d]=%#llx tt=%u", k,
                             (unsigned long long)v, t);
                    if (t == 6 && v >= 0x100000000ULL) {
                        uint32_t slen = 0;
                        if (safe_read((uintptr_t)v + 0x14, &slen, 4) &&
                            slen > 0 && slen < 200) {
                            char sb[208];
                            if (safe_read((uintptr_t)v + 0x18, sb, slen)) {
                                sb[slen] = 0;
                                LOG_CORE("ARM: fslot[%+d] STR=\"%s\"", k, sb);
                            }
                        }
                    }
                }
                char rb[512];
                int got = extract_top_string(L, rb, sizeof(rb));
                if (got > 0)
                    arm_set_result("dcall ok out=\"%s\"", rb);
                else
                    arm_set_result("dcall ok");
            }
            if (saved_top_v && is_memory_writable(L + LUA_TOP_OFF))
                *(uintptr_t*)(L + LUA_TOP_OFF) = saved_top_v;
            if (saved_gt_v && is_memory_writable(L + 0x40))
                *(uintptr_t*)(L + 0x40) = saved_gt_v;
            g_pcall_in_hook = 0;
        } catch (...) {
            g_pcall_in_hook = 0;
            rc = -3;
            arm_set_result("C++ exception during staged run");
        }
    } else {
        /* fault path: restore the FULL frame state so the game's own
         * pcall continues on a consistent thread (ci/base_ci/base/top) */
        g_pcall_in_hook = 0;
        if (saved_top_v && is_memory_writable(L + LUA_TOP_OFF))
            *(uintptr_t*)(L + LUA_TOP_OFF) = saved_top_v;
        if (saved_ci_v && is_memory_writable(L + 0x50))
            *(uintptr_t*)(L + 0x50) = saved_ci_v;
        if (saved_baseci_v && is_memory_writable(L + 0x58))
            *(uintptr_t*)(L + 0x58) = saved_baseci_v;
        if (saved_base_v && is_memory_writable(L + 0x60))
            *(uintptr_t*)(L + 0x60) = saved_base_v;
        if (saved_gt_v && is_memory_writable(L + 0x40))
            *(uintptr_t*)(L + 0x40) = saved_gt_v;
        rc = (jv == 2) ? -2 : -4;
        arm_set_result("%s during staged run on L=%p (contained, frame restored)",
                       jv == 2 ? "TIMEOUT" : "SEGV", (void*)L);
    }
    remove_alrm_guard(&old_alrm);
    remove_segv_guard(&sa, old_sa);
    g_arm_fired_rc = rc;
    g_arm_fired_L = L;
    uintptr_t gtmp = 0;
    if (safe_read(L + LUA_G_OFF, &gtmp, 8)) g_arm_fired_G = gtmp;
    g_arm_fire_count++;
    LOG_CORE("ARM: fired on L=%p G=%#llx rc=%d", (void*)L,
             (unsigned long long)g_arm_fired_G, rc);
}

/* Entry from the trampoline on every lua_pcall in the process. Hot path
 * when disarmed: two atomic loads. When armed, the first game-universe
 * thread to call pcall claims the staged chunk and runs it inline. */
static void pcall_hook_entry(uintptr_t L) {
    if (g_pcall_in_hook) return;
    if (__atomic_load_n(&g_arm_state, __ATOMIC_ACQUIRE) != ARM_ARMED) return;
    if (L < 0x100000000ULL || L > 0x74000000000ULL || (L & 0xF)) return;
    uint8_t hdr[0x70];
    if (!safe_read(L, hdr, sizeof(hdr))) return;
    if (hdr[LUA_TT_OFF] != 0xA) return;                 /* collectable thread */
    uintptr_t G = *(uintptr_t*)(hdr + LUA_G_OFF);
    uintptr_t want = g_arm_g_filter ? g_arm_g_filter : (uintptr_t)g_main_G;
    /* filter 1 = accept ANY universe (discovery mode: the fired G is
     * reported by __POLL__, letting the operator pin the game G) */
    if (want && want != 1 && G != want) return;
    int expected = ARM_ARMED;
    if (!__atomic_compare_exchange_n(&g_arm_state, &expected, ARM_BUSY,
                                     0, __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE))
        return;
    run_staged_on(L);
    __atomic_store_n(&g_arm_state, ARM_DONE, __ATOMIC_RELEASE);
}

extern "C" int executor_arm(const char* code, char* out, size_t out_len) {
    if (!code || !*code) {
        snprintf(out, out_len, "ERR: empty source\n");
        return -1;
    }
    char err[200] = {0};
    g_arm_has_bc = 0;
    int src;
    if (strncmp(code, "BC:", 3) == 0) src = arm_stage_hex(code + 3, err, sizeof(err));
    else                              src = arm_stage_compile(code, err, sizeof(err));
    if (src != 0) {
        snprintf(out, out_len, "ERR: stage failed: %s\n", err);
        return -1;
    }
    uintptr_t fn = exec_fn_addr(EXEC_FN_PCALL);
    if (!fn) {
        snprintf(out, out_len,
                 "ERR: lua_pcall unresolved on client %s (run __RESOLVE__)\n",
                 executor_client_version());
        return -1;
    }
    if (executor_hook_pcall(fn) != 0) {
        snprintf(out, out_len, "ERR: hook install failed (see payload log)\n");
        return -1;
    }
    g_arm_fired_rc = -999;
    g_arm_result[0] = 0;
    __atomic_store_n(&g_arm_state, ARM_ARMED, __ATOMIC_RELEASE);
    return snprintf(out, out_len,
                    "ARMED: %zu bytes staged, pcall hook @%p (wide=%d), "
                    "G filter=%#llx%s\n"
                    "fires inline on the next game-universe pcall — "
                    "poll with __POLL__\n",
                    g_arm_bc_len, (void*)fn, g_pcall_wide,
                    (unsigned long long)(g_arm_g_filter ? g_arm_g_filter
                                                        : (uintptr_t)g_main_G),
                    g_arm_g_filter ? "" : " (g_main_G)");
}

extern "C" int executor_arm_poll(char* out, size_t out_len) {
    int st = __atomic_load_n(&g_arm_state, __ATOMIC_ACQUIRE);
    const char* sn = st == ARM_IDLE ? "IDLE"  : st == ARM_ARMED ? "ARMED" :
                     st == ARM_BUSY ? "BUSY"  : "DONE";
    int n = snprintf(out, out_len, "state=%s fires=%llu hooked=%d\n", sn,
                     (unsigned long long)g_arm_fire_count, g_pcall_hooked);
    if (st == ARM_DONE) {
        n += snprintf(out + n, out_len - n, "L=%p G=%#llx rc=%d\n%s\n",
                      (void*)g_arm_fired_L, (unsigned long long)g_arm_fired_G,
                      g_arm_fired_rc, g_arm_result);
    }
    return n;
}

extern "C" int executor_arm_rearm(char* out, size_t out_len) {
    if (!g_arm_has_bc) {
        snprintf(out, out_len, "ERR: nothing staged (run __ARM__ first)\n");
        return -1;
    }
    if (!g_pcall_hooked) {
        uintptr_t fn = exec_fn_addr(EXEC_FN_PCALL);
        if (!fn || executor_hook_pcall(fn) != 0) {
            snprintf(out, out_len, "ERR: re-hook failed (see payload log)\n");
            return -1;
        }
    }
    g_arm_fired_rc = -999;
    g_arm_result[0] = 0;
    __atomic_store_n(&g_arm_state, ARM_ARMED, __ATOMIC_RELEASE);
    return snprintf(out, out_len, "REARMED (%zu bytes staged)\n", g_arm_bc_len);
}

extern "C" int executor_arm_disarm(char* out, size_t out_len) {
    __atomic_store_n(&g_arm_state, ARM_IDLE, __ATOMIC_RELEASE);
    int uh = executor_unhook_pcall();
    return snprintf(out, out_len, "DISARMED (unhook %s)\n",
                    uh == 0 ? "ok" : "skipped/failed");
}

extern "C" int executor_arm_set_gfilter(uintptr_t G, char* out, size_t out_len) {
    g_arm_g_filter = G;
    return snprintf(out, out_len,
                    "G filter = %#llx (0 = follow g_main_G=%p, 1 = any universe)\n",
                    (unsigned long long)G, (void*)g_main_G);
}

extern "C" int executor_exec_gamestate(const char* code, char* out, size_t out_len) {
    int n = 0;
    char why[160] = {0};
    uintptr_t L = confirmed_main_thread(why, sizeof(why));
    if (!L) {
        snprintf(out, out_len, "ERR: %s\n", why);
        return -1;
    }
    n += snprintf(out + n, out_len - n, "main L=%p\n", (void*)L);

    /* HIJACK first: run on a parked GAME coroutine so our code inherits
     * the real script context (write/physics natives need it). Fallback
     * to the fresh lua_newthread co when no parked game co is available. */
    uintptr_t hijacked_co = 0;
    uint8_t saved_st = 0;
    uintptr_t saved_ci = 0;
    uintptr_t saved_gt = 0;
    uintptr_t co = exec_pick_parked_game_co();
    if (co) {
        uintptr_t base_ci = 0;
        if (safe_read(co + 0x58, &base_ci, 8) && base_ci &&
            is_memory_writable(co + 0x50) && is_memory_writable(co + LUA_STATUS_OFF)) {
            safe_read(co + LUA_STATUS_OFF, &saved_st, 1);
            safe_read(co + 0x50, &saved_ci, 8);
            /* forge the runner's START shape: status 0 + ci==base_ci.
             * [co+0x58] (the ci allocation tail) stays REAL so luaD_call
             * allocates our frame's ci ABOVE the game's live frames. */
            *(uint8_t*)(co + LUA_STATUS_OFF) = 0;
            *(uintptr_t*)(co + 0x50) = base_ci;
            hijacked_co = co;
            /* the script coroutine's globals table is the SANDBOXED env
             * (game resolves to a security-wrapper FUNCTION there —
             * "Instance expected, got function"). Point our hijacked co's
             * gt at the main's RAW globals so imports resolve properly
             * while the co keeps its own script identity for the write
             * natives. [co+0x40] is the gt slot — safe to swap (not
             * ci/base/top). */
            uintptr_t main_gt = 0, co_gt = 0;
            safe_read(L + 0x40, &main_gt, 8);
            safe_read(co + 0x40, &co_gt, 8);
            if (main_gt >= 0x100000000ULL && main_gt <= 0x74000000000ULL &&
                is_memory_writable(co + 0x40)) {
                *(uintptr_t*)(co + 0x40) = main_gt;
                saved_gt = co_gt;
                LOG_CORE("EXEC: HIJACK gt swap: co+0x40 %#llx -> %#llx (raw)",
                         (unsigned long long)co_gt,
                         (unsigned long long)main_gt);
            }
            LOG_CORE("EXEC: HIJACK parked game co=%p (saved st=%u ci=%#llx)",
                     (void*)co, (unsigned)saved_st,
                     (unsigned long long)saved_ci);
        } else {
            co = 0;
        }
    }
    if (!co) {
        co = exec_newthread(L);
        if (!co) {
            n += snprintf(out + n, out_len - n, "ERR: lua_newthread failed\n");
            return -1;
        }
    }
    log_thread_state("CO-FRESH", co);

    /* Direct pipeline for 0.741.0.7411056 (every address derived from the
     * real binary, call-chain verified in the loadstring implementation):
     *   1. src  = std::string __init(code, len)          — 0x10000c75c
     *   2. cont = compile_entry(sret, src)               — 0x10364fdb4:
     *      {module0=compile(src)@0, module1=compile("")@8, flag@0x10}
     *      (rawload reads member1 — the wrong slot; we take member0)
     *   3. bc   = std::string at *(cont+0)+0x18          — module layout
     *   4. closure = luau_load(co, "INJ", bc.data, bc.size, 0)
     *   5. closure fixup: move it to B[0] (stack slot 0) and plant the
     *      main thread into upvalue 0 (closure+0x30): lua_resume derives
     *      its `from` via tothread(co, -10003) = upvalue 0 of the func
     *      at stack slot 0 — without this resume faults on a bare
     *      lua_newthread coroutine. */
    uintptr_t fn_rawload = exec_fn_addr(EXEC_FN_RAWLOAD);
    /* Raw-bytecode mode: a request of the form "BC:<hex>" bypasses the
     * (dead) compile step entirely — the blob is fed straight to luau_load.
     * Pair it with chunks pulled out of the module cache and decoded with
     * __DECODE__. */
    uint8_t* bc_raw = NULL;
    size_t bc_raw_len = 0;
    if (strncmp(code, "BC:", 3) == 0) {
        const char* hex = code + 3;
        size_t hl = strlen(hex);
        while (hl > 0 && (hex[hl-1] == '\n' || hex[hl-1] == '\r' || hex[hl-1] == ' ')) hl--;
        if (hl >= 2 && (hl & 1) == 0) {
            bc_raw = (uint8_t*)malloc(hl / 2 ? hl / 2 : 1);
            if (bc_raw) {
                for (size_t i = 0; i < hl / 2; i++) {
                    unsigned v = 0;
                    if (sscanf(hex + i * 2, "%2x", &v) != 1) {
                        free(bc_raw);
                        bc_raw = NULL;
                        break;
                    }
                    bc_raw[i] = (uint8_t)v;
                }
                if (bc_raw) bc_raw_len = hl / 2;
            }
        }
        if (!bc_raw) {
            snprintf(out, out_len, "ERR: bad BC: hex payload\n");
            return -1;
        }
        LOG_CORE("EXEC: raw bytecode mode: %zu bytes, head=%02x %02x %02x %02x",
                 bc_raw_len, bc_raw[0], bc_raw[1], bc_raw[2], bc_raw[3]);
    }

    uintptr_t fn_compile = exec_fn_addr(EXEC_FN_COMPILE);
    if (!bc_raw && (!fn_rawload || !fn_compile)) {
        snprintf(out, out_len,
                 "ERR: execution blocked — %s%s unresolved on client %s "
                 "(see __RESOLVE__)\n",
                 fn_rawload ? "" : "rawload ",
                 fn_compile ? "" : "compile ",
                 executor_client_version());
        return -1;
    }

    uintptr_t slide = executor_image_slide();

    /* __init(this, ptr, len) and compile_entry(sret, src) — link-time
     * constants for this build, byte-verified before use. */
    uintptr_t fn_init = 0x10000c75cULL + slide;
    uintptr_t fn_ccompile = 0x10364fdb4ULL + slide;
    if (!bc_raw) {
        uint32_t first = 0;
        if (!safe_read(fn_init, &first, 4) || first != 0xa9bc5ff8u ||
            !safe_read(fn_ccompile, &first, 4) || first != 0xd10103ffu) {
            snprintf(out, out_len,
                     "ERR: string/compile signatures drifted — client %s "
                     "needs re-derivation\n",
                     executor_client_version());
            return -1;
        }
    }

    uint8_t srcStr[24];
    memset(srcStr, 0, sizeof(srcStr));
    size_t slen = bc_raw ? 0 : strlen(code);

    int rr = -9;
    uint8_t cont[0x18];                 /* compile_entry sret container */
    memset(cont, 0, sizeof(cont));
    if (bc_raw) {
        rr = 0;                          /* skip compile, load raw below */
    } else {
        struct sigaction old_sa[2], old_alrm, sa;
        install_segv_guard(&sa, old_sa);
        install_alrm_guard(&sa, &old_alrm);
        alarm(20);
        g_exec_segv = 0;
        g_exec_timeout = 0;
        int jv = sigsetjmp(g_exec_jmp, 1);
        LOG_CORE("EXEC: init+compile stage jv=%d", jv);
        if (jv == 0) {
            try {
                ((void (*)(void*, const char*, size_t))fn_init)(srcStr, code, slen);
#if defined(__aarch64__)
                __asm__ volatile(
                    "mov x8, %[dst]\n"
                    "mov x0, %[srcp]\n"
                    "blr %[f]\n"
                    :
                    : [dst] "r" ((uintptr_t)cont),
                      [srcp] "r" ((uintptr_t)srcStr),
                      [f] "r" (fn_ccompile)
                    : "x0", "x1", "x2", "x3", "x4", "x5", "x6", "x7", "x8",
                      "x9", "x10", "x11", "x12", "x13", "x14", "x18",
                      "memory", "cc");
                rr = 0;
#else
                rr = -7; /* sret call needs the arm64 asm shim */
#endif
            } catch (...) {
                rr = -5;
                LOG_CORE("EXEC: init+compile exc");
            }
        } else {
            rr = -4;
        }
        LOG_CORE("EXEC: compile done rr=%d cont={%#llx,%#llx,%#llx}",
                 rr,
                 rr ? 0ull : (unsigned long long)*(uintptr_t*)cont,
                 rr ? 0ull : (unsigned long long)*(uintptr_t*)(cont + 8),
                 (unsigned long long)*(uintptr_t*)(cont + 0x10));
        if (rr == 0) {
            /* diagnostics: the module-cache manager singleton + both
             * member targets, 0x30 bytes each */
            uintptr_t mgr = 0;
            if (safe_read(0x106c4d4f0ULL + slide, &mgr, 8))
                LOG_CORE("EXEC: module mgr @%#llx",
                         (unsigned long long)mgr);
            for (int m = 0; m < 2; m++) {
                uintptr_t mp = *(uintptr_t*)(cont + m * 8) & PTR_MASK;
                if (mp < 0x100000000ULL || mp > 0x74000000000ULL) continue;
                uint8_t mb[0x30];
                if (!safe_read(mp, mb, sizeof(mb))) continue;
                LOG_CORE("EXEC: member%d %p:", m, (void*)mp);
                for (int d = 0; d < 0x30; d += 8)
                    LOG_CORE("  +%02x: %016llx", d,
                             (unsigned long long)*(uint64_t*)(mb + d));
            }
        }
        remove_alrm_guard(&old_alrm);
        remove_segv_guard(&sa, old_sa);
    }

    /* release the source string if __init allocated a long buffer;
     * the compiled module is cache-owned — never freed here */
    if ((srcStr[0x17] & 0x80) && *(void**)srcStr) free(*(void**)srcStr);

    /* extract the bytecode (data, size) from member0's module string */
    const char* bc_data = NULL;
    size_t bc_len = 0;
    if (bc_raw) {
        bc_data = (const char*)bc_raw;
        bc_len = bc_raw_len;
    } else if (rr == 0) {
        uintptr_t module = *(uintptr_t*)cont & PTR_MASK;
        if (module < 0x100000000ULL || module > 0x74000000000ULL) {
            n += snprintf(out + n, out_len - n,
                          "ERR: compile container has no module0 (%#llx)\n",
                          (unsigned long long)*(uintptr_t*)cont);
            return -1;
        }
        uint8_t mod[0x48];
        if (!safe_read(module, mod, sizeof(mod))) {
            n += snprintf(out + n, out_len - n,
                          "ERR: module unreadable @%p\n", (void*)module);
            return -1;
        }
        LOG_CORE("EXEC: module0 dump %p:", (void*)module);
        for (int d = 0; d < 0x48; d += 8)
            LOG_CORE("  +%02x: %016llx", d,
                     (unsigned long long)*(uint64_t*)(mod + d));
        const uint8_t* bcs = mod + 0x18;          /* module string @ +0x18 */
        if (bcs[0x17] & 0x80) {                   /* long form */
            bc_data = *(const char**)(mod + 0x18);
            bc_len = *(size_t*)(mod + 0x20);
        } else {                                   /* short: inline */
            bc_data = (const char*)(mod + 0x18);
            bc_len = bcs[0x17];
        }
        /* the data pointer must be a plain, readable heap pointer — PAC
         * signed or chained pointers here mean the layout guess is wrong */
        if (bc_data && (bc_data < (const char*)0x100000000ULL ||
                        bc_data > (const char*)0x74000000000ULL)) {
            n += snprintf(out + n, out_len - n,
                          "ERR: module string data ptr invalid (%#llx, "
                          "size=%#zx sizebyte=%#x) — layout needs rework\n",
                          (unsigned long long)(uintptr_t)bc_data, bc_len,
                          bcs[0x17]);
            LOG_CORE("EXEC: bad bc_data=%#llx len=%#zx — aborting safely",
                     (unsigned long long)(uintptr_t)bc_data, bc_len);
            return -1;
        }
        if (!bc_data || bc_len == 0 || bc_len > 0x400000ULL) {
            n += snprintf(out + n, out_len - n,
                          "ERR: compiler returned empty/oversize bytecode "
                          "(sizebyte=%#x mod0=%p mod1=%p)\n",
                          bcs[0x17], (void*)*(uintptr_t*)cont,
                          (void*)*(uintptr_t*)(cont + 8));
            return -1;
        }
        LOG_CORE("EXEC: bytecode %zu bytes @ %p head=%02x %02x %02x %02x",
                 bc_len, (void*)bc_data,
                 bc_len > 0 ? (uint8_t)bc_data[0] : 0,
                 bc_len > 1 ? (uint8_t)bc_data[1] : 0,
                 bc_len > 2 ? (uint8_t)bc_data[2] : 0,
                 bc_len > 3 ? (uint8_t)bc_data[3] : 0);
        /* dead-compiler detector: module string == source passthrough */
        if (bc_len == slen && bc_data != code && memcmp(bc_data, code, slen) == 0) {
            n += snprintf(out + n, out_len - n,
                          "ERR: compiler is dead on this build — module "
                          "string equals the source (passthrough)\n");
            return -1;
        }
    }

    if (rr == 0) {
        struct sigaction osa2[2], oalrm2, sa2;
        install_segv_guard(&sa2, osa2);
        install_alrm_guard(&sa2, &oalrm2);
        alarm(15);
        g_exec_segv = 0;
        g_exec_timeout = 0;
        int jv2 = sigsetjmp(g_exec_jmp, 1);
        if (jv2 == 0) {
            try {
                rr = ((int (*)(uintptr_t, const char*, const char*, size_t, int))
                      exec_fn_addr(EXEC_FN_BUfload))(co, "INJ", bc_data, bc_len, 0);
            } catch (...) {
                rr = -5;
            }
        } else {
            rr = -4;
        }
        remove_alrm_guard(&oalrm2);
        remove_segv_guard(&sa2, osa2);
        LOG_CORE("EXEC: luau_load -> %d (segv=%d to=%d)", rr,
                 (int)g_exec_segv, (int)g_exec_timeout);
    }

    if (rr != 0) {
        char eb[608];
        int got = extract_top_string(co, eb, sizeof(eb));
        n += snprintf(out + n, out_len - n, "ERR: load ret=%d", rr);
        if (got > 0) n += snprintf(out + n, out_len - n, " err=\"%s\"", eb);
        n += snprintf(out + n, out_len - n, "\n");
        log_thread_state("CO-LOADFAIL", co);
        return -1;
    }
    log_thread_state("CO-LOADED", co);
    /* dump the freshly-loaded proto's code words: shows what the client's
     * loader did to our wire opcodes (atom rewrites / renumbering) */
    {
        uintptr_t tp0 = 0;
        safe_read(co + LUA_TOP_OFF, &tp0, 8);
        uintptr_t top0 = unpack_top(tp0);
        if (top0 >= 0x100000000ULL && is_memory_readable(top0 - 0x10)) {
            uintptr_t clv = *(uintptr_t*)(top0 - 0x10);
            uint32_t clt = 0;
            safe_read(top0 - 0x10 + 0xc, &clt, 4);
            LOG_CORE("PROTODUMP: closure=%#llx tt=%u", (unsigned long long)clv, clt);
            if (clt == 8 && clv >= 0x100000000ULL && is_memory_readable(clv)) {
                uintptr_t proto = *(uintptr_t*)(clv + 0x18);
                LOG_CORE("PROTODUMP: proto=%#llx", (unsigned long long)proto);
                if (proto >= 0x100000000ULL && is_memory_readable(proto)) {
                    uintptr_t code = *(uintptr_t*)(proto + 0x50);
                    uintptr_t karr = *(uintptr_t*)(proto + 0x10);
                    LOG_CORE("PROTODUMP: code=%#llx k=%#llx",
                             (unsigned long long)code, (unsigned long long)karr);
                    if (code >= 0x100000000ULL && is_memory_readable(code)) {
                        uint32_t w[24] = {0};
                        safe_read(code, w, sizeof(w));
                        for (int q = 0; q < 24; q++)
                            LOG_CORE("PROTODUMP: code[%2d] = %08x  (op=%u A=%u B=%u C=%u D=%u)",
                                     q, w[q], w[q] & 0xff, (w[q] >> 8) & 0xff,
                                     (w[q] >> 16) & 0xff, (w[q] >> 24) & 0xff,
                                     (w[q] >> 16) & 0xffff);
                    }
                }
            }
        }
    }

    /* ---- run: lua_pcall executes the closure synchronously (0.741's
     * lua_resume only moves values — the scheduler runs game coroutines,
     * and ours are not registered with it). The closure stays where
     * luau_load pushed it: at top-1. ---- */
    uintptr_t co_stack = 0;
    safe_read(co + LUA_STACK_OFF, &co_stack, 8);
    uintptr_t tp = 0;
    safe_read(co + LUA_TOP_OFF, &tp, 8);
    uintptr_t top = unpack_top(tp);
    uint64_t fv = 0;
    uint32_t ft = 0;
    if (top >= 0x100000000ULL && is_memory_readable(top - 0x10)) {
        safe_read(top - 0x10, &fv, 8);
        safe_read(top - 0x10 + 0xc, &ft, 4);
    }
    LOG_CORE("EXEC: closure at top-1: val=%#llx tt=%u (top=%#llx stack=%#llx)",
             (unsigned long long)fv, ft,
             (unsigned long long)top, (unsigned long long)co_stack);
    if (ft != 8) {
        n += snprintf(out + n, out_len - n,
                      "ERR: no closure on co top (val=%#llx tt=%u)\n",
                      (unsigned long long)fv, ft);
        return -1;
    }

    if (fv >= 0x100000000ULL && fv < 0x74000000000ULL) {
        uint64_t c[6] = {0, 0, 0, 0, 0, 0};
        safe_read(fv, c, sizeof(c));
        LOG_CORE("EXEC: closure obj %#llx: +0=%#llx +8=%#llx +10=%#llx +18=%#llx +20=%#llx +28=%#llx",
                 (unsigned long long)fv, (unsigned long long)c[0],
                 (unsigned long long)c[1], (unsigned long long)c[2],
                 (unsigned long long)c[3], (unsigned long long)c[4],
                 (unsigned long long)c[5]);
    }

    /* Identity fix: the game's native methods (GetService/Connect) check
     * the calling thread's identity in the ExtraSpace before L. Our fresh
     * co has a zero identity -> "The current thread cannot connect".
     * Copy the ExtraSpace words from the game's main thread (the identity
     * lives in the 0x18 bytes BEFORE the lua_State object).
     * SKIP for the hijacked game coroutine — it already carries the real
     * script identity; overwriting it would corrupt game state. */
    if (!hijacked_co) {
    {
        uintptr_t before_co[8] = {0};
        uintptr_t before_main[8] = {0};
        safe_read(co - 0x18, before_co, 0x18);
        safe_read(L - 0x18, before_main, 0x18);
        LOG_CORE("EXEC: extraspace co={%#llx,%#llx,%#llx} main={%#llx,%#llx,%#llx}",
                 (unsigned long long)before_co[0],
                 (unsigned long long)before_co[1],
                 (unsigned long long)before_co[2],
                 (unsigned long long)before_main[0],
                 (unsigned long long)before_main[1],
                 (unsigned long long)before_main[2]);
        if (is_memory_writable(co - 0x18)) {
            /* copy the shared-block pointer + identity + caps */
            *(uintptr_t*)(co - 0x18) = before_main[0];
            *(uintptr_t*)(co - 0x10) = before_main[1];
            *(uintptr_t*)(co - 0x08) = before_main[2];
            LOG_CORE("EXEC: extraspace copied from main");
        }
    }

    /* NOTE: do NOT copy lua_State fields +0x50..0x88 from main here —
     * that clobbers ci(+0x50)/base_ci(+0x58)/base(+0x60)/top(+0x70)/
     * stack(+0x78) of the fresh co, which the runner's pre-check and
     * func-slot computation depend on (was the "attempt to call a
     * table" root cause). The SAFE subset is the RBX thread wrapper
     * pointer at +0x48 (lua_pushthread reads [L+0x48] -> [x+0x90] for
     * the security context) — copy JUST that. */
    {
        uintptr_t wmain = 0, wco = 0;
        safe_read(L + 0x48, &wmain, 8);
        safe_read(co + 0x48, &wco, 8);
        if (wmain >= 0x100000000ULL && wmain <= 0x74000000000ULL &&
            is_memory_writable(co + 0x48)) {
            *(uintptr_t*)(co + 0x48) = wmain;
            LOG_CORE("EXEC: RBX wrapper copied: co+0x48 %#llx -> %#llx",
                     (unsigned long long)wco, (unsigned long long)wmain);
        } else {
            LOG_CORE("EXEC: no RBX wrapper on main (=%#llx)", (unsigned long long)wmain);
        }
    }
    } /* end extraspace/wrapper identity block */

    /* Frame protocol (disasm-verified): the runner computes
     *   arg = co->top - count*16
     * and the interpreter start path (0x1026e8f54, status==0) calls
     *   luaD_call(co, arg-16, -1)   -> func = top - (count+1)*16.
     * luau_load left the closure at top-1, so count MUST be 0:
     * func = top-16 = the closure. The pre-check (0x1026e8e88) accepts
     * status==0 when [co+0x50]==[co+0x58] (ci==base_ci, true for a fresh
     * lua_newthread co) and from=NULL is handled (nCcalls=1). */
    int r = exec_run(co, 0);
    /* restore the hijacked coroutine's real scheduler state BEFORE
     * anything else touches it — the game's own script frames and the
     * parked status must survive our run */
    if (hijacked_co) {
        if (is_memory_writable(hijacked_co + 0x50) &&
            is_memory_writable(hijacked_co + LUA_STATUS_OFF)) {
            *(uintptr_t*)(hijacked_co + 0x50) = saved_ci;
            *(uint8_t*)(hijacked_co + LUA_STATUS_OFF) = saved_st;
            if (saved_gt && is_memory_writable(hijacked_co + 0x40))
                *(uintptr_t*)(hijacked_co + 0x40) = saved_gt;
            LOG_CORE("EXEC: HIJACK restored (st=%u ci=%#llx gt=%#llx)",
                     (unsigned)saved_st, (unsigned long long)saved_ci,
                     (unsigned long long)saved_gt);
        }
    }
    LOG_CORE("EXEC: run(co=%p) -> %d", (void*)co, r);
    log_thread_state("CO-AFTER", co);
    /* dump the top stack slots raw — the error object hunting ground */
    {
        uintptr_t tp2 = 0;
        safe_read(co + LUA_TOP_OFF, &tp2, 8);
        uintptr_t top2 = unpack_top(tp2);
        for (int k = 1; k <= 10; k++) {
            uintptr_t slot = top2 - (uintptr_t)k * 0x10;
            if (slot < 0x100000000ULL || !is_memory_readable(slot)) break;
            uint64_t v = 0;
            uint32_t t = 0;
            safe_read(slot, &v, 8);
            safe_read(slot + 0xc, &t, 4);
            LOG_CORE("EXEC: slot[-%d] = %#llx tt=%u", k,
                     (unsigned long long)v, t);
            /* decode string slots (tt=6): data at +0x18 in the TString */
            if (t == 6 && v >= 0x100000000ULL && is_memory_readable((uintptr_t)v + 0x18)) {
                char sb[48] = {0};
                safe_read((uintptr_t)v + 0x18, sb, 44);
                sb[44] = 0;
                for (int c = 0; c < 44 && sb[c]; c++)
                    if ((unsigned char)sb[c] < 0x20 || (unsigned char)sb[c] > 0x7e) sb[c] = '.';
                LOG_CORE("EXEC: slot[-%d] STR = \"%s\"", k, sb);
            }
        }
    }

    /* results of the chunk sit below co's top (ok flag, error object) */
    {
        char rb[608];
        int got = extract_top_string(co, rb, sizeof(rb));
        n += snprintf(out + n, out_len - n, "pcall=%d", r);
        if (got > 0) n += snprintf(out + n, out_len - n, " err/result=\"%s\"", rb);
        n += snprintf(out + n, out_len - n, "\n");
    }
    return r;
}

/* List the live candidates from the last heap scan (__CANDS__): address,
 * G, status — lets the operator pick a GAME-universe thread for __SETMAIN__. */

extern "C" int executor_list_candidates(char* buf, size_t len) {
    int n = 0;
    n += snprintf(buf + n, len - n, "live=%d main=%p\n", g_live_n, (void*)g_main_L);
    /* G popularity */
    for (int i = 0; i < g_live_n && n < (int)len - 96; i++) {
        uintptr_t L = g_live_L[i];
        uintptr_t G = 0, stk = 0, tp = 0;
        uint8_t st = 0xff;
        safe_read(L + LUA_G_OFF, &G, 8);
        safe_read(L + LUA_STACK_OFF, &stk, 8);
        safe_read(L + LUA_TOP_OFF, &tp, 8);
        safe_read(L + LUA_STATUS_OFF, &st, 1);
        n += snprintf(buf + n, len - n, "cand %d L=%#llx G=%#llx st=%u top=%#llx\n",
                      i, (unsigned long long)L, (unsigned long long)G,
                      (unsigned)st, (unsigned long long)tp);
    }
    return n;
}

/* Interactive diagnostics for __DIAG__: main-thread cache + live snapshot. */
extern "C" int executor_diag(char* buf, size_t len) {
    int n = 0;
    n += snprintf(buf + n, len - n, "slide=%#lx main_cached=%p valid=%d live_cands=%d\n",
                  executor_image_slide(), (void*)g_main_L,
                  g_main_L ? (int)validate_main_thread(g_main_L) : 0, g_live_n);
    if (g_main_L) {
        log_thread_state("DIAG-MAIN", g_main_L);
        n += snprintf(buf + n, len - n, "G=%p\n", (void*)g_main_G);
    }
    return n;
}

/* Bootstrap the main-thread cache from a thread captured out of the game's
 * own lua_resume call (lldb one-shot): derive its G, store G->mainthread. */
extern "C" int executor_set_main(uintptr_t thread_L, char* buf, size_t len) {
    uintptr_t G = 0;
    if (!safe_read(thread_L + LUA_G_OFF, &G, 8) ||
        G < 0x100000000ULL || G > 0x74000000000ULL || (G & 0xF) != 0) {
        snprintf(buf, len, "ERR: %#lx has no sane G", (unsigned long)thread_L);
        return -1;
    }
    uintptr_t mt = 0;
    {
        /* the mainthread slot moved across versions — find the backref */
        uint8_t gbuf[0x2c0];
        if (safe_read(G, gbuf, sizeof(gbuf))) {
            for (int off = 0x20; off + 8 <= (int)sizeof(gbuf) && !mt; off += 8) {
                uintptr_t cand = *(uintptr_t*)(gbuf + off);
                if (validate_main_thread(cand)) mt = cand;
            }
        }
    }
    if (!validate_main_thread(mt)) {
        /* No mainthread backref inside G+0x20..0x2c0 — fall back to the
         * caller-supplied thread itself: for lua_newthread + identity we
         * only need a live thread carrying the target G (a parked game
         * coroutine is perfect). */
        mt = 0;
        uint8_t lh[0x88];
        if (thread_L >= 0x100000000ULL && thread_L <= 0x74000000000ULL &&
            !(thread_L & 0xF) && safe_read(thread_L, lh, sizeof(lh)) &&
            lh[LUA_TT_OFF] == 0xA &&
            *(uintptr_t*)(lh + LUA_G_OFF) == G &&
            *(uintptr_t*)(lh + LUA_STACK_OFF) >= 0x100000000ULL &&
            *(uintptr_t*)(lh + LUA_STACK_OFF) <= 0x74000000000ULL) {
            mt = thread_L;
        }
        if (!mt) {
            snprintf(buf, len, "ERR: G=%p mainthread %#lx invalid and thread %#lx invalid",
                     (void*)G, (unsigned long)mt, (unsigned long)thread_L);
            return -1;
        }
    }
    g_main_L = mt;
    g_main_G = G;
    log_thread_state("SETMAIN", mt);
    snprintf(buf, len, "OK: main=%p G=%p (from thread %#lx)", (void*)mt,
             (void*)G, (unsigned long)thread_L);
    return 0;
}

/* Background watchdog: DISABLED rescans — with the game joined, a full
 * heap re-walk (150s) wedges the IPC thread and destabilizes the client
 * (observed crashes after a handful of probes). The cached main is
 * revalidated cheaply; if it goes stale the exec path handles it. */
static void* main_watchdog_thread(void* arg) {
    (void)arg;
    for (;;) {
        sleep(30);
        if (g_main_L && validate_main_thread(g_main_L)) continue;
        /* soft refresh only: try the G-preference pick, never a full scan */
        if (g_main_G && g_live_n > 0) {
            for (int i = 0; i < g_live_n; i++) {
                uintptr_t G = 0;
                safe_read(g_live_L[i] + LUA_G_OFF, &G, 8);
                if (G != g_main_G) continue;
                if (!validate_usable_thread(g_live_L[i])) continue;
                g_main_L = g_live_L[i];
                break;
            }
        }
    }
    return NULL;
}

/* __DECODE__ <hex module-string-struct addr>: run the client's own chunk
 * decoder (0x101448b48 on 0.741: decoder(sret-string, in-string)) on a live
 * module string and hex-dump the result. The module cache holds the game's
 * magic-wrapped (0xE009325B4A107A52...) server chunks — this reveals the
 * inner format without any guessing. */
extern "C" int executor_decode_chunk(uintptr_t str_addr, char* buf, size_t len) {
    int n = 0;
    uintptr_t slide = executor_image_slide();
    uintptr_t fn = 0x101448b48ULL + slide;
    uint32_t first = 0;
    if (!safe_read(fn, &first, 4) || first != 0xd10203ffu) {
        snprintf(buf, len, "ERR: decoder signature drifted (%#x) on %s\n",
                 first, executor_client_version());
        return -1;
    }
    if (str_addr < 0x100000000ULL || str_addr > 0x74000000000ULL) {
        snprintf(buf, len, "ERR: bad string addr\n");
        return -1;
    }
    uint8_t in[24];
    if (!safe_read(str_addr, in, sizeof(in))) {
        snprintf(buf, len, "ERR: string unreadable\n");
        return -1;
    }
    uint8_t out[24];
    memset(out, 0, sizeof(out));
    int rc = 0;
    {
        struct sigaction osa[2], oalrm, sa;
        install_segv_guard(&sa, osa);
        install_alrm_guard(&sa, &oalrm);
        alarm(15);
        g_exec_segv = 0;
        g_exec_timeout = 0;
        int jv = sigsetjmp(g_exec_jmp, 1);
        if (jv == 0) {
            try {
#if defined(__aarch64__)
                __asm__ volatile(
                    "mov x8, %[dst]\n"
                    "mov x0, %[srcp]\n"
                    "blr %[f]\n"
                    :
                    : [dst] "r" ((uintptr_t)out),
                      [srcp] "r" ((uintptr_t)str_addr),
                      [f] "r" (fn)
                    : "x0", "x1", "x2", "x3", "x4", "x5", "x6", "x7", "x8",
                      "x9", "x10", "x11", "x12", "x13", "x14", "x18",
                      "memory", "cc");
                rc = 0;
#else
                rc = -7;
#endif
            } catch (...) {
                rc = -5;
            }
        } else {
            rc = -4;
        }
        remove_alrm_guard(&oalrm);
        remove_segv_guard(&sa, osa);
    }
    n += snprintf(buf + n, len - n, "decode rc=%d segv=%d\n", rc, (int)g_exec_segv);
    if (rc != 0) return -1;
    /* result string: classic layout */
    const char* data = NULL;
    size_t dlen = 0;
    if (out[0x17] & 0x80) {
        data = *(const char**)out;
        dlen = *(size_t*)(out + 8);
    } else {
        data = (const char*)out;
        dlen = out[0x17];
    }
    n += snprintf(buf + n, len - n, "out: len=%#zx data=%p sizebyte=%#x\n",
                  dlen, (void*)(uintptr_t)data, out[0x17]);
    if (!data || dlen == 0 || dlen > 0x10000) return 0;
    uint8_t db[1024];
    size_t take = dlen < sizeof(db) ? dlen : sizeof(db);
    if (!safe_read((uintptr_t)data, db, take)) {
        n += snprintf(buf + n, len - n, "out data unreadable\n");
        return 0;
    }
    for (size_t i = 0; i < take && n < (int)len - 24; i += 8) {
        uint64_t v = 0;
        size_t k = take - i < 8 ? take - i : 8;
        memcpy(&v, db + i, k);
        n += snprintf(buf + n, len - n, "+%04zx: %016llx\n", i,
                      (unsigned long long)v);
    }
    /* printable prefix */
    n += snprintf(buf + n, len - n, "ascii: ");
    for (size_t i = 0; i < take && n < (int)len - 8; i++) {
        uint8_t c = db[i];
        buf[n++] = (c >= 0x20 && c < 0x7f) ? (char)c : '.';
    }
    buf[n++] = '\n';
    return n;
}


extern "C" int executor_find_main_sc(char* buf, size_t len) {
    int n = 0;
    if (!g_vtable_data) {
        n += snprintf(buf + n, len - n, "ERR: vtable not mapped (hunter idle)\n");
        return -1;
    }
    void* instances[16];
    int nsc = scan_rw_for_vtable(g_vtable_data, instances, 16);
    n += snprintf(buf + n, len - n, "ScriptContext instances: %d\n", nsc);
    for (int i = 0; i < nsc && n < (int)len - 200; i++) {
        uintptr_t sc = (uintptr_t)instances[i];
        /* level 0: the instance body itself; level 1: one pointer hop */
        static const uintptr_t spans[2][2] = {{0, 0x2000}, {0, 0x800}};
        for (int level = 0; level < 2; level++) {
            uint8_t* chunk = (uint8_t*)malloc(spans[level][1]);
            if (!chunk) break;
            if (safe_read(sc, chunk, spans[level][1])) {
                for (uintptr_t off = 0; off + 0x70 <= spans[level][1]; off += 8) {
                    uintptr_t cand = sc + off;
                    if (level == 1) {
                        cand = *(uintptr_t*)(chunk + off);
                        if (cand < 0x100000000ULL || cand > 0x74000000000ULL ||
                            (cand & 0xF) != 0)
                            continue;
                    }
                    if (lua_state_usable(cand)) {
                        uintptr_t G = 0, mt = 0;
                        safe_read(cand + 0x48, &G, 8);
                        if (G < 0x100000000ULL || G > 0x74000000000ULL) continue;
                        safe_read(G + 0x90, &mt, 8);
                        if (!validate_main_thread(mt)) continue;
                        g_main_L = mt;
                        g_main_G = G;
                        log_thread_state("SCFIND-MAIN", mt);
                        n += snprintf(buf + n, len - n,
                                      "FOUND: sc#%d lvl%d off=%#lx main=%p G=%p\n",
                                      i, level, (unsigned long)off, (void*)mt,
                                      (void*)G);
                        free(chunk);
                        return 0;
                    }
                }
            }
            free(chunk);
        }
    }
    n += snprintf(buf + n, len - n, "not found in %d instances\n", nsc);
    return -1;
}

/* Scan readable regions for qword == value (chained-fixup pointers are only
 * resolvable at runtime, so pointer tables must be hunted in live memory). */
extern "C" int executor_findptr(uint64_t value, char* buf, size_t len) {
    int hits = 0;
    int n = 0;
    mach_vm_address_t addr = 0;
    mach_vm_size_t size = 0;
    while (hits < 24) {
        mach_msg_type_number_t cnt = VM_REGION_BASIC_INFO_COUNT_64;
        vm_region_basic_info_data_64_t info;
        mach_port_t object_name = 0;
        kern_return_t kr = mach_vm_region(mach_task_self(), &addr, &size,
                                          VM_REGION_BASIC_INFO_64,
                                          (vm_region_info_t)&info, &cnt, &object_name);
        if (kr != KERN_SUCCESS) break;
        bool scannable = (info.protection & VM_PROT_READ) &&
                         addr >= 0x100000000ULL && addr < 0x74000000000ULL &&
                         size >= 8 && size < 0x80000000ULL;
        if (scannable) {
            uint8_t* chunk = (uint8_t*)malloc(1 << 20);
            if (chunk) {
                mach_vm_size_t done = 0;
                while (done + 8 <= size && hits < 24) {
                    mach_vm_size_t want = size - done < (1 << 20) ? size - done : (1 << 20);
                    mach_vm_size_t got = 0;
                    if (mach_vm_read_overwrite(mach_task_self(), addr + done,
                                               want, (mach_vm_address_t)chunk,
                                               &got) != KERN_SUCCESS)
                        break;
                    for (mach_vm_size_t i = 0; i + 8 <= got && hits < 24; i += 8) {
                        if (*(uint64_t*)(chunk + i) == value) {
                            n += snprintf(buf + n, len - n, "hit %p\n",
                                          (void*)(addr + done + i));
                            hits++;
                        }
                    }
                    done += got;
                }
                free(chunk);
            }
        }
        addr += size;
    }
    if (hits == 0) n += snprintf(buf + n, len - n, "no hits for %#llx\n",
                                 (unsigned long long)value);
    return n;
}

extern "C" int executor_exec_bc(const uint8_t* bc, size_t nbc, char* out, size_t out_len) {
    uintptr_t slide = executor_image_slide();
    uintptr_t fn_bufload = exec_fn_addr(EXEC_FN_BUfload);    /* (L, chunkname, bc, bclen, env) */
    uintptr_t fn_pcall = exec_fn_addr(EXEC_FN_PCALL);
    uintptr_t fn_newthread_rt = exec_fn_addr(EXEC_FN_NEWTHREAD);
    uintptr_t fn_resume_rt = exec_fn_addr(EXEC_FN_RESUME);
    int n = 0;

    if (!fn_bufload || !fn_newthread_rt || !fn_resume_rt) {
        snprintf(out, out_len,
                 "ERR: execution blocked — unresolved on client %s: %s%s%s "
                 "(see __RESOLVE__; stale constants are never substituted)\n",
                 executor_client_version(),
                 fn_bufload ? "" : "luau_load ",
                 fn_newthread_rt ? "" : "lua_newthread ",
                 fn_resume_rt ? "" : "lua_resume ");
        return -1;
    }

    find_live_thread();
    if (g_live_n == 0) {
        snprintf(out, out_len, "ERR: no live thread\n");
        return -1;
    }
    int try_n = g_live_n < 48 ? g_live_n : 48;
    for (int a = 0; a < g_live_n; a++) {
        for (int b = a + 1; b < g_live_n; b++) {
            if (g_live_pri[b] > g_live_pri[a]) {
                uintptr_t tL = g_live_L[a]; g_live_L[a] = g_live_L[b]; g_live_L[b] = tL;
                uintptr_t ts = g_live_ss[a]; g_live_ss[a] = g_live_ss[b]; g_live_ss[b] = ts;
                uintptr_t tk = g_live_stack[a]; g_live_stack[a] = g_live_stack[b]; g_live_stack[b] = tk;
                uintptr_t tp = g_live_top[a]; g_live_top[a] = g_live_top[b]; g_live_top[b] = tp;
                int tg = g_live_pri[a]; g_live_pri[a] = g_live_pri[b]; g_live_pri[b] = tg;
            }
        }
    }

    for (int ci = 0; ci < try_n; ci++) {
        uintptr_t L = g_live_L[ci];
        uintptr_t stack = g_live_stack[ci];
        uintptr_t top_abs = g_live_top[ci];
        int r2 = -9;
        n = 0;
        n += snprintf(out + n, out_len - n, "L=%p slide=%#lx (cand %d/%d)\n", (void*)L,
                      slide, ci + 1, try_n);

        uintptr_t glue = 0;
        safe_read(L + 0x78, &glue, 8);
        uintptr_t Lg = 0;
        safe_read(L + 0x48, &Lg, 8);
        uintptr_t mt = 0;
        if (Lg >= 0x100000000ULL && Lg <= 0x74000000000ULL)
            safe_read(Lg + 0x90, &mt, 8);
        if (mt != L || glue < 0x100000000ULL || glue > 0x74000000000ULL) {
            LOG_CORE("EXECBC: SKIP L=%p glue=%#llx mt=%#llx", (void*)L,
                     (unsigned long long)glue, (unsigned long long)mt);
            continue;
        }
        LOG_CORE("EXECBC: MAIN CONFIRMED L=%p glue=%#llx", (void*)L,
                 (unsigned long long)glue);

        uintptr_t tp = top_abs;
        safe_read(L + 0x58, &tp, 8);
        if ((tp >> 56) == 0xca)
            tp = ((tp >> 32) & 0xffffff) << 32 | (tp & 0xffffffff);
        if (tp < 0x100000000ULL || tp > 0x74000000000ULL) tp = top_abs;

        struct sigaction old_sa[2], old_alrm, sa;
        /* NOTE: no probe-bufload on main anymore — it leaked a closure onto
         * main's stack (never popped), confusing both stack accounting and
         * the GC. Validation happens on co via co-bufload below. */
        int rr = 0;
        n += snprintf(out + n, out_len - n, "probe skipped (clean)\n");

        if (rr == 0) {
            /* Execute via a fresh coroutine + lua_resume (the native path
             * Roblox itself uses): their luaD_call defers direct calls to
             * the scheduler (-1), but resuming a fresh coroutine runs it */
            uintptr_t fn_newthread = fn_newthread_rt;
            uintptr_t fn_bufload2 = fn_bufload;
            /* real lua_resume(co, from, nargs): runs closure already on co's stack */
            uintptr_t fn_resume = fn_resume_rt;

            /* CRITICAL: a parked main thread can have top BELOW stack.
             * lua_newthread pushes a TValue at main->top — normalize first,
             * restore the original value afterwards or the game crashes */
            uintptr_t main_top_orig = 0;
            safe_read(L + 0x58, &main_top_orig, 8);
            if ((main_top_orig >> 56) == 0xca)
                main_top_orig = ((main_top_orig >> 32) & 0xffffff) << 32 | (main_top_orig & 0xffffffff);
            uintptr_t main_stack = g_live_stack[ci];
            int top_normalized = 0;
            if (main_top_orig < main_stack || main_top_orig > main_stack + 0x400000ULL) {
                if (is_memory_writable(L + 0x58)) {
                    *(uintptr_t*)(L + 0x58) = main_stack;
                    top_normalized = 1;
                    LOG_CORE("EXECBC: normalized parked main top %#llx -> stack %#llx",
                             (unsigned long long)main_top_orig,
                             (unsigned long long)main_stack);
                }
            }

            /* 1) co = NATIVE game coroutine (has full Roblox wrapper: glue,
             * scheduler registration, identity). Fresh lua_newthread threads
             * lack the wrapper and crash the scheduler with Variant-cast.
             * Phase A stored idle native coroutines (pri=1, tt=0xA). */
            uintptr_t co = 0;
            for (int z = 0; z < g_live_n; z++) {
                uint8_t b0 = 0;
                if (g_live_pri[z] <= 1 &&
                    safe_read(g_live_L[z], &b0, 1) && b0 == 0xA) {
                    /* must be fresh-idle: ci == base_ci */
                    uintptr_t cci = 0, ccib = 0;
                    safe_read(g_live_L[z] + 0x50, &cci, 8);
                    safe_read(g_live_L[z] + 0x68, &ccib, 8);
                    if (cci == ccib) { co = g_live_L[z]; break; }
                }
            }
            if (!co) {
            install_segv_guard(&sa, old_sa);
            install_alrm_guard(&sa, &old_alrm);
            alarm(10);
            g_exec_segv = 0;
            g_exec_timeout = 0;
            int jv3 = sigsetjmp(g_exec_jmp, 1);
            if (jv3 == 0) {
                try {
                    uintptr_t (*newthread)(uintptr_t) =
                        (uintptr_t(*)(uintptr_t))fn_newthread;
                    co = newthread(L);
                } catch (...) {
                    co = 0;
                    LOG_CORE("EXECBC: newthread exc");
                }
            }
            remove_alrm_guard(&old_alrm);
            remove_segv_guard(&sa, old_sa);
            LOG_CORE("EXECBC: newthread -> co=%#llx jv=%d", (unsigned long long)co, jv3);
            /* GC ROOTING: keep the TValue lua_newthread pushed onto main's
             * stack AND the parked-top normalization in place until resume
             * completes. Popping early left the thread unrooted — the
             * incremental GC collected closure/proto/k during our slow
             * scans, and resume then executed freed memory (op 0x66 -> br 0).
             * Restore happens after resume in the cleanup block below. */
            if (jv3 != 0 || co < 0x100000000ULL || co > 0x74000000000ULL) {
                /* failed to create thread: undo rooting changes now */
                if (is_memory_writable(L + 0x58)) {
                    uintptr_t mtp = 0;
                    safe_read(L + 0x58, &mtp, 8);
                    if ((mtp >> 56) != 0xca && mtp >= 0x100000000ULL)
                        *(uintptr_t*)(L + 0x58) = mtp - 0x10;
                    if (top_normalized)
                        *(uintptr_t*)(L + 0x58) = main_top_orig;
                }
                n += snprintf(out + n, out_len - n, "ERR: newthread failed\n");
                continue;
            }
            } else {
                LOG_CORE("EXECBC: using NATIVE coro co=%#llx", (unsigned long long)co);
            }

            /* 1.2) glue: fresh coroutines have [co+0x78]==NULL, but the game
             * scheduler/VM dereferences the Roblox Thread object there
             * (main's glue is non-NULL in-game). Copy main's glue so resume
             * sees a live Thread reference instead of a NULL deref. */
            {
                uintptr_t main_glue = 0, co_glue = 0;
                safe_read(L + 0x78, &main_glue, 8);
                safe_read(co + 0x78, &co_glue, 8);
                LOG_CORE("EXECBC: glue main=%#llx co=%#llx",
                         (unsigned long long)main_glue,
                         (unsigned long long)co_glue);
                if (!co_glue && main_glue >= 0x100000000ULL &&
                    main_glue <= 0x74000000000ULL && is_memory_writable(co + 0x78))
                    *(uintptr_t*)(co + 0x78) = main_glue;
            }

            /* 1.25) harvest a valid continuation trampoline: scan thread
             * stacks for function TValues (tt=8), log every candidate's
             * [Closure+0x28]; use the first non-NULL as our trampoline */
            {
                int found = 0;
                uintptr_t bases[24];
                int nbases = 0;
                bases[nbases++] = L;
                for (int z = 0; z < g_live_n && nbases < 24; z++) {
                    uint8_t b0 = 0;
                    if (safe_read(g_live_L[z], &b0, 1) && b0 == 0xA &&
                        g_live_pri[z] <= 1)
                        bases[nbases++] = g_live_L[z];
                }
                for (int bi = 0; bi < nbases && !found; bi++) {
                    uintptr_t ms = 0;
                    if (!safe_read(bases[bi] + 0x38, &ms, 8)) continue;
                    if (ms < 0x100000000ULL || ms > 0x74000000000ULL) continue;
                    int readok = 0, fns = 0;
                    for (int off = -0x1000; off < 0x2000 && !found; off += 16) {
                        uintptr_t slot = ms + off;
                        uint64_t v = 0, t = 0;
                        if (!safe_read(slot, &v, 8)) continue;
                        if (!safe_read(slot + 8, &t, 8)) continue;
                        readok++;
                        if ((t & 0xff) != 8) continue;
                        fns++;
                        if (v < 0x100000000ULL || v > 0x74000000000ULL) continue;
                        uint64_t cont = 0;
                        safe_read(v + 0x28, &cont, 8);
                        LOG_CORE("EXECBC: stackfn[%d+%#x] %llx tt=8 cont=%llx",
                                 bi, off, (unsigned long long)v,
                                 (unsigned long long)cont);
                        if (cont >= 0x100000000ULL && cont <= 0x74000000000ULL) {
                            g_harvested_cont = cont;
                            found = 1;
                            LOG_CORE("EXECBC: harvested trampoline %#llx from thread %d",
                                     (unsigned long long)cont, bi);
                        }
                    }
                    LOG_CORE("EXECBC: stackscan th%d base=%#llx readok=%d funcs=%d",
                             bi, (unsigned long long)bases[bi], readok, fns);
                }
            }

            /* 1.28) DISABLED: writing a harvested native continuation into
             * Closure+0x28 corrupts the .l.uprefs[0] TValue of Lua closures
             * (union aliasing). The VM reads proto/uprefs from the union —
             * any foreign pointer here poisons execution state. */

            /* 1.3) [L+5] native-execution flag: lua_newthread copies it from
             * the parent; a parked main has it set, which routes our fresh
             * closure into the native-codegen trampoline whose slot is NULL
             * for non-codegen closures -> br 0 -> SIGSEGV(pc=0).
             * Force the plain interpreter path. */
            {
                uint8_t f5_main = 0, f5_co = 0;
                safe_read(L + 5, &f5_main, 1);
                safe_read(co + 5, &f5_co, 1);
                if (is_memory_writable(co + 5)) *(uint8_t*)(co + 5) = 0;
                LOG_CORE("EXECBC: native flag main=%u co=%u -> forced 0", f5_main, f5_co);
            }

            /* 1.5) resolve game env table and push it onto co's stack.
             * bufload's env param is a STACK INDEX (env==0 → [L+0x70] gt).
             * We hand the closure the game's real globals via ci->func of
             * main: [main+0x50]=ci, [ci+0x18]=func TValue, tag==8 → Closure,
             * env Table* at Closure+0x10 (verified in luaF_newLclosure
             * 0x102c49738: stp x21,x20,[x0,#0x10] = env,proto). */
            uintptr_t envT = 0;
            {
                uintptr_t mci = 0, fs = 0, ftag = 0, cl = 0;
                safe_read(L + 0x50, &mci, 8);
                if (mci >= 0x100000000ULL && safe_read(mci + 0x18, &fs, 8) &&
                    fs >= 0x100000000ULL && is_memory_readable(fs)) {
                    safe_read(fs + 0xc, &ftag, 4);
                    if ((ftag & 0xff) == 8 && safe_read(fs, &cl, 8) &&
                        cl >= 0x100000000ULL)
                        safe_read(cl + 0x10, &envT, 8);
                }
                uintptr_t co_gt = 0;
                safe_read(co + 0x70, &co_gt, 8);
                if (envT < 0x100000000ULL || envT > 0x74000000000ULL)
                    envT = co_gt; /* fallback: inherited gt */
                LOG_CORE("EXECBC: envT=%#llx (gt fallback=%#llx)",
                         (unsigned long long)envT, (unsigned long long)co_gt);
            }
            int env_idx = 0;
            {
                uintptr_t cobase = 0, cotop = 0;
                safe_read(co + 0x38, &cobase, 8);
                safe_read(co + 0x58, &cotop, 8);
                if (envT >= 0x100000000ULL && cotop >= 0x100000000ULL &&
                    is_memory_writable(cotop) && is_memory_writable(cotop + 0xf)) {
                    /* manual TValue push: {value=Table*, tt=7} — no VM running,
                     * write value/tt/top back-to-back so GC never sees it below top */
                    *(uintptr_t*)cotop = envT;
                    *(uint32_t*)(cotop + 0xc) = 7;
                    *(uintptr_t*)(co + 0x58) = cotop + 0x10;
                    env_idx = (int)((cotop - cobase) >> 4) + 1;
                    LOG_CORE("EXECBC: env pushed idx=%d", env_idx);
                }
            }

            /* 2) load bytecode into the coroutine */
            install_segv_guard(&sa, old_sa);
            install_alrm_guard(&sa, &old_alrm);
            alarm(10);
            g_exec_segv = 0;
            g_exec_timeout = 0;
            int rb = -9;
            int jvb = sigsetjmp(g_exec_jmp, 1);
            if (jvb == 0) {
                try {
                    int (*bufload2)(uintptr_t, const char*, const char*, size_t, int) =
                        (int(*)(uintptr_t, const char*, const char*, size_t, int))fn_bufload2;
                    rb = bufload2(co, "=?INJ", (const char*)bc, nbc, env_idx);
                } catch (const std::exception& e) {
                    rb = -3;
                    LOG_CORE("EXECBC: co-bufload exc: %s", e.what());
                } catch (...) {
                    rb = -3;
                    LOG_CORE("EXECBC: co-bufload exc unknown");
                }
            }
            remove_alrm_guard(&old_alrm);
            remove_segv_guard(&sa, old_sa);
            if (jvb == 2 || g_exec_timeout) rb = -2;
            else if (jvb == 1 || g_exec_segv) rb = -4;
            LOG_CORE("EXECBC: co-bufload -> %d", rb);
            if (rb == 0) {
                /* dump: closure -> proto -> code pointer + first insns,
                 * and live kDispatchTable slots for the opcodes we emit */
                uintptr_t ctp = 0;
                safe_read(co + 0x58, &ctp, 8);
                uintptr_t fv = 0;
                if (ctp >= 0x100000000ULL && is_memory_readable(ctp - 0x10))
                    fv = *(uintptr_t*)(ctp - 0x10);
                if (fv >= 0x100000000ULL && is_memory_readable(fv)) {
                    uint8_t cd[0x40] = {0};
                    safe_read(fv, cd, sizeof(cd));
                    LOG_CORE("EXECBC: closure %llx: %02x%02x%02x%02x%02x%02x%02x%02x | proto=%llx env=%llx",
                             (unsigned long long)fv, cd[0],cd[1],cd[2],cd[3],
                             cd[4],cd[5],cd[6],cd[7],
                             (unsigned long long)*(uint64_t*)(cd+0x18),
                             (unsigned long long)*(uint64_t*)(cd+0x10));
                    uintptr_t proto = *(uintptr_t*)(cd + 0x18);
                    if (proto >= 0x100000000ULL && is_memory_readable(proto)) {
                        uint8_t pd[0x40] = {0};
                        safe_read(proto, pd, sizeof(pd));
                        LOG_CORE("EXECBC: proto %llx: %02x%02x%02x%02x%02x%02x%02x%02x %02x%02x%02x%02x%02x%02x%02x%02x",
                                 (unsigned long long)proto, pd[0],pd[1],pd[2],pd[3],
                                 pd[4],pd[5],pd[6],pd[7],pd[8],pd[9],pd[10],pd[11],
                                 pd[12],pd[13],pd[14],pd[15]);
                        /* scan proto for a pointer whose target starts with
                         * our first remapped instruction word */
                        uint32_t i0 = 0;
                        memcpy(&i0, bc, 4);
                        for (int off = 0; off < 0x38; off += 8) {
                            uintptr_t p = *(uintptr_t*)(pd + off);
                            if (p >= 0x100000000ULL && is_memory_readable(p)) {
                                uint32_t insn0 = 0;
                                safe_read(p, &insn0, 4);
                                LOG_CORE("EXECBC: proto+%#x -> ptr %llx first_insn=%08x (bc_first=%08x)",
                                         off, (unsigned long long)p, insn0, i0);
                            }
                        }
                    }
                }
                /* live dispatch table slots */
                {
                    uintptr_t slide_bc = executor_image_slide();
                    uintptr_t tab = 0x106eed6c0ULL + slide_bc;
                    LOG_CORE("EXECBC: dispatch table @ %#llx (slide=%#llx)",
                             (unsigned long long)tab, (unsigned long long)slide_bc);
                    int idxs[6] = {84, 125, 135, 199, 225, 255};
                    for (int k = 0; k < 6; k++) {
                        int idx = idxs[k];
                        uintptr_t a = tab + idx * 8;
                        uint64_t v = 0;
                        safe_read(a, &v, 8);
                        LOG_CORE("EXECBC: dispatch[%d] = %#llx", idx,
                                 (unsigned long long)v);
                    }
                }
            }
            if (rb != 0) {
                n += snprintf(out + n, out_len - n, "ERR: co-bufload ret=%d\n", rb);
                continue;
            }
            log_thread_state("EXECBC-CO-LOADED", co);
            /* closure must be at co top-16 with tt==8 before we resume */
            {
                uintptr_t ct = 0;
                safe_read(co + 0x58, &ct, 8);
                ct = unpack_top(ct);
                uint64_t cv = 0;
                uint32_t ctag = 0;
                if (ct >= 0x100000000ULL && is_memory_readable(ct - 0x10)) {
                    safe_read(ct - 0x10, &cv, 8);
                    safe_read(ct - 0x10 + 0xc, &ctag, 4);
                }
                LOG_CORE("EXECBC: co closure val=%#llx tt=%u",
                         (unsigned long long)cv, ctag);
                if (ctag != 8) {
                    n += snprintf(out + n, out_len - n,
                                  "ERR: no closure on co top (val=%#llx tt=%u) — bufload did not push\n",
                                  (unsigned long long)cv, ctag);
                    continue;
                }
            }

            /* 3) diagnostics: ExtraSpace (bytes before lua_State) of our co
             * vs a NATIVE game coroutine — Roblox keeps per-thread identity
             * metadata there; fresh threads may lack it and crash in resume */
            {
                uint8_t ours[0x40] = {0}, native[0x40] = {0};
                int have_native = 0;
                uintptr_t natL = 0;
                for (int z = 0; z < g_live_n; z++) {
                    uint8_t ttb = 0;
                    if (safe_read(g_live_L[z], &ttb, 1) && ttb == 0xA &&
                        g_live_L[z] != co) { natL = g_live_L[z]; have_native = 1; break; }
                }
                safe_read(co - 0x40, ours, 0x40);
                if (have_native) safe_read(natL - 0x40, native, 0x40);
                LOG_CORE("EXECBC: OUR extra   %02x%02x%02x%02x%02x%02x%02x%02x | %02x%02x%02x%02x%02x%02x%02x%02x",
                         ours[0], ours[1], ours[2], ours[3], ours[4], ours[5], ours[6], ours[7],
                         ours[8], ours[9], ours[10], ours[11], ours[12], ours[13], ours[14], ours[15]);
                LOG_CORE("EXECBC: NATIVE extra %02x%02x%02x%02x%02x%02x%02x%02x | %02x%02x%02x%02x%02x%02x%02x%02x (L=%p)",
                         native[0], native[1], native[2], native[3], native[4], native[5], native[6], native[7],
                         native[8], native[9], native[10], native[11], native[12], native[13], native[14], native[15],
                         (void*)natL);
            }

            /* 2.6) ENTRY-STUB TRANSPLANT: the binary's luaD_call computes
             * desc = *(proto+0), then target = *(desc+0x28) - (desc+0x28)
             * and blr target. A freshly loaded proto has a descriptor whose
             * +0x28 equals its own address => target = 0 => br NULL.
             * Harvest the computed entry from a NATIVE proto and install it
             * into our descriptor in the same self-relocated form. */
            {
                uintptr_t ct3 = 0;
                safe_read(co + 0x58, &ct3, 8);
                ct3 = unpack_top(ct3);
                uintptr_t cl3 = 0;
                if (ct3 >= 0x100000000ULL && is_memory_readable(ct3 - 0x10))
                    cl3 = *(uintptr_t*)(ct3 - 0x10);
                uintptr_t our_proto = cl3 ? *(uintptr_t*)(cl3 + 0x18) : 0;
                if (our_proto >= 0x100000000ULL && is_memory_readable(our_proto)) {
                    uintptr_t our_desc = *(uintptr_t*)(our_proto);
                    LOG_CORE("STUB: our proto=%llx desc=%llx",
                             (unsigned long long)our_proto,
                             (unsigned long long)our_desc);
                    if (our_desc >= 0x100000000ULL && is_memory_readable(our_desc)) {
                        /* find native lua closure on main stack */
                        uintptr_t mL = g_live_L[0];
                        uintptr_t mstack = 0, mtop = 0;
                        safe_read(mL + 0x38, &mstack, 8);
                        safe_read(mL + 0x58, &mtop, 8);
                        mtop = unpack_top(mtop);
                        for (uintptr_t s = mstack; s + 16 <= mtop; s += 16) {
                            uint32_t tag = 0; uint64_t val = 0;
                            if (!safe_read(s, &val, 8) || !safe_read(s + 0xc, &tag, 4))
                                continue;
                            if ((tag & 0xff) != 8 || val < 0x100000000ULL ||
                                !is_memory_readable(val))
                                continue;
                            uint8_t isc = 0;
                            safe_read(val + 3, &isc, 1);
                            uintptr_t npr = *(uintptr_t*)(val + 0x18);
                            if (isc != 0 || npr < 0x100000000ULL ||
                                !is_memory_readable(npr) || npr == our_proto)
                                continue;
                            uintptr_t ndesc = *(uintptr_t*)(npr);
                            if (ndesc < 0x100000000ULL || !is_memory_readable(ndesc))
                                continue;
                            uintptr_t slot2 = ndesc + 0x28;
                            uintptr_t stored = *(uintptr_t*)slot2;
                            uintptr_t stub = stored - slot2;
                            LOG_CORE("STUB: native proto=%llx desc=%llx stored=%llx stub=%llx",
                                     (unsigned long long)npr,
                                     (unsigned long long)ndesc,
                                     (unsigned long long)stored,
                                     (unsigned long long)stub);
                            if (stub >= 0x100000000ULL && stub <= 0x74000000000ULL &&
                                is_memory_writable(our_desc + 0x28)) {
                                *(uintptr_t*)(our_desc + 0x28) = stub + (our_desc + 0x28);
                                LOG_CORE("STUB: TRANSPLANTED -> stored=%#llx",
                                         (unsigned long long)(stub + our_desc + 0x28));
                            }
                            break;
                        }
                    }
                }
            }

            /* 2.5) PRE-RESUME deep dump: closure -> proto fields, candidate
             * code pointers and their first words, ci->savedpc */
            {
                uintptr_t ct2 = 0;
                safe_read(co + 0x58, &ct2, 8);
                ct2 = unpack_top(ct2);
                uintptr_t cl2 = 0;
                if (ct2 >= 0x100000000ULL && is_memory_readable(ct2 - 0x10))
                    cl2 = *(uintptr_t*)(ct2 - 0x10);
                if (cl2 >= 0x100000000ULL) {
                    uint8_t cd[0x20] = {0};
                    safe_read(cl2, cd, sizeof(cd));
                    LOG_CORE("DUMP: closure %llx: %02x%02x%02x%02x%02x%02x%02x%02x "
                             "%02x%02x%02x%02x%02x%02x%02x%02x",
                             (unsigned long long)cl2,
                             cd[0],cd[1],cd[2],cd[3],cd[4],cd[5],cd[6],cd[7],
                             cd[8],cd[9],cd[10],cd[11],cd[12],cd[13],cd[14],cd[15]);
                    uintptr_t pr = *(uintptr_t*)(cl2 + 0x18);
                    LOG_CORE("DUMP: closure+0x18 (proto?) = %#llx",
                             (unsigned long long)pr);
                    if (pr >= 0x100000000ULL && is_memory_readable(pr)) {
                        uint8_t pd[0x30] = {0};
                        safe_read(pr, pd, sizeof(pd));
                        LOG_CORE("DUMP: proto bytes: %02x%02x%02x%02x%02x%02x%02x%02x "
                                 "%02x%02x%02x%02x%02x%02x%02x%02x",
                                 pd[0],pd[1],pd[2],pd[3],pd[4],pd[5],pd[6],pd[7],
                                 pd[8],pd[9],pd[10],pd[11],pd[12],pd[13],pd[14],pd[15]);
                        static const int coffs[3] = {0x10, 0x18, 0x20};
                        for (int q = 0; q < 3; q++) {
                            uintptr_t cp = *(uintptr_t*)(pr + coffs[q]);
                            if (cp < 0x100000000ULL || !is_memory_readable(cp))
                                continue;
                            uint32_t w[6] = {0};
                            safe_read(cp, w, sizeof(w));
                            LOG_CORE("DUMP: proto+%#x ptr=%#llx insns: %08x %08x %08x %08x %08x %08x",
                                     coffs[q], (unsigned long long)cp,
                                     w[0],w[1],w[2],w[3],w[4],w[5]);
                        }
                    } else {
                        LOG_CORE("DUMP: closure+0x18 unreadable — try +0x20:");
                        uintptr_t pr2 = *(uintptr_t*)(cl2 + 0x20);
                        LOG_CORE("DUMP: closure+0x20 = %#llx", (unsigned long long)pr2);
                    }
                }
                /* ci->savedpc of the co's current call frame */
                uintptr_t cci = 0, csaved = 0;
                safe_read(co + 0x50, &cci, 8);
                if (cci >= 0x100000000ULL && is_memory_readable(cci)) {
                    safe_read(cci + 0x18, &csaved, 8);
                    LOG_CORE("DUMP: co->ci=%#llx ci+0x18=%#llx",
                             (unsigned long long)cci, (unsigned long long)csaved);
                }

                /* GROUND TRUTH: find a NATIVE game Lua closure on main's
                 * stack and dump its proto layout for comparison */
                {
                    uintptr_t mL = g_live_L[0];
                    uintptr_t mstack = 0, mtop = 0;
                    safe_read(mL + 0x38, &mstack, 8);
                    safe_read(mL + 0x58, &mtop, 8);
                    mtop = unpack_top(mtop);
                    LOG_CORE("DUMP: main stack=%#llx top=%#llx",
                             (unsigned long long)mstack, (unsigned long long)mtop);
                    int dumped = 0;
                    for (uintptr_t s = mstack; s + 16 <= mtop && dumped < 3; s += 16) {
                        uint32_t tag = 0;
                        uint64_t val = 0;
                        if (!safe_read(s, &val, 8) || !safe_read(s + 0xc, &tag, 4))
                            continue;
                        if ((tag & 0xff) != 8) continue;
                        if (val < 0x100000000ULL || !is_memory_readable(val)) continue;
                        uint8_t isc = 0;
                        safe_read(val + 3, &isc, 1);
                        uintptr_t pr2 = *(uintptr_t*)(val + 0x18);
                        LOG_CORE("DUMP: native cl=%llx isC=%u proto?=%llx",
                                 (unsigned long long)val, isc,
                                 (unsigned long long)pr2);
                        if (isc == 0 && pr2 >= 0x100000000ULL &&
                            is_memory_readable(pr2)) {
                            uint8_t pd[0x28] = {0};
                            safe_read(pr2, pd, sizeof(pd));
                            LOG_CORE("DUMP: native proto bytes: "
                                     "%02x%02x%02x%02x%02x%02x%02x%02x "
                                     "%02x%02x%02x%02x%02x%02x%02x%02x",
                                     pd[0],pd[1],pd[2],pd[3],pd[4],pd[5],pd[6],pd[7],
                                     pd[8],pd[9],pd[10],pd[11],pd[12],pd[13],pd[14],pd[15]);
                            static const int poffs[4] = {0x08, 0x10, 0x18, 0x20};
                            for (int q = 0; q < 4; q++) {
                                uintptr_t cp = *(uintptr_t*)(pr2 + poffs[q]);
                                if (cp < 0x100000000ULL || !is_memory_readable(cp))
                                    continue;
                                uint32_t w[4] = {0};
                                safe_read(cp, w, sizeof(w));
                                LOG_CORE("DUMP: nproto+%#x ptr=%#llx w: %08x %08x %08x %08x",
                                         poffs[q], (unsigned long long)cp,
                                         w[0],w[1],w[2],w[3]);
                            }
                            dumped++;
                        }
                    }
                }
            }

            /* 3) lua_resume(co) — native execution path */
            install_segv_guard(&sa, old_sa);
            install_alrm_guard(&sa, &old_alrm);
            alarm(15);
            g_exec_segv = 0;
            g_exec_timeout = 0;
            int jvr = sigsetjmp(g_exec_jmp, 1);
            if (jvr == 0) {
                try {
                int (*resume)(uintptr_t, uintptr_t, int) =
                    (int(*)(uintptr_t, uintptr_t, int))fn_resume;
                /* from = main thread, mirroring in-game coroutine.resume */
                r2 = resume(co, L, 0);
                } catch (const std::exception& e) {
                    r2 = -3;
                    LOG_CORE("EXECBC: resume exc: %s", e.what());
                } catch (...) {
                    r2 = -3;
                    LOG_CORE("EXECBC: resume exc unknown");
                }
            }
            remove_alrm_guard(&old_alrm);
            remove_segv_guard(&sa, old_sa);
            if (jvr == 2 || g_exec_timeout) r2 = -2;
            else if (jvr == 1 || g_exec_segv) r2 = -4;
            LOG_CORE("EXECBC: resume -> %d (jv=%d segv=%d to=%d)", r2, jvr,
                     (int)g_exec_segv, (int)g_exec_timeout);
            n += snprintf(out + n, out_len - n, "resume ret=%d\n", r2);

            /* CLEANUP: pop the rooted thread TValue from main's stack and
             * restore the parked top — only AFTER resume is done. */
            if (is_memory_writable(L + 0x58)) {
                uintptr_t mtp = 0;
                safe_read(L + 0x58, &mtp, 8);
                if ((mtp >> 56) != 0xca && mtp >= 0x100000000ULL)
                    *(uintptr_t*)(L + 0x58) = mtp - 0x10;
                if (top_normalized)
                    *(uintptr_t*)(L + 0x58) = main_top_orig;
                LOG_CORE("EXECBC: cleanup: popped thread ref, top restored");
            }

            uint8_t st_co = 9;
            safe_read(co + 3, &st_co, 1);
            LOG_CORE("EXECBC: co status=%u", st_co);
            /* the error object sits on the coroutine's stack top */
            uintptr_t ctp = 0;
            safe_read(co + 0x58, &ctp, 8);
            uintptr_t ct = ((ctp >> 56) == 0xca) ?
                ((ctp >> 32) & 0xffffff) << 32 | (ctp & 0xffffffff) : ctp;
            uint64_t ev = 0;
            uint64_t et = 0;
            if (ct >= 0x100000000ULL && is_memory_readable(ct - 0x10)) {
                ev = *(uint64_t*)(ct - 0x10);
                et = *(uint64_t*)(ct - 0x08);
            }
            LOG_CORE("EXECBC: co-top err val=%#llx tag=%#llx",
                     (unsigned long long)ev, (unsigned long long)(et >> 32));
            if ((et >> 32) == 6 && ev >= 0x100000000ULL && ev < 0x74000000000ULL) {
                uint32_t slen = 0;
                char sbuf[1025];
                sbuf[0] = 0;
                if (safe_read(ev + 0x14, &slen, 4) && slen > 0 && slen < 1024 &&
                    safe_read(ev + 0x18, sbuf, slen)) {
                    sbuf[slen] = 0;
                    LOG_CORE("EXECBC: CO ERROR: %s", sbuf);
                    n += snprintf(out + n, out_len - n, "co-error: \"%.512s\"\n", sbuf);
                }
            }
        }

        /* read error/result slots below top of the coroutine's caller (L) */
        {
            uintptr_t tp2 = 0;
            safe_read(L + 0x58, &tp2, 8);
            uintptr_t t2 = ((tp2 >> 56) == 0xca) ?
                ((tp2 >> 32) & 0xffffff) << 32 | (tp2 & 0xffffffff) : tp2;
            for (int i = -1; i < 0; i++) {
                uintptr_t slot = t2 + (uintptr_t)i * 0x10;
                uint64_t v = 0, t = 0;
                if (slot >= 0x100000000ULL && is_memory_readable(slot)) {
                    v = *(uint64_t*)slot;
                    t = *(uint32_t*)(slot + 0xc);
                }
                n += snprintf(out + n, out_len - n, "  [%d] tag=%#llx\n", i,
                              (unsigned long long)t);
                if (t == 6 && v >= 0x100000000ULL && v < 0x74000000000ULL) {
                    uint32_t slen = 0;
                    char sbuf[1025];
                    sbuf[0] = 0;
                    if (safe_read(v + 0x14, &slen, 4) && slen > 0 && slen < 1024 &&
                        safe_read(v + 0x18, sbuf, slen)) {
                        sbuf[slen] = 0;
                        LOG_CORE("EXECBC: msg: %s", sbuf);
                        n += snprintf(out + n, out_len - n, "  msg: \"%.512s\"\n", sbuf);
                    }
                }
            }
        }

        /* restore top */
        if (is_memory_writable(L + 0x58))
            *(uintptr_t*)(L + 0x58) = g_live_tp[ci];

        if (rr == 0) return r2;
    }
    snprintf(out, out_len, "ERR: all %d candidates failed\n", try_n);
    return -1;
}

extern "C" int executor_unhook_vtable(char* buf, size_t len) {
    if (!g_hook_active || g_vtable_nslots == 0) {
        snprintf(buf, len, "ERR: no active hooks");
        return -1;
    }
    int restored = 0;
    for (int i = 0; i < g_vtable_nslots; i++) {
        uintptr_t slot = g_vtable_data + (uintptr_t)i * 8;
        uintptr_t cur = *(volatile uintptr_t*)slot;
        uintptr_t target = g_vtable_orig[i] & PTR_MASK;
        if ((cur & PTR_MASK) != target) {
            *(volatile uintptr_t*)slot = g_vtable_orig[i];
            restored++;
        }
    }
    g_hook_active = 0;
    int n = snprintf(buf, len, "OK: unhooked, restored %d slots (captured L=%p)",
                     restored, (void*)g_game_lua_state);
    return n;
}

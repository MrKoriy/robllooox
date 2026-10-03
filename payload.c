/*
 * payload.c — injectable Lua executor payload for macOS
 *
 * Loaded into a target process via DYLD_INSERT_LIBRARIES or lldb dlopen.
 * Spawns a UNIX-domain-socket IPC server that receives Lua code,
 * executes it in an embedded Lua state and returns captured output.
 *
 * Protocol (one request per connection):
 *   client: send Lua source, then shutdown(write)
 *   server: execute, send response text, close
 * Control commands (exact match):
 *   __PING__  -> "PONG ..."          (health check, no Lua needed)
 *   __RESET__ -> recreate Lua state  ("OK: Lua state reset")
 *   __RESOLVE__ -> client version + anchor-based symbol resolution report
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <dlfcn.h>
#include <pthread.h>
#include <signal.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <errno.h>
#include <syslog.h>
#include "executor_core.h"

#define FALLBACK_SCRIPT_PATH "/tmp/rbx_script.lua"
#define INITIAL_READ_CAP     65536
#define READ_GROW_THRESHOLD  4096
#define CLIENT_TIMEOUT_SEC   15
#define LUA_MULTRET          (-1)

/* ------------------------------------------------------------------ */
/* Lua C API typedefs (resolved at runtime, version-tolerant)          */
/* ------------------------------------------------------------------ */

typedef void lua_State;
typedef lua_State  *(*fn_luaL_newstate)(void);
typedef void        (*fn_luaL_openlibs)(lua_State *);
typedef int         (*fn_luaL_loadstring)(lua_State *, const char *);
typedef int         (*fn_lua_pcall51)(lua_State *, int, int, int);
typedef int         (*fn_lua_pcallk)(lua_State *, int, int, int, long, void *);
typedef const char *(*fn_lua_tostring51)(lua_State *, int);
typedef const char *(*fn_lua_tolstring)(lua_State *, int, size_t *);
typedef void        (*fn_lua_settop)(lua_State *, int);
typedef int         (*fn_lua_gettop)(lua_State *);
typedef void        (*fn_lua_close)(lua_State *);
typedef const char *(*fn_lua_pushstring)(lua_State *, const char *);
typedef int         (*fn_lua_getglobal)(lua_State *, const char *);
typedef void        (*fn_lua_setglobal)(lua_State *, const char *);

static fn_luaL_newstate  p_luaL_newstate  = NULL;
static fn_luaL_openlibs  p_luaL_openlibs  = NULL;
static fn_luaL_loadstring p_luaL_loadstring = NULL;
static fn_lua_pcall51    p_lua_pcall51    = NULL;  /* 5.1 / Luau export  */
static fn_lua_pcallk     p_lua_pcallk     = NULL;  /* 5.2+ export        */
static fn_lua_tostring51 p_lua_tostring51 = NULL;  /* 5.1 export         */
static fn_lua_tolstring  p_lua_tolstring  = NULL;  /* universal export   */
static fn_lua_settop     p_lua_settop     = NULL;
static fn_lua_gettop     p_lua_gettop     = NULL;
static fn_lua_close      p_lua_close      = NULL;
static fn_lua_pushstring p_lua_pushstring = NULL;
static fn_lua_getglobal  p_lua_getglobal  = NULL;
static fn_lua_setglobal  p_lua_setglobal  = NULL;

static lua_State *g_L = NULL;
static pthread_mutex_t g_lua_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t g_log_mutex = PTHREAD_MUTEX_INITIALIZER;
static char g_log_path[256] = {0};

/* ------------------------------------------------------------------ */
/* Logging: syslog + stderr + file                                     */
/* ------------------------------------------------------------------ */

/* Non-static: executor_core.cpp calls this via extern "C" (LOG_CORE). */
void log_msg(const char *fmt, ...) {
    char body[1024];
    va_list args;
    va_start(args, fmt);
    vsnprintf(body, sizeof(body), fmt, args);
    va_end(args);

    syslog(LOG_NOTICE, "%s", body);
    fprintf(stderr, "[INJ] %s\n", body);

    pthread_mutex_lock(&g_log_mutex);
    if (!g_log_path[0]) {
        snprintf(g_log_path, sizeof(g_log_path),
                 "/tmp/inj_payload_%d.log", getuid());
    }
    FILE *f = fopen(g_log_path, "a");
    if (f) {
        time_t now = time(NULL);
        struct tm tm;
        localtime_r(&now, &tm);
        char ts[32];
        strftime(ts, sizeof(ts), "%Y-%m-%d %H:%M:%S", &tm);
        fprintf(f, "%s [pid %d] %s\n", ts, getpid(), body);
        fclose(f);
    }
    pthread_mutex_unlock(&g_log_mutex);
}

/* ------------------------------------------------------------------ */
/* Growable string buffer for building responses                       */
/* ------------------------------------------------------------------ */

typedef struct {
    char  *data;
    size_t len;
    size_t cap;
} strbuf;

static void sb_init(strbuf *sb) {
    sb->cap = 1024;
    sb->len = 0;
    sb->data = malloc(sb->cap);
    if (sb->data) sb->data[0] = '\0';
}

static void sb_append_n(strbuf *sb, const char *s, size_t n) {
    if (!sb->data || !s) return;
    if (sb->len + n + 1 > sb->cap) {
        size_t ncap = sb->cap * 2;
        while (ncap < sb->len + n + 1) ncap *= 2;
        char *nd = realloc(sb->data, ncap);
        if (!nd) return;
        sb->data = nd;
        sb->cap  = ncap;
    }
    memcpy(sb->data + sb->len, s, n);
    sb->len += n;
    sb->data[sb->len] = '\0';
}

static void sb_append(strbuf *sb, const char *s) {
    if (s) sb_append_n(sb, s, strlen(s));
}

/* ------------------------------------------------------------------ */
/* Lua symbol resolution                                               */
/* ------------------------------------------------------------------ */

static void *resolve_symbol(void *handle, const char *symbol) {
    void *sym = dlsym(handle, symbol);
    if (!sym) {
        char buf[128];
        snprintf(buf, sizeof(buf), "_%s", symbol);
        sym = dlsym(handle, buf);
    }
    return sym;
}

static int init_lua_symbols(void) {
    void *handle = RTLD_DEFAULT;
    p_luaL_newstate = (fn_luaL_newstate)resolve_symbol(handle, "luaL_newstate");

    if (!p_luaL_newstate) {
        log_msg("Lua symbols not found in process namespace. Loading liblua.dylib...");
        static const char *candidates[] = {
            "/opt/homebrew/lib/liblua.dylib",
            "/opt/homebrew/lib/liblua5.4.dylib",
            "/usr/local/lib/liblua.dylib",
            "liblua.dylib",
            "liblua5.4.dylib",
            "liblua5.1.dylib",
            NULL
        };
        void *lib_handle = NULL;
        for (int i = 0; candidates[i] && !lib_handle; i++) {
            lib_handle = dlopen(candidates[i], RTLD_NOW | RTLD_GLOBAL);
        }
        if (!lib_handle) {
            log_msg("ERROR: Failed to load any liblua variant: %s", dlerror());
            return 0;
        }
        handle = lib_handle;
        p_luaL_newstate = (fn_luaL_newstate)resolve_symbol(handle, "luaL_newstate");
    }

    if (!p_luaL_newstate) {
        log_msg("ERROR: Unable to resolve luaL_newstate symbol.");
        return 0;
    }

    p_luaL_openlibs   = (fn_luaL_openlibs)resolve_symbol(handle, "luaL_openlibs");
    p_luaL_loadstring = (fn_luaL_loadstring)resolve_symbol(handle, "luaL_loadstring");
    /* lua_pcall is a macro in 5.2+; the real export there is lua_pcallk */
    p_lua_pcall51     = (fn_lua_pcall51)resolve_symbol(handle, "lua_pcall");
    p_lua_pcallk      = (fn_lua_pcallk)resolve_symbol(handle, "lua_pcallk");
    /* lua_tostring is a macro in 5.2+; the real export is lua_tolstring */
    p_lua_tostring51  = (fn_lua_tostring51)resolve_symbol(handle, "lua_tostring");
    p_lua_tolstring   = (fn_lua_tolstring)resolve_symbol(handle, "lua_tolstring");
    p_lua_settop      = (fn_lua_settop)resolve_symbol(handle, "lua_settop");
    p_lua_gettop      = (fn_lua_gettop)resolve_symbol(handle, "lua_gettop");
    p_lua_close       = (fn_lua_close)resolve_symbol(handle, "lua_close");
    p_lua_pushstring  = (fn_lua_pushstring)resolve_symbol(handle, "lua_pushstring");
    p_lua_getglobal   = (fn_lua_getglobal)resolve_symbol(handle, "lua_getglobal");
    p_lua_setglobal   = (fn_lua_setglobal)resolve_symbol(handle, "lua_setglobal");

    if (!p_luaL_loadstring || (!p_lua_pcall51 && !p_lua_pcallk) ||
        (!p_lua_tostring51 && !p_lua_tolstring)) {
        log_msg("ERROR: Incomplete Lua API (loadstring=%p pcall=%p/%p tostring=%p/%p).",
                (void *)p_luaL_loadstring, (void *)p_lua_pcall51,
                (void *)p_lua_pcallk, (void *)p_lua_tostring51,
                (void *)p_lua_tolstring);
        return 0;
    }

    log_msg("Lua API resolved (pcall: %s, tostring: %s).",
            p_lua_pcall51 ? "lua_pcall" : "lua_pcallk",
            p_lua_tolstring ? "lua_tolstring" : "lua_tostring");
    return 1;
}

static int api_pcall(lua_State *L, int nargs, int nresults, int errfunc) {
    if (p_lua_pcall51) return p_lua_pcall51(L, nargs, nresults, errfunc);
    return p_lua_pcallk(L, nargs, nresults, errfunc, 0, NULL);
}

static const char *api_tostring(lua_State *L, int idx) {
    if (p_lua_tolstring)   return p_lua_tolstring(L, idx, NULL);
    if (p_lua_tostring51)  return p_lua_tostring51(L, idx);
    return NULL;
}

/* ------------------------------------------------------------------ */
/* Lua state lifecycle                                                 */
/* ------------------------------------------------------------------ */

/* Redirects print() into the _INJ_OUT global string so C can capture it. */
static const char *kBootstrap =
    "do\n"
    "  _INJ_OUT = ''\n"
    "  local _tostring = tostring\n"
    "  local _concat = table.concat\n"
    "  print = function(...)\n"
    "    local n = select('#', ...)\n"
    "    local parts = {}\n"
    "    for i = 1, n do parts[i] = _tostring(select(i, ...)) end\n"
    "    _INJ_OUT = _INJ_OUT .. _concat(parts, '\\t') .. '\\n'\n"
    "  end\n"
    "end\n";

/* Caller must hold g_lua_mutex. */
static void destroy_lua_state_locked(void) {
    if (g_L && p_lua_close) {
        p_lua_close(g_L);
    }
    g_L = NULL;
}

/* Caller must hold g_lua_mutex. */
static lua_State *create_lua_state_locked(void) {
    destroy_lua_state_locked();

    g_L = p_luaL_newstate();
    if (!g_L) {
        log_msg("ERROR: Failed to allocate Lua state.");
        return NULL;
    }
    if (p_luaL_openlibs) p_luaL_openlibs(g_L);

    if (p_luaL_loadstring(g_L, kBootstrap) == 0) {
        api_pcall(g_L, 0, 0, 0);
    }
    if (p_lua_settop) p_lua_settop(g_L, 0);

    log_msg("Lua state initialized (%p).", g_L);
    return g_L;
}

static lua_State *get_lua_state(void) {
    pthread_mutex_lock(&g_lua_mutex);
    if (g_L == NULL) {
        if (!p_luaL_newstate && !init_lua_symbols()) {
            pthread_mutex_unlock(&g_lua_mutex);
            return NULL;
        }
        create_lua_state_locked();
    }
    pthread_mutex_unlock(&g_lua_mutex);
    return g_L;
}

/* ------------------------------------------------------------------ */
/* Lua execution with output capture                                   */
/* ------------------------------------------------------------------ */

static int host_is_roblox(void) {
    const char *p = getprogname();
    return p && strcasestr(p, "Roblox");
}

static char *execute_lua_code(const char *code) {
    strbuf sb;
    sb_init(&sb);

    /* In the Roblox host, route everything through the game-state
     * executor: it discovers the game VM's main thread on demand, so no
     * separate capture step is required. Standalone Lua stays the
     * fallback for non-Roblox hosts and a cold pipeline. */
    if (host_is_roblox()) {
        char exec_resp[4096] = {0};
        extern int executor_exec_gamestate(const char*, char*, size_t);
        executor_exec_gamestate(code, exec_resp, sizeof(exec_resp));
        if (strncmp(exec_resp, "main L=", 7) == 0) {
            sb_append(&sb, exec_resp);
            return sb.data;
        }
        log_msg("gamestate pipeline unavailable (%.80s) — standalone fallback",
                exec_resp);
    }

    if (!get_lua_state()) {
        sb_append(&sb, "ERR: Lua API unavailable (is liblua installed?)");
        return sb.data;
    }

    pthread_mutex_lock(&g_lua_mutex);
    lua_State *L = g_L;

    /* Reset per-request output buffer */
    if (p_lua_pushstring && p_lua_setglobal) {
        p_lua_pushstring(L, "");
        p_lua_setglobal(L, "_INJ_OUT");
    }

    int base = p_lua_gettop ? p_lua_gettop(L) : 0;

    int load_status = p_luaL_loadstring(L, code);
    if (load_status != 0) {
        const char *err = api_tostring(L, -1);
        sb_append(&sb, "COMPILE ERR: ");
        sb_append(&sb, err ? err : "unknown");
        if (p_lua_settop) p_lua_settop(L, base);
        pthread_mutex_unlock(&g_lua_mutex);
        return sb.data;
    }

    int pcall_status = api_pcall(L, 0, LUA_MULTRET, 0);
    if (pcall_status != 0) {
        const char *err = api_tostring(L, -1);
        sb_append(&sb, "RUNTIME ERR: ");
        sb_append(&sb, err ? err : "unknown");
        if (p_lua_settop) p_lua_settop(L, base);
        pthread_mutex_unlock(&g_lua_mutex);
        return sb.data;
    }

    /* Captured print() output */
    if (p_lua_getglobal) {
        p_lua_getglobal(L, "_INJ_OUT");
        const char *out = api_tostring(L, -1);
        if (out && out[0]) sb_append(&sb, out);
        if (p_lua_settop) p_lua_settop(L, -2); /* pop _INJ_OUT */
    }

    /* Return values left by the chunk */
    if (p_lua_gettop) {
        int nres = p_lua_gettop(L) - base;
        if (nres > 0) {
            sb_append(&sb, "=> ");
            for (int i = 1; i <= nres; i++) {
                const char *v = api_tostring(L, base + i);
                sb_append(&sb, v ? v : "(non-string)");
                if (i < nres) sb_append(&sb, ", ");
            }
            sb_append(&sb, "\n");
        }
    }

    if (p_lua_settop) p_lua_settop(L, base);
    pthread_mutex_unlock(&g_lua_mutex);

    if (sb.len == 0) sb_append(&sb, "OK");
    return sb.data;
}

/* ------------------------------------------------------------------ */
/* Control commands                                                    */
/* ------------------------------------------------------------------ */

/* Returns a malloc'd response if the message is a control command,
 * or NULL if it should be treated as Lua code. */
static char *handle_control_command(const char *msg) {
    /* trim trailing whitespace/newlines for comparison */
    size_t n = strlen(msg);
    while (n > 0 && (msg[n-1] == '\n' || msg[n-1] == '\r' ||
                     msg[n-1] == ' '  || msg[n-1] == '\t')) n--;

    if (n == 8 && strncmp(msg, "__PING__", 8) == 0) {
        char buf[160];
        const char *lua_state = "unavailable";
        if (p_luaL_newstate || init_lua_symbols()) lua_state = g_L ? "ready" : "idle";
        snprintf(buf, sizeof(buf), "PONG pid=%d lua=%s", getpid(), lua_state);
        return strdup(buf);
    }
    if (n == 9 && strncmp(msg, "__RESET__", 9) == 0) {
        if (!p_luaL_newstate && !init_lua_symbols()) {
            return strdup("ERR: Lua API unavailable");
        }
        pthread_mutex_lock(&g_lua_mutex);
        lua_State *L = create_lua_state_locked();
        pthread_mutex_unlock(&g_lua_mutex);
        return strdup(L ? "OK: Lua state reset" : "ERR: failed to recreate state");
    }
    if (n == 10 && strncmp(msg, "__VTABLE__", 10) == 0) {
        char buf[4096];
        executor_vtable_lab(buf, sizeof(buf));
        return strdup(buf);
    }
    if (n == 10 && strncmp(msg, "__UNHOOK__", 10) == 0) {
        char buf[256];
        executor_unhook_vtable(buf, sizeof(buf));
        return strdup(buf);
    }
    if (n >= 8 && strncmp(msg, "__HOOK__", 8) == 0) {
        int first = 0, last = -1;
        if (sscanf(msg + 8, " %d %d", &first, &last) < 1) last = -1;
        char buf[512];
        executor_hook_vtable(first, last, buf, sizeof(buf));
        return strdup(buf);
    }
    if (n >= 8 && strncmp(msg, "__SCANL__", 8) == 0) {
        char buf[512];
        executor_scan_heap(buf, sizeof(buf));
        return strdup(buf);
    }
    if (n >= 7 && strncmp(msg, "__DUMP__", 8) == 0) {
        uintptr_t addr = 0;
        if (sscanf(msg + 8, " %lx", &addr) != 1)
            return strdup("ERR: usage __DUMP__ <hexaddr>");
        char* out = malloc(64 * 32 + 64);
        if (!out) return strdup("ERR: oom");
        executor_dump(addr, out, 64 * 32 + 64);
        return out;
    }
    if (n >= 9 && strncmp(msg, "__SCDUMP__", 9) == 0) {
        char* out = malloc(64 * 96 + 64);
        if (!out) return strdup("ERR: oom");
        executor_sc_dump(out, 64 * 96 + 64);
        return out;
    }
    if (n >= 7 && strncmp(msg, "__XREF__", 8) == 0) {
        uintptr_t addr = 0;
        if (sscanf(msg + 8, " %lx", &addr) != 1)
            return strdup("ERR: usage __XREF__ <hexaddr>");
        char* out = malloc(16 * 48 + 64);
        if (!out) return strdup("ERR: oom");
        executor_xref(addr, out, 16 * 48 + 64);
        return out;
    }
    if (n >= 9 && strncmp(msg, "__BACKREF__", 11) == 0) {
        uintptr_t addr = 0;
        if (sscanf(msg + 11, " %lx", &addr) != 1)
            return strdup("ERR: usage __BACKREF__ <hexaddr>");
        char* out = malloc(40 * 80 + 64);
        if (!out) return strdup("ERR: oom");
        executor_backref(addr, out, 40 * 80 + 64);
        return out;
    }
    if (n >= 10 && strncmp(msg, "__EXECBC__", 10) == 0) {
        const char* hex = msg + 10;
        while (*hex == ' ' || *hex == '\t') hex++;
        size_t hl = strlen(hex);
        while (hl > 0 && (hex[hl-1]=='\n' || hex[hl-1]=='\r' || hex[hl-1]==' '))
            hl--;
        if (hl < 2 || (hl & 1)) return strdup("ERR: bad hex length");
        size_t bl = hl / 2;
        uint8_t* bc = (uint8_t*)malloc(bl ? bl : 1);
        if (!bc) return strdup("ERR: oom");
        for (size_t i = 0; i < bl; i++) {
            unsigned v = 0;
            if (sscanf(hex + i*2, "%2x", &v) != 1) { free(bc); return strdup("ERR: bad hex"); }
            bc[i] = (uint8_t)v;
        }
        char* out = malloc(8192);
        if (!out) { free(bc); return strdup("ERR: oom"); }
        extern int executor_exec_bc(const uint8_t*, size_t, char*, size_t);
        executor_exec_bc(bc, bl, out, 8192);
        free(bc);
        return out;
    }
    if (n >= 7 && strncmp(msg, "__EXEC__", 8) == 0) {
        const char* code = msg + 8;
        while (*code == ' ' || *code == '\t') code++;
        char* out = malloc(8192);
        if (!out) return strdup("ERR: oom");
        executor_exec_gamestate(code, out, 8192);
        return out;
    }
    if (n >= 11 && strncmp(msg, "__RESOLVE__", 11) == 0) {
        char* out = malloc(16384);
        if (!out) return strdup("ERR: oom");
        extern int executor_resolve(char*, size_t);
        executor_resolve(out, 16384);
        return out;
    }
    if (n >= 7 && strncmp(msg, "__DIAG__", 8) == 0) {
        char* out = malloc(2048);
        if (!out) return strdup("ERR: oom");
        executor_diag(out, 2048);
        return out;
    }
    if (n >= 9 && strncmp(msg, "__SCFIND__", 10) == 0) {
        char* out = malloc(2048);
        if (!out) return strdup("ERR: oom");
        extern int executor_find_main_sc(char*, size_t);
        executor_find_main_sc(out, 2048);
        return out;
    }
    if (n >= 10 && strncmp(msg, "__SETMAIN__", 11) == 0) {
        unsigned long long thr = 0;
        if (sscanf(msg + 11, " %llx", &thr) != 1)
            return strdup("ERR: usage __SETMAIN__ <hex thread L>");
        char rbuf[256];
        extern int executor_set_main(unsigned long, char*, size_t);
        executor_set_main((unsigned long)thr, rbuf, sizeof(rbuf));
        return strdup(rbuf);
    }
    if (n >= 10 && strncmp(msg, "__DECODE__", 10) == 0) {
        unsigned long long saddr = 0;
        if (sscanf(msg + 10, " %llx", &saddr) != 1)
            return strdup("ERR: usage __DECODE__ <hex module-string addr>");
        char* out = malloc(16384);
        if (!out) return strdup("ERR: oom");
        extern int executor_decode_chunk(uintptr_t, char*, size_t);
        executor_decode_chunk((uintptr_t)saddr, out, 16384);
        return out;
    }
    if (n >= 10 && strncmp(msg, "__FINDPTR__", 11) == 0) {
        unsigned long long value = 0;
        if (sscanf(msg + 11, " %llx", &value) != 1)
            return strdup("ERR: usage __FINDPTR__ <hexvalue>");
        char* out = malloc(4096);
        if (!out) return strdup("ERR: oom");
        extern int executor_findptr(unsigned long long, char*, size_t);
        executor_findptr(value, out, 4096);
        return out;
    }
    if (n >= 8 && strncmp(msg, "__SET8__", 8) == 0) {
        unsigned long long addr = 0, val = 0;
        if (sscanf(msg + 8, " %llx %llx", &addr, &val) != 2)
            return strdup("ERR: usage __SET8__ <hexaddr> <hexval>");
        *(volatile uint8_t*)addr = (uint8_t)val;
        char rbuf[96];
        snprintf(rbuf, sizeof(rbuf), "OK: [%#llx]=%#x (readback %#x)",
                 addr, (unsigned)val, *(volatile uint8_t*)addr);
        return strdup(rbuf);
    }
    log_msg("unhandled control: '%s' (n=%zu)", msg, n);
    return NULL;
}

/* ------------------------------------------------------------------ */
/* IPC server                                                          */
/* ------------------------------------------------------------------ */

static int write_all(int fd, const char *buf, size_t len) {
    size_t off = 0;
    while (off < len) {
        ssize_t w = write(fd, buf + off, len - off);
        if (w < 0) {
            if (errno == EINTR) continue;
            return -1;
        }
        off += (size_t)w;
    }
    return 0;
}

static void handle_client(int client_fd) {
    struct timeval tv = { .tv_sec = CLIENT_TIMEOUT_SEC, .tv_usec = 0 };
    setsockopt(client_fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    size_t cap = INITIAL_READ_CAP, len = 0;
    char *buf = malloc(cap);
    if (!buf) return;

    ssize_t r;
    while ((r = read(client_fd, buf + len, cap - len - 1)) > 0) {
        len += (size_t)r;
        if (cap - len - 1 < READ_GROW_THRESHOLD) {
            size_t ncap = cap * 2;
            char *nb = realloc(buf, ncap);
            if (!nb) break;
            buf = nb;
            cap = ncap;
        }
    }
    buf[len] = '\0';

    if (len == 0) {
        free(buf);
        return;
    }

    log_msg("Received IPC payload (%zu bytes)", len);

    char *result = handle_control_command(buf);
    if (!result) result = execute_lua_code(buf);

    write_all(client_fd, result, strlen(result));
    write_all(client_fd, "\n", 1);
    shutdown(client_fd, SHUT_RDWR);

    free(result);
    free(buf);
}

static void run_fallback_script(void) {
    struct stat st;
    if (stat(FALLBACK_SCRIPT_PATH, &st) != 0 || st.st_size == 0) return;

    log_msg("Found fallback script %s, executing...", FALLBACK_SCRIPT_PATH);
    FILE *f = fopen(FALLBACK_SCRIPT_PATH, "r");
    if (!f) return;

    char *buf = malloc((size_t)st.st_size + 1);
    if (buf) {
        size_t got = fread(buf, 1, (size_t)st.st_size, f);
        buf[got] = '\0';
        char *res = execute_lua_code(buf);
        log_msg("Fallback script result: %s", res);
        free(res);
        free(buf);
    }
    fclose(f);
}

static void *ipc_server_thread(void *arg) {
    (void)arg;
    int server_fd;
    struct sockaddr_un addr;
    char socket_path[256];

    snprintf(socket_path, sizeof(socket_path), "/tmp/inj_ipc_%d.sock", getuid());
    unlink(socket_path);

    if ((server_fd = socket(AF_UNIX, SOCK_STREAM, 0)) == -1) {
        log_msg("Failed to create IPC socket: %s", strerror(errno));
        return NULL;
    }

    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, socket_path, sizeof(addr.sun_path) - 1);

    if (bind(server_fd, (struct sockaddr *)&addr, sizeof(addr)) == -1) {
        log_msg("Notice: /tmp bind blocked (%s). Trying local workspace socket...",
                strerror(errno));
        snprintf(socket_path, sizeof(socket_path), "./inj_ipc.sock");
        unlink(socket_path);
        memset(&addr, 0, sizeof(addr));
        addr.sun_family = AF_UNIX;
        strncpy(addr.sun_path, socket_path, sizeof(addr.sun_path) - 1);

        if (bind(server_fd, (struct sockaddr *)&addr, sizeof(addr)) == -1) {
            log_msg("ERROR: Failed to bind local IPC socket: %s", strerror(errno));
            close(server_fd);
            return NULL;
        }
    }

    /* Only the owner may execute code in this process */
    chmod(socket_path, 0600);

    if (listen(server_fd, 8) == -1) {
        log_msg("Failed to listen on IPC socket: %s", strerror(errno));
        close(server_fd);
        unlink(socket_path);
        return NULL;
    }

    log_msg("IPC server listening on %s (pid %d)", socket_path, getpid());

    run_fallback_script();

    while (1) {
        int client_fd = accept(server_fd, NULL, NULL);
        if (client_fd == -1) {
            if (errno == EINTR) continue;
            usleep(10000);
            continue;
        }
        handle_client(client_fd);
        close(client_fd);
    }

    /* unreachable */
    close(server_fd);
    unlink(socket_path);
    return NULL;
}

/* ------------------------------------------------------------------ */
/* Entry point                                                         */
/* ------------------------------------------------------------------ */

__attribute__((constructor))
void inj_init(void) {
    /* A client disconnecting mid-response must not kill the host process */
    signal(SIGPIPE, SIG_IGN);

    openlog("inj_payload", LOG_PID | LOG_CONS, LOG_USER);
    log_msg("Payload loaded, starting IPC server & executor core...");
    executor_init();

    pthread_t tid;
    if (pthread_create(&tid, NULL, ipc_server_thread, NULL) == 0) {
        pthread_detach(tid);
    } else {
        log_msg("Failed to spawn IPC thread: %s", strerror(errno));
    }
}

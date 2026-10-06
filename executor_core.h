/*
 * executor_core.h — Native Roblox Luau Executor Core for macOS
 */

#ifndef EXECUTOR_CORE_H
#define EXECUTOR_CORE_H

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef void lua_State;

/* Initialize pattern scanning and hooks for Roblox game state */
bool executor_init(void);

/* Get captured game lua_State* */
lua_State* executor_get_game_state(void);

/* Elevate Luau ExtraSpace security identity and capabilities */
void executor_set_identity(lua_State* L, int identity, uint64_t capabilities);

/* Compile Lua source code to Luau bytecode string */
char* executor_compile_luau(const char* source, size_t* out_len, char* err_buf, size_t err_buf_len);

/* Execute Lua code inside live game lua_State* */
int executor_execute(const char* code, char* response_buf, size_t response_buf_len);

/* Check if game lua_State is ready and DataModel is active */
bool executor_is_ready(void);

/* Vtable hook lab: dump live vtable slots + writability test */
int executor_vtable_lab(char* buf, size_t len);

/* Install vtable trampoline hooks on slot range [first, last] */
int executor_hook_vtable(int first, int last, char* buf, size_t len);

/* Restore original vtable slots */
int executor_unhook_vtable(char* buf, size_t len);

/* Full-heap scan for the game lua_State (backref invariant) — zero game
 * modification, cannot crash the client. */
int executor_scan_heap(char* buf, size_t len);

/* Read-only memory dump: 64 qwords at addr (kernel-mediated read) */
int executor_dump(uintptr_t addr, char* buf, size_t len);

/* Dump ScriptContext instances with heap-pointer annotation */
int executor_sc_dump(char* buf, size_t len);

/* Find code references (adrp+ldr/add) to an absolute address */
int executor_xref(uintptr_t target, char* buf, size_t len);
int executor_backref(uintptr_t target, char* buf, size_t len);

/* ASLR slide of the RobloxPlayer image (link-time __TEXT is 0x100000000) */
uintptr_t executor_image_slide(void);

/* Execute Lua code inside the live game thread (ForgeChunks-style VM):
 * decompress L, intern source string, push, loadstring, protected call. */
int executor_exec_gamestate(const char* code, char* out, size_t out_len);

/* Diagnostics: main-thread cache validity + live snapshot (__DIAG__). */
int executor_diag(char* buf, size_t len);

/* Version-agnostic symbol resolution (__RESOLVE__): reports the client
 * version + image UUID, every symbol found through string anchors, and which
 * exec-pipeline symbols are usable. Link-time constants are only ever used
 * when the running client is the exact build they were captured from. */
int executor_resolve(char* buf, size_t len);

/* Running client's CFBundleVersion, or "unknown". */
const char* executor_client_version(void);

/* __DECODE__ <hex module-string addr>: run the client's chunk decoder on a
 * live magic-wrapped server chunk and hex-dump the inner format. */
int executor_decode_chunk(uintptr_t str_addr, char* buf, size_t len);

/* Deferred execution via the game's own protected-call path (write-barrier
 * route 1): stage source (compiled) or raw bytecode ("BC:<hex>"), patch the
 * game lua_pcall entry, and run the staged chunk inline on the next
 * game-universe thread that calls pcall — full script identity and live
 * native dispatchers. __ARM__ stages+hooks+arms, __POLL__ reads the parked
 * result, __REARM__ refires the staged chunk, __DISARM__ unpatches,
 * __ARMG__ <hexG> pins the universe filter (0 = follow the cached main). */
int executor_arm(const char* code, char* out, size_t out_len);
int executor_arm_poll(char* out, size_t out_len);
int executor_arm_rearm(char* out, size_t out_len);
int executor_arm_disarm(char* out, size_t out_len);
int executor_arm_set_gfilter(uintptr_t G, char* out, size_t out_len);

#ifdef __cplusplus
}
#endif

#endif /* EXECUTOR_CORE_H */

#!/usr/bin/env python3
"""luau_hunter.py — capture the game lua_State via ScriptContext vtable slots.

Async debugger with an external listener: the listener pump (WaitForEvent)
processes stop events and keeps the game running between captures; Python
breakpoint callbacks validate x0/x1 for LUA_TTHREAD and record hits.
Ends with a graceful Detach — the game is never killed.

Run: lldb -b -o "command script import tools/luau_hunter.py" \
         -o "script luau_hunter.run(<pid>, <seconds>)"
"""
import lldb
import time

PTR_MASK = 0xFFFFFFFFF
VTABLE_DATA = 0x1091e4238  # runtime addr of ScriptContext vtable (0.733.603)

HITS = []


def load_slots(path="/tmp/vtable_slots.txt"):
    slots = []
    with open(path) as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            idx, addr = line.split()
            slots.append((int(idx, 16), int(addr, 16)))
    return slots


def is_script_context(proc, obj):
    """x0 is a ScriptContext if *(x0-8) (low-36) points at the known vtable."""
    if obj < 0x100000000 or obj > 0x30000000000:
        return False
    mem = proc.ReadMemory(obj - 8, 8)
    if mem is None or len(mem) < 8:
        return False
    vp = int.from_bytes(mem, "little") & PTR_MASK
    return vp == (VTABLE_DATA & PTR_MASK)


def _reg(frame, name):
    try:
        return frame.FindRegister(name)
    except Exception:
        return None


def cb(frame, bp_loc, dict):
    try:
        x0 = _reg(frame, "x0")
        x1 = _reg(frame, "x1")
        if not x0 or not x1:
            return False
        x0v = x0.GetValueAsUnsigned()
        x1v = x1.GetValueAsUnsigned()

        proc = frame.GetThread().GetProcess()
        if not is_script_context(proc, x0v):
            return False
        for name, v in (("x0", x0v), ("x1", x1v)):
            if v < 0x100000000 or v > 0x30000000000:
                continue
            mem = proc.ReadMemory(v, 16)
            if mem is None or len(mem) < 16:
                continue
            if mem[8] == 8:  # tt == LUA_TTHREAD
                HITS.append((bp_loc.GetBreakpoint().GetID(), name, v, x0v))
                bp_loc.GetBreakpoint().SetEnabled(False)
                return False
    except Exception:
        pass
    return False


def cli_run(seconds=45, outfile="/tmp/luau_hits.txt"):
    """Run inside the MAIN debugger (lldb -p <pid> -b). Callbacks resolve in
    the same interpreter that imported this module; the private state thread
    drives the target while this command thread sleeps."""
    dbg = lldb.debugger
    target = dbg.GetSelectedTarget()
    proc = target.GetProcess()
    print(f"attached to pid {proc.GetProcessID()}, state={proc.GetState()}")

    slots = load_slots()
    for idx, addr in slots:
        bp = target.BreakpointCreateByAddress(addr)
        if bp and bp.IsValid():
            bp.SetScriptCallbackFunction("luau_hunter.cb")
    print(f"armed {len(slots)} breakpoints")

    with open(outfile, "w"):
        pass
    proc.Continue()
    print("continuing; capturing...")
    time.sleep(seconds)

    proc.Stop()
    deadline = time.time() + 5
    while time.time() < deadline and proc.GetState() != lldb.eStateStopped:
        time.sleep(0.1)

    total_hits = sum(bp.GetHitCount() for bp in target.breakpoint_iter())
    print(f"total breakpoint hits: {total_hits}")
    proc.Detach()

    with open(outfile, "w") as f:
        for slot, name, v, this in HITS:
            f.write(f"slot={slot:#x} {name}={v:#x} this={this:#x}\n")
    print(f"captured {len(HITS)} Lua-thread candidates")
    for slot, name, v, this in HITS:
        print(f"  slot={slot:#x} {name}={v:#x} this={this:#x}")


def run(pid, seconds=30, outfile="/tmp/luau_hits.txt"):
    print("use cli_run with lldb -p (main debugger) instead")
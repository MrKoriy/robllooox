#!/usr/bin/env python3
"""pc_sample.py — lldb PC-sampling for RobloxPlayer.

Attaches to the live process, samples the PC register N times,
writes raw PCs to a file. The histogram of hot PCs localizes
the Luau interpreter loop / pcall path (PIVOT 2, option 2).

Usage: lldb -b -o "command script import tools/pc_sample.py" \
            -o "script pc_sample.run(<pid>, <samples>, <outfile>)"
"""
import lldb
import time


def run(pid, samples=150, outfile="/tmp/pc_samples.txt", quiet=False):
    dbg = lldb.SBDebugger.Create()
    dbg.SetAsync(False)  # sync: API calls block until the state machine settles
    target = dbg.CreateTarget("")
    err = lldb.SBError()
    proc = target.AttachToProcessWithID(dbg.GetListener(), pid, err)
    if not proc or not proc.IsValid() or err.Fail():
        print("attach failed:", err)
        return
    if proc.GetState() != lldb.eStateStopped:
        print("attach: unexpected state", proc.GetState())
        proc.Detach()
        return

    pcs = []
    try:
        for i in range(samples):
            proc.Stop()
            stopped_pc = None
            for t in proc.threads:
                if t.IsStopped():
                    stopped_pc = t.GetFrameAtIndex(0).GetPC()
                    break
            if stopped_pc is None and i < 3:
                print(f"sample {i}: nthreads={proc.GetNumThreads()} no stopped thread")
            if stopped_pc is not None:
                pcs.append(stopped_pc)
            proc.Continue()
            time.sleep(0.01)
    except Exception as e:
        print("sampling error:", e)
    finally:
        proc.Detach()

    with open(outfile, "w") as f:
        for pc in pcs:
            f.write(f"0x{pc:x}\n")
    print(f"wrote {len(pcs)} samples to {outfile}")
    if not quiet:
        from collections import Counter
        c = Counter(pcs)
        print("top exact PCs:")
        for pc, n in c.most_common(15):
            print(f"  {pc:#x} x{n}")
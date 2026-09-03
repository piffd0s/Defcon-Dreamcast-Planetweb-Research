#!/usr/bin/env python3
"""r15_capture.py -- capture R15_AT_UNLINK (stack addr of the saved-PR slot at the
sub_8C063F38 linked-list unlink). Relies on:
  - Flycast launched with Debug.GDBWaitForConnection=yes + AutoLoadState=yes
    -> golden looping state loaded, dynarec cache FLUSHED (bm_Reset+ResetCache),
       guest HALTED waiting for us. So a Z0 bp on the (now cold) teardown block
       compiles fresh on first hit and FIRES (defeats the dynarec wall).
The looping browser navigates /rp/<n> every ~3s; each nav tears down the prior
page's interface-manager list -> sub_8C063F38 unlink -> our bp fires."""
import sys, time
sys.path.insert(0, "/media/adversary/Storage/dc_browser_extract/poc")
from gdbstub_probe import RSP, read_regs, set_bp

ENTRY   = 0x8C063F44   # right after the 4 pushes (r14/r13/r12/pr); r15 == saved-PR slot
UNLINK  = 0x8C063FA8   # the mov.l r2,@(0x3C,r3) write itself
LO, HI  = 0x8C063F44, 0x8C063FAC

def main():
    # connect (flycast is halted, waiting-for-debugger)
    for attempt in range(30):
        try:
            r = RSP(); break
        except Exception as e:
            time.sleep(0.5)
    else:
        print("could not connect to gdb stub"); return 1
    print("connected to gdb stub")
    # drain any stop packet
    r.s.setblocking(False)
    try:
        while r.s.recv(4096): pass
    except: pass
    r.s.setblocking(True)
    # ensure halted
    r.s.send(b"\x03"); time.sleep(0.3)
    try:
        r.s.setblocking(False)
        while r.s.recv(4096): pass
    except: pass
    r.s.setblocking(True)
    regs = read_regs(r)
    print("halted; pc=%08x r15=%08x" % (regs["pc"], regs["r15"]))
    # arm breakpoints (cold cache -> will compile fresh -> fire)
    print("set Z0 @%08x ->" % ENTRY, set_bp(r, ENTRY))
    print("set Z0 @%08x ->" % UNLINK, set_bp(r, UNLINK))
    # continue and wait for a hit across several nav cycles
    t0 = time.time()
    while time.time() - t0 < 60:
        r.send("c")
        resp = r.recv(timeout=20)
        if resp is None:
            print("  (no stop yet, re-continue)"); continue
        if not (resp.startswith("T") or resp.startswith("S")):
            print("  unexpected stop:", resp[:40]); continue
        regs = read_regs(r)
        pc = regs["pc"]; r15 = regs["r15"]
        print("STOP pc=%08x r15=%08x" % (pc, r15))
        if LO <= pc <= HI:
            print("\n=== R15_AT_UNLINK = 0x%08X ===" % r15)
            print("    fake.prev = R15_AT_UNLINK-0x3C = 0x%08X" % (r15 - 0x3C))
            print("    saved-PR slot = 0x%08X  (overwrite with loader addr)" % r15)
            # also show the saved PR value to sanity-check it's a code return addr
            from gdbstub_probe import read_mem
            pr_on_stack = int.from_bytes(read_mem(r, r15, 4), "little")
            print("    *(r15) saved PR currently = 0x%08X" % pr_on_stack)
            return 0
        else:
            print("  stop not in unlink range; continuing")
    print("TIMEOUT: breakpoint did not fire in window")
    return 2

if __name__ == "__main__":
    raise SystemExit(main())

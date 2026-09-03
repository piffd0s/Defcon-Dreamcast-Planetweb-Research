#!/usr/bin/env python3
"""
hw_capture.py -- capture get_sof using a HARDWARE breakpoint (Z1, SH-4 UBC) to
avoid the software-bp TRAPA collision with the guest's own TRAPA syscalls (this
Flycast stub reports every guest TRAPA as a stop -> sw bp is unusable). Z1 fires
ONLY when PC == the address, no RAM patch, immune to dynarec caching + guest
syscalls. Filters stops by pc (defensive) and captures comp_info + heap neighbor.
"""
import sys, time
sys.path.insert(0, "/media/adversary/Storage/dc_browser_extract/poc")
from gdbstub_probe import RSP, read_regs, read_mem, cont

LOG = open("/tmp/hw.log", "w")
def log(s):
    print(s); LOG.write(s + "\n"); LOG.flush()

BP_ALLOC = 0x8C16760E
BP_WRITE = 0x8C167620

def dump(r, addr, length, label):
    d = read_mem(r, addr, length)
    log("  [%s] %#x (%d B):" % (label, addr, len(d)))
    for o in range(0, len(d), 16):
        log("    %08x  %s" % (addr + o, " ".join("%02x" % b for b in d[o:o+16])))

def main():
    r = RSP()
    r.s.send(b"\x03"); time.sleep(0.3); log("halt: %r" % r.recv(3))
    # Z1 hw-bp unsupported on this stub -> Z0 sw-bp + pc-filter (guest crawls
    # through its TRAPA syscalls at RSP speed; we skip past them).
    z0a = r.cmd("Z0,%x,2" % BP_ALLOC)
    z0w = r.cmd("Z0,%x,2" % BP_WRITE)
    log("Z0 sw-bp alloc=%r write=%r; continue + filter guest TRAPAs..." % (z0a, z0w))
    comp = None; passthru = 0
    for _ in range(2000):
        st = cont(r, timeout=900)
        regs = read_regs(r)
        if not regs:
            log("no regs (stop=%r) -> guest died? (overflow faulted)" % st); break
        pc = regs["pc"]
        if pc not in (BP_ALLOC, BP_WRITE):
            passthru += 1
            if passthru % 50 == 0: log("  ...%d guest TRAPAs passed (pc=%08x)" % (passthru, pc))
            continue
        cinfo = regs.get("r14", 0)
        nf = None
        mb = read_mem(r, cinfo + 0x24, 4)
        if len(mb) == 4: nf = int.from_bytes(mb, "little")
        log("\n=== GET_SOF pc=%08x cinfo=%08x Nf=%s r0=%08x r6=%08x r10=%08x ===" %
            (pc, cinfo, nf, regs.get("r0",0), regs.get("r6",0), regs.get("r10",0)))
        if pc == BP_ALLOC:
            comp = regs.get("r0", 0)
            log("  SOF#1 alloc comp_info=%08x size=%#x" % (comp, regs.get("r6",0)))
            dump(r, comp - 0x10, 0x90, "comp_info+hdr")
        elif pc == BP_WRITE:
            r10 = regs.get("r10", 0)
            if nf and nf > 4:
                log("  >>> SOF#2 Nf=%d base=%08x reuse=%s -> overflow %dB" %
                    (nf, r10, "YES" if r10==comp else "?", (nf-1)*0x54))
                dump(r, r10 + 0x3E00, 0x240, "PRE-overflow pool tail +0x3E00")
                dump(r, r10 + 0x4000, 0x240, "PRE-overflow next chunk +0x4000")
                log("  continue -> overflow executes")
            else:
                log("  SOF#1 write base r10=%08x Nf=%s" % (r10, nf))
    log("\ncapture done (passthru=%d guest TRAPAs)" % passthru)

if __name__ == "__main__":
    main()

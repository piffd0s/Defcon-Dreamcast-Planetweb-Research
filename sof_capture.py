#!/usr/bin/env python3
"""
sof_capture.py -- M1 dynamic capture for the get_sof comp_info heap overflow.

Attaches to Flycast SH-4 GDB stub (:3263), sets two software breakpoints in
get_sof (sub_8C1673EC) and captures, across one decode of the two-SOF overflow
JPEG (poc/crashes/sof_overflow/sof_nf2_255.jpg served via /rp/0):

  bp 0x8C16760E  -- alloc just returned (SOF#1 only, comp_info==NULL path):
                    r0 = comp_info base, r6 = alloc size (Nf*0x54), r14 = cinfo
                    -> dump the pool around comp_info (what FOLLOWS it = what the
                       overflow will smash) + the pool header.
  bp 0x8C167620  -- write-loop base (every get_sof): r10 = comp_info, Nf@cinfo+0x24
                    -> SOF#1 (Nf=1) confirms base; SOF#2 (Nf=255) confirms REUSE
                       (same r10, no realloc) and we snapshot the SPILL ZONE just
                       before the 21KB overflow runs.

Run in background; then navigate the DC browser HOME so eden (chain=fuzz, REPRO)
redirects /->/rp/0 and the browser decodes the JPEG. Log -> /tmp/sof_capture.log.
The stub traps the sw breakpoints; it does NOT trap a CPU exception, so if the
overflow faults, flycast dies (watch flycast.log / fc_conn.log) right after the
last 'continue'.
"""
import sys, time
sys.path.insert(0, "/media/adversary/Storage/dc_browser_extract/poc")
from gdbstub_probe import RSP, read_regs, read_mem, set_bp, cont

LOG = open("/tmp/sof_capture.log", "w")
def log(s):
    print(s); LOG.write(s + "\n"); LOG.flush()

def dump(r, addr, length, label):
    data = read_mem(r, addr, length)
    log("  [%s] %#x .. %#x (%d bytes):" % (label, addr, addr + length, len(data)))
    for off in range(0, len(data), 16):
        row = data[off:off+16]
        hexs = " ".join("%02x" % b for b in row)
        log("    %08x  %s" % (addr + off, hexs))

def main():
    r = RSP()
    log("connected to :3263; arming breakpoints")
    log("  bp 0x8C16760E (alloc ret): %s" % set_bp(r, 0x8C16760E))
    log("  bp 0x8C167620 (write base): %s" % set_bp(r, 0x8C167620))
    log("continue -- now navigate the DC browser HOME to load /rp/0 ...")
    comp_info = None
    for hit in range(8):
        st = cont(r, timeout=900)
        regs = read_regs(r)
        if not regs:
            log("hit#%d: no regs (stop=%r) -- guest may have died" % (hit, st)); break
        pc = regs.get("pc", 0)
        cinfo = regs.get("r14", 0)
        nf = None
        if cinfo:
            mb = read_mem(r, cinfo + 0x24, 4)
            if len(mb) == 4: nf = int.from_bytes(mb, "little")
        log("\n=== hit#%d pc=%08x cinfo=%08x Nf=%s ===" % (hit, pc, cinfo, nf))

        if pc == 0x8C16760E:                      # alloc return (SOF#1)
            comp_info = regs.get("r0", 0)
            size = regs.get("r6", 0)
            log("  SOF#1 alloc: comp_info=%08x size=%#x (Nf*0x54)" % (comp_info, size))
            # pool header sits BEFORE the data; dump a window around + after comp_info
            dump(r, comp_info - 0x20, 0x20, "pool-hdr-ish (before comp_info)")
            dump(r, comp_info, 0x80, "comp_info start")
            # what follows the ~16KB first pool: peek the spill landing zone
            dump(r, comp_info + 0x3F00, 0x200, "spill-zone preview (+0x3F00)")

        elif pc == 0x8C167620:                    # write base (SOF#1 and SOF#2)
            r10 = regs.get("r10", 0)
            log("  write base r10=%08x  (comp_info was %s)" %
                (r10, "%08x" % comp_info if comp_info else "?"))
            if nf and nf > 4:                     # SOF#2 -- overflow imminent
                log("  >>> SOF#2 Nf=%d : REUSE %s -> overflow %d bytes IMMINENT"
                    % (nf, "CONFIRMED" if r10 == comp_info else "DIFF(!)", (nf - 1) * 0x54))
                base = r10
                # snapshot the spill boundary: end of the ~16KB pool -> next chunk
                dump(r, base + 0x3E00, 0x300, "PRE-overflow @+0x3E00 (pool tail)")
                dump(r, base + 0x4000, 0x400, "PRE-overflow @+0x4000 (spill into next chunk)")
                log("  continuing -> overflow runs; watch flycast.log for SH4 exception")
        # keep going to catch the SOF#2 hit / observe post-overflow
    log("\ncapture loop done")

if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""
early_capture.py -- attach to Flycast's GDB stub the INSTANT it binds (fresh
boot via fc_restore), set the get_sof breakpoints BEFORE get_sof's first decode,
so the dynarec compiles the block with the TRAPA live (bps set on an already-
cached block do NOT fire). Then capture the two-SOF overflow:
  bp 0x8C16760E  SOF#1 alloc return: r0=comp_info, r6=size; snapshot neighbor
  bp 0x8C167620  write base (every get_sof): r10=comp_info, Nf@cinfo+0x24
On SOF#2 (Nf big) snapshot the spill zone, then continue -> overflow runs.

Run AFTER kicking fc_restore.sh (which relaunches flycast). Log -> /tmp/early.log.
"""
import sys, time, socket
sys.path.insert(0, "/media/adversary/Storage/dc_browser_extract/poc")
from gdbstub_probe import RSP, read_regs, read_mem, set_bp

LOG = open("/tmp/early.log", "w")
def log(s):
    print(s); LOG.write(s + "\n"); LOG.flush()

def wait_port(host="127.0.0.1", port=3263, deadline=60):
    t0 = time.time()
    while time.time() - t0 < deadline:
        try:
            s = socket.create_connection((host, port), timeout=1); s.close(); return True
        except OSError:
            time.sleep(0.2)
    return False

def dump(r, addr, length, label):
    d = read_mem(r, addr, length)
    log("  [%s] %#x (%d B):" % (label, addr, len(d)))
    for o in range(0, len(d), 16):
        log("    %08x  %s" % (addr + o, " ".join("%02x" % b for b in d[o:o+16])))

def wait_log(needle, path="/tmp/fc_conn.log", deadline=40):
    t0 = time.time()
    while time.time() - t0 < deadline:
        try:
            if needle in open(path, "r", errors="ignore").read():
                return True
        except OSError:
            pass
        time.sleep(0.3)
    return False

def main():
    log("waiting for stub :3263 ...")
    if not wait_port():
        log("stub never came up"); return
    r = RSP()
    import os
    if os.environ.get("COLD"):
        log("COLD boot: arming bp immediately (get_sof not yet compiled; wide manual-connect window)")
    elif wait_log("Loaded state"):
        log("state loaded; arming bp now (PPP not up yet -> get_sof not compiled)")
    else:
        log("WARN: no 'Loaded state' seen; arming anyway")
    r.s.send(b"\x03"); time.sleep(0.3); log("halt: %r" % r.recv(3))
    log("set bp 0x8C16760E: %s" % set_bp(r, 0x8C16760E))
    log("set bp 0x8C167620: %s" % set_bp(r, 0x8C167620))
    log("breakpoints armed BEFORE first decode; continue + wait for get_sof")
    comp = None
    from gdbstub_probe import cont
    for hit in range(10):
        st = cont(r, timeout=900)
        regs = read_regs(r)
        if not regs:
            log("hit#%d no regs (stop=%r) -> guest died? (overflow faulted)" % (hit, st)); break
        pc = regs["pc"]; cinfo = regs.get("r14", 0)
        nf = None
        mb = read_mem(r, cinfo + 0x24, 4)
        if len(mb) == 4: nf = int.from_bytes(mb, "little")
        log("\n=== hit#%d pc=%08x cinfo=%08x Nf=%s r0=%08x r6=%08x r10=%08x ===" %
            (hit, pc, cinfo, nf, regs.get("r0",0), regs.get("r6",0), regs.get("r10",0)))
        if pc == 0x8C16760E:
            comp = regs.get("r0", 0)
            log("  SOF#1 alloc comp_info=%08x size=%#x" % (comp, regs.get("r6",0)))
            dump(r, comp - 0x10, 0x90, "comp_info+hdr")
            dump(r, comp + 0x3F00, 0x120, "neighbor preview +0x3F00")
        elif pc == 0x8C167620:
            r10 = regs.get("r10", 0)
            if nf and nf > 4:
                log("  >>> SOF#2 Nf=%d base=%08x reuse=%s -> overflow %dB IMMINENT" %
                    (nf, r10, "YES" if r10==comp else "no(%08x)"%comp if comp else "?", (nf-1)*0x54))
                dump(r, r10 + 0x3E00, 0x240, "PRE-overflow pool tail +0x3E00")
                dump(r, r10 + 0x4000, 0x240, "PRE-overflow next chunk +0x4000")
                log("  continue -> overflow executes (watch for guest death = fault)")
            else:
                log("  SOF#1 write base r10=%08x (Nf=%s)" % (r10, nf))
    log("\ncapture done")

if __name__ == "__main__":
    main()

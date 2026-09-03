#!/usr/bin/env python3
"""
native_recon.py -- static RE of the PlanetWeb native engine (1ST_READ.BIN, SH4)
to locate the sendCommand() dispatcher and recover the command -> handler map.

The Java bridge (NativeSystemInterface$$native.sendCommand(int,Object,Object))
switches on the int command code in native SH4. Small codes (1,3,100-107,111)
are matched with `cmp/eq #imm,r0`; larger codes (200..1006) with a 16-bit
literal pool + `cmp/eq r1,r0`. We find the compare-chain by clustering
`cmp/eq #imm,r0` (0x88II) sites, resync-disassemble it (capstone SH4, skipping
interleaved literal pools), and emit each code's handler address.

  python3 native_recon.py [1ST_READ.BIN]
"""
import sys, os, struct, re
from capstone import Cs, CS_ARCH_SH, CS_MODE_LITTLE_ENDIAN
import capstone

BIN = sys.argv[1] if len(sys.argv) > 1 else \
    "/media/adversary/Storage/dc_browser_extract/dc_extracted/track03_files/1ST_READ.BIN"
BASE = 0x8c010000

NAMES = {1:"sendEdenClientStarted",3:"sendEdenClientFinishedInit",
 100:"setRawDeviceID  *** WRITES FLASH ***",101:"getRawDeviceID",102:"getMake",
 103:"getModel",104:"getOEM",105:"getUserAgent",106:"getBrowserRevision",
 107:"getDeviceRevision",111:"setSecurityFile  *** NATIVE PARSER of attacker byte[] ***",
 200:"queryNetworkState",203:"networkRequestConnect",300:"openURL",301:"goBack",
 310:"notifyPendingIM",312:"notifyIMReady",313:"notifyIMDisabled",400:"isFeatureEnabled",
 401:"setFeatureEnabled",1000:"vmuGetAvailableStorage",1001:"vmuBeginUpdate",
 1002:"vmuEndUpdate",1003:"vmuPutFile",1004:"vmuDeleteFile",1005:"vmuGetFile",1006:"vmuFreeFile"}

def md_sh():
    mode = CS_MODE_LITTLE_ENDIAN
    for m in ("CS_MODE_SH4A", "CS_MODE_SH4"):
        if hasattr(capstone, m): mode |= getattr(capstone, m); break
    return Cs(CS_ARCH_SH, mode)

def find_dispatcher(d):
    """cluster cmp/eq #imm,r0 (file bytes [II,0x88]) where II is a command code."""
    codes = [1, 3] + list(range(0x64, 0x70))
    hits = []
    for II in codes:
        pat = bytes([II, 0x88]); s = 0
        while True:
            i = d.find(pat, s)
            if i < 0: break
            if i % 2 == 0: hits.append((i, II))
            s = i + 1
    hits.sort()
    best = (0, 0)
    for i, (o, _) in enumerate(hits):
        cs = set(); j = i
        while j < len(hits) and hits[j][0] < o + 0x80: cs.add(hits[j][1]); j += 1
        if len(cs) > best[0]: best = (len(cs), o)
    return best[1] if best[0] else None

def resync(md, d, foff, end):
    pos = foff
    while pos < end:
        got = False
        for insn in md.disasm(d[pos:end], BASE + pos):
            got = True; yield insn; pos = insn.address - BASE + insn.size
        if not got: pos += 2

def u16(d, vaddr): return struct.unpack_from("<H", d, vaddr - BASE)[0]

def recover_map(md, d, foff):
    """walk the compare chain, return {code: handler_vaddr}."""
    m = {}; pending = None; last_lit = None
    start = max(0, foff - 0x40)
    for insn in resync(md, d, start, foff + 0x200):
        mn, op = insn.mnemonic, insn.op_str.replace(" ", "")
        if mn == "mov.w":
            mm = re.match(r"(0x[0-9a-f]+),r1", op)
            if mm: last_lit = int(mm.group(1), 0)
        elif mn == "cmp/eq":
            mm = re.match(r"#(\-?\d+|0x[0-9a-f]+),r0", op)
            if mm: pending = int(mm.group(1), 0)
            elif op == "r1,r0" and last_lit: pending = u16(d, last_lit)
        elif mn in ("bra", "bt", "bf", "bt/s", "bf/s") and pending is not None:
            mm = re.match(r"(0x[0-9a-f]+)", op)
            if mm and mn in ("bra", "bt", "bt/s"):   # branch-taken-on-equal -> handler
                m[pending] = int(mm.group(1), 0); pending = None
    return m

def main():
    d = open(BIN, "rb").read()
    md = md_sh()
    print("=== 1ST_READ.BIN SH4 recon ===")
    print("  size=%d base=%#x first8=%s (unscrambled SH4)" % (len(d), BASE, d[:8].hex()))

    foff = find_dispatcher(d)
    if foff is None: sys.exit("dispatcher not found")
    print("  sendCommand dispatcher @ %#010x (file +%#x)" % (BASE + foff, foff))

    m = recover_map(md, d, foff)
    print("\n  CODE  HANDLER       COMMAND")
    print("  " + "-" * 70)
    for code in sorted(m):
        print("  %-5d %#010x  %s" % (code, m[code], NAMES.get(code, "?")))

    print("\n  *** highest-value memory-corruption targets ***")
    for code in (111, 100, 1003, 300):
        if code in m:
            print("    code %-4d @ %#010x  %s" % (code, m[code], NAMES.get(code, "")))
    print("\n  next: disassemble these handlers; look for unbounded copy of the")
    print("        attacker byte[]/String into a fixed buffer (overflow -> SH4 control).")

if __name__ == "__main__":
    main()

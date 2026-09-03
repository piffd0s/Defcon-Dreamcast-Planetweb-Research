#!/usr/bin/env python3
"""
fnptr_scan.py -- scan 1ST_READ.BIN (SH4) for "call *G" sites: a global G is
loaded from a PC literal, dereferenced, and the result is jsr/jmp'd. If G lies
above the overflow start (DST=0x8c29abe6) it's a clean control target: overwrite
the 4 bytes at G via the linear overflow -> PC = our value when that site runs.

  python3 fnptr_scan.py
"""
import struct
from capstone import Cs, CS_ARCH_SH, CS_MODE_LITTLE_ENDIAN
import capstone

BIN = "/media/adversary/Storage/dc_browser_extract/dc_extracted/track03_files/1ST_READ.BIN"
BASE = 0x8c010000; DST = 0x8c29abe6
d = open(BIN, "rb").read(); N = len(d)
mode = CS_MODE_LITTLE_ENDIAN
for m in ("CS_MODE_SH4A", "CS_MODE_SH4"):
    if hasattr(capstone, m): mode |= getattr(capstone, m); break
md = Cs(CS_ARCH_SH, mode)
def u32(v): return struct.unpack_from("<I", d, v - BASE)[0] if 0 <= v-BASE < N-3 else 0

# regs: name -> ('val',V)  (V loaded as immediate/literal)  or  ('deref',G) (=*G)
def scan(start, end):
    hits = []
    pos = start
    while pos < end:
        got = False
        reg = {}
        for insn in md.disasm(d[pos:end], BASE+pos):
            got = True; pos = insn.address - BASE + insn.size
            mn, op = insn.mnemonic, insn.op_str.replace(" ", "")
            # mov.l <pooladdr>,rN  -> rN = literal value
            if mn == "mov.l" and op[:2] == "0x" and ",r" in op:
                a, rn = op.split(","); reg[rn] = ('val', u32(int(a, 0)))
            # mov.l @rN,rM  -> rM = *(value in rN) if rN holds a global addr
            elif mn == "mov.l" and op.startswith("@r") and "," in op and "(" not in op:
                src, rm = op.split(","); rn = src[1:]
                t = reg.get(rn)
                if t and t[0] == 'val' and 0x8c000000 <= t[1] < 0x8d000000:
                    reg[rm] = ('deref', t[1])
                else:
                    reg[rm] = None
            # jsr/jmp @rM -> if rM = *(G), record call *G
            elif mn in ("jsr", "jmp") and op.startswith("@r"):
                rm = op[1:]
                t = reg.get(rm)
                if t and t[0] == 'deref':
                    hits.append((insn.address, t[1]))
                # clobbers handled below
            else:
                # crude clobber: any "...,rX" dest invalidates rX
                if "," in op:
                    dst = op.split(",")[-1]
                    if dst.startswith("r"): reg[dst] = None
        if not got: pos += 2
    return hits

print("scanning .text for call-*-global ...")
hits = scan(0, 0x300000)            # ~3MB code window
# keep those whose global G is in the overflow-reachable BSS (above DST)
targets = {}
for site, G in hits:
    tag = "OVERFLOW-REACHABLE" if G > DST else "below-DST"
    targets.setdefault(G, []).append(site)
print("total call-*-global sites: %d ; distinct globals: %d" % (len(hits), len(targets)))
print("\n== globals CALLED as fn-ptr and ABOVE DST (overflow targets) ==")
reach = sorted([g for g in targets if g > DST])
for g in reach[:40]:
    print("  G=%#010x  (DST+%#x)  called from %d site(s): %s"
          % (g, g-DST, len(targets[g]), [hex(s) for s in targets[g][:4]]))
print("\ntotal overflow-reachable fn-ptr globals: %d" % len(reach))

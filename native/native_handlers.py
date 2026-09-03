#!/usr/bin/env python3
"""
native_handlers.py -- disassemble specific SH4 handler bodies in 1ST_READ.BIN,
tracking PC-relative literal loads so we can resolve call targets, buffer
pointers, and lengths -- i.e. spot the byte[]->fixed-buffer copy (overflow).

  python3 native_handlers.py 0x8c04e0dc [bytes]
  python3 native_handlers.py            # defaults: setRawDeviceID + setSecurityFile
"""
import sys, struct
from capstone import Cs, CS_ARCH_SH, CS_MODE_LITTLE_ENDIAN
import capstone

BIN = "/media/adversary/Storage/dc_browser_extract/dc_extracted/track03_files/1ST_READ.BIN"
BASE = 0x8c010000
d = open(BIN, "rb").read()

def u32(v): return struct.unpack_from("<I", d, v - BASE)[0] if 0 <= v-BASE < len(d)-3 else None
def u16(v):
    x = struct.unpack_from("<H", d, v - BASE)[0]; return x-0x10000 if x>=0x8000 else x

def md_sh():
    mode = CS_MODE_LITTLE_ENDIAN
    for m in ("CS_MODE_SH4A", "CS_MODE_SH4"):
        if hasattr(capstone, m): mode |= getattr(capstone, m); break
    return Cs(CS_ARCH_SH, mode)
MD = md_sh()

def classify(v):
    if v is None: return ""
    if 0x8c010000 <= v < 0x8c800000:
        # is it code (disassembles) or data?
        return "CODE_PTR" if (v-BASE) < len(d) else "PTR"
    if 0 < v <= 0x10000: return "len/const=%d" % v
    return ""

def disasm(addr, n=0x180, label=""):
    print("\n========== handler %s @ %#010x ==========" % (label, addr))
    reg = {}                      # reg-name -> loaded literal value
    pos = addr - BASE; end = pos + n
    while pos < end:
        got = False
        for insn in MD.disasm(d[pos:end], BASE + pos):
            got = True; pos = insn.address - BASE + insn.size
            mn, op = insn.mnemonic, insn.op_str
            note = ""
            # track literal loads: "mov.l 0xADDR,rN" / "mov.w 0xADDR,rN" / "mov #imm,rN"
            t = op.replace(" ", "")
            if mn == "mov.l" and t[:2] == "0x" and ",r" in t:
                a, r = t.split(","); val = u32(int(a, 0)); reg[r] = val
                note = "   ; %s = %s %s" % (r, hex(val) if val is not None else "?", classify(val))
            elif mn == "mov.w" and t[:2] == "0x" and ",r" in t:
                a, r = t.split(","); val = u16(int(a, 0)); reg[r] = val
                note = "   ; %s = %d" % (r, val)
            elif mn == "mov" and t[:1] == "#" and ",r" in t:
                a, r = t.split(",");
                try: reg[r] = int(a[1:], 0)
                except: pass
            elif mn in ("jsr", "jmp") and "@r" in op:
                r = op.replace("@", "").strip()
                tgt = reg.get(r)
                note = "   ; CALL %s%s" % (hex(tgt) if tgt else r, " "+classify(tgt) if tgt else "")
            elif mn in ("bsr", "bsrf"):
                note = "   ; CALL %s" % op
            elif mn.startswith("add") and t.startswith("#-") and t.endswith("r15"):
                note = "   ; *** stack frame / local buffer alloc ***"
            elif mn in ("mov.b", "mov.w", "mov.l") and "@" in op and "-" not in op and op.endswith(")") is False:
                pass
            flag = ""
            if mn in ("jsr","jmp","bsr","bsrf","bt","bf","bt/s","bf/s","bra"): flag = ""
            print("  %#010x  %-8s %-22s%s" % (insn.address, mn, op, note))
        if not got:
            # capstone choked on this halfword (incomplete SH4 support or data);
            # emit the raw 2-byte opcode and stay 2-byte aligned
            hw = struct.unpack_from("<H", d, pos)[0]
            print("  %#010x  .word    0x%04x                  ; (undecoded/data)" % (BASE+pos, hw))
            pos += 2

if __name__ == "__main__":
    if len(sys.argv) > 1:
        disasm(int(sys.argv[1], 0), int(sys.argv[2], 0) if len(sys.argv) > 2 else 0x180, "cli")
    else:
        disasm(0x8c04e0dc, 0x140, "code100 setRawDeviceID")
        disasm(0x8c04e626, 0x160, "code3/111 marshaller (setSecurityFile path)")

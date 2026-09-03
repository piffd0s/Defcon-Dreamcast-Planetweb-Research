#!/usr/bin/env python3
"""Full self-contained DOOM loader stub: mask IRQ -> scan for magic -> hex-decode
& copy doom.bin->0x8CC00000 and wad->0x8C010000 -> set g_wad -> jmp DOOM.
Blob after magic = hex of [doom.bin][wad] (lengths hardcoded in the stub). Decoder
skips CR/LF. Built with the (fixed) byte-safe assembler."""
import sys,struct; sys.path.insert(0,"poc")
import sh4_asm as A
from sh4_asm import (load_reg,assemble_safe,LABEL,BF,BT,BRA,I_movb_at,I_extub,I_cmpeqi,
    I_mov,I_addi,I_cmphs,I_movl_st,I_movb_st,I_nop,I_jmp,I_or,w)
def I_shll2(rn): return w(0x4008|(rn<<8))
def I_cmppl(rn): return w(0x4015|(rn<<8))            # cmp/pl Rn (T if Rn>0)
def I_movl_ld(rm,rn): return w(0x6002|(rn<<8)|(rm<<4))   # mov.l @Rm,Rn

def _paint(color, tag):
    # DIAGNOSTIC ONLY: flood the LIVE framebuffer with a solid color so we can SEE how far the
    # stub gets on real hardware. Reads FB_R_SOF1 (0xA05F8050) for the current PVR scanout base
    # (fb = 0xA5000000 | (sof & 0xFFFFFF)) and fills 640x480x2 bytes. Uses ONLY r10-r13 (never
    # live elsewhere in the stub), so it clobbers nothing. The PVR scans VRAM continuously, so the
    # color appears instantly and persists until the next paint / DOOM overwrites it.
    from sh4_asm import I_and
    return [load_reg(10,0xA05F8050), I_movl_ld(10,10),        # r10 = *FB_R_SOF1 (scanout offset)
            load_reg(13,0x00FFFFFF), I_and(13,10),            # r10 &= 0x00FFFFFF
            load_reg(13,0xA5000000), I_or(13,10),             # r10 = 0xA5000000 | off  (fb base)
            load_reg(11,color), load_reg(12,640*480//2),      # r11 = color (2px/dword), r12 = dwords
            LABEL("pf"+tag), I_movl_st(11,10), I_addi(4,10),
            I_addi(0xFF,12), I_cmppl(12), BT("pf"+tag)]
import os as _os
_mf=_os.path.join(_os.path.dirname(_os.path.abspath(__file__)),"magic.txt")
MAGIC=open(_mf,"rb").read().strip() if _os.path.exists(_mf) else b"DCDOOMGO"
assert len(MAGIC)==8, "magic must be 8 bytes"
SCAN_LO,SCAN_HI=0x8C400000,0x8CFF0000
DOOM_DST,WAD_DST=0x8CC00000,0x8C450000   # WAD: above browser image (no SMC), below DOOM heap base 0x8C860000
GWA,GWS=0x8CC56DA8,0x8CC56DA4   # re-extracted after setvbuf rebuild
PR=0x8C3CC444

def get_nibble(tag):
    # read chars at r5; SKIP ANY non-hex byte (robust to whatever the browser inserts);
    # convert a lowercase hex digit -> r0 ; r5 advanced.
    return [LABEL("gn"+tag),
        I_movb_at(5,0), I_addi(1,5), I_extub(0,0),
        load_reg(1,0x61), I_cmphs(1,0), BF("c09"+tag),     # r0>=0x61 -> maybe a-f
        load_reg(1,0x67), I_cmphs(1,0), BT("gn"+tag),      # r0>=0x67 -> not hex, skip
        I_addi(0xA9,0), BRA("dn"+tag), I_nop(),             # a-f: -0x57
        LABEL("c09"+tag),
        load_reg(1,0x30), I_cmphs(1,0), BF("gn"+tag),      # r0<0x30 -> skip
        load_reg(1,0x3A), I_cmphs(1,0), BT("gn"+tag),      # r0>=0x3A -> skip
        I_addi(0xD0,0),                                     # 0-9: -0x30
        LABEL("dn"+tag)]

def copy_loop(tag):
    o=[LABEL("cp"+tag)]
    o+=get_nibble(tag+"a"); o+=[I_shll2(0),I_shll2(0),I_mov(0,4)]   # hi<<4 -> r4
    o+=get_nibble(tag+"b"); o+=[I_or(0,4)]                          # |lo -> r4
    o+=[I_movb_st(4,6), I_addi(1,6), I_addi(0xFF,7), I_cmppl(7), BT("cp"+tag)]
    return o


def get_b64(tag):
    # read a base64 char at r5 (skip non-b64); 6-bit value -> r0 ; r5 advanced
    from sh4_asm import I_shlr2, I_and
    return [LABEL("g"+tag),
        I_movb_at(5,0), I_addi(1,5), I_extub(0,0),
        load_reg(1,0x41), I_cmphs(1,0), BF("lt41"+tag),     # r0<0x41
        load_reg(1,0x5B), I_cmphs(1,0), BT("ge5B"+tag),     # r0>=0x5B
        I_addi(0xBF,0), BRA("dn"+tag), I_nop(),             # A-Z: -0x41
        LABEL("ge5B"+tag),
        load_reg(1,0x61), I_cmphs(1,0), BF("sk"+tag),       # r0<0x61 -> skip
        load_reg(1,0x7B), I_cmphs(1,0), BT("sk"+tag),       # r0>=0x7B -> skip
        I_addi(0xB9,0), BRA("dn"+tag), I_nop(),             # a-z: -0x47
        LABEL("lt41"+tag),
        load_reg(1,0x30), I_cmphs(1,0), BF("lt30"+tag),     # r0<0x30
        load_reg(1,0x3A), I_cmphs(1,0), BT("sk"+tag),       # r0>=0x3A -> skip
        I_addi(4,0), BRA("dn"+tag), I_nop(),                # 0-9: +4
        LABEL("lt30"+tag),
        I_cmpeqi(0x2B), BT("pl"+tag),                       # '+'
        I_cmpeqi(0x2F), BT("sl"+tag),                       # '/'
        BRA("sk"+tag), I_nop(),
        LABEL("pl"+tag), I_movi6(62), BRA("dn"+tag), I_nop(),
        LABEL("sl"+tag), I_movi6(63), BRA("dn"+tag), I_nop(),
        LABEL("sk"+tag), BRA("g"+tag), I_nop(),             # not b64 -> read next
        LABEL("dn"+tag)]

def I_movi6(v): return w(0xE000|v)   # mov #v,r0

def copy_loop_b64(tag):
    from sh4_asm import I_shlr2, I_and
    o=[LABEL("cp"+tag)]
    o+=get_b64(tag+"0"); o+=[I_mov(0,8)]           # v0->r8
    o+=get_b64(tag+"1"); o+=[I_mov(0,9)]           # v1->r9
    o+=get_b64(tag+"2"); o+=[I_mov(0,10)]          # v2->r10
    o+=get_b64(tag+"3"); o+=[I_mov(0,11)]          # v3->r11
    # b0=(v0<<2)|(v1>>4)
    o+=[I_mov(8,4),I_shll2(4), I_mov(9,1),I_shlr2(1),I_shlr2(1), I_or(1,4),
        I_movb_st(4,6), I_addi(1,6), I_addi(0xFF,7), I_cmppl(7), BF("end"+tag)]
    # b1=((v1&0xF)<<4)|(v2>>2)
    o+=[I_mov(9,4), load_reg(1,0xF),I_and(1,4), I_shll2(4),I_shll2(4),
        I_mov(10,1),I_shlr2(1), I_or(1,4),
        I_movb_st(4,6), I_addi(1,6), I_addi(0xFF,7), I_cmppl(7), BF("end"+tag)]
    # b2=((v2&3)<<6)|v3
    o+=[I_mov(10,4), load_reg(1,3),I_and(1,4), I_shll2(4),I_shll2(4),I_shll2(4),
        I_or(11,4),
        I_movb_st(4,6), I_addi(1,6), I_addi(0xFF,7), I_cmppl(7), BT("cp"+tag),
        LABEL("end"+tag)]
    return o


def I_movbp(rm,rn): return w(0x6004|(rn<<8)|(rm<<4))   # mov.b @Rm+,Rn
def I_add(rm,rn):   return w(0x300C|(rn<<8)|(rm<<4))   # add Rm,Rn
def I_sub(rm,rn):   return w(0x3008|(rn<<8)|(rm<<4))   # sub Rm,Rn (Rn=Rn-Rm)

def copy_loop_raw(tag):
    # raw memcpy: r5=src (post-inc), r6=dest, r7=count
    return [LABEL("cp"+tag),
        I_movbp(5,4), I_movb_st(4,6), I_addi(1,6), I_addi(0xFF,7),
        I_cmppl(7), BT("cp"+tag)]

def full_stub_raw(doom_len, wad_len, diag=False):
    """scan JVM heap for MAGIC, then RAW memcpy doom->DOOM_DST, wad->WAD_DST
    (data already binary in a Java byte[]), set g_wad, jmp DOOM.
    diag=True inserts framebuffer progress markers: RED=entry, GREEN=scan-found, BLUE=copy-done."""
    it=[]
    if diag: it += _paint(0xF800F800, "R")   # RED: stub entered + executing (entry/cache OK)
    # save the ORIGINAL (browser) SR in r8, then set BL=1 for an uninterrupted scan.
    # before jumping to DOOM we RESTORE r8 so DOOM inherits the live browser SR exactly
    # like the proven boot_doom.py recipe (which only set PC + continued). Forcing
    # SR=0x40000000 caused "SH4 exception when blocked" (irq -> browser handler on the
    # smashed stack while BL auto-set).
    it+=[A.I_stc_sr(1), I_mov(1,8), load_reg(4,0x10000000), I_or(4,1), A.I_ldc_sr(1)]
    it+=[load_reg(2,SCAN_LO),load_reg(3,SCAN_HI),LABEL("outer"),I_mov(2,1)]
    for ch in MAGIC:
        it+=[I_movb_at(1,0),I_extub(0,0),I_cmpeqi(ch),BF("next"),I_addi(1,1)]  # advance after EACH char
    # r1 now = magic+8; verify doom's header follows (skip the Java MAGIC *constant* array,
    # which has heap pointers after it). doom hdr = 06 df 07 d0 07 d1 00 e2; check only the
    # bytes <0x80 (06@+8, 07@+10, 07@+12) -- cmp/eq #imm SIGN-extends, so >=0x80 can't match.
    it+=[I_movb_at(1,0),I_extub(0,0),I_cmpeqi(0x06),BF("next"),I_addi(2,1)]   # doom[0]==06 ; ->+10
    it+=[I_movb_at(1,0),I_extub(0,0),I_cmpeqi(0x07),BF("next"),I_addi(2,1)]   # doom[2]==07 ; ->+12
    it+=[I_movb_at(1,0),I_extub(0,0),I_cmpeqi(0x07),BF("next")]               # doom[4]==07
    it+=[BRA("found"),I_nop(),LABEL("next"),I_addi(1,2),I_cmphs(3,2),BF("outer")]
    it+=[LABEL("halt"),BRA("halt"),I_nop()]
    # r2 = blob_start (magic addr). Copy the WAD OUT to a FIXED low address WAD_DST
    # (0x8C450000): above the browser image (no SMC), and BELOW DOOM's heap base
    # (0x8C860000, set in dc_syscalls.c) so DOOM's zone never clobbers it. The previous
    # blob-wad_len dest landed inside DOOM's heap -> the zone overwrote the WAD -> garbage
    # -> demo "version 17" -> Z_Malloc 1.6GB -> _exit. doom.bin heap was moved above this.
    it+=[LABEL("found")]
    if diag: it += _paint(0x07E007E0, "G")   # GREEN: scan located the blob (MAGIC + doom header)
    it+=[load_reg(9, WAD_DST)]                                 # r9 = fixed WAD_DST
    # 1) copy WAD FIRST (before the doom copy overwrites the blob's WAD region at DOOM_DST):
    #    src = blob_start+8+doom_len (WAD in blob) ; dst = r9 ; count = wad_len
    it+=[load_reg(0, 8+doom_len), I_mov(2,5), I_add(0,5)]      # r5 = WAD-in-blob
    it+=[I_mov(9,6), load_reg(7,wad_len)]; it+=copy_loop_raw("w")
    # 2) copy doom: src = blob_start+8 ; dst = DOOM_DST ; count = doom_len
    it+=[I_mov(2,5), I_addi(8,5)]                              # r5 = doom-in-blob
    it+=[load_reg(6,DOOM_DST), load_reg(7,doom_len)]; it+=copy_loop_raw("d")
    if diag: it += _paint(0x001F001F, "B")   # BLUE: both copies done -> next is g_wad + SR + jmp DOOM
    # 3) g_wad: addr = r9 (relocated WAD) ; size = wad_len
    it+=[load_reg(1,GWA), I_movl_st(9,1)]
    it+=[load_reg(0,wad_len), load_reg(1,GWS), I_movl_st(0,1)]
    # restore browser SR but with IMASK=15 (mask all external IRQs): DOOM boots uninterrupted
    # and installs its own handlers before re-enabling. Inheriting IMASK=0 let a VBlank IRQ
    # fire into the browser handler on our modified state -> double-fault "exception when blocked".
    # build 0xF0 via 0x0F<<4 (mov #imm sign-extends, so can't load 0xF0 directly), OR into r8.
    it+=[load_reg(0,0xEFFFFFFF), A.I_and(0,8)]                # CLEAR BL (bit28): DOOM must run with exceptions
                                                              # ENABLED (BL=0). Inheriting browser BL=1 made the
                                                              # first DOOM exception instantly fatal (inconsistent crashes).
    it+=[A.I_movi(0x0F,0), I_shll2(0), I_shll2(0), I_or(0,8), A.I_ldc_sr(8)]  # set IMASK=15, restore SR
    it+=[load_reg(0,DOOM_DST), I_jmp(0), I_nop()]
    return assemble_safe(it)

def full_stub(doom_len,wad_len):
    it=[]
    it+=A.mask_irq()
    it+=[load_reg(2,SCAN_LO),load_reg(3,SCAN_HI),LABEL("outer"),I_mov(2,1)]
    for i,ch in enumerate(MAGIC):
        it+=[I_movb_at(1,0),I_extub(0,0),I_cmpeqi(ch),BF("next")]
        if i!=len(MAGIC)-1: it+=[I_addi(1,1)]
    it+=[BRA("found"),I_nop(),LABEL("next"),I_addi(1,2),I_cmphs(3,2),BF("outer")]
    it+=[LABEL("halt"),BRA("halt"),I_nop()]                         # not found -> halt
    it+=[LABEL("found"),I_mov(2,5),I_addi(8,5)]                     # r5 = magic+8
    it+=[load_reg(6,DOOM_DST),load_reg(7,doom_len)]; it+=copy_loop("d")
    it+=[load_reg(6,WAD_DST),load_reg(7,wad_len)];   it+=copy_loop("w")
    it+=[load_reg(0,WAD_DST),load_reg(1,GWA),I_movl_st(0,1)]
    it+=[load_reg(0,wad_len),load_reg(1,GWS),I_movl_st(0,1)]
    it+=[load_reg(1,0x40000000),A.I_ldc_sr(1)]      # SR=MD only (BL=0,FD=0) so DOOM runs
    it+=[load_reg(0,DOOM_DST),I_jmp(0),I_nop()]
    return assemble_safe(it)

if __name__=="__main__":
    stub,bad=full_stub(0x10,0x10)   # tiny lens for the byte-safety check
    print("full stub %d bytes, byte-safe: %s%s"%(len(stub),not bad,("  BAD@"+str(bad[:6]) if bad else "")))

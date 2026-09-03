#!/usr/bin/env python3
"""
Minimal label-aware SH-4 assembler that emits BYTE-SAFE code (no 0x00/0x20/0x22 in
any instruction byte, incl. branch displacements). Used to build the self-contained
DOOM loader stub (scan email body for magic -> hex-decode/copy -> set g_wad -> jmp).

Two-pass: resolve labels, then encode. Branch displacement bytes are validated;
if an unsafe displacement is unavoidable, insert NOP(s) to shift it (caller can pad).
"""
import struct
BAD = set(b'\x00\x20\x22')

def w(x): return struct.pack("<H", x)

def safe_adds(b):
    out=[]; rem=b
    while rem>0:
        s=min(rem,0x7F)
        if s in (0x20,0x22): s-=1
        out.append(s); rem-=s
    return out

# ---- instruction emitters (return raw bytes; label refs handled in assemble()) ----
def I_movi(imm,rn):       return w(0xE000|(rn<<8)|(imm&0xFF))
def I_shll8(rn):          return w(0x4018|(rn<<8))
def I_shll2(rn):          return w(0x4008|(rn<<8))
def I_shlr2(rn):          return w(0x4009|(rn<<8))   # shlr2 (>>2)
def I_and(rm,rn):         return w(0x2009|(rn<<8)|(rm<<4))  # and Rm,Rn
def I_shll(rn):           return w(0x4000|(rn<<8))
def I_addi(imm,rn):       return w(0x7000|(rn<<8)|(imm&0xFF))
def I_add(rm,rn):         return w(0x300C|(rn<<8)|(rm<<4))
def I_mov(rm,rn):         return w(0x6003|(rn<<8)|(rm<<4))
def I_movb_at(rm,rn):     return w(0x6000|(rn<<8)|(rm<<4))   # mov.b @Rm,Rn (sign-ext)
def I_movl_at(rm,rn):     return w(0x6002|(rn<<8)|(rm<<4))   # mov.l @Rm,Rn
def I_movl_atp(rm,rn):    return w(0x6006|(rn<<8)|(rm<<4))   # mov.l @Rm+,Rn
def I_movb_st(rm,rn):     return w(0x2000|(rn<<8)|(rm<<4))   # mov.b Rm,@Rn
def I_movl_st(rm,rn):     return w(0x2002|(rn<<8)|(rm<<4))   # mov.l Rm,@Rn
def I_movb_stp(rm,rn):    return w(0x2004|(rn<<8)|(rm<<4))   # mov.b Rm,@-Rn (pre-dec) -- not used
def I_extub(rm,rn):       return w(0x600C|(rn<<8)|(rm<<4))   # extu.b Rm,Rn
def I_cmpeqi(imm):        return w(0x8800|(imm&0xFF))        # cmp/eq #imm,r0
def I_cmphs(rm,rn):       return w(0x3002|(rn<<8)|(rm<<4))   # cmp/hs Rm,Rn (T: Rn>=Rm unsigned)
def I_cmphi(rm,rn):       return w(0x3006|(rn<<8)|(rm<<4))   # cmp/hi Rm,Rn (T: Rn>Rm)
def I_tst(rm,rn):         return w(0x2008|(rn<<8)|(rm<<4))
def I_jmp(rn):            return w(0x402B|(rn<<8))
def I_nop():              return w(0x6003)                   # mov r0,r0 (byte-safe nop)
def I_stc_sr(rn):         return w(0x0002|(rn<<8))           # stc SR,Rn  (rn=1 -> safe)
def I_ldc_sr(rm):         return w(0x400E|(rm<<8))           # ldc Rm,SR
def I_or(rm,rn):          return w(0x200B|(rn<<8)|(rm<<4))   # or Rm,Rn

def mask_irq():
    """set SR.BL (bit28) so the long scan/copy can't be interrupted. uses r1,r4 (safe regs)."""
    return [I_stc_sr(1), load_reg(4, 0x10000000), I_or(4,1), I_ldc_sr(1)]

def load_reg(rn,val):
    val&=0xFFFFFFFF
    b=[(val>>(8*i))&0xFF for i in range(4)]
    hb=3
    while hb>0 and b[hb]==0: hb-=1
    o=b""; top=b[hb]
    if top in (0x20,0x22): o+=I_movi(top-1,rn)+I_addi(1,rn)
    else: o+=I_movi(top,rn)
    for pos in range(hb-1,-1,-1):
        o+=I_shll8(rn)
        for a in safe_adds(b[pos]): o+=I_addi(a,rn)
    return o

# branch ops carry a label; resolved in assemble()
def BF(lbl):  return ("bf",lbl)
def BT(lbl):  return ("bt",lbl)
def BRA(lbl): return ("bra",lbl)
def LABEL(n): return ("label",n)

def _enc_branch(kind,disp):
    # disp in instructions-units already = (target-(PC+4))//2
    if kind in ("bf","bt"):
        d=disp & 0xFF
        op = (0x8B00 if kind=="bf" else 0x8900) | d
    else:  # bra
        d=disp & 0xFFF
        op = 0xA000 | d
    return w(op)

def _bad_branches(items):
    """return list of item-indices of branches whose displacement byte is unsafe."""
    addr={}; pc=0; flat=[]
    for i,it in enumerate(items):
        if isinstance(it,tuple) and it[0]=="label": addr[it[1]]=pc; continue
        flat.append((pc,i,it)); pc += 2 if isinstance(it,tuple) else len(it)
    bad=[]
    for pc,i,it in flat:
        if isinstance(it,tuple):
            kind,lbl=it; disp=(addr[lbl]-(pc+4))//2; enc=_enc_branch(kind,disp)
            if any(c in BAD for c in enc): bad.append((i,lbl))
    return bad

def assemble_safe(items, max_iter=4000):
    """Greedy: repeatedly find a branch with an unsafe displacement byte and insert
    one NOP between it and its target (shifts that disp by 1), until all bytes safe."""
    work=list(items)
    for _ in range(max_iter):
        bb=_bad_branches(work)
        if not bb:
            return assemble(work)
        idx,lbl=bb[0]
        lpos=next(j for j,it in enumerate(work) if isinstance(it,tuple) and it[0]=="label" and it[1]==lbl)
        ins = idx+1 if lpos>idx else idx     # put a nop strictly between branch and target
        work.insert(ins, I_nop())
    return assemble(work)

def assemble(items):
    # items: list of raw bytes (insns) or ("label",n)/("bf"/"bt"/"bra",lbl)
    # pass 1: addresses (each insn=2 bytes; branch=2 bytes)
    addr={}; pc=0; flat=[]
    for it in items:
        if isinstance(it,tuple) and it[0]=="label":
            addr[it[1]]=pc; continue
        flat.append((pc,it))
        pc += 2 if isinstance(it,tuple) else len(it)   # branch tuple=2B; raw blob=len
    # pass 2: encode
    out=b""
    for pc,it in flat:
        if isinstance(it,tuple):
            kind,lbl=it; tgt=addr[lbl]; disp=(tgt-(pc+4))//2
            out+=_enc_branch(kind,disp)
        else:
            out+=it
    bad=[(i,c) for i,c in enumerate(out) if c in BAD]
    return out,bad

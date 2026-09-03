"""
ida_recover_functions.py -- IDAPython function-recovery for the PlanetWeb
Dreamcast browser 1ST_READ.BIN (flat SH-4 little-endian image @ 0x8C010000).

Run inside IDA AFTER the binary is loaded/based at 0x8C010000:
    File -> Script file...  (Alt+F7)  -> pick this file
or paste into the Python CLI:
    exec(open(r"/media/adversary/Storage/dc_browser_extract/poc/native/ida_recover_functions.py").read())

What it does (raw binary has no auto-marked code, so we seed + sweep):
  1. seed code + a function at the entry (0x8C010000) so call-flow analysis runs
  2. full reanalysis over the whole image, blocking until idle
  3. prologue sweep: create a function at every `sts.l pr,@-r15` (0x4F22) --
     recovers functions only reachable via fn-ptr tables (the image codecs:
     get_dht / get_sof etc. are dispatched indirectly and call-flow misses them)
  4. turn the known codec fn-ptr table entries into offsets so IDA carves
     functions at their targets
  5. sanity-check the JPEG anchors (message table @0x8C1B3CC8) and report

Target for F-12: get_dht (JPEG DHT huffval[256] overflow). After this runs,
Search -> Immediate value -> 80 (JTRC_DHT) lands inside get_dht; the missing
`count > 256` guard before the huffval copy loop is the bug.
"""
import ida_bytes
import ida_funcs
import ida_auto
import ida_name
import idautils
import idc

BASE = 0x8C010000
END  = 0x8C44A0C0          # BASE + filesize(0x43A0C0); image is 4,432,064 bytes
ENTRY = 0x8C010000

# Known indirect-dispatch fn-ptr tables worth forcing into offsets.
# (entries are 4-byte LE pointers into .text)
CODEC_TABLES = [
    (0x8C17E1E0, 16),     # GIF codec fn-ptr table (count is a guess; trim junk after)
]

# JPEG libjpeg anchors (VA = 0x8C010000 + file_offset, verified 1:1)
JPEG_MSG_TABLE = 0x8C1B3CC8     # jpeg_std_message_table (char*[], jerror.h order)
ANCHORS = {
    0x8C1B3FDC: "Bogus Huffman table definition (code 8, JERR_BAD_HUFF_TABLE)",
    0x8C1B4A88: "Define Huffman Table 0x%02x   (code 80, JTRC_DHT  -> get_dht)",
    0x8C1B4D50: "Start Of Frame 0x%02x...       (code 100, JTRC_SOF -> get_sof)",
}


def seed_entry():
    print("[1] seeding code + function at entry %08X" % ENTRY)
    ida_bytes.del_items(ENTRY, ida_bytes.DELIT_SIMPLE, 2)
    idc.create_insn(ENTRY)
    if not ida_funcs.get_func(ENTRY):
        ida_funcs.add_func(ENTRY)


def reanalyze():
    print("[2] full reanalysis %08X..%08X (blocking)" % (BASE, END))
    ida_auto.plan_and_wait(BASE, END)


def prologue_sweep():
    print("[3] prologue sweep for `sts.l pr,@-r15` (0x4F22)")
    made = 0
    ea = BASE
    while ea < END:
        if ida_bytes.get_word(ea) == 0x4F22:          # sts.l pr,@-r15 = fn entry
            if not ida_funcs.get_func(ea):
                if ida_funcs.add_func(ea):
                    made += 1
        ea += 2
    ida_auto.auto_wait()
    print("    created %d new functions" % made)
    return made


def codec_tables():
    print("[4] forcing codec fn-ptr tables into offsets")
    for tbl, n in CODEC_TABLES:
        for i in range(n):
            a = tbl + i * 4
            tgt = ida_bytes.get_dword(a)
            if BASE <= tgt < END:
                idc.op_plain_offset(a, 0, 0)
                if not ida_funcs.get_func(tgt):
                    ida_funcs.add_func(tgt)
    ida_auto.auto_wait()


def verify():
    print("[5] anchor sanity check")
    w = ida_bytes.get_word(ENTRY)
    print("    entry word @ %08X = %04X  (expect 0009 nop)" % (ENTRY, w))
    for va, desc in ANCHORS.items():
        s = idc.get_strlit_contents(va, -1, idc.STRTYPE_C)
        tag = s.decode("latin1", "ignore") if s else "(not yet a string -- press A here)"
        print("    %08X : %s" % (va, desc))
    print("    JPEG message table base = %08X (define as offset array to auto-name strings)"
          % JPEG_MSG_TABLE)
    nf = sum(1 for _ in idautils.Functions(BASE, END))
    print("    total functions in image: %d" % nf)


def main():
    seed_entry()
    reanalyze()
    prologue_sweep()
    codec_tables()
    verify()
    print("[done] next: Search -> Immediate value -> 80 to land in get_dht;"
          " find the huffval[256] copy loop with no `count>256` guard.")


if __name__ == "__main__":
    main()

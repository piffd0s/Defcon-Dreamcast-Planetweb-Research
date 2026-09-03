"""
ida_deep_analysis.py -- raise the analysis quality of 1ST_READ.BIN in IDA 9.x so
undiscovered/unnamed functions become understandable.

Run AFTER ida_recover_functions.py. Passes (all idempotent, re-runnable):
  1. define_strings  : carve C strings across the image so xrefs resolve + the
                       string view is populated.
  2. recover_gaps    : find undefined gaps in code and, where a gap begins with a
                       real SH-4 prologue, make code + a function (conservative --
                       only decodes recognizable function starts, not data/pools).
  3. name_by_strings : for every function still named sub_*, rename it after the
                       most distinctive string it references (fn_<slug>). This is
                       the big readability win -- a func that loads "Begin parsing
                       JavaScript" becomes fn_Begin_parsing_JavaScr, etc.
  4. annotate        : add a repeatable comment to each function listing the
                       strings it references (non-destructive context for analysis).
  5. name_jpeg       : label the JPEG message table + get_dht/get_sof if found.
  6. report          : coverage stats (functions, named, % of image in functions).

Usage in IDA:
    exec(open(r"/media/adversary/Storage/dc_browser_extract/poc/native/ida_deep_analysis.py").read())
or Alt+F7. Tune MIN_STR / MAX_SLUG / SKIP_LIB below.
"""
import string as _string
import ida_bytes
import ida_funcs
import ida_auto
import ida_name
import ida_segment
import idautils
import idc

BASE = 0x8C010000
END  = 0x8C44A0C0
MIN_STR  = 5      # min length to define/use a string
MAX_SLUG = 22     # max chars of a string baked into a function name

# SH-4 instruction words that legitimately START a function (LE).
PROLOGUE = set([
    0x4F22,                                            # sts.l pr,@-r15
    0x2FE6, 0x2FD6, 0x2FC6, 0x2FB6,                    # mov.l r14..r11,@-r15
    0x2FA6, 0x2F96, 0x2F86,                            # mov.l r10..r8,@-r15
])
def is_prologue(word):
    if word in PROLOGUE:
        return True
    if (word & 0xFF00) == 0x7F00 and (word & 0x80):   # add #-imm,r15 (stack alloc)
        return True
    return False

_PRINT = set(ord(c) for c in (_string.ascii_letters + _string.digits + _string.punctuation + " "))


# --------------------------------------------------------------------------- #
def define_strings():
    print("[1] defining strings...")
    data = ida_bytes.get_bytes(BASE, END - BASE)
    made = 0
    i, n = 0, len(data)
    while i < n:
        if data[i] in _PRINT and data[i] != 0:
            j = i
            while j < n and data[j] in _PRINT and data[j] != 0:
                j += 1
            if j < n and data[j] == 0 and (j - i) >= MIN_STR:
                ea = BASE + i
                fl = ida_bytes.get_flags(ea)
                if ida_bytes.is_unknown(fl):
                    if idc.create_strlit(ea, BASE + j + 1):
                        made += 1
            i = j + 1
        else:
            i += 1
    ida_auto.auto_wait()
    print("    defined %d new strings" % made)


def recover_gaps():
    print("[2] recovering functions in undefined code gaps...")
    made = 0
    ea = BASE
    while ea < END:
        fl = ida_bytes.get_flags(ea)
        if ida_bytes.is_unknown(fl):
            word = ida_bytes.get_word(ea)
            if is_prologue(word):
                if idc.create_insn(ea) and ida_funcs.add_func(ea):
                    made += 1
                    f = ida_funcs.get_func(ea)
                    if f:
                        ea = f.end_ea
                        continue
        ea += 2
    ida_auto.auto_wait()
    print("    created %d functions in gaps" % made)


def _slug(s):
    out = []
    for c in s:
        if c.isalnum():
            out.append(c)
        elif c in " _-/.":
            out.append("_")
        if len(out) >= MAX_SLUG:
            break
    sl = "".join(out).strip("_")
    return sl or "str"

def _func_strings(fea):
    """list of (string_addr, text) referenced from inside function fea."""
    out = []
    f = ida_funcs.get_func(fea)
    if not f:
        return out
    for ea in idautils.FuncItems(fea):
        for xr in idautils.DataRefsFrom(ea):
            fl = ida_bytes.get_flags(xr)
            if ida_bytes.is_strlit(fl):
                s = idc.get_strlit_contents(xr, -1, idc.STRTYPE_C)
                if s:
                    out.append((xr, s.decode("latin1", "ignore")))
    # de-dup keep order
    seen, uniq = set(), []
    for a, t in out:
        if a not in seen:
            seen.add(a); uniq.append((a, t))
    return uniq

def name_by_strings():
    print("[3] naming sub_* functions after referenced strings...")
    renamed = 0
    for fea in list(idautils.Functions(BASE, END)):
        nm = ida_name.get_name(fea)
        if not nm or not nm.startswith("sub_"):
            continue                       # skip user/lib/already-named
        strs = _func_strings(fea)
        if not strs:
            continue
        # most distinctive = longest string referenced
        best = max(strs, key=lambda t: len(t[1]))[1]
        cand = "fn_" + _slug(best)
        if ida_name.set_name(fea, cand, ida_name.SN_NOWARN | ida_name.SN_FORCE):
            renamed += 1
    print("    renamed %d functions" % renamed)


def annotate():
    print("[4] annotating functions with their referenced strings...")
    done = 0
    for fea in list(idautils.Functions(BASE, END)):
        strs = _func_strings(fea)
        if not strs:
            continue
        lines = ["strings:"]
        for _, t in strs[:8]:
            t = t.replace("\n", " ")[:60]
            lines.append("  " + t)
        if len(strs) > 8:
            lines.append("  ... (%d more)" % (len(strs) - 8))
        idc.set_func_cmt(fea, "\n".join(lines), 1)   # repeatable
        done += 1
    print("    annotated %d functions" % done)


def name_jpeg():
    print("[5] labeling JPEG anchors...")
    tbl = 0x8C1B3CC8
    ida_name.set_name(tbl, "jpeg_std_message_table", ida_name.SN_NOWARN | ida_name.SN_FORCE)
    pairs = {
        0x8C1B3FDC: "str_JERR_BAD_HUFF_TABLE",
        0x8C1B4A88: "str_JTRC_DHT",
        0x8C1B4D50: "str_JTRC_SOF",
    }
    for a, nm in pairs.items():
        ida_name.set_name(a, nm, ida_name.SN_NOWARN | ida_name.SN_FORCE)
    print("    labeled message table + key strings (define %08X as offset array to"
          " auto-name the rest)" % tbl)


def report():
    print("[6] coverage report")
    funcs = list(idautils.Functions(BASE, END))
    named = sum(1 for f in funcs if not (ida_name.get_name(f) or "").startswith("sub_"))
    covered = 0
    for f in funcs:
        ff = ida_funcs.get_func(f)
        if ff:
            covered += ff.end_ea - ff.start_ea
    total = END - BASE
    print("    functions       : %d" % len(funcs))
    print("    named (non sub_): %d (%.0f%%)" % (named, 100.0 * named / max(1, len(funcs))))
    print("    bytes in funcs  : %d / %d  (%.1f%% of image)"
          % (covered, total, 100.0 * covered / total))


def main():
    define_strings()
    recover_gaps()
    name_by_strings()
    annotate()
    name_jpeg()
    report()
    print("[done] string view + named/commented functions are now populated;"
          " jump anywhere and the func comment tells you what it touches.")


if __name__ == "__main__":
    main()

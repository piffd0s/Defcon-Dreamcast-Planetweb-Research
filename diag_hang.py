#!/usr/bin/env python3
# READ-ONLY diagnostic: how far did the planted stub get? Reads guest RAM via /proc/mem.
import re, glob, struct, os
GUEST = 0x8C000000
bases = re.findall(r"RAM\(16 MB\)\s+0x([0-9a-fA-F]+)", open("/tmp/fc_conn.log").read())
base = int(bases[-1], 16)
fp = None
for c in glob.glob("/proc/*/cmdline"):
    try:
        cl = open(c, "rb").read().replace(b"\x00", b" ").lower()
        if b"flycast" in cl and b"diag_hang" not in cl:
            fp = c.split("/")[2]; break
    except: pass
if fp is None:
    for c in glob.glob("/proc/*/comm"):
        try:
            if "flycast" in open(c).read().lower(): fp = c.split("/")[2]; break
        except: pass
print("flycast pid", fp, "RAM host base 0x%x" % base)
f = open("/proc/%s/mem" % fp, "rb")
def rd(a, n): f.seek(base + (a - GUEST)); return f.read(n)
def hx(b): return " ".join("%02x" % x for x in b)
def asc(b): return "".join(chr(x) if 32 <= x < 127 else "." for x in b)
ROOT = "/media/adversary/Storage/dc_browser_extract/poc"
stub = open(ROOT + "/build/stub.bin", "rb").read()
doomhdr = open(ROOT + "/build/doom.bin", "rb").read(16)

g = rd(0x8C29ADE8, 24)
print("\n[1] stub @0x8C29ADE8:", "PLANTED OK" if g == stub[:24] else "*** MISMATCH ***")
print("    RAM :", hx(g)); print("    file:", hx(stub[:24]))

d = rd(0x8CC00000, 16)
print("\n[2] doom @0x8CC00000:", "COPIED" if d[:8] == doomhdr[:8] else "not copied")
print("    RAM :", hx(d), "| file:", hx(doomhdr))

w = rd(0x8C450000, 8)
print("\n[3] WAD @0x8C450000:", hx(w), "ascii:", asc(w))

log = rd(0x8CF00000, 6000)
# find end: a long run of zeros marks the tail of the written log
end = len(log)
z = log.find(b"\x00\x00\x00\x00\x00\x00\x00\x00")
if z > 0: end = z
txt = log[:end]
print("\n[4] DOOM log @0x8CF00000 (%d bytes):" % end)
# print line-by-line (the log uses \n? it shows '.' for non-printable; reconstruct)
print("    " + asc(txt))
print("\n[4b] LAST 200 chars (the stall point):")
print("    " + asc(txt[-200:]))

def w32(a): return struct.unpack("<I", rd(a, 4))[0]
print("\n[6] WAD header @0x8C450000:")
wn = w32(0x8C450004); wdir = w32(0x8C450008)
print("    numlumps=%d (0x%x)  dir_offset=0x%x" % (wn, wn, wdir))
wadlen = os.path.getsize("/media/adversary/Storage/dc_browser_extract/poc/wad/doom1_trim.wad")
print("    file wad size=%d (0x%x); dir should be at WAD_DST+0x%x = 0x%08X"
      % (wadlen, wadlen, wdir, 0x8C450000 + wdir))
print("\n[7] g_wad globals: GWA=*0x8CC56C58=0x%08X  GWS=*0x8CC56C54=%d (0x%x)"
      % (w32(0x8CC56C58), w32(0x8CC56C54), w32(0x8CC56C54)))
print("    expected GWA=0x8C450000  GWS=%d (0x%x)" % (wadlen, wadlen))
import os as _os
print("\n[8] PNAMES in the in-RAM WAD directory?")
diraddr = 0x8C450000 + wdir
dirbytes = rd(diraddr, wn * 16)
print("    directory @0x%08X read %d bytes; PNAMES present in RAM dir: %s"
      % (diraddr, len(dirbytes), b"PNAMES" in dirbytes))
# tail sanity: last 16 bytes of the copied WAD
print("    WAD tail @0x%08X: %s" % (0x8C450000 + wadlen - 16, hx(rd(0x8C450000 + wadlen - 16, 16))))
print("\n[9] byte-compare in-RAM WAD @0x8C450000 vs file doom1_trim.wad:")
wf = open("/media/adversary/Storage/dc_browser_extract/poc/wad/doom1_trim.wad", "rb").read()
ram = rd(0x8C450000, len(wf))
first = -1
for i in range(len(wf)):
    if ram[i] != wf[i]: first = i; break
if first < 0:
    print("    IDENTICAL -- full WAD copied correctly")
else:
    print("    first mismatch at WAD offset 0x%x (=%d)  [dir_offset=0x%x]" % (first, first, wdir))
    print("    file[%x:+16]: %s" % (first, hx(wf[first:first+16])))
    print("    ram [%x:+16]: %s" % (first, hx(ram[first:first+16])))
    # how much of the tail is zero in RAM?
    nz = sum(1 for b in ram[first:] if b != 0)
    print("    of %d bytes after mismatch, %d are non-zero in RAM" % (len(ram)-first, nz))
print("\n[5] DOOMSTG1 in scan range 0x8C400000..0x8CFF0000:")
found = []
for off in range(0x400000, 0xFF0000, 0x10000):
    try: chunk = rd(GUEST + off, 0x10008)
    except: continue
    i = chunk.find(b"DOOMSTG1")
    while i != -1 and len(found) < 8:
        found.append(GUEST + off + i); i = chunk.find(b"DOOMSTG1", i + 1)
for a in found: print("    @0x%08X next16: %s" % (a, hx(rd(a + 8, 16))))
if not found: print("    *** NOT FOUND in scan range -> stub scan spins forever ***")
f.close()

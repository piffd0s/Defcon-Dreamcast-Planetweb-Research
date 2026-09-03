#!/usr/bin/env python3
"""
make_minimap.py -- build a TINY DOOM IWAD (single textured room, node-less) that
fits the Dreamcast browser's small Java applet heap. Uses real Freedoom palette
+ one real wall texture + real flats, so it still looks like DOOM but is ~tens of
KB instead of 1.4 MB.

  python3 make_minimap.py            # -> wad/doom_mini.wad
  python3 make_minimap.py --flip     # flip wall winding (if walls don't render)
"""
import struct, sys, os
here = os.path.dirname(os.path.abspath(__file__))
SRC = os.path.join(here, "wad", "freedoom1.wad")
OUT = os.path.join(here, "wad", "doom_mini.wad")
FLIP = "--flip" in sys.argv

d = open(SRC, "rb").read()
n, off = struct.unpack("<II", d[4:12])
names, pos, ln = [], [], []
for i in range(n):
    fp, sz = struct.unpack("<II", d[off+i*16:off+i*16+8])
    nm = d[off+i*16+8:off+i*16+16].split(b'\0')[0].decode('latin1').upper()
    names.append(nm); pos.append(fp); ln.append(sz)
def idx(nm, frm=0):
    for i in range(frm, n):
        if names[i]==nm: return i
    return -1
def data(i): return d[pos[i]:pos[i]+ln[i]]
def nm8(b,o): return b[o:o+8].split(b'\0')[0].decode('latin1').upper()

# pick a real wall texture + flats actually used by E1M1 (guaranteed present)
m = idx("E1M1")
sd = data(idx("SIDEDEFS", m))
WALL = None
for i in range(len(sd)//30):
    for o in (20,12,4):                 # mid, lower, upper
        t = nm8(sd, i*30+o)
        if t and t!="-": WALL=t; break
    if WALL: break
sec = data(idx("SECTORS", m))
FLOOR = nm8(sec, 4); CEIL = nm8(sec, 12)
if FLOOR=="F_SKY1": FLOOR="FLOOR4_8"
if CEIL=="F_SKY1": CEIL="CEIL3_5"
print("using wall=%s floor=%s ceil=%s" % (WALL, FLOOR, CEIL))

# resolve the wall texture's patches
pn = data(idx("PNAMES")); pc = struct.unpack("<I", pn[:4])[0]
pnames = [nm8(pn,4+i*8) for i in range(pc)]
tx = data(idx("TEXTURE1")); ntex = struct.unpack("<I", tx[:4])[0]
offs = [struct.unpack("<I", tx[4+i*4:8+i*4])[0] for i in range(ntex)]
need_patch = set()
for o in offs:
    if nm8(tx,o)!=WALL: continue
    npat = struct.unpack("<H", tx[o+20:o+22])[0]
    for k in range(npat):
        pi = struct.unpack("<H", tx[o+22+k*10+4:o+22+k*10+6])[0]
        if pi<len(pnames): need_patch.add(pnames[pi])

# ---- synthesize a single square room ----
S = 512
V = [(-S,-S),(S,-S),(S,S),(-S,S)]           # 0..3 corners (y up)
# linedefs as a loop; front side = sector 0. winding chosen so interior is front.
order = [(0,1),(1,2),(2,3),(3,0)]
if FLIP: order = [(b,a) for a,b in order]
def s16(v): return struct.pack("<h", v)
def u16(v): return struct.pack("<H", v)
def nm(s): return s.encode('latin1')[:8].ljust(8,b'\0')

VERTEXES = b"".join(s16(x)+s16(y) for x,y in V)
SIDEDEFS = b""; LINEDEFS = b""; SEGS = b""
for li,(a,b) in enumerate(order):
    SIDEDEFS += s16(0)+s16(0)+nm("-")+nm("-")+nm(WALL)+u16(0)   # mid=WALL, sector 0
    LINEDEFS += u16(a)+u16(b)+u16(0x0001)+u16(0)+u16(0)+u16(li)+u16(0xFFFF) # 1-sided, front=sidedef li
    SEGS     += u16(a)+u16(b)+s16(0)+u16(li)+u16(0)+s16(0)       # v1,v2,angle,line,side0,off
SSECTORS = u16(len(order))+u16(0)            # one subsector: all segs
NODES = b""                                   # node-less
SECTORS = s16(0)+s16(128)+nm(FLOOR)+nm(CEIL)+u16(200)+u16(0)+u16(0)
THINGS = s16(0)+s16(0)+s16(90)+u16(1)+u16(0x0007)   # player1 start at center facing +y

# ---- assemble tiny IWAD ----
keep=[]
def add(nm_, by=None, lump=None):
    if lump is not None: keep.append((nm_, data(lump)))
    else: keep.append((nm_, by))
for core in ("PLAYPAL","COLORMAP","PNAMES","TEXTURE1"):
    add(core, lump=idx(core))
for p in sorted(need_patch): add(p, lump=idx(p))
for f in {FLOOR, CEIL}:
    i=idx(f)
    if i>=0: add(f, lump=i)
add("E1M1", b"")
add("THINGS", THINGS); add("LINEDEFS", LINEDEFS); add("SIDEDEFS", SIDEDEFS)
add("VERTEXES", VERTEXES); add("SEGS", SEGS); add("SSECTORS", SSECTORS)
add("NODES", NODES); add("SECTORS", SECTORS)

body=bytearray(); ents=[]; cur=12
for nm_,by in keep:
    ents.append((cur,len(by),nm_)); body+=by; cur+=len(by)
diroff=12+len(body)
hdr=b"IWAD"+struct.pack("<II",len(keep),diroff)
direc=bytearray()
for fp,sz,nm_ in ents: direc+=struct.pack("<II",fp,sz)+nm(nm_)
open(OUT,"wb").write(hdr+body+direc)
print("wrote %s  size=%.1f KB  lumps=%d" % (OUT, os.path.getsize(OUT)/1024, len(keep)))

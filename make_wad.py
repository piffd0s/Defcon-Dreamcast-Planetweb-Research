#!/usr/bin/env python3
"""
make_wad.py -- build a small device IWAD from a full one.

The Dreamcast has 16 MB RAM, so the 28 MB Freedoom IWAD is dev-only. This trims
a source IWAD down to a single map plus ONLY the textures/patches/flats that map
references, keeping PLAYPAL/COLORMAP/PNAMES/TEXTURE1 so the engine renders it
identically. Output is a valid IWAD a few MB in size.

  python3 make_wad.py [srcwad] [mapname] [outwad]
  default: wad/freedoom1.wad E1M1 wad/doom_e1m1.wad
"""
import struct, sys, os

src  = sys.argv[1] if len(sys.argv) > 1 else "wad/freedoom1.wad"
MAP  = sys.argv[2] if len(sys.argv) > 2 else "E1M1"
out  = sys.argv[3] if len(sys.argv) > 3 else "wad/doom_e1m1.wad"
here = os.path.dirname(os.path.abspath(__file__))
src  = os.path.join(here, src); out = os.path.join(here, out)

d = open(src, "rb").read()
n, off = struct.unpack("<II", d[4:12])
names, pos, ln = [], [], []
for i in range(n):
    fp, sz = struct.unpack("<II", d[off+i*16:off+i*16+8])
    nm = d[off+i*16+8:off+i*16+16].split(b'\0')[0].decode('latin1').upper()
    names.append(nm); pos.append(fp); ln.append(sz)

def idx(name, frm=0):
    for i in range(frm, n):
        if names[i] == name: return i
    return -1
def data(i): return d[pos[i]:pos[i]+ln[i]]
def nm8(b, o): return b[o:o+8].split(b'\0')[0].decode('latin1').upper()

m = idx(MAP)
if m < 0: sys.exit("map %s not found" % MAP)
SUB = ["THINGS","LINEDEFS","SIDEDEFS","VERTEXES","SEGS","SSECTORS","NODES","SECTORS","REJECT","BLOCKMAP"]

# textures used by the map (sidedefs) + flats (sectors)
sd = data(idx("SIDEDEFS", m)); used_tex = set()
for i in range(len(sd)//30):
    for o in (4,12,20):
        t = nm8(sd, i*30+o)
        if t and t != "-": used_tex.add(t)
sec = data(idx("SECTORS", m)); used_flat = set()
for i in range(len(sec)//26):
    for o in (4,12):
        f = nm8(sec, i*26+o)
        if f and f != "F_SKY1": used_flat.add(f)

# PNAMES + TEXTURE1 -> patches needed for used textures
pn = data(idx("PNAMES")); pcount = struct.unpack("<I", pn[:4])[0]
pnames = [nm8(pn, 4+i*8) for i in range(pcount)]
tx = data(idx("TEXTURE1")); ntex = struct.unpack("<I", tx[:4])[0]
offs = [struct.unpack("<I", tx[4+i*4:8+i*4])[0] for i in range(ntex)]
need_patch = set()
for o in offs:
    name = nm8(tx, o)
    if name not in used_tex: continue
    pc = struct.unpack("<H", tx[o+20:o+22])[0]
    for k in range(pc):
        pi = struct.unpack("<H", tx[o+22+k*10+4:o+22+k*10+6])[0]
        if pi < len(pnames): need_patch.add(pnames[pi])

# assemble lump list (name, bytes), de-duplicated, in a sane order
keep = []
seen = set()
def add(name, frm=0):
    i = idx(name, frm)
    if i >= 0 and name not in seen:
        keep.append((names[i], data(i))); seen.add(name)

for core in ("PLAYPAL","COLORMAP","PNAMES","TEXTURE1","TEXTURE2"): add(core)
for p in sorted(need_patch): add(p)
for f in sorted(used_flat):  add(f)
# the map: marker (empty) + sublumps in canonical order
keep.append((MAP, b"")); seen.add(MAP)
for s in SUB:
    i = idx(s, m)
    if i >= 0: keep.append((s, data(i)))

# write IWAD
body = bytearray(); dir_entries = []
cur = 12
for nm, b in keep:
    dir_entries.append((cur, len(b), nm)); body += b; cur += len(b)
diroff = 12 + len(body)
hdr = b"IWAD" + struct.pack("<II", len(keep), diroff)
directory = bytearray()
for fp, sz, nm in dir_entries:
    directory += struct.pack("<II", fp, sz) + nm.encode('latin1')[:8].ljust(8, b'\0')
open(out, "wb").write(hdr + body + directory)

print("wrote %s" % out)
print("  lumps=%d  size=%.2f MB  (textures=%d patches=%d flats=%d)"
      % (len(keep), os.path.getsize(out)/1e6, len(used_tex), len(need_patch), len(used_flat)))

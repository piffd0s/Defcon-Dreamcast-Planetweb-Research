#!/usr/bin/env python3
import struct, os
def lumps(path):
    d = open(path, "rb").read()
    magic, n, off = struct.unpack("<4sII", d[:12])
    L = []
    for i in range(n):
        lo, ls, nm = struct.unpack("<II8s", d[off+i*16:off+i*16+16])
        L.append((nm.rstrip(b'\0').decode('latin1'), lo, ls))
    return magic, n, L
R = "/media/adversary/Storage/dc_browser_extract/poc/"
for p in [R+"wad/doom1_trim.wad", R+"wad/doom1.wad"]:
    try:
        mg, n, L = lumps(p)
        names = [x[0] for x in L]
        print("%s: %s n=%d size=%d" % (p, mg, n, os.path.getsize(p)))
        for key in ["PNAMES", "TEXTURE1", "TEXTURE2", "PLAYPAL", "COLORMAP", "F_START", "S_START", "P_START"]:
            print("   %-9s %s" % (key, "present" if key in names else "*** MISSING ***"))
    except Exception as e:
        print(p, "ERR", e)

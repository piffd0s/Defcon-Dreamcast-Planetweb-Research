#!/usr/bin/env python3
# Is DOOM rendering to the framebuffer it targets (VRAM 0x600000), and is it changing?
import re, glob, time
log = open("/tmp/fc_conn.log").read()
vram_base = int(re.findall(r"VRAM64\(8 MB\)\s+0x([0-9a-fA-F]+)", log)[-1], 16)
fp = None
for c in glob.glob("/proc/*/cmdline"):
    try:
        cl = open(c, "rb").read().replace(b"\x00", b" ").lower()
        if b"flycast" in cl and b"diag" not in cl: fp = c.split("/")[2]; break
    except: pass
f = open("/proc/%s/mem" % fp, "rb")
def rv(off, n): f.seek(vram_base + off); return f.read(n)
def stat(b): return sum(1 for x in b if x != 0)
print("flycast", fp, "VRAM host base 0x%x" % vram_base)

# DOOM target = 0xA5600000 = VRAM offset 0x600000, 640x400 RGB555 region
SPAN = 640*400*2
for off, name in [(0x000000, "VRAM@0x000000"), (0x200000, "VRAM@0x200000"),
                  (0x400000, "VRAM@0x400000"), (0x600000, "VRAM@0x600000 (DOOM target)")]:
    b = rv(off, SPAN); nz = stat(b)
    print("   %-28s %d/%d non-zero (%.1f%%)" % (name, nz, SPAN, 100.0*nz/SPAN))

# is DOOM's target changing frame-to-frame? (loop alive + rendering)
a = rv(0x600000, SPAN); time.sleep(1.0); b = rv(0x600000, SPAN)
diff = sum(1 for i in range(0, SPAN, 64) if a[i] != b[i])
print("\n[ANIM] VRAM@0x600000 sampled 1s apart: %d/%d sample points changed -> %s"
      % (diff, SPAN//64, "ANIMATING (loop+render alive)" if diff > 0 else "STATIC (frozen frame)"))
# dump a few pixels from the DOOM target
px = rv(0x600000 + (40*640+0)*2, 32)
print("    first row pixels:", " ".join("%02x%02x" % (px[i+1], px[i]) for i in range(0, 32, 2)))
f.close()

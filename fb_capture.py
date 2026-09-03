#!/usr/bin/env python3
"""fb_capture.py -- dump the PVR display framebuffer over Flycast's GDB stub to a PNG.

Reads FB_R_SOF1 to find what the PVR is currently scanning out, so it works for the
browser as well as for DOOM (which hardcodes 0xA5600000). RGB565 -> PNG, no deps.

  python3 fb_capture.py out.png [width] [height]
"""
import sys, os, struct, zlib, time
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from gdbstub_probe import RSP, read_mem

FB_R_SOF1 = 0xA05F8050
FB_R_CTRL = 0xA05F8044

def u32(r, addr):
    d = read_mem(r, addr, 4)
    return struct.unpack("<I", d)[0] if d and len(d) == 4 else None

def write_png(fn, W, H, rgb):
    def ch(t, d):
        c = t + d
        return struct.pack(">I", len(d)) + c + struct.pack(">I", zlib.crc32(c) & 0xffffffff)
    rows = b"".join(b"\x00" + rgb[y*W*3:(y+1)*W*3] for y in range(H))
    open(fn, "wb").write(b"\x89PNG\r\n\x1a\n"
        + ch(b"IHDR", struct.pack(">IIBBBBB", W, H, 8, 2, 0, 0, 0))
        + ch(b"IDAT", zlib.compress(bytes(rows), 9)) + ch(b"IEND", b""))

def main():
    out = sys.argv[1] if len(sys.argv) > 1 else "fb.png"
    W = int(sys.argv[2]) if len(sys.argv) > 2 else 640
    H = int(sys.argv[3]) if len(sys.argv) > 3 else 480
    r = RSP()
    r.s.send(b"\x03"); time.sleep(0.3); r.recv(3)          # halt
    sof = u32(r, FB_R_SOF1); ctrl = u32(r, FB_R_CTRL)
    print("FB_R_SOF1=%s FB_R_CTRL=%s" % (hex(sof) if sof is not None else "?",
                                         hex(ctrl) if ctrl is not None else "?"))
    base = 0xA5000000 + (sof & 0x00FFFFFF) if sof else 0xA5600000
    print("reading %dx%d RGB565 from %#x" % (W, H, base))
    raw = bytearray()
    for y in range(H):
        chunk = read_mem(r, base + y*W*2, W*2)
        if not chunk or len(chunk) != W*2:
            print("short read at row %d" % y); break
        raw += chunk
    # FB_R_CTRL[3:2] = fb_depth: 0 = RGB0555, 1 = RGB565. Guessing wrong does not
    # fail, it just skews the colours (0555 decoded as 565 comes out green), so
    # take the format from the register instead of assuming.
    depth = ((ctrl or 0) >> 2) & 3
    print("pixel format: %s" % ("RGB565" if depth == 1 else "RGB0555"))
    rgb = bytearray()
    if depth == 1:
        for i in range(0, len(raw) - 1, 2):
            v = raw[i] | (raw[i+1] << 8)
            rgb += bytes((((v >> 11) & 0x1f) * 255 // 31,
                          ((v >> 5) & 0x3f) * 255 // 63,
                          (v & 0x1f) * 255 // 31))
    else:
        for i in range(0, len(raw) - 1, 2):
            v = raw[i] | (raw[i+1] << 8)
            rgb += bytes((((v >> 10) & 0x1f) * 255 // 31,
                          ((v >> 5) & 0x1f) * 255 // 31,
                          (v & 0x1f) * 255 // 31))
    rows_read = len(rgb) // (W*3)
    write_png(out, W, rows_read, rgb)
    nz = sum(1 for b in raw if b)
    print("wrote %s (%dx%d), %d/%d non-zero bytes" % (out, W, rows_read, nz, len(raw)))
    r.cmd("c")   # resume so the emulator keeps running

main()

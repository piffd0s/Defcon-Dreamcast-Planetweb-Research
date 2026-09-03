#!/usr/bin/env python3
"""
dns_redirect.py -- answer DNS A queries for the dead Planetweb hosts with YOUR
server IP, so the emulated Dreamcast's browser connects to the rogue Eden server.

Point Flycast's (or the browser profile's) DNS at the box running this, then run
eden_mitm.py on :80. Needs root for :53.

  sudo python3 dns_redirect.py <YOUR_IP> [--all]
    <YOUR_IP>  the IP of the machine running eden_mitm.py
    --all      answer EVERY query with YOUR_IP (default: only *.planetweb.com)
"""
import socket, struct, sys

if len(sys.argv) < 2:
    sys.exit("usage: sudo python3 dns_redirect.py <YOUR_IP> [--all]")
IP = sys.argv[1]
ALL = "--all" in sys.argv
IPB = bytes(int(x) for x in IP.split("."))

def qname(data, off):
    parts = []
    while True:
        n = data[off]
        if n == 0: off += 1; break
        parts.append(data[off+1:off+1+n].decode("latin1")); off += 1 + n
    return ".".join(parts), off

# bind to the target IP itself (not 0.0.0.0) so we don't clash with libvirt's
# dnsmasq on other interface IPs; the guest's DNS is set to this IP anyway.
BIND = IP
for a in sys.argv[2:]:
    if a.startswith("--bind="): BIND = a.split("=", 1)[1]
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind((BIND, 53))
print("DNS redirector on %s:53 -> %s (%s)" % (BIND, IP, "ALL names" if ALL else "*.planetweb.com only"))
while True:
    data, addr = s.recvfrom(512)
    try:
        tid = data[:2]
        name, end = qname(data, 12)
        qtype = struct.unpack(">H", data[end:end+2])[0]
        hit = ALL or name.endswith("planetweb.com")
        print("  query %-40s %s" % (name, "-> " + IP if hit else "(ignored)"))
        if not hit or qtype != 1:
            continue
        # response: flags=0x8180, QD=1, AN=1
        resp = tid + b"\x81\x80" + b"\x00\x01\x00\x01\x00\x00\x00\x00"
        resp += data[12:end+4]                       # echo question
        resp += b"\xc0\x0c" + b"\x00\x01\x00\x01"    # name ptr, type A, class IN
        resp += b"\x00\x00\x00\x3c"                  # TTL 60
        resp += b"\x00\x04" + IPB                    # rdlength 4 + IP
        s.sendto(resp, addr)
    except Exception as e:
        print("  err:", e)

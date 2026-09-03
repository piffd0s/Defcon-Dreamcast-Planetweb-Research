#!/usr/bin/env python3
"""
gdbstub_probe.py -- RSP (GDB Remote Serial Protocol) client for Flycast's SH-4
stub (port 3263). Used to CHARACTERIZE the parser overflows dynamically without
needing a CPU exception: set software breakpoints (Z0/Z1) at known native decoder
addresses, continue, then read SH-4 registers + memory at the suspected OOB-write
site to measure table base, write address, and how much of the value/offset is
attacker-controlled.

NOTE (from prior session): the Flycast stub traps software/hardware breakpoints
fine, but does NOT trap raw CPU exceptions -- so we rely on breakpoints placed
*before* the write, then single-step over the write to read its effective address.

Static leads (1ST_READ.BIN @ base 0x8c010000):
  GIF/LZW decoder code .... 0x8c013000 - 0x8c016000
  GIF decoder state struct  0x8c1b6318 (29 code refs)
  LZW BSS table candidates  0x8c2783e0, 0x8c298784, 0x8c319b20
  64KB scratch buffer ..... 0x8c278410 - 0x8c288410
  JPEG decoder code ....... ~0x8c1b3000 - 0x8c1b6000 (DHT / SOF / DQT)

Usage:
  python3 gdbstub_probe.py regs                 # dump SH-4 regs once (must be halted)
  python3 gdbstub_probe.py mem 0x8c278410 256   # hexdump guest memory
  python3 gdbstub_probe.py bp 0x8c013000        # set bp, continue, report state on hit
  python3 gdbstub_probe.py watchwrite 0x8c013000 0x8c2783e0 0x10000
        # bp at decoder entry; on hit single-step, watching for any write whose
        # effective addr lands in [base, base+span) -> prints the OOB write
"""
import socket, sys, time

HOST, PORT = "127.0.0.1", 3263

# SH-4 'g' packet register order (Flycast/GDB sh): r0..r15, pc, pr, gbr, vbr,
# mach, macl, sr, fpul, fpscr, fr0..fr15 (we only decode the integer block).
REG_NAMES = ["r0","r1","r2","r3","r4","r5","r6","r7","r8","r9","r10","r11",
             "r12","r13","r14","r15","pc","pr","gbr","vbr","mach","macl","sr"]

class RSP:
    def __init__(self, host=HOST, port=PORT, timeout=5):
        self.s = socket.create_connection((host, port), timeout=timeout)
        self.s.settimeout(timeout)
        self.buf = b""
    def _read(self, n=4096):
        try: return self.s.recv(n)
        except socket.timeout: return b""
    def _csum(self, body):
        return sum(body) & 0xff
    def send(self, body):
        b = body.encode() if isinstance(body, str) else body
        pkt = b"$" + b + b"#" + ("%02x" % self._csum(b)).encode()
        self.s.sendall(pkt)
        # consume the '+' ack
        t0 = time.time()
        while time.time()-t0 < 2:
            d = self._read(1)
            if d == b"+": break
            if not d: break
    def recv(self, timeout=5):
        t0 = time.time()
        while b"#" not in self.buf:
            if time.time()-t0 > timeout: break
            d = self._read()
            if not d: time.sleep(0.01); continue
            self.buf += d
        if b"$" not in self.buf: return None
        i = self.buf.index(b"$")
        j = self.buf.index(b"#", i)
        body = self.buf[i+1:j]
        self.buf = self.buf[j+3:]
        self.s.sendall(b"+")
        return body.decode(errors="replace")
    def cmd(self, body, timeout=5):
        self.send(body); return self.recv(timeout)

def le32(hexpairs):
    b = bytes.fromhex(hexpairs)
    return int.from_bytes(b[:4], "little")

def read_regs(r):
    g = r.cmd("g")
    if not g or g in ("", "E01"): return None
    out = {}
    for i, name in enumerate(REG_NAMES):
        chunk = g[i*8:(i+1)*8]
        if len(chunk) == 8: out[name] = le32(chunk)
    return out

def read_mem(r, addr, length):
    out = b""
    while length > 0:
        n = min(length, 256)
        resp = r.cmd("m%x,%x" % (addr, n))
        if not resp or resp.startswith("E"): break
        out += bytes.fromhex(resp)
        addr += n; length -= n
    return out

def hexdump(data, base):
    for off in range(0, len(data), 16):
        row = data[off:off+16]
        hexs = " ".join("%02x" % b for b in row)
        asc = "".join(chr(b) if 32 <= b < 127 else "." for b in row)
        print("0x%08x  %-47s  %s" % (base+off, hexs, asc))

def set_bp(r, addr):  # Z0 = sw bp, kind 2 (16-bit SH4 insn)
    return r.cmd("Z0,%x,2" % addr)

def cont(r, timeout=30):
    r.send("c"); return r.recv(timeout)

def step(r):
    r.send("s"); return r.recv(10)

def main():
    if len(sys.argv) < 2:
        print(__doc__); return
    op = sys.argv[1]
    r = RSP()
    if op == "regs":
        regs = read_regs(r)
        if not regs: print("no regs (is the guest halted? hit a bp first)"); return
        for i, n in enumerate(REG_NAMES):
            if n in regs:
                end = "\n" if (i % 4 == 3) else "   "
                print("%-4s=%08x" % (n, regs[n]), end=end)
        print()
    elif op == "mem":
        addr = int(sys.argv[2], 0); ln = int(sys.argv[3], 0)
        hexdump(read_mem(r, addr, ln), addr)
    elif op == "bp":
        addr = int(sys.argv[2], 0)
        print("set bp:", set_bp(r, addr))
        print("continue... (trigger a decode in the browser)")
        st = cont(r, timeout=120)
        print("stop reply:", st)
        regs = read_regs(r)
        if regs: print("pc=%08x r4=%08x r5=%08x r6=%08x"
                        % (regs.get("pc",0), regs.get("r4",0), regs.get("r5",0), regs.get("r6",0)))
    elif op == "watchwrite":
        bp = int(sys.argv[2], 0); base = int(sys.argv[3], 0); span = int(sys.argv[4], 0)
        print("bp @ %08x; watching writes into [%08x,%08x)" % (bp, base, base+span))
        set_bp(r, bp); st = cont(r, timeout=120); print("hit:", st)
        # single-step, snapshot the watched window each step, report on change
        snap = read_mem(r, base, min(span, 0x800))
        for i in range(20000):
            step(r)
            cur = read_mem(r, base, min(span, 0x800))
            if cur != snap:
                regs = read_regs(r)
                # find first differing byte
                d = next((k for k in range(len(cur)) if k < len(snap) and cur[k] != snap[k]), 0)
                print("WRITE detected step %d: base+0x%x  pc=%08x" %
                      (i, d, regs.get("pc",0) if regs else 0))
                snap = cur
                if d >= span - 0x40:  # near/over the end of the table -> overflow edge
                    print(">>> write near table end -- candidate OOB boundary")
        print("done stepping")
    else:
        print("unknown op", op); print(__doc__)

if __name__ == "__main__":
    main()

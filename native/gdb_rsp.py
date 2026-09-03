#!/usr/bin/env python3
"""
gdb_rsp.py -- minimal GDB remote-serial-protocol client for Flycast's SH4 GDB
stub (no sh-elf-gdb needed). Read/write memory, set breakpoints, read regs,
continue/step. Used to dynamically confirm + develop the setRawDeviceID overflow.

  import gdb_rsp; g=gdb_rsp.RSP("127.0.0.1",3263); g.connect()
  g.read_mem(0x8c29abe6, 16); g.set_bp(0x8c04e0ea); g.cont(); g.regs()
"""
import socket, sys

class RSP:
    def __init__(self, host="127.0.0.1", port=3263):
        self.host, self.port = host, port
        self.s = None

    def connect(self):
        self.s = socket.create_connection((self.host, self.port), timeout=10)
        self.s.settimeout(10)
        # GDB stubs expect a leading + sometimes; enable no-ack later if desired
        return self

    @staticmethod
    def _ck(data):
        return sum(data.encode()) & 0xff

    def send(self, data):
        pkt = "$%s#%02x" % (data, self._ck(data))
        self.s.sendall(pkt.encode())
        # read ack '+'
        a = self.s.recv(1)
        if a != b'+':
            # some stubs in no-ack mode don't ack; tolerate
            self._pushback = a
        return self.recv()

    _pushback = b''
    def _recv1(self):
        if self._pushback:
            b = self._pushback[:1]; self._pushback = self._pushback[1:]; return b
        return self.s.recv(1)

    def recv(self):
        # read until $...#cs
        buf = b''
        # skip to '$'
        while True:
            c = self._recv1()
            if c == b'$': break
            if c == b'': raise IOError("closed")
        while True:
            c = self._recv1()
            if c == b'#': break
            buf += c
        self._recv1(); self._recv1()           # checksum 2 chars
        self.s.sendall(b'+')                    # ack
        return buf.decode(errors='replace')

    # ---- high level ----
    def halt(self):
        self.s.sendall(b'\x03')                 # Ctrl-C interrupt
        return self.recv()

    def read_mem(self, addr, length):
        r = self.send("m%x,%x" % (addr, length))
        if r.startswith("E"): return None
        return bytes.fromhex(r)

    def write_mem(self, addr, data):
        return self.send("M%x,%x:%s" % (addr, len(data), data.hex()))

    def set_bp(self, addr, kind=2):   # SH4 insn = 2 bytes
        return self.send("Z0,%x,%x" % (addr, kind))
    def del_bp(self, addr, kind=2):
        return self.send("z0,%x,%x" % (addr, kind))
    def set_watch(self, addr, length=4, kind=2):  # Z2 write watchpoint
        return self.send("Z2,%x,%x" % (addr, length))

    def cont(self):
        # 'c' gets no reply until the next stop; fire and don't block
        pkt = "$c#%02x" % self._ck("c"); self.s.sendall(pkt.encode())
        try:
            a = self.s.recv(1)
            if a != b'+': self._pushback = a
        except Exception: pass
    def wait_stop(self, timeout=10):
        old = self.s.gettimeout(); self.s.settimeout(timeout)
        try: return self.recv()
        except Exception: return None
        finally: self.s.settimeout(old)
    def step(self):   return self.send("s")
    def regs(self):   return self.send("g")
    def read_reg(self, n):
        r = self.send("p%x" % n)
        if not r or r.startswith("E"): return None
        return int.from_bytes(bytes.fromhex(r), "little")   # SH4 LE
    def pc(self): return self.read_reg(16)   # SH4: 0-15=r0-r15, 16=pc
    def why(self):    return self.send("?")

    def close(self):
        if self.s: self.s.close()

if __name__ == "__main__":
    host = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
    port = int(sys.argv[2]) if len(sys.argv) > 2 else 3263
    g = RSP(host, port).connect()
    print("halt reason:", g.why())
    # sanity: read the device-ID buffer + the object pointer
    print("0x8c29abe6:", (g.read_mem(0x8c29abe6, 16) or b'').hex())
    print("0x8c29ac28:", (g.read_mem(0x8c29ac28, 4) or b'').hex())
    g.close()

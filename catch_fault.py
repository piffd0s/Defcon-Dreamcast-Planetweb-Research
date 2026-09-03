#!/usr/bin/env python3
"""
catch_fault.py -- catch the SH-4 exception raised by the JPEG-DHT BSS-overflow
crash and read the faulting PC + data address, via Flycast's GDB stub (:3263).

Background: the overflow corrupts BSS; a follow-on decode then makes an
out-of-bounds access. The SH-4 takes a general exception -> vectors to VBR+0x100
(BL is 0 at the *first* fault: SR was 0x60000000). Flycast's fatal "SH4 exception
when blocked" is the SECOND, nested exception (BL=1). So a breakpoint at the
VBR+0x100 vector catches the FIRST fault before the fatal one.

VBR was read live = 0x8c00f400  -> general exception vector = 0x8c00f500.

This sets a bp there, continues, and on each stop reads EXPEVT to classify the
exception. TRAPA(0x160)/interrupt entries are resumed; a real fault
(addr error 0x0E0/0x100/0x0A0/0x0C0, illegal instr 0x180/0x1A0, I-side 0x040)
is reported with the faulting GPRs, SPC-equivalent and TEA (faulting address).

Usage: arm the SAFE ff_36-alone repro loop, get the browser online & looping,
run this, THEN (in another shell) escalate by copying ff_37/ff_38 into www/repro/
so the loop cycles 36->37->38 and faults into the vector bp.

  python3 catch_fault.py [vbr_hex]
"""
import socket, sys, time, struct

HOST, PORT = "127.0.0.1", 3263
VBR = int(sys.argv[1], 16) if len(sys.argv) > 1 else 0x8c00f400
VEC = VBR + 0x100   # general exception vector

EXPEVT = 0xff000024; TEA = 0xff00000c; TRA = 0xff000020
EXC_NAME = {0x040:"I-TLB-miss",0x060:"I-TLB-prot",0x0a0:"I-addr-err",
            0x0e0:"D-addr-err-read",0x100:"D-addr-err-write",
            0x0c0:"D-TLB-prot-read",0x120:"D-TLB-prot-write",
            0x160:"TRAPA(syscall)",0x180:"illegal-instr",0x1a0:"slot-illegal",
            0x1c0:"NMI",0x1e0:"user-break"}
RESUME = {0x160}  # syscalls/traps are normal -> keep going

REG = ["r0","r1","r2","r3","r4","r5","r6","r7","r8","r9","r10","r11","r12",
       "r13","r14","r15","pc","pr","gbr","vbr","mach","macl","sr"]

class C:
    def __init__(s):
        s.s=socket.create_connection((HOST,PORT),timeout=5); s.s.settimeout(5); s.b=b""
    def raw(s,b): s.s.sendall(b)
    def pkt(s,b):
        s.s.sendall(b"$"+b+b"#"+("%02x"%(sum(b)&0xff)).encode())
        try: s.s.recv(1)
        except: pass
    def recv(s,t=60):
        t0=time.time()
        while b"#" not in s.b:
            if time.time()-t0>t: return None
            try: d=s.s.recv(4096)
            except socket.timeout: continue
            if not d: time.sleep(0.01); continue
            s.b+=d
        i=s.b.index(b"$"); j=s.b.index(b"#",i); body=s.b[i+1:j]; s.b=s.b[j+3:]
        s.s.sendall(b"+"); return body.decode(errors="replace")
    def cmd(s,b,t=10): s.pkt(b); return s.recv(t)

def le(h,i): return int.from_bytes(bytes.fromhex(h[i*8:(i+1)*8]),"little")
def rd(c,a,n=4):
    r=c.cmd(b"m%x,%x"%(a,n));
    return None if (not r or r.startswith("E")) else int.from_bytes(bytes.fromhex(r),"little")

def main():
    c=C()
    c.raw(b"\x03"); time.sleep(0.2); c.recv(5)               # halt
    print("bp @ exception vector 0x%08x:"%VEC, c.cmd(b"Z0,%x,2"%VEC))
    print("continuing; escalate now (cp ff_37/ff_38 into www/repro/). Waiting...")
    while True:
        c.pkt(b"c")
        st=c.recv(120)
        if st is None: print("timeout / no stop"); break
        ev=rd(c,EXPEVT);
        if ev is None: print("stopped:",st,"(no EXPEVT)"); break
        code=ev & 0xfff
        nm=EXC_NAME.get(code,"?")
        if code in RESUME:
            continue                                          # normal syscall, resume
        # real fault -> dump
        print("\n*** FAULT CAUGHT *** EXPEVT=0x%03x (%s)"%(code,nm))
        tea=rd(c,TEA); tra=rd(c,TRA)
        print("TEA (faulting data addr) = 0x%08x"%(tea or 0))
        print("TRA = 0x%08x"%(tra or 0))
        g=c.cmd(b"g")
        if g and not g.startswith("E"):
            for i,n in enumerate(REG):
                if (i+1)*8<=len(g): print("%-4s=%08x"%(n,le(g,i)),end="  " if i%4!=3 else "\n")
            print()
            print("note: pc above = vector handler; faulting PC is in SPC (not in g-packet)")
        break
    print("(left halted; detach with: python3 -c \"import socket;s=socket.create_connection(('127.0.0.1',3263));s.sendall(b'$D#'+b'%02x'%(ord('D')));\" or just continue)")

if __name__=="__main__":
    main()

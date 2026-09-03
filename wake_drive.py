#!/usr/bin/env python3
"""wake_drive.py -- defeat the browser screensaver by sending input every ~2s,
wait for the screen to wake (non-black), then drive the D-pad across the
interactive IM page's elements while watching the two IM globals."""
import sys, time, subprocess, struct, zlib
sys.path.insert(0, "/media/adversary/Storage/dc_browser_extract/poc")
from gdbstub_probe import RSP, read_mem

DEST_G=0x8C3402F4; NODE_G=0x8C29AC2C

def drain(r):
    r.s.setblocking(False)
    try:
        while r.s.recv(4096): pass
    except: pass
    r.s.setblocking(True)
def halt(r): r.s.send(b"\x03"); time.sleep(0.25); drain(r)
def rd(r,a): return int.from_bytes(read_mem(r,a,4),"little")
def tap(k):
    try: subprocess.run(["python3","/media/adversary/Storage/dc_browser_extract/poc/input_drive.py",k],
                        timeout=20, capture_output=True)
    except: pass
def quick(r):
    halt(r); sof=rd(r,0xA05F8050); fb=0xA5000000+sof; nz=0
    for y in range(0,480,16):
        row=read_mem(r,fb+y*640*2,640*2); nz+=sum(1 for b in row if b)
    d=rd(r,DEST_G); n=rd(r,NODE_G); r.send("c"); return sof,nz,d,n
def grab(r,fn):
    halt(r); sof=rd(r,0xA05F8050); fb=0xA5000000+sof; W=640;H=480
    raw=bytearray()
    for y in range(H): raw+=read_mem(r,fb+y*W*2,W*2)
    r.send("c")
    def ch(t,dd): c=t+dd; return struct.pack(">I",len(dd))+c+struct.pack(">I",zlib.crc32(c)&0xffffffff)
    rgb=bytearray()
    for i in range(0,len(raw),2):
        v=raw[i]|(raw[i+1]<<8); rgb+=bytes((((v>>10)&0x1f)*255//31,((v>>5)&0x1f)*255//31,(v&0x1f)*255//31))
    rows=b"".join(b"\x00"+rgb[y*W*3:(y+1)*W*3] for y in range(H))
    open(fn,"wb").write(b"\x89PNG\r\n\x1a\n"+ch(b"IHDR",struct.pack(">IIBBBBB",W,H,8,2,0,0,0))+ch(b"IDAT",zlib.compress(rows,9))+ch(b"IEND",b""))
    print("  wrote",fn)

def main():
    r=RSP(); drain(r); r.send("c"); print("continued")
    # phase 1: wake the screen
    keys=["DOWN","UP","RIGHT","LEFT"]
    awake=False
    for i in range(20):
        tap(keys[i%4]); time.sleep(1.4)
        sof,nz,d,n=quick(r)
        print("wake%2d key=%-5s sof=0x%X nonzero=%d  G1=0x%08X G2=0x%08X"%(i,keys[i%4],sof,nz,d,n))
        if nz>500: awake=True; print("  >>> SCREEN AWAKE"); break
        if d or n: print("  >>> IM GLOBAL POPULATED"); break
    grab(r,"wake_screen.png")
    # phase 2: navigate elements (keep awake + focus links/fields)
    print("--- navigate ---")
    for i,k in enumerate(["DOWN","DOWN","DOWN","A","DOWN","DOWN","A"]):
        tap(k); time.sleep(1.2)
        sof,nz,d,n=quick(r)
        print("nav%2d key=%-5s nonzero=%d  G1=0x%08X G2=0x%08X"%(i,k,nz,d,n))
        if d or n: print("  >>> IM GLOBAL POPULATED <<<"); break
    grab(r,"nav_screen.png")
    r.send("c"); r.s.close()

if __name__=="__main__": main()

#!/usr/bin/env python3
"""driver_im.py -- hold ONE persistent GDB connection (so the stub doesn't pause
the guest on disconnect), resume the browser so it navigates to the interactive
IM page, drive the D-pad to focus interface elements, and watch the two IM globals
*(0x8C3402F4) / *(0x8C29AC2C) go non-NULL (= gadget armed)."""
import sys, time, subprocess, struct, zlib
sys.path.insert(0, "/media/adversary/Storage/dc_browser_extract/poc")
from gdbstub_probe import RSP, read_mem

DEST_G = 0x8C3402F4
NODE_G = 0x8C29AC2C

def drain(r):
    r.s.setblocking(False)
    try:
        while r.s.recv(4096): pass
    except: pass
    r.s.setblocking(True)

def halt(r):
    r.s.send(b"\x03"); time.sleep(0.3); drain(r)

def rd(r,a): return int.from_bytes(read_mem(r,a,4),"little")

def snap(r,tag):
    halt(r)
    d = rd(r,DEST_G); n = rd(r,NODE_G)
    extra=""
    if 0x8C000000<=d<0x8D000000:
        extra += "  dest+0x3C=0x%08X fnptr=0x%08X"%(d+0x3C, rd(r,d+0x3C))
    print("[%-10s] *(0x8C3402F4)=0x%08X  *(0x8C29AC2C)=0x%08X%s"%(tag,d,n,extra))
    r.send("c")   # resume
    return d,n

def grab_screen(r,fn):
    halt(r)
    sof=rd(r,0xA05F8050); fb=0xA5000000+sof; W=640;H=480
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

def drive(seq):
    subprocess.run(["python3","/media/adversary/Storage/dc_browser_extract/poc/input_drive.py"]+seq,
                   timeout=60)

def main():
    r=RSP(); drain(r)
    # the guest may be paused from a prior disconnect; resume it
    r.send("c"); print("resumed guest")
    time.sleep(6)                          # let the meta-refresh load the /im page
    snap(r,"im-loaded")
    grab_screen(r,"im_loaded.png")
    # drive the D-pad to move focus across interface elements (each focus = IM node)
    for i,seq in enumerate([["DOWN"],["DOWN"],["DOWN"],["RIGHT"],["UP"]]):
        drive(seq); time.sleep(1.2)
        snap(r,"after-%s%d"%(seq[0],i))
    grab_screen(r,"im_driven.png")
    print("done (connection stays open; run snapshot separately while this holds)")
    # hold the connection a while so the guest keeps running for a follow-up snapshot
    time.sleep(2)
    r.send("c")
    r.s.close()

if __name__=="__main__":
    main()

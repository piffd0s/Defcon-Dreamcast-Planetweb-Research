import sys,time,struct,zlib
sys.path.insert(0,".")
from gdbstub_probe import RSP, read_mem
def drain(r):
    r.s.setblocking(False)
    try:
        while r.s.recv(4096): pass
    except: pass
    r.s.setblocking(True)
def rd(r,a): return int.from_bytes(read_mem(r,a,4),"little")
def grab(r,fn):
    sof=rd(r,0xA05F8050); fb=0xA5000000+sof; W=640;H=480
    raw=bytearray()
    for y in range(H): raw+=read_mem(r,fb+y*W*2,W*2)
    def ch(t,dd): c=t+dd; return struct.pack(">I",len(dd))+c+struct.pack(">I",zlib.crc32(c)&0xffffffff)
    rgb=bytearray()
    for i in range(0,len(raw),2):
        v=raw[i]|(raw[i+1]<<8); rgb+=bytes((((v>>10)&0x1f)*255//31,((v>>5)&0x1f)*255//31,(v&0x1f)*255//31))
    rows=b"".join(b"\x00"+rgb[y*W*3:(y+1)*W*3] for y in range(H))
    open(fn,"wb").write(b"\x89PNG\r\n\x1a\n"+ch(b"IHDR",struct.pack(">IIBBBBB",W,H,8,2,0,0,0))+ch(b"IDAT",zlib.compress(rows,9))+ch(b"IEND",b""))
r=RSP(); drain(r); r.send("c"); print("watching IM globals; HIT RELOAD now...",flush=True)
hit=False
for t in range(80):  # ~4 min @3s
    time.sleep(3)
    r.s.send(b"\x03"); time.sleep(0.2); drain(r)
    d=rd(r,0x8C3402F4); n=rd(r,0x8C29AC2C)
    if d or n or t%6==0:
        print("t=%3ds G1(dest)=0x%08X G2(node)=0x%08X"%(t*3,d,n),flush=True)
    if (d or n) and not hit:
        hit=True
        print("*** IM GLOBALS POPULATED (dialog up) ***",flush=True)
        if 0x8C000000<=d<0x8D000000:
            print("    dest=0x%08X  dest+0x3C=0x%08X  fnptr there=0x%08X"%(d,d+0x3C,rd(r,d+0x3C)),flush=True)
        if 0x8C000000<=n<0x8D000000:
            print("    node=0x%08X  *(node+0x3C)=0x%08X"%(n,rd(r,n+0x3C)),flush=True)
        grab(r,"DIALOG_POPULATED.png"); print("    wrote DIALOG_POPULATED.png",flush=True)
        # keep watching a bit to see if it changes/teardown
    r.send("c")
print("watch done",flush=True)

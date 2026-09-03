import sys,time,subprocess,struct,zlib
sys.path.insert(0,".")
from gdbstub_probe import RSP, read_mem
DEST_G=0x8C3402F4; NODE_G=0x8C29AC2C
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
r=RSP(); drain(r); r.send("c"); print("monitor: guest continued",flush=True)
last=(0,0)
for t in range(150):   # ~10 min @4s
    time.sleep(4)
    r.s.send(b"\x03"); time.sleep(0.2); drain(r)
    d=rd(r,DEST_G); n=rd(r,NODE_G)
    sof=rd(r,0xA05F8050); fb=0xA5000000+sof; nz=0
    for y in range(0,480,32):
        row=read_mem(r,fb+y*640*2,640*2); nz+=sum(1 for b in row if b)
    req=subprocess.run("grep -cE 'GET|POST' /tmp/eden_im.log",shell=True,capture_output=True,text=True).stdout.strip()
    imf=subprocess.run("grep -cE '/imf|MULTI-FRAME' /tmp/eden_im.log",shell=True,capture_output=True,text=True).stdout.strip()
    if (d,n)!=last or t%5==0:
        print("t=%3ds G1=0x%08X G2=0x%08X screen_nz=%d req=%s frame=%s"%(t*4,d,n,nz,req,imf),flush=True)
    last=(d,n)
    if d or n:
        print("*** IM GLOBALS POPULATED: G1=0x%08X G2=0x%08X ***"%(d,n),flush=True)
        if 0x8C000000<=d<0x8D000000:
            print("    dest+0x3C=0x%08X  fnptr=0x%08X"%(d+0x3C,rd(r,d+0x3C)),flush=True)
        grab(r,"IM_POPULATED.png"); print("    wrote IM_POPULATED.png",flush=True)
        r.send("c"); break
    r.send("c")
print("monitor done",flush=True)

import sys,time,subprocess,struct,zlib
sys.path.insert(0,".")
from gdbstub_probe import RSP, read_mem
def drain(r):
    r.s.setblocking(False)
    try:
        while r.s.recv(4096): pass
    except: pass
    r.s.setblocking(True)
def rd(r,a): return int.from_bytes(read_mem(r,a,4),"little")
r=RSP(); drain(r); r.send("c"); print("FREE-RUNNING (no interrupts) - watching eden log",flush=True)
seen=0
for t in range(150):  # 10 min
    time.sleep(4)
    imf=int(subprocess.run("grep -cE '/imf' /tmp/eden_im.log",shell=True,capture_output=True,text=True).stdout.strip() or 0)
    tot=int(subprocess.run("grep -cE 'HTTP/1.0' /tmp/eden_im.log",shell=True,capture_output=True,text=True).stdout.strip() or 0)
    if t%4==0 or imf!=seen:
        print("t=%3ds browser_req=%d imf_frames=%d"%(t*4,tot,imf),flush=True)
    if imf>=2 and imf!=seen:   # frameset frames loaded -> ONE interrupt to read
        seen=imf; time.sleep(2)
        r.s.send(b"\x03"); time.sleep(0.25); drain(r)
        d=rd(r,0x8C3402F4); n=rd(r,0x8C29AC2C)
        print("  [read] G1=0x%08X G2=0x%08X"%(d,n),flush=True)
        if d or n:
            print("  *** IM POPULATED *** dest+0x3C=0x%08X fnptr=0x%08X"%(d+0x3C,rd(r,d+0x3C)) if 0x8C000000<=d<0x8D000000 else "  *** IM POPULATED (G2 only) ***",flush=True)
        r.send("c")
print("done",flush=True)

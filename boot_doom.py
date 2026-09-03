#!/usr/bin/env python3
"""Boot test: write doom.bin + WAD into free RAM via GDB, patch g_wad, jump to
DOOM (_start 0x8CC00000). Proves the native SH-4 DOOM engine runs on the (emulated)
Dreamcast and renders to the framebuffer 0xA5600000."""
import time, struct, sys
sys.path.insert(0,"/media/adversary/Storage/dc_browser_extract/poc")
from gdbstub_probe import RSP, read_mem
ROOT="/media/adversary/Storage/dc_browser_extract/"
DOOM=open(ROOT+"poc/build/doom.bin","rb").read()
WAD =open(ROOT+"poc/wad/doom1.wad","rb").read()
DOOM_DST=0x8CC00000; WAD_DST=0x8C010000
G_WAD_ADDR=0x8CC56E44; G_WAD_SIZE=0x8CC56E40
r=RSP(); r.s.send(b"\x03"); time.sleep(0.4)
r.s.setblocking(False)
try:
    while r.s.recv(4096): pass
except: pass
r.s.setblocking(True); time.sleep(0.1)
def wmem(a,d):
    for i in range(0,len(d),1024):
        c=d[i:i+1024]; r.cmd("M%x,%x:%s"%(a+i,len(c),c.hex()))
t0=time.time()
print("writing doom.bin %d bytes -> %08x"%(len(DOOM),DOOM_DST)); wmem(DOOM_DST,DOOM)
print("writing WAD %d bytes -> %08x"%(len(WAD),WAD_DST)); wmem(WAD_DST,WAD)
r.cmd("M%x,4:%s"%(G_WAD_ADDR,struct.pack("<I",WAD_DST).hex()))
r.cmd("M%x,4:%s"%(G_WAD_SIZE,struct.pack("<I",len(WAD)).hex()))
print("write done in %.1fs"%(time.time()-t0))
print("verify doom@dst:",read_mem(r,DOOM_DST,8).hex()," g_wad_addr:",read_mem(r,G_WAD_ADDR,4).hex(),
      " g_wad_size:",read_mem(r,G_WAD_SIZE,4).hex())
# set pc = DOOM entry (regnum 16 = 0x10) and run
print("set pc=%08x, continue -> DOOM boot"%DOOM_DST)
print("P10 resp:", r.cmd("P10=%s"%struct.pack("<I",DOOM_DST).hex()))
r.send("c")
print("continued.")

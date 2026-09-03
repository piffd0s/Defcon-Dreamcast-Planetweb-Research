#!/usr/bin/env python3
"""Build the next DOOM attempt with a UNIQUE tag in BOTH the email subject and the
scan magic, so the stub finds THIS attempt's fresh full blob (not a stale partial)
and you can tell which message to open."""
import sys,struct,os
sys.path.insert(0,os.path.dirname(os.path.abspath(__file__)))
ROOT=os.path.dirname(os.path.abspath(__file__))
nf=os.path.join(ROOT,"attempt_n.txt")
n=(int(open(nf).read())+1) if os.path.exists(nf) else 1
open(nf,"w").write(str(n))
magic=("DMxx%04d"%n).encode()          # 8 bytes, byte-safe
subject="DOOM-%04d"%n
open(os.path.join(ROOT,"magic.txt"),"wb").write(magic)
open(os.path.join(ROOT,"mail_subject.txt"),"w").write(subject)
import importlib, doom_full as F; importlib.reload(F)
import sh4_asm as A
doom=open(os.path.join(ROOT,"build/doom.bin"),"rb").read()
wad =open(os.path.join(ROOT,"wad/doom_mini.wad"),"rb").read()
open(os.path.join(ROOT,"doom_blob.txt"),"wb").write(magic + (doom+wad).hex().encode())
stub,bad=F.full_stub(len(doom),len(wad))
payload=b"A"*64+struct.pack("<I",F.PR)+A.w(0x6003)*(0x2000//2)+stub
open(os.path.join(ROOT,"name_payload.hex"),"w").write(payload.hex())
print("ATTEMPT %d: subject='%s'  magic=%s  stub=%d bytes byte-safe=%s  blob=%.2fMB"
      %(n,subject,magic.decode(),len(stub),not bad,(len(magic)+len(doom+wad)*2)/1e6))

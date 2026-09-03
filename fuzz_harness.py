#!/usr/bin/env python3
"""
fuzz_harness.py -- unattended browser-parser fuzzing campaign for the PlanetWeb
Dreamcast browser running in the (debug) Flycast emulator.

Loop per iteration:
  1. generate a batch of mutated images (GIF/JPEG) into www/fuzz/ + a start page
     (junkyard.html) that <img>-loads them all  (eden serves these from disk).
  2. boot debug Flycast (real BIOS); retry on reios-fallback / no-network (the
     emulated modem is flaky).
  3. once the browser connects + fetches the fuzz images, watch flycast.log for
     an SH4 exception / process death = a parser crash.
  4. on crash: save the batch + logs + the last-fetched image (prime suspect) to
     crashes/<iter>/, append to findings.log.
  5. kill, next iteration.

Run in background:  setsid python3 fuzz_harness.py --iters 200 >camp.log 2>&1 &
Pre-reqs: eden_mitm.py running on the edenport (splash chain); BIOS in the
build's data dirs; debug flycast built.
"""
import os, sys, time, random, glob, shutil, subprocess, signal, argparse

ROOT = "/media/adversary/Storage/dc_browser_extract"
POC  = ROOT + "/poc"
WWW  = POC + "/www"
FZ   = WWW + "/fuzz"
SEEDS= POC + "/fuzz_seeds"
FCBIN= ROOT + "/src-build/flycast-src/build/flycast"
GDI  = ROOT + "/Internet Browser V3.0 for Dreamcast (USA).gdi"
HOMED= ROOT + "/emu/fchome"
XAUTH= "/home/adversary/.Xauthority"
DISP = ":12.0"
EDENLOG = ROOT + "/emu/eden.log"
FCLOG   = "/tmp/fc_fuzz.log"
CRASHD  = POC + "/crashes"
FINDINGS= POC + "/findings.log"

def log(m):
    print("[%s] %s" % (time.strftime("%H:%M:%S"), m)); sys.stdout.flush()

# ---------------- mutation ----------------
def gif_fields(b):
    b = bytearray(b)
    s = random.choice(["scr","img","lzw","ct","rand"])
    if s == "scr" and len(b) >= 10:                      # logical screen w/h
        b[6:8] = random.choice([b"\xff\xff", b"\x00\x80", b"\xff\x7f"])
        b[8:10]= random.choice([b"\xff\xff", b"\x00\x40"])
    elif s == "img":                                     # image descriptor w/h
        i = b.find(b"\x2c")
        if i >= 0 and i+9 < len(b):
            b[i+5:i+7] = b"\xff\xff"; b[i+7:i+9] = b"\xff\xff"
    elif s == "lzw":                                     # illegal LZW min code size
        i = b.find(b"\x2c")
        if i >= 0 and i+10 < len(b): b[i+10] = random.choice([0,1,12,13,0xff])
    elif s == "ct" and len(b) > 10:                      # claim a global color table flag/size
        b[10] = 0xF7
    else:
        for _ in range(random.randint(1,8)):
            j = random.randrange(len(b)); b[j] = random.randrange(256)
    return bytes(b)

def jpg_fields(b):
    b = bytearray(b)
    def find(m):
        return b.find(m)
    s = random.choice(["sof","dht","dqt","trunc","rand"])
    if s == "sof":
        for m in (b"\xff\xc0", b"\xff\xc2"):
            i = find(m)
            if i >= 0 and i+9 < len(b):
                b[i+5:i+7] = random.choice([b"\xff\xff", b"\x40\x00"])   # height
                b[i+7:i+9] = random.choice([b"\xff\xff", b"\x40\x00"])   # width
                b[i+9] = random.choice([0, 0x40, 0xff])                  # #components
                break
    elif s == "dht":
        i = find(b"\xff\xc4")
        if i >= 0:
            for k in range(i+5, min(i+21, len(b))): b[k] = 0xff          # bogus huffman counts
    elif s == "dqt":
        i = find(b"\xff\xdb")
        if i >= 0 and i+3 < len(b): b[i+2:i+4] = b"\xff\xff"             # bad length
    elif s == "trunc":
        b = b[:random.randint(8, max(9, len(b)-1))]
    else:
        for _ in range(random.randint(1,10)):
            j = random.randrange(len(b)); b[j] = random.randrange(256)
    return bytes(b)

def mutate(path):
    b = open(path, "rb").read()
    ext = path.rsplit(".",1)[-1].lower()
    if ext == "gif": return gif_fields(b), "gif"
    return jpg_fields(b), "jpg"

def gen_batch(n, it):
    for f in glob.glob(FZ + "/m_*"): os.remove(f)
    seeds = glob.glob(SEEDS + "/*.gif") + glob.glob(SEEDS + "/*.jpg")
    names = []
    for i in range(n):
        data, ext = mutate(random.choice(seeds))
        nm = "m_%03d_%02d.%s" % (it, i, ext)
        open(FZ + "/" + nm, "wb").write(data); names.append(nm)
    html = "<html><body bgcolor=black>"
    for nm in names: html += '<img src="/fuzz/%s" width=16 height=16>\n' % nm
    html += "</body></html>"
    # served by eden for any /fz/... (per-boot-unique URL) -> always fresh, no VMU clear
    open(WWW + "/_fuzzpage.html", "w").write(html)
    return names

# ---------------- emulator control ----------------
def kill_flycast():
    subprocess.run("for p in $(ps -eo pid,comm|awk '$2~/[Ff]lycast/{print $1}'); do kill $p 2>/dev/null; done",
                   shell=True)
    time.sleep(3)

def launch_flycast():
    open(FCLOG, "w").close()
    env = dict(os.environ, HOME=HOMED, XAUTHORITY=XAUTH, DISPLAY=DISP)
    fcout = open(FCLOG, "w")
    # cwd MUST be ROOT: flycast finds the real BIOS via ./data/dc_boot.bin (else reios)
    return subprocess.Popen([FCBIN, GDI], env=env, stdout=fcout, stderr=fcout,
                            stdin=subprocess.DEVNULL, start_new_session=True, cwd=ROOT)

def eden_lines():
    try: return open(EDENLOG, errors="replace").read().count("\n")
    except: return 0

def fc_has(*subs):
    try: t = open(FCLOG, errors="replace").read()
    except: return False
    return any(s in t for s in subs)

def new_eden(base):
    try: return open(EDENLOG, errors="replace").read().splitlines()[base:]
    except: return []

# ---------------- one iteration ----------------
def boot_and_connect(timeout=80):
    """returns 'ok' once the browser fetched edenclient.conf, else 'reios'/'noconn'"""
    base = eden_lines()
    p = launch_flycast()
    t0 = time.time()
    while time.time() - t0 < timeout:
        time.sleep(4)
        if fc_has("Did not load BIOS", "using reios"):
            return "reios", base
        if any("edenclient.conf" in l for l in new_eden(base)):
            return "ok", base
        if p.poll() is not None:
            return "died", base
    return "noconn", base

def watch_decode(base, window=35):
    """after connect: wait for fuzz fetches; detect crash. returns (status, suspect)"""
    t0 = time.time(); last_fuzz = None
    while time.time() - t0 < window:
        time.sleep(3)
        if fc_has("SH4 exception", "Fatal", "has stopped"):
            for l in new_eden(base):
                if "/fuzz/m_" in l: last_fuzz = l.split('/fuzz/')[1].split()[0].rstrip('"')
            return "CRASH", last_fuzz
        fetched = [l for l in new_eden(base) if "/fuzz/m_" in l]
        if fetched: last_fuzz = fetched[-1].split('/fuzz/')[1].split()[0].rstrip('"')
    return "clean", last_fuzz

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--iters", type=int, default=100)
    ap.add_argument("--batch", type=int, default=8)
    ap.add_argument("--seed", type=int, default=1234)
    a = ap.parse_args()
    random.seed(a.seed)
    os.makedirs(FZ, exist_ok=True); os.makedirs(CRASHD, exist_ok=True)
    # ensure eden serves the 'fuzz' chain (FuzzNav -> per-boot-unique /fz/ URL)
    port = open(ROOT+"/emu/edenport").read().strip()
    subprocess.run("fuser -k %s/tcp 2>/dev/null; sleep 1" % port, shell=True)
    subprocess.Popen(["python3", POC+"/eden_mitm.py", "--chain", "fuzz", "-p", port,
                      "--host", "eden.planetweb.com"], cwd=POC,
                     stdout=open(ROOT+"/emu/eden.log","w"), stderr=subprocess.STDOUT,
                     stdin=subprocess.DEVNULL, start_new_session=True)
    time.sleep(2)
    log("eden serving 'fuzz' chain on :%s" % port)
    if not (glob.glob(SEEDS+"/*.gif") or glob.glob(SEEDS+"/*.jpg")):
        log("no seeds in %s -- aborting" % SEEDS); return
    log("campaign start: %d iters x batch %d" % (a.iters, a.batch))
    crashes = 0
    for it in range(a.iters):
        names = gen_batch(a.batch, it)
        # boot with retries (reios/noconn are transient)
        st = base = None
        for attempt in range(4):
            st, base = boot_and_connect()
            if st == "ok": break
            log("iter %d boot attempt %d: %s -- retrying" % (it, attempt, st))
            kill_flycast()
        if st != "ok":
            log("iter %d: could not connect after retries; skipping batch" % it); kill_flycast(); continue
        status, suspect = watch_decode(base)
        if status == "CRASH":
            crashes += 1
            cd = "%s/iter_%03d" % (CRASHD, it); os.makedirs(cd, exist_ok=True)
            for nm in names: shutil.copy(FZ+"/"+nm, cd)
            shutil.copy(FCLOG, cd+"/flycast.log")
            open(cd+"/info.txt","w").write("suspect (last fuzz img fetched): %s\nbatch: %s\n" % (suspect, names))
            msg = "*** CRASH iter %d  suspect=%s  saved->%s ***" % (it, suspect, cd)
            log(msg); open(FINDINGS,"a").write(time.strftime("%F %T ")+msg+"\n")
        else:
            log("iter %d: clean (last fetched %s)" % (it, suspect))
        kill_flycast()
    log("campaign done. crashes=%d (see %s)" % (crashes, FINDINGS))

if __name__ == "__main__":
    main()

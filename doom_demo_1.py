#!/usr/bin/env python3
"""
doom_demo_1.py -- one-command DEF CON demo:
    Dreamcast PlanetWeb browser  ->  email MIME overflow  ->  native SH-4 DOOM.

    sudo python3 doom_demo_1.py

It brings up everything, boots the browser, waits for you to go online, then stages
the payload over the emulator's SH-4 GDB stub and tells you exactly when to open the
DOOM-STAGE email. No Java, no jar, no rogue Eden server -- the email overflow is the
only exploit in the chain.

You still do three things by hand (they need console input the script can't give):
    1. take the browser ONLINE  (A x3 -> Start -> web browser)
    2. have a POP3 account configured (host = ppp.ppp.com, any user/pass)
    3. when the script says CHECK EMAIL, open the DOOM-STAGE message

Everything else -- DNS, POP3 server, the splash page, launching + relaunching the
emulator through its startup race, and the RAM staging -- is automatic.

Requires root (binds :53, :80, :110). Run it from the repo root with sudo.
"""

import os, sys, time, struct, socket, subprocess, threading, signal, shutil
import http.server, socketserver

# ------------------------------------------------------------------ paths / config
ROOT      = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, ROOT)

FLYCAST   = os.path.join(ROOT, "src-build/flycast-src/build/Flycast.app/Contents/MacOS/Flycast")
FCHOME    = os.path.join(ROOT, "emu/fchome")
FCLOG     = os.path.join(FCHOME, ".flycast/data/flycast.log")
DNS_PY    = os.path.join(ROOT, "dns_redirect.py")
MAIL_PY   = os.path.join(ROOT, "mail_poc.py")
WWW       = os.path.join(ROOT, "www")

# the browser disc (your 3-track GD-ROM dump); override with DISC=/path in the env
DISC = os.environ.get("DISC",
    os.path.expanduser("~/Downloads/Internet Browser V3.0 for Dreamcast (USA)/"
                       "Internet Browser V3.0 for Dreamcast (USA).gdi"))

# Golden savestate: a browser already past the intro, online, mail-configured, on the
# web page. Bake it once with --bake; every normal run warm-boots from it (instant, no
# Sega-swirl, no intro-clicking, no going-online-by-hand). Flycast names the state file
# after the disc; AutoLoadState=yes loads it at boot. Mail settings live in flash
# (dc_nvmem) + VMU, which we snapshot alongside so a warm boot is fully configured.
GOLDEN     = os.path.join(ROOT, "emu/golden.state")
NVMEM_GOLD = os.path.join(ROOT, "emu/golden_nvmem.bin")
VMU_GOLD   = os.path.join(ROOT, "emu/golden_vmuA1.bin")
# ARMED state: a snapshot taken AFTER the payload is staged and the DOOM-STAGE mail is
# downloaded. Reloading it restores the whole 16 MB of RAM with the blob @0x8C867000 and
# stub @0x8C29ADE8 already frozen in place -- so at showtime there's no staging, no GDB,
# no clobber window: just click the email. If present, a normal run prefers it.
ARMED      = os.path.join(ROOT, "emu/golden_armed.state")
ARMED_NVMEM= os.path.join(ROOT, "emu/golden_armed_nvmem.bin")
FCDATA     = os.path.join(FCHOME, ".flycast/data")
STATEFILE  = os.path.join(FCDATA, os.path.splitext(os.path.basename(DISC))[0] + ".state")
NVMEM      = os.path.join(FCDATA, "dc_nvmem.bin")

# payload inputs (built by build_stage_email.py; already present in the repo)
MAGIC_F = os.path.join(ROOT, "magic.txt")
STUB_F  = os.path.join(ROOT, "build/stub.bin")
DOOM_F  = os.path.join(ROOT, "build/doom.bin")
WAD_F   = os.path.join(ROOT, "wad/doom1_trim.wad")

# addresses -- these are the validated constants; do not change without rebuilding
STUB_ADDR        = 0x8C29ADE8          # where the email's saved-PR points
BLOB_ADDR        = 0x8C867000          # blob lands here (inside the stub's scan window)
SCAN_LO, SCAN_HI = 0x8C400000, 0x8CFF0000
GDB_PORT         = 3263

FLYCAST_ATTEMPTS = 12                  # the startup vmem race needs a few tries sometimes

# ------------------------------------------------------------------ small helpers
G = "\033[92m"; Y = "\033[93m"; R = "\033[91m"; B = "\033[1m"; X = "\033[0m"
def say(m):  print("   " + m, flush=True)
def hdr(m):  print("\n" + G + "=" * 66 + "\n== " + m + "\n" + "=" * 66 + X, flush=True)
def warn(m): print(R + "!! " + m + X, flush=True, file=sys.stderr)

procs = []   # (name, Popen)

def host_ip():
    if os.environ.get("HOST_IP"):
        return os.environ["HOST_IP"]
    try:
        dev = subprocess.check_output(["route", "-n", "get", "default"], text=True)
        iface = next(l.split()[-1] for l in dev.splitlines() if "interface:" in l)
        return subprocess.check_output(["ipconfig", "getifaddr", iface], text=True).strip()
    except Exception:
        return "127.0.0.1"

def real_user():
    return os.environ.get("SUDO_USER") or subprocess.check_output(
        ["stat", "-f%Su", "/dev/console"], text=True).strip()

def kill_stale():
    """Reap leftovers from earlier runs. We run as root, so we can also kill orphaned
    doom_demo / Flycast instances -- the exact tangle that jams the ports otherwise.
    Protect ourselves: skip our own pid, our parent (the sudo wrapper), and anything in
    our process group, so we never kill the live session."""
    me = os.getpid(); parent = os.getppid()
    try: my_pgid = os.getpgid(0)
    except Exception: my_pgid = -1
    protected = {me, parent, 0}

    def reap(pattern, label):
        try:
            out = subprocess.check_output(["pgrep", "-f", pattern], text=True).split()
        except subprocess.CalledProcessError:
            out = []
        for s in out:
            pid = int(s)
            if pid in protected:
                continue
            try:
                if os.getpgid(pid) == my_pgid:   # same session -> that's us
                    continue
            except Exception:
                pass
            try:
                os.kill(pid, signal.SIGTERM); say("reaped stale %s (pid %d)" % (label, pid))
            except Exception:
                pass

    for name in ("dns_redirect.py", "mail_poc.py", "eden_mitm.py", "mail_mitm.py", "doom_demo_1.py"):
        reap(name, name)
    # stray Flycast (ours isn't started yet at this point)
    try:
        for s in subprocess.check_output(["pgrep", "-x", "Flycast"], text=True).split():
            try: os.kill(int(s), signal.SIGTERM); say("reaped stale Flycast (pid %s)" % s)
            except Exception: pass
    except subprocess.CalledProcessError:
        pass
    time.sleep(2)

def cleanup(*_):
    print()
    for name, p in procs:
        if p.poll() is None:
            try: p.terminate()
            except Exception: pass
    # SIGTERM (never -9) so macOS doesn't flag a crash and block the next launch
    subprocess.run(["pkill", "-TERM", "-x", "Flycast"], stderr=subprocess.DEVNULL)
    say("stopped all servers + emulator")
    os._exit(0)

# ------------------------------------------------------------------ GDB (RSP) client
class RSP:
    def __init__(self, host="127.0.0.1", port=GDB_PORT, timeout=8):
        self.s = socket.create_connection((host, port), timeout=timeout)
        self.s.settimeout(timeout); self.buf = b""
    def _csum(self, b): return sum(b) & 0xff
    def send(self, body):
        b = body.encode() if isinstance(body, str) else body
        self.s.sendall(b"$" + b + b"#" + ("%02x" % self._csum(b)).encode())
        t0 = time.time()
        while time.time() - t0 < 2:
            d = self.s.recv(1)
            if d in (b"+", b""): break
    def recv(self, timeout=8):
        t0 = time.time()
        while b"#" not in self.buf:
            if time.time() - t0 > timeout: return None
            try: d = self.s.recv(4096)
            except socket.timeout: return None
            if not d: time.sleep(0.01); continue
            self.buf += d
        i = self.buf.index(b"$"); j = self.buf.index(b"#", i)
        body = self.buf[i+1:j]; self.buf = self.buf[j+3:]
        self.s.sendall(b"+")
        return body.decode(errors="replace")
    def cmd(self, body, timeout=8):
        self.send(body); return self.recv(timeout)

def halt(r):
    r.s.send(b"\x03"); time.sleep(0.3)
    r.s.setblocking(False)
    try:
        while r.s.recv(4096): pass
    except Exception: pass
    r.s.setblocking(True)

def read_mem(r, addr, n):
    out = bytearray()
    while n > 0:
        c = min(n, 512)
        resp = r.cmd("m%x,%x" % (addr, c))
        if not resp or (len(resp) >= 3 and resp[0] == "E" and len(resp) == 3):
            break
        out += bytes.fromhex(resp); addr += c; n -= c
    return bytes(out)

def write_mem(r, addr, data, label="", chunk=1024):
    total = len(data); nextpct = 10
    for i in range(0, total, chunk):
        c = data[i:i+chunk]
        if r.cmd("M%x,%x:%s" % (addr+i, len(c), c.hex())) != "OK":
            return False
        if label and total > 65536:
            pct = 100 * (i + len(c)) // total
            if pct >= nextpct:
                say("  %s %3d%%" % (label, pct)); nextpct += 10
    return True

# ------------------------------------------------------------------ in-process web
online_evt = threading.Event()

class SplashHandler(http.server.SimpleHTTPRequestHandler):
    def __init__(self, *a, **k):
        super().__init__(*a, directory=WWW, **k)
    def log_message(self, *a):
        pass
    def end_headers(self):
        self.send_header("Cache-Control", "no-cache, no-store, must-revalidate")
        super().end_headers()
    def do_GET(self):
        if not online_evt.is_set():
            online_evt.set()
        super().do_GET()

def start_web(ip):
    # any hostname the browser asks for resolves to us, so "/" is the splash page
    src = os.path.join(WWW, "junkyard.html")
    dst = os.path.join(WWW, "index.html")
    try:
        if os.path.exists(src) and (not os.path.exists(dst)
                                    or open(src, "rb").read() != open(dst, "rb").read()):
            shutil.copyfile(src, dst)
    except PermissionError:
        # a leftover root-owned index.html from a prior sudo run; content already matches
        pass
    httpd = socketserver.ThreadingTCPServer((ip, 80), SplashHandler)
    httpd.daemon_threads = True
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    return httpd

# ------------------------------------------------------------------ flycast launch
def have_golden():
    return os.path.exists(GOLDEN)

def launch_flycast(ip, bake=False, force_armed=False, save_on_quit=False, cold=False):
    user = real_user()
    os.makedirs(FCDATA, exist_ok=True)
    # cold overrides warm: render fresh (no savestate) to avoid the browser's
    # black-on-restore repaint quirk, but keep the configured flash so mail is set up.
    warm = (not cold) and (force_armed or ((not bake) and have_golden()))

    if cold:
        # fresh render, but restore the golden flash (mail account + first-time setup)
        for f in (os.listdir(FCDATA) if os.path.isdir(FCDATA) else []):
            if f.endswith(".state"):
                try: os.remove(os.path.join(FCDATA, f))
                except Exception: pass
        if os.path.exists(NVMEM_GOLD):
            shutil.copyfile(NVMEM_GOLD, NVMEM)
    elif force_armed:
        # the caller already placed the armed state as STATEFILE -- just AutoLoad it
        pass
    elif warm:
        # warm boot: drop the golden state + flash into place so AutoLoadState finds them
        shutil.copyfile(GOLDEN, STATEFILE)
        if os.path.exists(NVMEM_GOLD):
            shutil.copyfile(NVMEM_GOLD, NVMEM)
        if os.path.exists(VMU_GOLD):
            shutil.copyfile(VMU_GOLD, os.path.join(
                FCDATA, os.path.splitext(os.path.basename(DISC))[0] + "_vmu_save_A1.bin"))
    else:
        # cold boot: remove any stale state so we start clean
        for f in (os.listdir(FCDATA) if os.path.isdir(FCDATA) else []):
            if f.endswith(".state"):
                try: os.remove(os.path.join(FCDATA, f))
                except Exception: pass

    subprocess.run(["sudo", "-u", user, "defaults", "write",
                    "com.flyinghead.Flycast", "ApplePersistenceIgnoreState", "-bool", "YES"],
                   stderr=subprocess.DEVNULL, env=dict(os.environ, HOME=FCHOME))

    args = ["sudo", "-u", user, "env", "HOME=" + FCHOME, FLYCAST,
            "-config", "log:LogToFile=yes",
            "-config", "config:Debug.GDBEnabled=yes",
            "-config", "config:Debug.GDBPort=%d" % GDB_PORT,
            "-config", "network:Enable=yes",
            "-config", "network:DCNet=no",
            "-config", "network:EmulateBBA=yes",
            "-config", "network:DNS=" + ip,
            # warm run auto-loads the golden state; bake run auto-saves on quit.
            # section is 'config'; the option NAME already carries the 'Dreamcast.' prefix
            "-config", "config:Dreamcast.AutoLoadState=" + ("yes" if warm else "no"),
            "-config", "config:Dreamcast.AutoSaveState=" + ("yes" if (bake or save_on_quit) else "no"),
            DISC]

    say("boot mode: " + (G + "WARM (golden state)" + X if warm
                         else (Y + "BAKE (will save state on quit)" + X if bake
                               else "COLD (no golden state yet -- run --bake once)")))

    for attempt in range(1, FLYCAST_ATTEMPTS + 1):
        try: open(FCLOG, "w").close()
        except Exception: pass
        p = subprocess.Popen(args, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        ok = None
        for _ in range(30):
            time.sleep(1)
            try: log = open(FCLOG, errors="ignore").read()
            except Exception: log = ""
            if "Verify Failed" in log: ok = False; break
            if "Game ID" in log:       ok = True;  break
            if p.poll() is not None:   ok = False; break
        why = "RAM-reservation race"
        if ok:
            # "Game ID" only proves reios started -- a boot can still hang after that
            # (a crash-written flash does exactly this: stuck on the Sega logo). Verify
            # the SH-4 is actually executing browser code before accepting the boot.
            if boot_is_live():
                if attempt > 1: say("(booted on attempt %d)" % attempt)
                return p
            ok = False; why = "boot hung after reios (guest not executing)"
        say("attempt %d: %s, relaunching" % (attempt, why))
        try: p.terminate()
        except Exception: pass
        subprocess.run(["pkill", "-TERM", "-x", "Flycast"], stderr=subprocess.DEVNULL)
        time.sleep(2)
    warn("Flycast would not start in %d attempts (see %s)" % (FLYCAST_ATTEMPTS, FCLOG))
    cleanup()

def boot_is_live():
    """Sample the SH-4 PC over the GDB stub a few times; a healthy boot has the PC
    advancing through the browser image (1ST_READ.BIN @ 0x8C010000). A hung boot sits
    at one address. Always resumes the guest after each sample."""
    if not wait_gdb():
        return False
    pcs = []
    for _ in range(4):
        try:
            s = socket.create_connection(("127.0.0.1", GDB_PORT), timeout=3); s.settimeout(3)
            s.sendall(b"\x03"); time.sleep(0.2)
            s.setblocking(False)
            try:
                while s.recv(4096): pass
            except Exception: pass
            s.setblocking(True)
            s.sendall(b"$g#67")
            buf = b""; t0 = time.time()
            while b"#" not in buf and time.time() - t0 < 3:
                try: d = s.recv(4096)
                except socket.timeout: break
                if not d: break
                buf += d
            if b"$" in buf and b"#" in buf:
                g = buf[buf.index(b"$")+1:buf.index(b"#")]
                if len(g) >= 17*8:
                    pcs.append(struct.unpack("<I", bytes.fromhex(g[16*8:16*8+8].decode()))[0])
            s.sendall(b"$c#63")   # ALWAYS resume
            s.close()
        except Exception:
            pass
        time.sleep(0.8)
    if len(pcs) < 2:
        return False
    # executing if the PC moved and lands in RAM code (browser/reios region)
    return len(set(pcs)) > 1 and all(0x8C000000 <= p < 0x8D000000 for p in pcs)

def wait_gdb():
    for _ in range(30):
        try:
            s = socket.create_connection(("127.0.0.1", GDB_PORT), timeout=2); s.close()
            return True
        except Exception:
            time.sleep(1)
    return False

# ------------------------------------------------------------------ staging
def stage():
    magic = open(MAGIC_F, "rb").read().strip()
    doom  = open(DOOM_F, "rb").read()
    wad   = open(WAD_F, "rb").read()
    stub  = open(STUB_F, "rb").read()
    blob  = magic + doom + wad
    assert len(magic) == 8, "magic.txt must be 8 bytes"
    if not (SCAN_LO <= BLOB_ADDR < SCAN_HI):
        warn("blob addr outside scan window"); return False

    hdr("staging the payload over the SH-4 GDB stub")
    say("magic %r  doom %d B  wad %d B  blob %d B  stub %d B"
        % (magic, len(doom), len(wad), len(blob), len(stub)))
    try:
        r = RSP()
    except Exception as e:
        warn("cannot reach the GDB stub on :%d (%s)" % (GDB_PORT, e)); return False
    halt(r)
    t0 = time.time()
    if not write_mem(r, BLOB_ADDR, blob, "blob"): warn("blob write failed"); return False
    if not write_mem(r, STUB_ADDR, stub, "stub"): warn("stub write failed"); return False
    # verify before we ever tell the operator to fire the email
    gm = read_mem(r, BLOB_ADDR, 8)
    gs = read_mem(r, STUB_ADDR, len(stub))
    ok = (gm == magic) and (gs == stub)
    say("blob magic @0x%08X : %s" % (BLOB_ADDR, "OK" if gm == magic else "MISMATCH"))
    say("stub       @0x%08X : %s (%d B)" % (STUB_ADDR, "OK" if gs == stub else "MISMATCH", len(stub)))
    say("staged + verified in %.1fs" % (time.time() - t0))
    r.send("c")   # resume the guest
    return ok

def verify_staged():
    """Read back the blob magic + stub over GDB (halt, read, resume). Used to confirm
    the payload survived a savestate save/load round-trip. Returns (blob_ok, stub_ok)."""
    magic = open(MAGIC_F, "rb").read().strip()
    stub  = open(STUB_F, "rb").read()
    try:
        r = RSP()
    except Exception:
        return (False, False)
    halt(r)
    gm = read_mem(r, BLOB_ADDR, 8)
    gs = read_mem(r, STUB_ADDR, len(stub))
    r.send("c")
    return (gm == magic, gs == stub)

# ------------------------------------------------------------------ arm the state (payload frozen in RAM)
def arm_state(ip):
    """Warm-boot the base golden state, you download the DOOM-STAGE mail, we stage the
    payload, then you Cmd-Q to snapshot -- freezing the staged RAM into golden_armed.state.
    Reloading that state needs no staging and has no clobber window: just click the email."""
    if not have_golden():
        warn("no base golden.state yet -- run  --bake  first"); cleanup()
    hdr("ARM MODE -- freeze the staged payload into a savestate (one time)")
    fc = launch_flycast(ip, save_on_quit=True)   # warm-boot base golden state, save on Cmd-Q
    if not wait_gdb():
        warn("emulator did not come up"); cleanup()
    say("browser restored online. Now:")
    say("  1. " + B + "Check Mail" + X + " to DOWNLOAD DOOM-STAGE (do NOT open it)")
    say("waiting for the download...")
    fetched = threading.Event()
    threading.Thread(target=lambda: (sys.stdin.readline(), fetched.set()), daemon=True).start()
    while not fetched.is_set():
        try:
            if "sending crafted message" in open("/tmp/demo_mail.log", errors="ignore").read():
                break
        except Exception: pass
        time.sleep(1)
    say(G + "downloaded." + X + " staging the payload...")
    if not stage():
        warn("staging failed -- aborting arm"); cleanup()
    hdr(Y + B + "NOW: quit Flycast (Cmd-Q) to snapshot the armed state" + X)
    say("do it promptly -- we want the snapshot taken with the payload freshly staged.")
    say("waiting for you to quit Flycast...")
    fc.wait()
    time.sleep(2)
    if not os.path.exists(STATEFILE):
        warn("no state written (quit with Cmd-Q?)"); cleanup()
    shutil.copyfile(STATEFILE, ARMED)
    if os.path.exists(NVMEM): shutil.copyfile(NVMEM, ARMED_NVMEM)
    say("armed state saved (%d KB). validating the round-trip..." % (os.path.getsize(ARMED)//1024))

    # VALIDATE: reload the armed state headless and confirm the payload survived
    shutil.copyfile(ARMED, STATEFILE)
    if os.path.exists(ARMED_NVMEM): shutil.copyfile(ARMED_NVMEM, NVMEM)
    v = launch_flycast(ip, force_armed=True)   # AutoLoadState of the armed state
    if not wait_gdb():
        warn("validation boot failed"); cleanup()
    time.sleep(3)
    blob_ok, stub_ok = verify_staged()
    subprocess.run(["pkill", "-TERM", "-x", "Flycast"], stderr=subprocess.DEVNULL)
    if blob_ok and stub_ok:
        hdr(G + "ARMED STATE VALIDATED" + X)
        say("blob @0x%08X and stub @0x%08X survived save/load." % (BLOB_ADDR, STUB_ADDR))
        say("showtime demo is now: warm-boot -> CLICK THE EMAIL -> DOOM. No staging.")
    else:
        warn("round-trip check: blob_ok=%s stub_ok=%s -- payload did NOT survive."
             % (blob_ok, stub_ok))
        say("the browser likely clobbered it before the snapshot. Re-run --arm and Cmd-Q")
        say("faster after 'downloaded/staging'. Removing the bad armed state.")
        for f in (ARMED, ARMED_NVMEM):
            try: os.remove(f)
            except Exception: pass

# ------------------------------------------------------------------ bake the golden state
def bake_state(ip):
    """Cold-boot with AutoSaveState. You drive the browser to a good state (online,
    mail configured, on the web page), then quit Flycast (Cmd-Q) -- Flycast writes the
    state on exit, and we snapshot it + flash as the golden set."""
    hdr("BAKE MODE -- create the golden savestate (one time)")
    say("servers are up. In the emulator:")
    say("  1. take the browser ONLINE (A x3 -> Start -> web browser)")
    say("  2. configure the POP3 account if not already: host " + B + "ppp.ppp.com" + X + ", any user/pass")
    say("  3. leave it ON THE WEB-BROWSER PAGE (the DEF CON splash), online")
    say("  4. then " + B + "quit Flycast (Cmd-Q)" + X + " -- it saves state on exit")
    say("")
    say("waiting for you to quit Flycast...")
    fc = launch_flycast(ip, bake=True)
    if not wait_gdb():
        warn("emulator did not come up"); cleanup()
    say("emulator up -- drive the browser, then Cmd-Q when it's in the state you want")
    fc.wait()   # blocks until the user quits Flycast
    time.sleep(2)
    if not os.path.exists(STATEFILE):
        warn("no state was written (%s). Did you quit with Cmd-Q? AutoSaveState may need a"
             " running game." % STATEFILE); cleanup()
    os.makedirs(os.path.dirname(GOLDEN), exist_ok=True)
    shutil.copyfile(STATEFILE, GOLDEN)
    if os.path.exists(NVMEM): shutil.copyfile(NVMEM, NVMEM_GOLD)
    vmuA1 = os.path.join(FCDATA, os.path.splitext(os.path.basename(DISC))[0] + "_vmu_save_A1.bin")
    if os.path.exists(vmuA1): shutil.copyfile(vmuA1, VMU_GOLD)
    hdr(G + "GOLDEN STATE SAVED" + X)
    say("state : %s (%d KB)" % (GOLDEN, os.path.getsize(GOLDEN)//1024))
    say("flash : %s" % (NVMEM_GOLD if os.path.exists(NVMEM_GOLD) else "(none)"))
    say("")
    say("now every  sudo python3 doom_demo_1.py  warm-boots straight to this state.")

# ------------------------------------------------------------------ main
def main():
    bake = "--bake" in sys.argv
    arm  = "--arm" in sys.argv
    cold = "--cold" in sys.argv
    have_armed = os.path.exists(ARMED) and not cold
    if os.geteuid() != 0:
        warn("needs root for :53/:80/:110 -- run:  sudo python3 doom_demo_1.py"); sys.exit(1)
    for f in (FLYCAST, DISC, MAGIC_F, STUB_F, DOOM_F, WAD_F, DNS_PY, MAIL_PY):
        if not os.path.exists(f):
            warn("missing required file: %s" % f); sys.exit(1)

    signal.signal(signal.SIGINT, cleanup)
    signal.signal(signal.SIGTERM, cleanup)
    ip = host_ip()

    hdr("DEF CON -- Dreamcast PlanetWeb  ->  email overflow  ->  native SH-4 DOOM")
    say("host IP   %s   (guest DNS points here)" % ip)
    say("disc      %s" % os.path.basename(DISC))
    say("golden    %s" % ("present" if have_golden() else "ABSENT -- run once with --bake"))
    say("armed     %s" % ("present (one-click demo)" if have_armed else "absent -- build with --arm"))
    if ip == "127.0.0.1":
        warn("HOST_IP resolved to loopback -- the guest can't reach that. Set HOST_IP=<lan ip>.")

    kill_stale()

    say("[1/4] DNS  : all names -> %s" % ip)
    procs.append(("dns", subprocess.Popen(
        [sys.executable, "-u", DNS_PY, ip, "--all", "--bind=" + ip],
        stdout=open("/tmp/demo_dns.log", "w"), stderr=subprocess.STDOUT)))
    time.sleep(1)

    say("[2/4] POP3 : DOOM-STAGE overflow mail on :110")
    procs.append(("mail", subprocess.Popen(
        [sys.executable, "-u", MAIL_PY, "--pop", "110"],
        stdout=open("/tmp/demo_mail.log", "w"), stderr=subprocess.STDOUT)))
    time.sleep(1)

    say("[3/4] WEB  : splash page on :80 (%s)" % WWW)
    start_web(ip)

    if bake:
        bake_state(ip)
        cleanup()

    if arm:
        arm_state(ip)
        cleanup()

    # ---- ARMED fast path: payload already frozen in the state; just click the email ----
    if have_armed:
        say("[4/4] EMU  : warm-booting the ARMED state (payload pre-staged)")
        shutil.copyfile(ARMED, STATEFILE)
        if os.path.exists(ARMED_NVMEM): shutil.copyfile(ARMED_NVMEM, NVMEM)
        launch_flycast(ip, force_armed=True)
        if not wait_gdb():
            warn("GDB stub never came up on :%d" % GDB_PORT); cleanup()
        blob_ok, stub_ok = verify_staged()
        say("payload check: blob %s  stub %s" % ("OK" if blob_ok else "MISSING",
                                                 "OK" if stub_ok else "MISSING"))
        if blob_ok and stub_ok:
            hdr(Y + B + "READY -- CLICK THE DOOM-STAGE EMAIL. That's it." + X)
            say("payload is already staged in the restored RAM; opening the message fires")
            say("the overflow -> stub @0x%08X -> native SH-4 DOOM. No staging, no wait." % STUB_ADDR)
        else:
            hdr(R + "armed state did not restore the payload -- falling back to live staging" + X)
            say("open nothing yet; use Check Mail below to re-stage, or rebuild with --arm.")
        say("")
        say("proof shot once DOOM is up (another terminal): python3 fb_capture.py proof.png")
        say(B + "Ctrl-C here stops everything." + X)
        if blob_ok and stub_ok:
            signal.pause()
        # else fall through to the live-staging flow below

    say("[4/4] EMU  : launching the Dreamcast (%s)" % ("COLD -- fresh render" if cold else "warm" if have_golden() else "cold"))
    warm = have_golden() and not cold
    launch_flycast(ip, cold=cold)
    if not wait_gdb():
        warn("GDB stub never came up on :%d" % GDB_PORT); cleanup()
    say("emulator up, GDB stub ready")

    if warm:
        hdr("STEP 1 -- browser is already online (warm boot)")
        say("the golden state restored the browser online, on the splash page. If the")
        say("connection went stale across the load, a Check Mail below re-opens it.")
    else:
        hdr("STEP 1 -- TAKE THE BROWSER ONLINE")
        say(B + "A x3 -> Start -> web browser." + X + "  Let it connect (splash page loads).")
        if cold:
            say("(cold boot renders fresh -- no black screen. Your mail account is already")
            say(" configured from the golden flash, so just go online and Check Mail.)")

    # STEP 2: download the message but DON'T open it. We stage on the download, so the
    # staged blob (which lives in JVM-heap RAM and gets overwritten by browsing churn)
    # is only exposed for the couple of seconds between download and open. Staging at
    # page-load -- with the mail download and your click still to come -- was what let
    # the blob get clobbered and the stub fall through to 0x8C29B860.
    hdr("STEP 2 -- CHECK MAIL, then SELECT the DOOM-STAGE message")
    say(B + "Mail -> Check Mail." + X + "  Then click the message once to PREVIEW it.")
    say("(previewing sends POP3 TOP -- we stage on that, before you open it. Opening the")
    say(" 315-byte message renders instantly, faster than staging, so TOP is the trigger.)")
    say("waiting for you to preview the message...")
    fetched = threading.Event()
    threading.Thread(target=lambda: (sys.stdin.readline(), fetched.set()), daemon=True).start()
    armed = False
    while not fetched.is_set():
        try:
            log = open("/tmp/demo_mail.log", errors="ignore").read()
            # stage on TOP (preview, precedes RETR with think-time) or RETR (open;
            # mail_poc delays the body so staging still lands). Match RECEIVED cmds.
            if "b'TOP" in log or "b'RETR" in log:
                break
        except Exception:
            pass
        if not armed and (online_evt.is_set()):
            armed = True
            say("(browser online -- Check Mail, then preview the message; or press Enter to stage)")
        time.sleep(0.3)
    say(G + "mail client is fetching the message." + X + "  staging the payload now...")

    if not stage():
        warn("staging/verification failed -- do NOT open the email. Re-run the demo.")
        say("(leaving everything up so you can inspect; Ctrl-C to stop)")
        signal.pause()

    hdr(Y + B + "READY -- OPEN THE DOOM-STAGE MESSAGE NOW  (within a few seconds!)" + X)
    say("open it promptly -- the staged blob is in JVM-heap RAM and browser activity")
    say("can overwrite it. On open: saved PR -> 0x%08X -> the stub relocates the WAD +" % STUB_ADDR)
    say("engine and jumps into native SH-4 DOOM.")
    say("")
    say("proof shot once DOOM is up (another terminal): python3 fb_capture.py proof.png")
    say(B + "Ctrl-C here stops everything." + X)
    signal.pause()

if __name__ == "__main__":
    main()

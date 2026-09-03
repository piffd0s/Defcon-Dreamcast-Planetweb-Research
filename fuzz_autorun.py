#!/usr/bin/env python3
"""
fuzz_autorun.py -- UNATTENDED browser parser fuzzer.

Uses the online-savestate /rp loop in fuzz mode (eden RPFUZZ marker: fresh mutated
image per page). Watches eden's request flow; when it stalls (the browser crashed
or hung on a malformed image), it:
  1. attributes the culprit (last /fuzz/ff_* served before the stall),
  2. saves the culprit + recent samples + flycast.log to crashes/auto_<ts>/,
  3. runs fc_restore.sh to bring the browser back online (~2s, no boot combo),
and continues -- looping indefinitely, accumulating distinct crashers.

Run:  cd poc && setsid python3 -u fuzz_autorun.py >/tmp/fuzz_autorun.log 2>&1 &
Watch: tail -f /tmp/fuzz_autorun.log   (and crashes/auto_*/)
Stop:  kill <pid>   (by PID -- never pkill -f, it self-kills the shell)
"""
import os, re, time, glob, shutil, subprocess, signal, sys

ROOT = "/media/adversary/Storage/dc_browser_extract"
EDEN = ROOT + "/emu/eden.log"
FC   = "/tmp/fc_conn.log"
FZ   = ROOT + "/poc/www/fuzz"
CRASH= ROOT + "/poc/crashes"
RESTORE = ROOT + "/poc/fc_restore.sh"

STALL_SECS = 14       # no new eden request for this long => crash/hang
POLL = 2

def eden_text():
    try: return open(EDEN, errors="replace").read()
    except: return ""

def flycast_alive():
    try: return bool(subprocess.check_output("ps -eo comm|grep -i flycast", shell=True))
    except: return False

def fc_fatal():
    try:
        t = open(FC, errors="replace").read()
        return ("SH4 exception" in t) or ("has stopped" in t)
    except: return False

def last_culprit(t):
    m = re.findall(r"GET /fuzz/(ff_\d+[\w]*\.\w+)", t)
    return m[-1] if m else None

def save_crash(kind, culprit, n):
    ts = time.strftime("%Y%m%d_%H%M%S")
    d = "%s/auto_%s_%s" % (CRASH, ts, kind)
    os.makedirs(d, exist_ok=True)
    # FIRST: copy the EXACT culprit by name (attribution-correct), before the
    # live fuzzer's retention cleanup deletes it.
    if culprit:
        cf = os.path.join(FZ, culprit)
        if os.path.exists(cf):
            try: shutil.copy(cf, d + "/CULPRIT_" + culprit)
            except: pass
        else:
            with open(d + "/CULPRIT_MISSING.txt", "w") as f:
                f.write("culprit %s already rotated out of %s\n" % (culprit, FZ))
    # plus a window of recent served samples (by numeric order, not lexical)
    def keynum(p):
        m = re.search(r"ff_(\d+)", p); return int(m.group(1)) if m else 0
    for f in sorted(glob.glob(FZ + "/ff_*"), key=keynum)[-12:]:
        try: shutil.copy(f, d)
        except: pass
    try: shutil.copy(FC, d + "/flycast.log")
    except: pass
    with open(d + "/INFO.txt", "w") as f:
        f.write("kind=%s\nculprit=%s\ncrash#=%d\ntime=%s\n" % (kind, culprit, n, ts))
    print("  saved -> %s  (culprit=%s)" % (d, culprit))
    return d

def restore():
    print("  restoring online state (fc_restore.sh)...")
    try:
        r = subprocess.run(["bash", RESTORE], capture_output=True, text=True, timeout=90)
        print("  " + (r.stdout.strip() or r.stderr.strip()[:200]))
        return r.returncode == 0
    except Exception as e:
        print("  restore error:", e); return False

def main():
    print("=== fuzz_autorun start", time.strftime("%H:%M:%S"), "===")
    prev = -1; stall = 0; crashes = 0
    while True:
        t = eden_text(); reqs = t.count("HTTP/1")
        if reqs != prev:
            prev = reqs; stall = 0
        else:
            stall += POLL
        alive = flycast_alive(); fatal = fc_fatal()
        # recover on: death/fault; a stall WITH activity (reqs>0); OR a long stall
        # even with reqs==0 (browser frozen making no requests -> e.g. deep-nest JS hang).
        crashed = (not alive) or fatal or (stall >= STALL_SECS and reqs > 0) or (stall >= STALL_SECS * 3)
        if crashed:
            kind = "FAULT" if (fatal or not alive) else "HANG"
            culprit = last_culprit(t)
            if culprit is None and alive and not fatal:
                # transient resume/nav stall (no image attributed) -> recover, don't log a bogus crash
                print("[%s] transient stall (no culprit) -> restoring" % time.strftime("%H:%M:%S"))
                restore(); time.sleep(3); prev = -1; stall = 0; continue
            crashes += 1
            print("[%s] CRASH #%d (%s) reqs=%d stall=%ds culprit=%s" %
                  (time.strftime("%H:%M:%S"), crashes, kind, reqs, stall, culprit))
            save_crash(kind, culprit, crashes)
            restore()
            # reset baseline: eden.log is fresh after restore
            time.sleep(3); prev = -1; stall = 0
            continue
        with open("/tmp/fuzz_autorun_status.txt", "w") as f:
            f.write("t=%s reqs=%d stall=%ds crashes=%d alive=%s\n" %
                    (time.strftime("%H:%M:%S"), reqs, stall, crashes, alive))
        time.sleep(POLL)

if __name__ == "__main__":
    try: main()
    except KeyboardInterrupt: print("stopped")

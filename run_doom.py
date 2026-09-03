#!/usr/bin/env python3
"""One-shot launcher for the native-DOOM exploit chain.

Deploys (optional), starts the rogue Eden server, boots a fresh browser, then watches
the staging and tells you EXACTLY when to open the DOOM-STAGE email.

Usage:
    python3 run_doom.py            # start eden + boot flycast + watch
    python3 run_doom.py --build    # rebuild jar+stub first (deploy.sh)
    python3 run_doom.py --native   # rebuild native doom.bin too (rebuild_doom.sh)
    python3 run_doom.py --no-boot  # don't reboot flycast (use the running one)

You still drive the console: go ONLINE in the browser and stay on the web-browser page;
when this prints 'READY' (and beeps), open the DOOM-STAGE email.
"""
import subprocess, time, re, sys, os, argparse

# macOS port: resolve the repo from this file instead of the old Linux mount.
POC = os.path.dirname(os.path.abspath(__file__))
MAC = os.path.join(POC, "mac")
LOG = "/tmp/eden_stagedoom.log"

def sh(script, *args):
    print("[*] running %s ..." % script)
    # the macOS versions of these live in mac/
    path = os.path.join(MAC, script)
    if not os.path.exists(path):
        path = os.path.join(POC, script)
    subprocess.run(["bash", path, *args], check=False)

def read_log():
    try:
        return open(LOG, "r", errors="ignore").read()
    except Exception:
        return ""

def count(pat, text=None):
    return (text if text is not None else read_log()).count(pat)

def progress(text):
    """Track each staged file separately: {total_bytes: max_end_seen}.
    doom.bin (~418 KB) and the WAD (~3.4 MB) chunk-interleave, so keying by /total
    keeps their bars independent instead of jumping when the file switches."""
    seen = {}
    for m in re.finditer(r"\[CHUNK\] \d+-(\d+)/(\d+)", text):
        end, tot = int(m.group(1)), int(m.group(2))
        if tot:
            seen[tot] = max(seen.get(tot, 0), end)
    return seen

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--build", action="store_true", help="rebuild jar+stub (deploy.sh)")
    ap.add_argument("--native", action="store_true", help="rebuild native doom too (rebuild_doom.sh)")
    ap.add_argument("--no-boot", action="store_true", help="don't reboot flycast")
    args = ap.parse_args()

    if args.native:
        sh("rebuild_doom.sh")
    elif args.build:
        sh("deploy.sh")
    sh("start_eden.sh", "stagedoom")
    if not args.no_boot:
        # macOS equivalent of fc_clean_boot.sh: boot a fresh browser with no
        # savestate autoload, so the StageDoom chain runs in order from scratch.
        sh("flycast.sh", "--clean")

    text = read_log()
    base_staged = count("staged doom=", text)
    base_stub = count("GET /stub.bin", text)

    print("\n" + "=" * 64)
    print("  GO ONLINE in the browser now -- stay on the WEB BROWSER page.")
    print("  Do NOT open the mail yet. I'll tell you when.")
    print("=" * 64 + "\n")

    staged = False
    last = ""
    t0 = time.time()
    def status(line):
        nonlocal last
        if line != last:
            pad = " " * max(0, len(last) - len(line))
            sys.stdout.write("\r" + line + pad); sys.stdout.flush()
            last = line
    try:
        while True:
            time.sleep(2)
            text = read_log()

            # authoritative completion signals (count-based, can't be missed)
            if not staged and count("staged doom=", text) > base_staged:
                staged = True
                sys.stdout.write("\r" + " " * 80 + "\r")
                print("[+] blob STAGED (complete). planting stub @0x8C29ADE8 ...")
            if staged and count("GET /stub.bin", text) > base_stub:
                print("\n" + "#" * 64)
                print("#")
                print("#   ✅  READY  --  OPEN THE  'DOOM-STAGE'  EMAIL NOW")
                print("#       (open it promptly; native DOOM will launch)")
                print("#")
                print("#" * 64)
                sys.stdout.write("\a"); sys.stdout.flush()
                time.sleep(0.3); sys.stdout.write("\a"); sys.stdout.flush()
                return

            # live phase/status (only meaningful before staged)
            if not staged:
                seen = progress(text)
                if seen:
                    parts = []
                    for tot in sorted(seen):
                        nm = "doom" if tot < 1000000 else "WAD"
                        parts.append("%s %3d%%" % (nm, 100 * seen[tot] // tot))
                    overall = 100 * sum(seen.values()) // sum(seen)   # sum of totals
                    fill = overall * 25 // 100
                    bar = "#" * fill + "-" * (25 - fill)
                    status("  staging [%s] %3d%%  (%s)" % (bar, overall, " · ".join(parts)))
                elif count("pwn.jar", text) > 0:
                    status("  chain loaded (pwn.jar) -- StageDoom starting the download...")
                else:
                    status("  waiting: go ONLINE in the browser, stay on the web page (no requests yet)...")

            if time.time() - t0 > 900:
                print("\n[!] timeout (15 min) -- no full staging. Is the browser online on the web-browser page?")
                return
    except KeyboardInterrupt:
        print("\n[*] stopped watching (eden + flycast still running).")

if __name__ == "__main__":
    main()

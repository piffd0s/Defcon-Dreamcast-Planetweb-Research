#!/usr/bin/env python3
"""Persistent fuzz monitor. Runs forever; watches eden + flycast logs and writes
a live status to /tmp/fuzz_status.txt (+ event log /tmp/fuzz_events.log). Reads
eden's log even if the file was unlinked (via /proc/<pid>/fd/1)."""
import os, re, time, glob, subprocess, shutil

ROOT="/media/adversary/Storage/dc_browser_extract"
EDEN=ROOT+"/emu/eden.log"; FC="/tmp/fc_conn.log"
STATUS="/tmp/fuzz_status.txt"; EVENTS="/tmp/fuzz_events.log"
PORT=open(ROOT+"/emu/edenport").read().strip()
FZ=ROOT+"/poc/www/fuzz"; CRASH=ROOT+"/poc/crashes"

def eden_pid():
    try:
        out=subprocess.check_output("ss -ltnp 2>/dev/null|grep ':%s '"%PORT,shell=True).decode()
        m=re.search(r"pid=(\d+)",out); return m.group(1) if m else None
    except: return None

def eden_text():
    # prefer real file; if empty/missing, read live via /proc (unlinked log)
    try:
        t=open(EDEN,errors="replace").read()
        if t.strip(): return t
    except: pass
    p=eden_pid()
    if p:
        try: return open("/proc/%s/fd/1"%p,errors="replace").read()
        except: pass
    return ""

def flycast_alive():
    try: return bool(subprocess.check_output("ps -eo comm|grep -i flycast",shell=True))
    except: return False

def fc_fault():
    try:
        t=open(FC,errors="replace").read()
        for kw in ("SH4 exception","Fatal","has stopped","Unhandled","SIGSEGV"):
            if kw in t:
                for ln in t.splitlines():
                    if kw in ln: return ln.strip()
        return None
    except: return None

def cur_marker(t):
    # current spectrum index or fuzz batch
    sp=re.findall(r"\[spectrum\] >>> #(\d+)/(\d+) : (\S+)", t)
    if sp: return ("spectrum", sp[-1][0], sp[-1][2])
    fb=re.findall(r"GET /fz/n?(\d+)", t)
    if fb: return ("fuzz", fb[-1], "")
    img=re.findall(r"GET /fuzz/(ff_\d+\.\w+)", t)
    if fb: return ("fuzz", fb[-1], img[-1] if img else "")
    g=re.findall(r"GET (/sp/\d+|/fz/\S+|/fuzz/\S+)", t)
    return ("?", g[-1] if g else "-", img[-1] if img else "")

def ev(msg):
    open(EVENTS,"a").write(time.strftime("%H:%M:%S ")+msg+"\n")

def main():
    ev("monitor start")
    last=None; stall=0; reqs_prev=0; faulted=False
    while True:
        t=eden_text(); reqs=t.count("HTTP/1")
        mode,idx,name=cur_marker(t)
        alive=flycast_alive(); fault=fc_fault()
        # state machine
        if fault or (not alive):
            state="FAULT"
            if not faulted:
                faulted=True
                cd=CRASH+"/fault_%s_%s"%(mode,idx); os.makedirs(cd,exist_ok=True)
                for f in glob.glob(FZ+"/ff_*")+glob.glob(FZ+"/d_*"):
                    try: shutil.copy(f,cd)
                    except: pass
                try: shutil.copy(FC,cd+"/flycast.log")
                except: pass
                ev("*** FAULT *** mode=%s idx=%s name=%s  detail=%s  saved=%s"%(mode,idx,name,fault or "flycast-exited",cd))
        elif reqs==reqs_prev and reqs>0:
            stall+=1
            state="STALL(%ds)"%(stall*2)
            if stall==4: ev("HANG suspected at %s idx=%s name=%s (no requests ~8s)"%(mode,idx,name))
        else:
            state="ADVANCING"
            if (mode,idx)!=last and idx!="-": ev("%s -> idx=%s %s (reqs=%d)"%(mode,idx,name,reqs))
            stall=0
        last=(mode,idx); reqs_prev=reqs
        with open(STATUS,"w") as f:
            f.write("t=%s  state=%s  mode=%s idx=%s name=%s  reqs=%d  flycast=%s\n"
                    %(time.strftime("%H:%M:%S"),state,mode,idx,name,reqs,"up" if alive else "DOWN"))
            f.write("recent eden:\n"+ "\n".join("  "+l for l in t.splitlines()[-8:]))
        time.sleep(2)

if __name__=="__main__":
    main()

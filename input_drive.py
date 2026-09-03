#!/usr/bin/env python3
"""
input_drive.py -- drive the PlanetWeb browser past its boot screen and into the
web browser via synthetic input to the Flycast window. Flycast keyboard map:
  DC A     = X key      (scancode 27)
  DC Start = Return     (scancode 40)
  DC DPad  = arrow keys
Usage: python3 input_drive.py <sequence>   e.g.  "A A A START RIGHT A"
       python3 input_drive.py keepalive    # one gentle input to defeat screensaver
"""
import sys, time
from Xlib import display, X, XK
from Xlib.ext import xtest

import os as _os
D = display.Display(_os.environ.get("FC_DISPLAY", ":10"))
root = D.screen().root
NETPID = D.intern_atom('_NET_WM_PID')

KEYS = {"A":XK.XK_x, "B":XK.XK_c, "X":XK.XK_s, "Y":XK.XK_d, "START":XK.XK_Return,
        "UP":XK.XK_Up, "DOWN":XK.XK_Down, "LEFT":XK.XK_Left, "RIGHT":XK.XK_Right}

def flycast_window():
    def walk(w):
        out=[]
        try:
            for c in w.query_tree().children: out.append(c); out+=walk(c)
        except: pass
        return out
    import subprocess
    pid=int(subprocess.check_output("ps -eo pid,comm|awk '$2~/[Ff]lycast/{print $1}'|head -1",shell=True) or 0)
    for w in walk(root):
        try:
            p=w.get_full_property(NETPID,0); g=w.get_geometry()
            if p and pid in list(p.value) and g.width>=200: return w
        except: pass
    return None

def focus(w):
    try:
        w.configure(stack_mode=X.Above); w.map()
        w.set_input_focus(X.RevertToParent, X.CurrentTime); D.sync()
    except Exception as e: print("focus warn:", e)

def tap(name, hold=0.06):
    ks = KEYS[name]; kc = D.keysym_to_keycode(ks)
    xtest.fake_input(D, X.KeyPress, kc); D.sync(); time.sleep(hold)
    xtest.fake_input(D, X.KeyRelease, kc); D.sync()

def main():
    w = flycast_window()
    if not w: print("no flycast window"); return
    if sys.argv[1:] == ["keepalive"]:
        focus(w); tap("DOWN"); time.sleep(0.1); tap("UP"); print("keepalive sent"); return
    focus(w); time.sleep(0.3)
    for tok in sys.argv[1:]:
        t = tok.upper()
        if t.isdigit():           # a delay token like "1500" ms
            time.sleep(int(t)/1000.0); continue
        if t in KEYS:
            tap(t); print("sent", t); time.sleep(0.5)
        else: print("unknown token", tok)

if __name__ == "__main__":
    main()

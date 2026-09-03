#!/usr/bin/env python3
"""fc_snapshot.py -- send F2 (btn_quick_save) to the running Flycast to save a
state of the CURRENT (e.g. online + looping) session, then copy it to the golden
backup used by fc_restore.sh. Requires the patched Flycast (savestate allowed
while online) and the F2->btn_quick_save keybind.
Usage: python3 fc_snapshot.py [--no-backup]"""
import os, sys, time, shutil
os.environ.setdefault("XAUTHORITY", "/home/adversary/.Xauthority")
ROOT = "/media/adversary/Storage/dc_browser_extract"
STATE = ROOT + "/emu/fchome/.local/share/flycast/Internet Browser V3.0 for Dreamcast (USA).state"
GOLD  = ROOT + "/emu/online_looping.state.backup"

sys.path.insert(0, ROOT + "/poc")
from Xlib import X, XK
from Xlib.ext import xtest
import input_drive as idv

def main():
    before = os.path.getmtime(STATE) if os.path.exists(STATE) else 0
    w = idv.flycast_window()
    if not w:
        print("no flycast window"); return 1
    idv.focus(w); time.sleep(0.4)
    kc = idv.D.keysym_to_keycode(XK.XK_F2)
    xtest.fake_input(idv.D, X.KeyPress, kc); idv.D.sync(); time.sleep(0.1)
    xtest.fake_input(idv.D, X.KeyRelease, kc); idv.D.sync()
    print("sent F2 (quick_save)")
    for _ in range(20):
        time.sleep(0.3)
        if os.path.exists(STATE) and os.path.getmtime(STATE) > before:
            sz = os.path.getsize(STATE)
            print("savestate written: %d bytes" % sz)
            if "--no-backup" not in sys.argv:
                shutil.copy(STATE, GOLD)
                print("copied to golden backup:", GOLD)
            return 0
    print("WARN: savestate file did not update (online savestate patch missing?)")
    return 1

if __name__ == "__main__":
    raise SystemExit(main())

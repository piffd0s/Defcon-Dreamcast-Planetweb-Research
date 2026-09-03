#!/usr/bin/env bash
# class_fuzz_campaign.sh -- unattended PersonalJava class-PARSER fuzzing via the
# GDB-stub in-process harness, with auto-recover. Each cycle:
#   1. boot a fresh flycast (golden online savestate, applet-only REPRO so a class
#      parse is guaranteed for capture)
#   2. class_fuzz_gdb.py capture   (snapshot loader/buf; dry-run validates)
#   3. class_fuzz_gdb.py fuzz N    (in-process: mutate class, re-invoke parser,
#      classify RETURN / FAULT@vec / DEAD; saves culprits to crashes/classfuzz_*)
#   4. when a fatal class kills flycast (DEAD), loop -> reboot + re-capture.
# Stop:  kill <pid-of-this-script>   (by PID; never pkill -f a script name -> self-kill)
set -u
ROOT=/media/adversary/Storage/dc_browser_extract
POC=$ROOT/poc
FCH=$ROOT/emu/fchome/.local/share/flycast
FC=$ROOT/src-build/flycast-src/build/flycast
GDI="$ROOT/Internet Browser V3.0 for Dreamcast (USA).gdi"
PERCYCLE=${1:-4000}        # max iterations per boot before voluntary recycle

cd "$POC"
# arm applet-only so capture always has a class parse to catch
rm -f www/RPFUZZ www/repro/*; cp classfuzz/valid.jar www/repro/0_valid.jar

cycle=0
while true; do
  cycle=$((cycle+1))
  echo "===== class-fuzz cycle $cycle $(date +%H:%M:%S) ====="
  # fresh flycast (kill ALL by numeric pid from comm match -- not our cmdline)
  for p in $(ps -eo pid,comm | awk '$2~/[Ff]lycast/{print $1}'); do kill -9 "$p" 2>/dev/null; done
  sleep 2
  cp "$ROOT/emu/online_looping.state.backup" "$FCH/Internet Browser V3.0 for Dreamcast (USA).state"
  : > /tmp/fc_conn.log
  HOME="$ROOT/emu/fchome" XAUTHORITY=/home/adversary/.Xauthority DISPLAY=:10 \
    setsid "$FC" "$GDI" >/tmp/fc_conn.log 2>&1 &
  # wait for the GDB stub
  up=0; for i in $(seq 1 30); do ss -ltnp 2>/dev/null | grep -q ':3263 ' && { up=1; break; }; sleep 1; done
  [ "$up" = 1 ] || { echo "stub never came up; retry"; continue; }
  # capture (connect during boot so bp is set before the applet's class parse)
  python3 -u class_fuzz_gdb.py capture >/tmp/classcap.log 2>&1
  if ! grep -q 'RETURN' /tmp/classcap.log; then
    echo "capture/dry-run failed this cycle:"; tail -3 /tmp/classcap.log; continue
  fi
  echo "capture OK -> fuzzing up to $PERCYCLE"
  python3 -u class_fuzz_gdb.py fuzz "$PERCYCLE" >>/tmp/classfuzz.log 2>&1
  echo "cycle $cycle done; faults so far: $(ls -d crashes/classfuzz_* 2>/dev/null | wc -l)"
done

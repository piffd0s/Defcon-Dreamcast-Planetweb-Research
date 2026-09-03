#!/usr/bin/env bash
# fc_restore.sh -- relaunch Flycast straight back into the ONLINE, looping browser
# state, with NO manual boot+connect combo. Uses the patched Flycast (savestate
# allowed while networking is online) + AutoLoadState=yes + a golden savestate.
#
# Use after a crash (the fuzz fault kills Flycast): just run this and the browser
# is back online and fuzzing within ~5s.
set -u
ROOT=/media/adversary/Storage/dc_browser_extract
FC="$ROOT/src-build/flycast-src/build/flycast"
GDI="$ROOT/Internet Browser V3.0 for Dreamcast (USA).gdi"
FCH="$ROOT/emu/fchome/.local/share/flycast"
GOLD="$ROOT/emu/online_looping.state.backup"
CFG="$ROOT/emu/fchome/.config/flycast/emu.cfg"

# 1) ensure NO Flycast is running (kill ALL by PID, never -f; force if needed)
for p in $(ps -eo pid,comm | awk '$2~/[Ff]lycast/{print $1}'); do kill "$p" 2>/dev/null; done
sleep 2
for p in $(ps -eo pid,comm | awk '$2~/[Ff]lycast/{print $1}'); do kill -9 "$p" 2>/dev/null; done
sleep 1

# 2) restore the golden online savestate (Flycast loads <game>.state for slot 0)
cp "$GOLD" "$FCH/Internet Browser V3.0 for Dreamcast (USA).state"

# 3) Flycast rewrites emu.cfg on clean exit -> re-assert AutoLoadState while stopped
sed -i 's/Dreamcast.AutoLoadState = no/Dreamcast.AutoLoadState = yes/' "$CFG"

# 4) fresh logs + launch (ROOT cwd for real BIOS; display :10)
#    CLEAR eden.log too, so the success check (and the orchestrator's stall
#    detection) only sees NEW requests -- not stale pre-crash entries.
: > /tmp/fc_conn.log
: > "$ROOT/emu/eden.log"
HOME="$ROOT/emu/fchome" XAUTHORITY=/home/adversary/.Xauthority DISPLAY=:10 \
  setsid "$FC" "$GDI" >/tmp/fc_conn.log 2>&1 &

# 5) wait for the auto-loaded online loop to come back (a GENUINE new request)
for i in $(seq 1 20); do
  sleep 2
  n=$(grep -cE 'fuzz/ff_|/rp/n|repro/' "$ROOT/emu/eden.log" 2>/dev/null); n=${n:-0}
  if grep -qi 'Loaded state' /tmp/fc_conn.log && [ "$n" -ge 1 ]; then
    echo "online loop restored (no combo) after $((i*2))s"; exit 0
  fi
done
echo "WARN: did not confirm online loop in 40s; check /tmp/fc_conn.log + eden.log"
exit 1

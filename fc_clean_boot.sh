#!/usr/bin/env bash
# fc_clean_boot.sh -- boot Flycast into a FRESH browser (no savestate autoload), so the
# Eden stagedoom chain (StageDoom v2: stage blob -> plant stub @0x8C29ADE8) runs in
# order from scratch. The user then connects (dialup) and opens the DOOM-STAGE email.
set -u
ROOT=/media/adversary/Storage/dc_browser_extract
FC="$ROOT/src-build/flycast-src/build/flycast"
GDI="$ROOT/Internet Browser V3.0 for Dreamcast (USA).gdi"
FCH="$ROOT/emu/fchome/.local/share/flycast"
CFG="$ROOT/emu/fchome/.config/flycast/emu.cfg"

# 1) kill any running Flycast
for p in $(ps -eo pid,comm | awk '$2~/[Ff]lycast/{print $1}'); do kill "$p" 2>/dev/null; done
sleep 2
for p in $(ps -eo pid,comm | awk '$2~/[Ff]lycast/{print $1}'); do kill -9 "$p" 2>/dev/null; done
sleep 1

# 2) disable savestate autoload + remove golden state -> clean boot
sed -i 's/Dreamcast.AutoLoadState = yes/Dreamcast.AutoLoadState = no/' "$CFG"
rm -f "$FCH/Internet Browser V3.0 for Dreamcast (USA).state"

# 3) launch fresh (ROOT cwd for real BIOS path; display :10)
: > /tmp/fc_conn.log
HOME="$ROOT/emu/fchome" XAUTHORITY=/home/adversary/.Xauthority DISPLAY=:10 \
  setsid "$FC" "$GDI" >/tmp/fc_conn.log 2>&1 &

sleep 8
echo "flycast pid: $(ps -eo pid,comm | awk '$2~/[Ff]lycast/{print $1}' | head -1)"
grep -aE "RAM\(16|Game ID|reios|picoppp" /tmp/fc_conn.log | tail -4

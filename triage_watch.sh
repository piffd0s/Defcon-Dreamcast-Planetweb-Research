#!/usr/bin/env bash
ROOT=/media/adversary/Storage/dc_browser_extract
ED=$ROOT/emu/eden.log; FC=/tmp/fc_conn.log
cur(){ grep -oE "\[spectrum\] >>> #[0-9]+/[0-9]+ : [0-9]+_cs[0-9]+_[a-z]+\.gif" "$ED" 2>/dev/null | tail -1; }
lastn=-1; stall=0
for i in $(seq 1 240); do   # ~20 min
  sleep 5
  c="$(cur)"; n=$(echo "$c"|grep -oE "#[0-9]+"|tr -d '#')
  if grep -qiE "exception|fatal|has stopped" "$FC" 2>/dev/null; then
    echo "*** FAULT (overflow candidate) while serving: ${c:-?} ***"
    grep -iE "exception|fatal|pc|spc|expevt|tea|address" "$FC" | tail -6
    cp "$FC" "$ROOT/poc/crashes/lzw_fault_fc.log"
    exit 0
  fi
  if [ -n "$n" ] && [ "$n" = "$lastn" ]; then
    stall=$((stall+1))
    if [ $stall -ge 5 ]; then echo ">>> HANG on: $c  (frozen ~25s, no advance, no fault)"; echo "    (reboot + start past this index to test the rest)"; exit 0; fi
  else
    [ -n "$n" ] && echo "[$((i*5))s] advancing: $c"
    lastn=$n; stall=0
  fi
done
echo "window ended at: $(cur)"

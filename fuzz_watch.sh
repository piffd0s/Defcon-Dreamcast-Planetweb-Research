#!/usr/bin/env bash
# continuous browser-parser fuzz watcher: tracks batches/images decoded, detects
# SH4 decoder crash, saves the suspect batch on crash.
ROOT=/media/adversary/Storage/dc_browser_extract
EDEN=$ROOT/emu/eden.log; FC=/tmp/fc_conn.log
last=0
for i in $(seq 1 600); do   # ~50 min @5s
  sleep 5
  batches=$(grep -c "GET /fz/" "$EDEN" 2>/dev/null)
  imgs=$(grep -c "/fuzz/d_" "$EDEN" 2>/dev/null)
  if grep -qiE "exception|fatal|stopped" "$FC" 2>/dev/null; then
    bid=$(grep -o "d_[0-9]*_" "$EDEN" | tail -1 | tr -d 'd_')
    cd=$ROOT/poc/crashes/crash_$(printf %05d ${bid:-0})
    mkdir -p "$cd"
    cp $ROOT/poc/www/fuzz/d_$(printf %05d ${bid:-0})_* "$cd"/ 2>/dev/null
    cp "$FC" "$cd"/flycast.log
    grep "/fuzz/d_" "$EDEN" | tail -12 > "$cd"/last_images.txt
    echo "*** CRASH after $batches batches / $imgs images decoded ***"
    echo "*** suspect batch d_$(printf %05d ${bid:-0})_* saved -> $cd ***"
    grep -iE "exception|fatal|stopped" "$FC" | tail -1
    exit 0
  fi
  if [ "$batches" != "$last" ]; then echo "[$((i*5))s] $batches batches / $imgs mutated images decoded (no crash)"; last=$batches; fi
done
echo "watch ended (no crash in window); $batches batches / $imgs images"

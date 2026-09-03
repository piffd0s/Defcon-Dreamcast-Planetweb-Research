#!/usr/bin/env bash
# start_eden.sh -- (re)start the Eden MITM server on the stagedoom chain.
# eden serves the service jar fresh from disk per request, so this also picks up
# a freshly-rebuilt pwn_stagedoom.jar. Restart is needed when eden_mitm.py itself
# changed (e.g. new /heapdiag route).
ROOT=/media/adversary/Storage/dc_browser_extract
pkill -f "eden_mitm.py" 2>/dev/null
sleep 1
: > /tmp/eden_stagedoom.log
cd "$ROOT"
setsid python3 -u poc/eden_mitm.py --chain stagedoom -p 8137 >/tmp/eden_stagedoom.log 2>&1 </dev/null &
sleep 2
echo "eden pid: $(pgrep -f 'eden_mitm.py' | head -1)"
head -6 /tmp/eden_stagedoom.log

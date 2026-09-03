#!/usr/bin/env bash
# start_eden.sh -- (re)start the Eden MITM server for the native-DOOM chain.
#
# macOS port of the Linux start_eden.sh. Two differences:
#   - ROOT is derived from this script's location, not /media/adversary/Storage/...
#   - the Linux rig ran eden on :8137 with an iptables REDIRECT from :80. There is
#     no iptables here, so we bind :80 directly -- which needs sudo.
#
# eden serves the service jar fresh from disk per request, so this also picks up a
# freshly rebuilt pwn_stagedoom.jar.
set -u
source "$(dirname "$0")/env.sh"
CHAIN="${1:-stagedoom}"
LOG=/tmp/eden_stagedoom.log

# kill by PID, never `pkill -f eden_mitm.py` from a shell whose own cmdline
# contains that string (self-kill).
for pid in $(pgrep -f "eden_mitm.py" 2>/dev/null); do
  [ "$pid" = "$$" ] || sudo kill "$pid" 2>/dev/null || kill "$pid" 2>/dev/null
done
sleep 1

: > "$LOG"
chmod a+rw "$LOG" 2>/dev/null

SUDO=""
if [ "$EDEN_PORT" -lt 1024 ] && [ "$(id -u)" != "0" ]; then
  SUDO="sudo"
  echo "[*] binding :$EDEN_PORT needs root -- you may be prompted for your password"
fi

$SUDO python3 -u "$POC/eden_mitm.py" --chain "$CHAIN" -p "$EDEN_PORT" >"$LOG" 2>&1 &
sleep 2

pid=$(pgrep -f "eden_mitm.py" | head -1)
echo "eden pid: ${pid:-<none>}  chain=$CHAIN port=$EDEN_PORT"
head -6 "$LOG"
[ -z "${pid:-}" ] && { echo "!! eden failed to start -- see $LOG" >&2; exit 1; }
exit 0

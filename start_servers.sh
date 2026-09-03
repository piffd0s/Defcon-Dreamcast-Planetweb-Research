#!/usr/bin/env bash
# Privileged network plumbing for the Flycast attack run (the agent runs the
# Eden HTTP server itself on $PORT; this only does the parts that need root):
#   - rogue DNS on <IP>:53  (eden.planetweb.com -> <IP>)
#   - iptables REDIRECT <IP>:80 -> $PORT  (since :80 is occupied / unbindable)
# Usage: sudo bash start_servers.sh [IP] [PORT]
IP="${1:-192.168.1.11}"
PORT="${2:-8137}"
POC=/media/adversary/Storage/dc_browser_extract/poc
LOG=/media/adversary/Storage/dc_browser_extract/emu

pkill -f dns_redirect.py 2>/dev/null; sleep 1
setsid python3 "$POC/dns_redirect.py" "$IP" --all >"$LOG/dns.log" 2>&1 </dev/null &
sleep 1; chmod a+rw "$LOG/dns.log" 2>/dev/null

# redirect port 80 -> our Eden server on $PORT, scoped to our IP only.
# OUTPUT covers Flycast's usermode-NAT (host-local) connections; PREROUTING
# covers anything arriving via a bridge.
for CH in OUTPUT PREROUTING; do
  iptables -t nat -D $CH -p tcp -d "$IP" --dport 80 -j REDIRECT --to-ports "$PORT" 2>/dev/null
  iptables -t nat -A $CH -p tcp -d "$IP" --dport 80 -j REDIRECT --to-ports "$PORT"
done

echo "== DNS on $IP:53 (all names -> $IP); iptables :80 -> :$PORT installed =="
tail -2 "$LOG/dns.log"
echo "(stop later with: sudo bash $POC/stop_servers.sh $IP $PORT)"

#!/usr/bin/env bash
# Undo start_servers.sh. Usage: sudo bash stop_servers.sh [IP] [PORT]
IP="${1:-192.168.1.11}"; PORT="${2:-8137}"
pkill -f dns_redirect.py 2>/dev/null
for CH in OUTPUT PREROUTING; do
  iptables -t nat -D $CH -p tcp -d "$IP" --dport 80 -j REDIRECT --to-ports "$PORT" 2>/dev/null
done
echo "stopped DNS + removed iptables :80->:$PORT redirect"

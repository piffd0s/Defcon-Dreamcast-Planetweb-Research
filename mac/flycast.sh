#!/usr/bin/env bash
# flycast.sh -- boot the browser disc in the repo-local Flycast.
#
# Usage: mac/flycast.sh [--clean] [--no-net] [--bba|--modem] [extra flycast args...]
#   --clean   wipe the savestate so the browser boots from scratch
#   --no-net  don't enable the emulated network (offline boot / smoke test)
#   --bba     Broadband Adapter (default) -- guest gets DHCP, DNS handed via DHCP
#   --modem   dial-up modem over PPP instead
set -u
source "$(dirname "$0")/env.sh"

CLEAN=0; NET=1; ARGS=()
for a in "$@"; do
  case "$a" in
    --clean)  CLEAN=1 ;;
    --no-net) NET=0 ;;
    --bba)    NET_MODE=bba ;;
    --modem)  NET_MODE=modem ;;
    *) ARGS+=("$a") ;;
  esac
done

[ -x "$FC" ] || { echo "!! Flycast not built. Run: mac/build_flycast.sh" >&2; exit 1; }
[ -f "$DISC" ] || { echo "!! disc not found: $DISC" >&2; exit 1; }

mkdir -p "$FCDATA"

# Terminate gracefully. SIGKILL leaves macOS "crash history" behind, which makes
# the next launch hang on the modal "reopen windows?" alert before main() runs.
pkill -TERM -x Flycast 2>/dev/null; sleep 2; pkill -9 -x Flycast 2>/dev/null; sleep 1

# Suppress that state-restoration alert for good, in this repo-local HOME.
mkdir -p "$FCHOME/Library/Preferences"
rm -rf "$FCHOME/Library/Saved Application State/com.flyinghead.Flycast.savedState"
HOME="$FCHOME" defaults write com.flyinghead.Flycast ApplePersistenceIgnoreState -bool YES 2>/dev/null
HOME="$FCHOME" defaults write com.flyinghead.Flycast NSQuitAlwaysKeepsWindows -bool false 2>/dev/null

if [ "$CLEAN" = 1 ]; then
  rm -f "$FCDATA"/*.state
  echo "[*] cleared savestates (fresh browser boot)"
fi

NETCFG=()
if [ "$NET" = 1 ]; then
  # DCNet is ON by default and would route the guest through flyinghead's public
  # service; we need traffic to reach OUR Eden server, so turn it off and point
  # the guest's DNS at us.
  #
  # BBA (default): Flycast maps the RTL8139 and runs a DHCP server for the guest
  # (Dreamcast gets 192.168.169.2), handing out network:DNS as the DNS server.
  # Modem: same DNS value, delivered via pico_ppp_set_dns1() during PPP instead.
  # Either way the guest must route to us, so DNS is the LAN IP, never loopback.
  BBA=$([ "$NET_MODE" = "bba" ] && echo yes || echo no)
  NETCFG=(-config network:Enable=yes
          -config network:DCNet=no
          -config "network:EmulateBBA=$BBA"
          -config "network:DNS=$HOST_IP")
fi

echo "[*] disc   : $DISC"
echo "[*] home   : $FCHOME"
echo "[*] gdb    : port $GDB_PORT"
if [ "$NET" = 1 ]; then
  echo "[*] network: $([ "$NET_MODE" = bba ] && echo "Broadband Adapter (DHCP)" || echo "modem (PPP)"), DNS -> $HOST_IP"
else
  echo "[*] network: off"
fi

# Flycast has a startup race: the emulation thread can reach addrspace::initMappings()
# before the main thread's addrspace::reserve() has finished. It then sees a null
# ram_base, falls back to malloc'd RAM, and the ARM64 dynarec aborts immediately:
#
#   E[COMMON]: Verify Failed : &mem_b[0] == ((u8*)getContext()->sq_buffer + ...)
#     in Init -> core/hw/sh4/dyna/driver.cpp : 349
#
# Traced with instrumented builds -- the failing runs log, in this order:
#   initMappings ram_base=0x0  /  FALLBACK BRANCH TAKEN  /  reserve: virtmem::init
#
# Enabling the network widens the window a lot, presumably by starting more
# threads during boot: measured 0/5 failures with networking off, 5/10 with the
# Broadband Adapter on. It is unrelated to the disc image or to the JIT signature
# (it reproduces with a valid one).
#
# It is purely a startup race -- once past it the emulator is stable -- so the
# launcher detects the abort and relaunches. Ten attempts makes a failed launch
# about a one-in-a-thousand event even at the 50% per-attempt rate.
ATTEMPTS="${FLYCAST_ATTEMPTS:-10}"
FCPID=""
for attempt in $(seq 1 "$ATTEMPTS"); do
  : > "$FC_LOG"
  : > "$FCDATA/flycast.log"
  HOME="$FCHOME" "$FC" \
      -config log:LogToFile=yes \
      -config config:Debug.GDBEnabled=yes \
      -config "config:Debug.GDBPort=$GDB_PORT" \
      ${NETCFG[@]+"${NETCFG[@]}"} ${ARGS[@]+"${ARGS[@]}"} "$DISC" >"$FC_LOG" 2>&1 &
  FCPID=$!

  ok=""
  for _ in $(seq 1 30); do
    sleep 1
    if grep -q "Verify Failed" "$FCDATA/flycast.log" 2>/dev/null; then ok=no; break; fi
    if grep -q "Game ID" "$FCDATA/flycast.log" 2>/dev/null; then ok=yes; break; fi
    kill -0 "$FCPID" 2>/dev/null || { ok=no; break; }
  done

  if [ "$ok" = yes ]; then
    [ "$attempt" -gt 1 ] && echo "[*] (took $attempt attempts -- see the vmem note in mac/README_MACOS.md)"
    break
  fi

  echo "[!] attempt $attempt: dynarec RAM reservation failed, relaunching"
  kill -TERM "$FCPID" 2>/dev/null
  for _ in $(seq 1 10); do pgrep -x Flycast >/dev/null || break; sleep 1; done
  pkill -9 -x Flycast 2>/dev/null; sleep 1
  FCPID=""
done

if [ -z "$FCPID" ]; then
  echo "!! Flycast would not start in $ATTEMPTS attempts -- see $FCDATA/flycast.log" >&2
  exit 1
fi
echo "[*] flycast pid $FCPID  (stdout: $FC_LOG, emulator log: $FCDATA/flycast.log)"
grep -aE "Game ID|reios|nvmem is|Verify Failed|Invalid CUE|error" "$FCDATA/flycast.log" 2>/dev/null | head -8

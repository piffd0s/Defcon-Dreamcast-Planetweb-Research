#!/usr/bin/env bash
# env.sh -- shared paths for the macOS port. Source this, don't run it.
#
# The original rig was a Linux box rooted at /media/adversary/Storage/dc_browser_extract.
# Everything here is relative to the repo instead, so it moves with the folder.

POC="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ROOT="$POC"

# Emulator: built by mac/build_flycast.sh. Signed ad-hoc with JIT entitlements --
# without those the ARM64 dynarec cannot reserve its 512 MB window and Flycast
# aborts with "Verify Failed ... driver.cpp:349".
FLYCAST_SRC="$ROOT/src-build/flycast-src"
FLYCAST_APP="$FLYCAST_SRC/build/Flycast.app"
FC="$FLYCAST_APP/Contents/MacOS/Flycast"

# Per-repo Flycast home, so the demo never touches your personal Flycast config.
# On macOS Flycast uses $HOME/.flycast/ when it exists (else ~/Library/Application Support).
FCHOME="$ROOT/emu/fchome"
FCCFG="$FCHOME/.flycast/emu.cfg"
FCDATA="$FCHOME/.flycast/data"

# The browser disc: the proper 3-track GD-ROM dump this PoC was developed against
# (track 3 = high-density area at LBA 45000). .gdi loads in Flycast as-is.
DISC="${DISC:-$HOME/Downloads/Internet Browser V3.0 for Dreamcast (USA)/Internet Browser V3.0 for Dreamcast (USA).gdi}"

# Fallback: the ECHELON self-boot CD-R conversion in ~/Downloads/PlanetWeb 3.0.
# Same 1ST_READ.BIN, but its shipped PW3.CUE does NOT load (FILE precedes
# REM SESSION, and Flycast clears the FILE context on every REM) -- point DISC at
# the rewritten PW3_flycast.cue if you ever need it. See mac/README_MACOS.md.

# Rogue Eden server. Port 80 is the real Eden port and needs sudo on macOS;
# there is no iptables here, so we bind :80 directly rather than redirecting.
EDEN_PORT="${EDEN_PORT:-80}"
EDEN_LOG="${EDEN_LOG:-/tmp/eden.log}"
FC_LOG="${FC_LOG:-/tmp/flycast.log}"

# IP the guest should reach us on.
#
# This must NOT be 127.0.0.1. Flycast passes network:DNS to the guest via
# pico_ppp_set_dns1(), so the Dreamcast's own TCP/IP stack is what interprets it --
# and to the Dreamcast, 127.0.0.1 is its OWN loopback, so those packets never cross
# the PPP link. It has to be an address the guest routes outward, which picoppp
# then proxies through a host socket. The Mac's LAN IP is what works.
_default_if="$(route -n get default 2>/dev/null | awk '/interface:/{print $2}')"
HOST_IP="${HOST_IP:-$(ipconfig getifaddr "${_default_if:-en0}" 2>/dev/null)}"
HOST_IP="${HOST_IP:-127.0.0.1}"

GDB_PORT="${GDB_PORT:-3263}"

# Guest network adapter: "bba" (Broadband Adapter, RTL8139 + DHCP) or "modem" (PPP).
# BBA is the attack path this PoC was developed against.
NET_MODE="${NET_MODE:-bba}"

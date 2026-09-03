#!/usr/bin/env bash
# Back up the WORKING native-DOOM exploit chain (snapshot of the full PoC) into a
# timestamped tarball under poc/backups/.
set -e
ROOT=/media/adversary/Storage/dc_browser_extract
TS=$(date +%Y%m%d_%H%M%S)
DEST="$ROOT/poc/backups"
mkdir -p "$DEST"
OUT="$DEST/doom_working_$TS.tar.gz"

# manifest describing the working state
cat > "$ROOT/poc/BACKUP_README.md" <<'EOF'
# Working native-DOOM exploit chain (Dreamcast PlanetWeb v3.0) -- BACKUP

End-to-end PROVEN: unauth Eden RCE -> Java StageDoom -> native MIME name= overflow ->
native SH-4 DOOM running LIVE on the browser.

## Pieces
- poc/src/org/junkyard/StageDoom.java  : stages MAGIC+doom+wad over CHUNKED HTTP (?start=N&len=M,
  32KB chunks; MAGIC written LAST), then plants the 366B SH-4 stub at FIXED 0x8C29ADE8 via
  setRawDeviceID(100)/getRawDeviceID(101) (IM head @0x46 kept as harmless fake node).
- poc/doom_full.py        : builds the SH-4 loader stub (scan DOOMSTG1 -> copy doom@0x8CC00000 +
  wad@0x8C450000 -> set g_wad (GWA/GWS) -> clear BL/mask IRQ -> jmp DOOM). build/stub.bin.
- poc/build_stage_email.py: tiny email = pad(64)+PR(0x8C29ADE8); writes build/stub.bin.
- poc/eden_mitm.py        : rogue Eden server; _send_binary serves ?start/&len chunks (+/heap,/heapdiag).
- poc/native_doom/doomgeneric_dc.c : DC platform layer; LIVE-READS FB_R_SOF1 for the real framebuffer,
  TMU2 timing. Build with native_doom/Makefile (sh-elf-gcc) -> doom.bin.
- poc/wad/doom1_trim.wad  : trimmed IWAD (audio removed; PNAMES/textures/levels intact), 3397116 B.
- src-build/flycast-src/core/hw/sh4/sh4_interrupts.cpp : patched (DOOMDBG/DOOMLOG dump). Rebuild flycast.

## Run
1) bash poc/rebuild_doom.sh      # native doom.bin + re-extract g_wad -> doom_full.py + jar + stub
2) bash poc/deploy.sh            # (or just) rebuild jar + stub
3) bash poc/start_eden.sh        # rogue Eden on :8137, chain stagedoom
4) bash poc/fc_clean_boot.sh     # fresh browser (DCNet=no, no savestate)
5) connect online, stay on web browser; wait for eden 'staged doom=418292' + stub plant
6) open the DOOM-STAGE email -> native DOOM.
Read guest RAM: echo '<pw>' | sudo -S python3 poc/diag_loop.py  (RAM base from /tmp/fc_conn.log)
EOF

cd "$ROOT"
tar czf "$OUT" \
  poc/src \
  poc/*.py poc/*.sh poc/*.md \
  poc/slides \
  poc/magic.txt poc/mail_subject.txt poc/name_payload.hex \
  poc/build/pwn_stagedoom.jar poc/build/doom.bin poc/build/stub.bin \
  poc/build/loader.bin poc/build/doom.jar \
  poc/native_doom \
  poc/wad/doom1_trim.wad \
  src-build/flycast-src/core/hw/sh4/sh4_interrupts.cpp \
  2>/dev/null

echo "[+] backup written: $OUT"
du -h "$OUT" | cut -f1
echo "[+] contents:"; tar tzf "$OUT" | wc -l; echo "files"
ls -la "$DEST"

# Resume notes — Dreamcast PlanetWeb browser fuzzing (pause 2026-06-06)

## Where we are
Autonomous in-browser parser fuzzer working end-to-end. **4 confirmed-live decoder
bugs (all DoS hangs + memory-corruption/ACE leads):**
1. GIF LZW min code size 12        -> poc/crashes/HANG_gif_lzw_codesize12.gif
2. GIF huge dims 65535x65535       -> poc/crashes/hangs_round2/ (and earlier batch)
3. JPEG SOF2 component count Nf=5  -> poc/crashes/jpeg_hangs/ff_00014.jpg
4. JPEG DHT Huffman counts sum=2745 (>>256)  -> poc/crashes/hangs_round2/ff_00005.jpg
   *** STRONGEST ACE LEAD: writes 2745 attacker entries into a fixed Huffman array ***
No clean FAULT (SH4 exception) yet — every malformed image HANGS (decoder spins).

## To restart tomorrow
1. Start DNS+iptables (user sudo) so eden.planetweb.com -> 192.168.1.11:80->8137.
2. eden (fault-hunting fuzzer):
   cd poc && setsid python3 eden_mitm.py --chain fuzz -p $(cat ../emu/edenport) \
     --host eden.planetweb.com >../emu/eden.log 2>&1 &
3. Boot Flycast from ROOT cwd (real BIOS via ./data/dc_boot.bin), good VMU restored:
   cp emu/vmu_online_backup.bin  emu/fchome/.local/share/flycast/vmu_save_A1.bin
   cp emu/nvmem_online_backup.bin emu/fchome/.local/share/flycast/dc_nvmem.bin
   HOME=$PWD/emu/fchome XAUTHORITY=/home/adversary/.Xauthority DISPLAY=:12.0 \
     setsid src-build/flycast-src/build/flycast "Internet Browser V3.0 ... .gdi" >/tmp/fc_conn.log 2>&1 &
4. Start monitor:  setsid python3 poc/monitor.py >/tmp/monitor.err 2>&1 &
   (watch /tmp/fuzz_status.txt + /tmp/fuzz_events.log)
5. USER: connect the browser online once (A x3 -> Start -> web browser); then it
   self-runs the single-image fault-fuzzer (one mutated img/page, JPEG-weighted).

## Next analysis step (ACE)
Focus the JPEG DHT Huffman overflow (#4): craft a DHT with controlled count
distribution + entropy data so the OOB write lands a chosen value; characterize via
GDB stub :3263 (set bp in the JPEG decoder ~0x8c1b3xxx before the overflow). See
poc/crashes/LZW_ACE_ASSESSMENT.md for the method. Decoders: JPEG ~0x8c1b3-5xxx,
GIF 0x8c013-015. Caveat: gdb stub does NOT trap CPU exceptions (only TRAPA bp).

## Gotchas
- Flycast needs cwd=ROOT for real BIOS (else reios hang).
- Browser caches home in VMU + ignores HTTP no-cache; cache-proof entry = FuzzNav
  unique /fz/ URL on a fresh boot. Navigate HOME (Start->A) to (re)start the loop.
- Never `pkill -f eden_mitm.py|monitor.py` from a shell whose cmdline has that string
  (self-kills, exit 144) -> kill by PID.

# Full native code-exec chain → in-memory DOOM (Sega Dreamcast PlanetWeb)

End-to-end: unauthenticated network position → native SH-4 code execution → a
real DOOM engine running in the console's RAM, drawing to the screen. No ASLR on
the Dreamcast, so every address below is deterministic and hardcodable.

## Stage 0 — Unauthenticated Java RCE  [VALIDATED, hands-off]
Rogue Eden server (`eden_mitm.py`) → browser downloads + runs our unsigned JAR,
fully privileged (no SecurityManager). Delivers `RawDeviceIDExploit`.

## Stage 1 — Java → native primitive  [VALIDATED live]
`sendMessage(100=setRawDeviceID, byte[], null)` → `memcpy(0x8C29ABE6, attacker,
attacker_len)`, no bounds check (handler `0x8C04E0DC`). Arbitrary content/len at a
fixed address.

## Stage 2 — Arbitrary write via fake-object unlink  [VALIDATED live]
Overflow sets `*0x8C29AC2C` → a fake node in our payload. The IM-teardown
`sub_8C063F38` unlink (`0x8C063FA8`): `*( *(node+0x40)+0x3C ) = *(node+0x3C)`.
We control both → arbitrary 32-bit write. (Proven: overwrote fn-ptr `0x8C378B84`
`0x8C067506→stub` on the live emulator.)

## Stage 3 — Native PC via return-address overwrite  [DESIGNED; no render fn-ptr needed]
Key no-ASLR trick: the unlink runs *inside* `sub_8C063F38`, whose epilogue
(`0x8C06401C`: `lds.l @r15+,pr; … rts`) restores PR from the stack. `sub_8C063F38`
has no local frame, so the saved-PR slot == `r15` at the unlink. Point the unlink
write there → on return, **PC = our stub**. Self-contained, deterministic.
- Needs ONE runtime constant: `R15_AT_UNLINK` (stack addr; read once via GDB when
  the IM path naturally calls `sub_8C063F38` — stable across boots, no ASLR).
- Set `fake.next = loader_stub`, `fake.prev = R15_AT_UNLINK - 0x3C`.

## Stage 4 — Loader/stager stub  [TO BUILD: small SH-4]
Runs as native code with full CPU control. Responsibilities:
  1. Download `doom.bin` (the engine) + the IWAD from the rogue eden server into
     free RAM, by calling the browser's own URL→buffer fetch routine (the image
     loader uses it; identify + call it — integration RE step).
  2. Copy `doom.bin` to its link base `0x8CC00000`; copy the WAD to a free region;
     patch `g_wad_addr`/`g_wad_size` in `doom.bin`.
  3. Disable interrupts; jump to `doom.bin` `_start` (0x8CC00000). DOOM owns the
     SH-4 from here; the browser is abandoned (its video output keeps scanning out
     VRAM, which DOOM now draws into).
  (Staging note: setRawDeviceID's fixed dst can't place a large binary; staging is
   done by the native stub via the browser net stack — or a 2nd-stage downloader.)

## Stage 5 — DOOM (doomgeneric + bare-metal DC platform)  [PLATFORM WRITTEN; needs toolchain+build]
`doomgeneric` (full id-DOOM engine) + `doomgeneric_dc.c` platform layer that
REUSES the browser's live video (PVR scans out VRAM regardless of CPU owner):
  - DG_DrawFrame → 2x-scale 320x200 ARGB → RGB555 → framebuffer `0xA5600000`
    (live PVR regs: FB_R_CTRL=1 RGB555, FB_R_SOF1=0x600000, 640px wide).
  - DG_GetTicksMs → SH-4 TMU2 (Pck/64).
  - DG_GetKey → TODO (Maple controller); first build runs DOOM's attract/demo loop
    = DOOM visibly running on screen.
  - malloc → bump heap in free RAM (`dc_syscalls.c`); file I/O → in-memory WAD.
Build: `sh-elf-gcc` (newlib), link at `0x8CC00000` (no-ASLR), `objcopy -O binary`
→ `doom.bin`. See Makefile.

## Status
| Stage | State |
|---|---|
| 0 Eden Java RCE | ✅ validated, hands-off |
| 1 setRawDeviceID primitive | ✅ validated live |
| 2 unlink arbitrary write | ✅ validated live (fn-ptr overwrite) |
| 3 return-addr overwrite → PC | ✅ technique confirmed; needs `R15_AT_UNLINK` (1 GDB read) |
| 4 loader/stager | ⏳ to build (+ find browser fetch routine) |
| 5 doomgeneric + DC platform | ⏳ platform+build files written; needs `gcc-sh-elf` + compile + free-RAM map + emulator test |

## Gating action
Install the SH cross-compiler (the only step needing sudo):
    sudo apt install gcc-sh-elf
Then: `cd poc/native_doom && make` → `doom.bin`. Remaining integration: confirm
free-RAM layout (heap/WAD/bin bases via GDB read), build the loader stub, wire
`eden_mitm` to serve `doom.bin`+WAD, and test on Flycast.

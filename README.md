# PlanetWeb Dreamcast Browser v3.0 — Eden service-subscription RCE

DistrictCon Junkyard PoC. Unauthenticated remote code execution against the
Sega Dreamcast **PlanetWeb Internet Browser v3.0 (USA)** "Eden" client — by
design, no memory corruption. Whoever answers for `eden.planetweb.com` (a dead
domain) makes the console download and execute an arbitrary Java service,
fully privileged (no SecurityManager).

## The chain

```
boot ─► Eden client ─► GET http://eden.planetweb.com/edenclient.conf   (loginurl)
     ─► POST /login        ─► login:response  + discovery:url          (attacker-controlled)
     ─► POST /discovery     ─► service + subscription-url               (attacker-controlled)
     ─► POST /subscribe     ─► service-download-url = /pwn.jar          (attacker-controlled)
     ─► GET  /pwn.jar       ─► JarClassLoader.loadClass(Main-Class).newInstance().run()
                               └─► our code runs on the device  ◄── RCE
     ─► payload: SystemInterface.openURL(/junkyard.html)               (hijack native renderer)
```

Why it works (all confirmed in the decompiled client):
- **No SecurityManager is ever installed** → the bundled `java.policy` is dead
  config; loaded code is fully privileged.
- **No JAR signature verification** (`JarResource` just fetches + unzips).
- **All transport is plaintext HTTP** to `eden.planetweb.com`.
- Service download URLs come straight out of server XML responses.

## Files

| File | What |
|------|------|
| `src/org/junkyard/Junk.java` | shared payload helpers (banner/prove/openURL/http) |
| `src/org/junkyard/SplashService.java` | chain `splash` service — browser hijack |
| `src/org/junkyard/Pwn.java` | chain `jdoom` service — launches the DOOM engine |
| `src/org/junkyard/NativeProbe.java` | chain `native` service — `sendCommand` bridge recon |
| `src/org/junkyard/doom/Wad.java` | DOOM IWAD loader (little-endian, in-memory) |
| `src/org/junkyard/doom/Level.java` | map loader: vertexes/linedefs/sidedefs/segs/ssectors/nodes/sectors/things |
| `src/org/junkyard/doom/Textures.java` | PLAYPAL/COLORMAP, flats, and patch→TEXTURE compositing |
| `src/org/junkyard/doom/DoomEngine.java` | **real BSP renderer**: textured walls, portals, per-pixel flats, lighting |
| `src/org/junkyard/doom/DoomShell.java` | AWT-1.1 shell — downloads the IWAD, blits via `MemoryImageSource`, input |
| `build.sh` | builds all 3 chain jars + `doom.jar` to **class v45.3** against the device's `classes.zip` |
| `make_wad.py` | trims a full IWAD to one map → **`wad/doom_e1m1.wad` (~1.4 MB)** for 16 MB RAM |
| `eden_mitm.py` | rogue Eden server with `--chain {splash,jdoom,native}`; serves the chain + `/report` |
| `make_splash.py`, `www/junkyard.{html,gif}` | the `splash` chain's page |
| `wad/freedoom1.wad` | license-clean DOOM IWAD (dev); trimmed → `wad/doom_e1m1.wad` served as `/doom.wad` |
| `www/e1m1_doom.png`, `e1m1_textured.png`, `e1m1_3d.png`, `e1m1_automap.png` | off-device renders proving each engine stage |

## Three selectable chains

All three use the **same** Eden service-subscription RCE; only the payload
served at `/pwn.jar` differs. Pick one per emulator boot with `--chain`:

| `--chain` | jar | what it does | try it when |
|-----------|-----|--------------|-------------|
| `splash`  | `pwn_splash.jar` | hijack the browser to a full-screen "PWNED" page | **first** — smallest moving part; confirms the RCE chain end-to-end |
| `jdoom`   | `pwn_jdoom.jar` + `doom.jar` + `doom.wad` | **real WAD/BSP DOOM** in the Java VM | once `splash` works — the headline demo |
| `native`  | `pwn_native.jar` | sweep the `sendCommand` native bridge, POST a recon map to `/report` | to advance the **native** full-speed route (stage 1) |

## Build & run

```bash
./build.sh                # builds all 3 chain jars + doom.jar (verifies v45.3)
python3 make_wad.py       # -> wad/doom_e1m1.wad  (~1.4 MB device IWAD)
python3 make_splash.py    # -> www/junkyard.gif

sudo python3 eden_mitm.py --chain splash -p 80   # try this first
sudo python3 eden_mitm.py --chain jdoom  -p 80   # then real DOOM
sudo python3 eden_mitm.py --chain native -p 80   # native bridge recon
```
Port 80 is required (it's the Eden server port). Then make the Dreamcast resolve
`eden.planetweb.com` to the box running the server (see **Emulator** below).

The server log narrates each step `[1]..[5]` as the console walks the chain;
`[5] serving pwn.jar` is the moment of code execution. For `native`, the recon
map is printed and written to `native_report.txt`.

## Emulator with Dreamcast network emulation

Use **Flycast** — the only well-maintained DC emulator with real network
emulation, and it needs no DreamPi/extra hardware:

1. **Broadband Adapter (BBA) path (preferred):** Flycast emulates the DC BBA
   (`Settings → Network → Enable Broadband Adapter / "Enable Networking"`),
   giving the guest a real TCP/IP stack bridged to your host. Set the **DNS** in
   Flycast's network settings (or in the browser's connection profile) to your
   host's IP so `eden.planetweb.com` resolves to the machine running
   `eden_mitm.py`. (If the browser build is modem-only, use the modem path.)
2. **Modem path:** Flycast also emulates the dial-up modem over a host PPP
   bridge; "dial" any number, then the browser's configured DNS must point at
   your server box.
3. Run `sudo python3 eden_mitm.py --chain <chain> -p 80` on that box, boot the
   Internet Browser V3.0 GD-ROM in Flycast, and trigger connect. Watch the log.

Alternatives: **lxdream** has some networking; **Redream/NullDC/DEmul** have
weak/none — Flycast is the recommendation. On **real hardware**, the DreamPi +
custom-DNS setup the DC online community already uses works identically: point
its DNS at your server.

## What's verified here vs. on-device

Confirmed offline in this repo (no Dreamcast needed):
- ✅ **all chains + the DOOM engine** compile against the device's real
  `classes.zip` (PersonalJava 1.1.8 only) and are **class version 45.3**.
- ✅ the device's own loader (`JarResource`/`Manifest`) resolves every chain's
  `Main-Class` + `Junk` + (for `jdoom`) the `doom.jar` engine via `Jar-Files`.
- ✅ server XML is parsed by the device's exact namespace-aware semantics and
  yields our injected URLs (`Validator`).
- ✅ the DOOM renderer produces correct **Freedoom E1M1** frames from the trimmed
  1.4 MB IWAD (`www/e1m1_trimmed.png`, `e1m1_spanflats.png`).

Needs an emulator / real console to observe:
- ▶ `splash`: `openURL` navigating + the page rendering.
- ▶ `jdoom`: the AWT `Frame` + framerate (interpreted SH4 at 320×200).
- ▶ `native`: which `sendCommand` codes are live (the recon map) + crash signals.

## What's verified here vs. on-device

Confirmed offline in this repo (no Dreamcast needed):
- ✅ `pwn.jar` compiles against the device's real `classes.zip` (only PersonalJava
  1.1.8 APIs) and is **class version 45.3** — what the VM accepts.
- ✅ The device's own loader code (`org.openbrew.util.zip.JarResource` /
  `Manifest`) locates our manifest, `Main-Class`, and class bytes.
- ✅ Every server XML response is parsed by the device's exact
  namespace-aware `getNode`/`getNodeAttribute`/`getNodeContent` semantics and
  yields our injected URLs (login→discovery→subscribe→jar). See `Validator`.

Needs an emulator / real console to observe (can't be done without the device):
- ▶ `openURL` actually navigating the native renderer to the splash page.
- ▶ rendering of `junkyard.gif`.

## Real DOOM (WAD + BSP) — in Java, no native exploit

`doom.jar` is a real DOOM engine: it loads an actual **IWAD** and renders maps
with the **BSP** algorithm — textured walls (composited from patches via
PNAMES/TEXTURE1), per-pixel textured floors/ceilings (flats), portals, and
PLAYPAL/COLORMAP lighting. It runs entirely inside the PlanetWeb VM, so no
native code-exec is needed. The device runtime (`classes.zip`) has every API
required (`MemoryImageSource`/`ColorModel`, `Frame`/`Graphics`, `KeyListener`,
`DataInputStream`). Everything compiles to **class v45.3** (PersonalJava 1.1.8).

Flow on device:
1. RCE chain delivers `pwn.jar`, which declares `Jar-Files: …/doom.jar`, so
   `ServiceManager` pulls the engine into the same `JarClassLoader`.
2. `Pwn.run()` → `Class.forName("org.junkyard.doom.DoomShell").newInstance()`.
3. `DoomShell` downloads the IWAD from `http://eden.planetweb.com/doom.wad`,
   builds `DoomEngine`, opens an AWT `Frame`, and runs the game loop
   (arrows/WASD to move + turn, `,`/`.` strafe, ESC quit).

Off-device verification in this repo:
- ✅ whole engine compiles to **v45.3** against `classes.zip` (1.1/AWT-1.1 only).
- ✅ device loader resolves `Pwn` + all five engine classes via `Jar-Files`
  (`ChainTest`).
- ✅ the renderer produces correct frames of **Freedoom E1M1** — see
  `www/e1m1_doom.png` (final), plus the staged proofs `e1m1_automap.png`
  (geometry), `e1m1_3d.png` (flat-shaded BSP), `e1m1_textured.png` (textures).

WAD on hardware: the Dreamcast has **16 MB RAM**, so the 28 MB Freedoom IWAD is
dev-only. For real hardware serve a ~4 MB IWAD (shareware `DOOM1.WAD`) or a
trimmed single-episode IWAD as `/doom.wad`. The engine loads any DOOM IWAD —
drop in `DOOM.WAD`/`DOOM2.WAD` and change `MAP` in `DoomShell`.

Needs console/emulator to confirm: the AWT `Frame` display + framerate
(interpreted SH4 at 320×200 — expect low but real FPS; per-pixel flats are the
main cost and can be moved to span-based rendering for speed).

## Native route (`--chain native`) — toward full-speed DOOM

Full-speed DOOM means the native KallistiOS port, which needs **native** code
execution. The whole native engine is driven from Java through one choke point —
`NativeSystemInterface.sendCommand(int, Object, Object)` (reached via the
protected `SystemInterface.sendMessage`). `NativeProbe` reflects into it (no
SecurityManager), **sweeps command codes** `0..1100` (denylisting `100`=write
FLASH and `111`=setSecurityFile), records each return/exception, stages
`/doom.bin`, and POSTs the map to `/report`.

That recon map — which codes are live, which throw, which hang/crash — is what
you mine on the emulator/console for a memory-corruption or code-exec primitive
to jump to a KOS DOOM binary.

**Static RE is already underway** (`native/`, full writeup in `native/NATIVE_RECON.md`):
- `1ST_READ.BIN` is unscrambled SH4 @ `0x8c010000`, disassembled with capstone `CS_ARCH_SH`.
- The native `sendCommand` **dispatcher is located (`0x8c04df80`) and decoded** —
  `native/native_recon.py` reproducibly recovers the **command→handler address map**
  for all 27 codes (e.g. `100 setRawDeviceID→FLASH @0x8c04e0dc`,
  `111 setSecurityFile→native parser @0x8c04e626`, `1003 vmuPutFile @0x8c04e408`).
- `native/analyze_report.py` scores the live sweep (`--selftest` for a demo).

Next: disassemble the crown-jewel handlers for an unbounded copy of the attacker
`byte[]`/`String` → SH4 overflow → ROP → jump to the staged KOS DOOM. Needs the
handler-body disasm + the live reachability map from the emulator.

### jdoom polish still open
Span-based flats and the device WAD are done. Remaining visual upgrades:
scrolling sky texture and sprites/things (enemies, items).

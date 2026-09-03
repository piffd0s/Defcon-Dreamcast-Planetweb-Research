# Running the PlanetWeb PoC on macOS (Apple Silicon)

The original rig was a Linux box rooted at `/media/adversary/Storage/dc_browser_extract`,
with X11, `iptables`, and a Flycast built there. This directory is the macOS port.
Nothing about the attack changed — only the emulator build and the network plumbing.

Verified on macOS 26.5.1, Apple M5 Max, Command Line Tools only (no full Xcode).

## Quick start

```bash
brew install cmake ninja        # one time
mac/build_flycast.sh            # build the emulator (a few minutes)
mac/flycast.sh --no-net         # smoke test: should print Game ID [T31901N]

sudo mac/start_demo.sh splash   # rogue Eden + DNS + browser; try this chain first
```

Then take the browser online and watch `/tmp/eden.log` for `[1]`..`[5]`.
`[5] serving pwn.jar` is the moment of code execution.

Chains, in the order worth trying: `splash` → `jdoom` → `stagedoom`
(`stagedoom` is the DEF CON demo: native SH-4 DOOM; wait for `READY`, then open
the DOOM-STAGE email).

### The demo on slide 26

`python3 run_doom.py` works as written — it was ported to resolve the repo from its
own location and to call `mac/start_eden.sh` + `mac/flycast.sh --clean` instead of
the Linux `start_eden.sh` / `fc_clean_boot.sh`. It starts Eden on the `stagedoom`
chain, boots a fresh browser, and watches staging until it prints `READY`.

```bash
python3 run_doom.py            # start eden + boot flycast + watch
python3 run_doom.py --no-boot  # reuse the running emulator
```

It prompts for your password, because Eden must own `:80`. To rehearse the plumbing
without sudo, run it on a high port — the chain will not reach the console, but
every server-side step is exercised:

```bash
EDEN_PORT=8137 python3 run_doom.py
```

Cosmetic, and inherited from the Linux version: the watcher prints
"chain loaded (pwn.jar)" as soon as Eden writes its startup banner, because the
banner line itself contains `pwn.jar`. The authoritative signals are the `[CHUNK]`
progress bars and `READY`.

## The disc

`~/Downloads/PlanetWeb 3.0/` holds `PW3.IMG` + `PW3.CUE`. It is the right disc —
Game ID `T31901N`, `PLANETWEB INTERNET BROWSER V3.0`, `1ST_READ.BIN` (4,432,064
bytes) at LBA 45059 — but **`PW3.CUE` does not load in Flycast**:

```
imgread/cue.cpp:201 W[GDROM]: CUE parse error: TRACK 01 not in a FILE context
ui/gui.cpp:1318 E[BOOT]: Invalid CUE file
```

The shipped cue puts `FILE` *before* `REM SESSION 01`, and Flycast's parser clears
the FILE context on every `REM` line, so `TRACK 01` ends up with no file.

`PW3_flycast.cue` (written next to the IMG; the original is untouched) fixes this.
`PW3.IMG` is a flat full-disc dump — file sector index equals absolute LBA, 2352-byte
MODE2 sectors with a 24-byte header — so one `FILE` context spanning both tracks
reproduces the real addresses: track 1 at LBA 0, track 2 at LBA 64074 (the
self-boot session's `IP.BIN`). The ISO structures live at their original GD-ROM
addresses (root directory at LBA 45023), which is why the absolute LBAs must be
preserved rather than relocated.

## Why the emulator is built from source

Upstream ships a macOS cask, but this project needs a custom build for two reasons,
both of which the talk depends on:

- **`-DENABLE_GDB_SERVER=ON`** — the SH-4 GDB stub on `:3263`. It is `OFF` by
  default upstream. `run_full_demo.py`, `gdbstub_probe.py`, and the framebuffer
  capture all drive it.
- **`mac/patches/02-doomdbg-fault-dump.patch`** — dumps SH-4 fault context
  (`epc`, `PR`, `SR.BL`, `r15`, `TEA`) on every exception, and drains DOOM's debug
  log from `0x8CF00000` before aborting. This is the patch from the Linux tree.

`mac/patches/01-macos-cmake-ninja.patch` is new and is a build fix, not a
behavioural change: upstream only supports the **Xcode generator** on macOS (which
needs the full Xcode app plus the Vulkan SDK), so with Ninja you must
`enable_language(OBJC/OBJCXX)` yourself, the `ZLIB_LIBRARY "-lz"` Xcode workaround
has to be skipped, and the MoltenVK post-build copy has to be guarded for
OpenGL-only builds.

## Four macOS-specific gotchas

**1. JIT entitlements are mandatory.** Unsigned, the kernel refuses Flycast's
contiguous 512 MB reservation, so the ARM64 dynarec aborts at startup:

```
E[COMMON]: Verify Failed : &mem_b[0] == ((u8*)getContext()->sq_buffer + sizeof(Sh4Context) + 0x0C000000)
 in Init -> core/hw/sh4/dyna/driver.cpp : 349
```

`build_flycast.sh` ad-hoc signs the bundle with `com.apple.security.cs.allow-jit`
(plus unsigned-executable-memory and disable-executable-page-protection). After the
fix the log reads `Info: nvmem is enabled`. **Re-sign after every rebuild** — the
build script does this for you.

**2. Flycast has a startup race that aborts the emulator (auto-retried).**
The emulation thread can reach `addrspace::initMappings()` before the main
thread's `addrspace::reserve()` completes. It sees a null `ram_base`, falls back
to `malloc`'d RAM, and the ARM64 dynarec then aborts instantly:

```
E[COMMON]: Verify Failed : &mem_b[0] == ((u8*)getContext()->sq_buffer + sizeof(Sh4Context) + 0x0C000000)
 in Init -> core/hw/sh4/dyna/driver.cpp : 349
```

Instrumented builds show the failing order plainly:
`initMappings ram_base=0x0` → `FALLBACK BRANCH TAKEN` → `reserve: virtmem::init`.

Enabling the network widens the window considerably, presumably by starting more
threads during boot — measured **0/5 failures with networking off, 5/10 with the
Broadband Adapter on**. It is *not* caused by the disc image, and *not* by the JIT
signature (it reproduces with a valid one). Once past startup the emulator is
stable, so `flycast.sh` detects the abort and relaunches, up to
`FLYCAST_ATTEMPTS` (default 10). Measured 5/5 successful launches through the
wrapper with BBA on.

If you launch `Flycast` by hand instead of through `flycast.sh`, expect to hit
this roughly half the time with networking on — just launch it again. This is
worth reporting upstream; it is a genuine bug, not a macOS quirk.

**3. Never `kill -9` Flycast.** macOS records the SIGKILL as a crash, and the next
launch blocks *before* `main()` on a modal "reopen windows?" alert
(`NSPersistentUIRestorer promptToIgnorePersistentStateWithCrashHistory:`). The
symptom is maddening: the process is alive, but there is no window, no log, no
config written, and nothing on the GDB port. `flycast.sh` terminates with SIGTERM
and sets `ApplePersistenceIgnoreState` in the repo-local HOME. If you ever hit it:

```bash
rm -rf emu/fchome/Library/Saved\ Application\ State/com.flyinghead.Flycast.savedState
```

**4. Logs.** Flycast's NSLog output does not reliably reach a redirected stdout on
macOS. `flycast.sh` passes `-config log:LogToFile=yes`, so the real log is
`emu/fchome/.flycast/data/flycast.log`. Read that, not `/tmp/flycast.log`.

## Network plumbing

macOS has no `iptables`, so `start_servers.sh`'s `REDIRECT :80 -> :8137` does not
apply. Instead `eden_mitm.py` binds `:80` directly, which — like `:53` for the DNS
redirector — is why `start_demo.sh` needs `sudo`.

`flycast.sh` launches with:

```
-config network:Enable=yes      # emulated network on
-config network:DCNet=no        # OFF: default ON routes the guest via flyinghead's
                                #      public service instead of your Eden server
-config network:EmulateBBA=yes  # Broadband Adapter (default) -- --modem for PPP
-config network:DNS=$HOST_IP    # the Mac's LAN IP, auto-detected in env.sh
```

**Adapter**: BBA is the default (`NET_MODE=bba`, or `mac/flycast.sh --bba`); pass
`--modem` for dial-up over PPP instead. With the BBA, Flycast maps the RTL8139 and
runs a DHCP server for the guest — the Dreamcast comes up as `192.168.169.2` and is
handed `network:DNS` as its DNS server. The modem path delivers the same value via
`pico_ppp_set_dns1()` during PPP negotiation. Either way the value reaching the
guest is identical, so the note below applies to both.

**`HOST_IP` must not be `127.0.0.1`.** Flycast passes `network:DNS` to the guest
via `pico_ppp_set_dns1()`, so it is the *Dreamcast's* stack that interprets the
address — and to the Dreamcast, `127.0.0.1` is its own loopback. Those queries
would never cross the PPP link. It has to be an address the guest routes outward,
which picoppp then proxies through a host socket, so the Mac's LAN IP is the right
answer. `env.sh` derives it from the default route (currently `10.5.192.183`);
override with `HOST_IP=<ip>` if you are on a different network at the venue.

Because that IP changes with the network you are on, re-check it before the talk:

```bash
source mac/env.sh; echo "$HOST_IP"
```

The macOS Application Firewall is **on** here. The first time Eden takes a
connection on the LAN IP you will get an "allow incoming connections" prompt for
`python3` — accept it, or the chain stalls between DNS and `[1]`.

## What is verified here, and what still needs a human

Confirmed working on this Mac:

- Flycast builds, is signed, and boots the disc: `Game ID is [T31901N]`, reios HLE
  BIOS (no real BIOS needed), `nvmem is enabled` (dynarec live), OpenGL 4.1.
- The GDB stub accepts connections on `:3263`.
- The browser runs: PVR VRAM holds live texture data and the browser wrote its own
  VMU save (`T31901N_vmu_save_A1.bin`).
- The full Eden chain serves correctly under macOS Python 3.9 — `/edenclient.conf`
  → `/login` → `/discovery` → `/subscribe` → `/pwn.jar` (2,948 B) → `/doom.jar`
  (17,472 B) → `/doom.wad`, with the device-side XML shapes intact.

Still needs you at the keyboard, because it needs console input:

- Taking the browser online (A ×3 → Start → web browser) and letting it connect.
- For `stagedoom`, opening the DOOM-STAGE email once the runner prints `READY`.

One thing you cannot do from a script: **screenshots of the browser**. Flycast
renders through OpenGL on the host and does not write the result back into guest
VRAM, so `fb_capture.py` (which reads `FB_R_SOF1` over the GDB stub) returns a black
frame for the browser. It works for native DOOM, which writes pixels straight into
VRAM at `0xA5600000` — that is exactly how `demo_doom_proof.png` was made. For the
browser, grant Screen Recording permission to your terminal and use `screencapture`.

## Rebuilding the jars

`build.sh` still points at the Linux paths and needs the device runtime
(`CLASSES.ZIP` / `PLANETWEB.JAR`) plus a JDK 8 — none of which are on this Mac.
The prebuilt jars in `build/` are the ones the chains serve, and `eden_mitm.py`
re-reads them from disk per request, so you only need `build.sh` if you change the
Java source.

## The jar-free email chain (validated)

Native SH-4 DOOM, triggered by the MIME `name=` overflow, with **no Java anywhere in
the chain**. This is the fastest and most reliable path on this Mac.

```bash
mac/flycast.sh --clean          # emulator (BBA)
sudo mac/start_mail.sh          # DNS(--all) + POP3 :110 + static www/  -- no Eden
#   take the browser online
python3 mac/native_stage.py     # blob + stub into RAM over the GDB stub -> READY
#   Check Mail -> open "DOOM-STAGE"
python3 fb_capture.py proof.png # DOOM writes to VRAM, so this one captures
```

**Why it beats the Java route.** `StageDoom` has to pull 3.8 MB through the emulated
link into a `byte[]` pinned in a 16 MB heap; observed here, it died at ~2.1 MB (50% of
the WAD) and the browser faulted. `native_stage.py` writes the same bytes straight to
`0x8C867000` over the GDB stub in **under a second** — no JVM allocation, no heap
pressure. The stub does not care how the blob arrived: it scans `0x8C400000..0x8CFF0000`
for `DOOMSTG1`, copies the WAD to `0x8C450000` **first** (the doom copy lands on the
blob's own WAD region), then the engine to `0x8CC00000`, patches `g_wad`, and jumps.

**The exploit is identical either way** and is proven on this image. When the mail was
opened with nothing planted, the DOOMDBG patch caught the fault:

```
DOOMDBG[1] Do_Exception epc=8c29b860 expEvn=180 BL=0 r15=8c00e830 pr=8c29ade8
```

`pr=8c29ade8` is the stub address: the overflow set saved PR, `rts` went there, and the
CPU ran garbage until an illegal instruction (`expEvn=0x180`). Plant the stub first and
the same jump lands in real code.

Ordering is the whole game: stage, verify, *then* open the mail. `native_stage.py
--verify` re-reads the magic, three offsets across the blob, and all 366 stub bytes, and
refuses to print READY if anything is off.

### Screenshots

`fb_capture.py` reads `FB_R_SOF1` for the current scanout base and `FB_R_CTRL[3:2]` for
the pixel format. It works for DOOM (which writes pixels into VRAM) but **not** for the
browser — Flycast renders the browser through host OpenGL and never writes the result
back to guest VRAM, so the browser always captures black. Note DOOM came up scanning
from `0xA5200000` here, not the `0xA5600000` that `run_full_demo.py` hardcodes, which is
why reading the register matters.

### Next step: drop the GDB stub from the code path

`jmp @r15` exists in the browser binary at **`0x8C1D8542`** (delay slot `mov #77,r11`,
harmless; PR bytes `42 85 1D 8C`, none of them `00`/`20`/`22`). Pointing saved PR there
instead of at a planted address makes the payload **position-independent**: at `rts`,
`r15` points into the overflow data the same `name=` copy just wrote, so execution lands
in your own bytes wherever the stack happens to be. That removes the fixed-address plant
entirely and retires Challenge #1 (the ~32 KB stack variance that made a hardcoded PR a
coin flip). The constraint is that an inline stub must avoid `00`/`20`/`22`, so it needs
a filtered-safe decoder — SH-4 encodings are full of `0x00` (`nop` = `09 00`).

The data half stays open: the browser has no clean URL-to-big-buffer fetch. The cheapest
lever is payload size — the engine is only 418 KB and the WAD is 87% of the blob:

| WAD | blob |
|---|---|
| `doom1_trim.wad` | 3.64 MB (current) |
| `doom_e1m1.wad` | 1.74 MB — full E1M1 |
| `doom_mini.wad` | 0.49 MB — single room |

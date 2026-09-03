# Dreamcast PlanetWeb Native DOOM Demo

This repository contains the minimal, tested files for launching native SH-4 DOOM through Sega Dreamcast PlanetWeb Internet Browser v3.0. The demo chains the browser's Eden service loading behavior, a native `setRawDeviceID` memory-write flaw, and a MIME attachment stack overflow. It runs without attaching a debugger or using GDB to stage the payload.

Use this project only with systems, software, and networks you own or are explicitly authorized to test.

## What is included

- `dreamcast_doom_native.py` — coordinates DNS, Eden HTTP, POP3, Flycast, staging, and cleanup.
- `dns_redirect.py`, `eden_mitm.py`, `mail_poc.py` — the three local services used by the chain.
- `build/` — the exact tested Java stage, native DOOM engine, and native loader stub.
- `src/` — the relevant Java source for the staged service.
- `patches/flycast-picoppp-reap.patch` — reduces picoTCP connection linger so payload staging can finish reliably.
- `emu/flycast-native/Flycast.app` — the dedicated signed Apple Silicon Flycast build used by the launcher.
- `wad/doom1_trim.wad` — the WAD matched to the size-baked loader stub.

For the complete dependency audit, setup details, operating sequence, and troubleshooting, read [DREAMCAST_DOOM_NATIVE_HOWTO.md](DREAMCAST_DOOM_NATIVE_HOWTO.md).

## Requirements

- macOS on Apple Silicon. The included Flycast executable is arm64.
- Python 3; the Python programs use only the standard library.
- Administrator access. The launcher binds DNS port 53, HTTP port 80, and POP3 port 110.
- A legally obtained PlanetWeb Internet Browser v3.0 `.gdi` and every track referenced by it.
- A configured local Flycast home at `emu/fchome/`. This mutable directory is intentionally not committed.
- A host IPv4 address reachable from Flycast's emulated Dreamcast network.

## Disc layout

Keep the browser disc descriptor and all its track files together outside the repository. The launcher's default is:

```text
~/Downloads/Internet Browser V3.0 for Dreamcast (USA)/
└── Internet Browser V3.0 for Dreamcast (USA).gdi
```

Set `DISC` to use another location.

## Preflight

From the repository root:

```bash
python3 -m py_compile \
  dreamcast_doom_native.py dns_redirect.py eden_mitm.py mail_poc.py

test -x emu/flycast-native/Flycast.app/Contents/MacOS/Flycast
test -f build/pwn_stagedoom.jar
test -f build/doom.bin
test -f build/stub_native.bin
test -f wad/doom1_trim.wad
```

The committed `doom.bin`, `stub_native.bin`, and `doom1_trim.wad` are a matched set. The loader stub contains the engine and WAD sizes; do not replace only one of these files.

## Run

When the default disc path and automatic host-IP detection are correct:

```bash
sudo python3 dreamcast_doom_native.py
```

To specify both explicitly:

```bash
sudo env \
  DISC="/absolute/path/to/Internet Browser V3.0 for Dreamcast (USA).gdi" \
  HOST_IP="192.0.0.2" \
  python3 dreamcast_doom_native.py
```

Then:

1. In PlanetWeb, press `A` three times, choose **Start**, and enter the web browser.
2. Let the browser connect and leave it on the browser screen. Do not open Mail yet.
3. Wait for the terminal to report `ARMED`.
4. Open **Mail**, choose **Check Mail**, and promptly open the `DOOM-STAGE` message.
5. Press `Ctrl-C` in the terminal to stop the services and emulator.

Opening the message before `ARMED` can trigger the return-address overwrite before the loader has been planted.

## Repository layout

```text
.
├── README.md
├── DREAMCAST_DOOM_NATIVE_HOWTO.md
├── dreamcast_doom_native.py
├── dns_redirect.py
├── eden_mitm.py
├── mail_poc.py
├── build/
│   ├── pwn_stagedoom.jar
│   ├── doom.bin
│   └── stub_native.bin
├── src/org/junkyard/
│   ├── Junk.java
│   └── StageDoom.java
├── patches/
│   └── flycast-picoppp-reap.patch
├── emu/flycast-native/Flycast.app/
└── wad/
    └── doom1_trim.wad
```

Local emulator profiles, firmware, flash/VMU state, disc images, toolchains, logs, and unrelated research are excluded by the repository allowlist.

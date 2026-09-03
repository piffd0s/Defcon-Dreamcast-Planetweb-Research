# DistrictCon Junkyard Submission — Sega Dreamcast PlanetWeb Browser
### Full Exploit Chain: Web Page → Unauthenticated RCE → Native SH-4 Code Execution → DOOM

## Proof of Eligibility
* **EOL Date?** Sega Dreamcast discontinued **March 31, 2001** (production ended; announced Jan 31, 2001). The online services the browser depends on (SegaNet / Dreamarena / PlanetWeb Eden) shut down 2002–2003. Browser vendor **PlanetWeb, Inc.** is also defunct.
* **EOL Confirmed by Vendor?** **Yes** — Sega publicly announced discontinuation of the Dreamcast (Jan 31, 2001). Both the hardware vendor (Sega) and the browser vendor (PlanetWeb) discontinued the product line and online services.
* **EOL Date Source:** Sega Corporation discontinuation announcement (Jan 31, 2001) / press coverage. *[ATTACH IMAGE: screenshot of the discontinuation announcement — e.g. https://en.wikipedia.org/wiki/Dreamcast#Discontinuation ]*

## Presentation Details
* Speaker Names for Display:

| Name | Handle | Phonetic Pronunciation (optional) | Socials (X, Instagram, Linkedin) |
| :-- | :-- | :-- | :-- |
| Christopher Hernandez | *[YOUR HANDLE]* | *[optional]* | *[X / IG / LinkedIn]* |

* Speaker socials, if any: *[fill in]*
* Coverterm for talk, for display: **"Owning the Dreamcast from a Web Page: Unauthenticated RCE to Native SH-4 Code Execution (and DOOM) in the PlanetWeb Browser"**

## Target Details
* **Target Name/Model:** Sega Dreamcast — PlanetWeb Internet Browser (the bundled web browser / online client; "Web Browser 3.0" disc, USA)
* **Target Version:** PlanetWeb Internet Browser **v3.0** (USA); `1ST_READ.BIN` SH-4 image loaded at `0x8C010000` (image `0x8C010000–0x8C44A0C0`); bundled PersonalJava 1.1.8 VM (class format v45.3) + Eden service framework. **No ASLR / no W^X** (deterministic addressing — a key enabler).
* **Target Category:** **game** (console hardware) — the vulnerability is in the console's bundled browser/online software.

## Proof of Disclosure
* **CVE (optional)?:** none (legacy, vendor defunct)
* **Coordinated Disclosure Date:** **N/A** — both the hardware vendor (Sega, Dreamcast EOL 2001) and the software vendor (PlanetWeb, Inc., defunct) no longer exist or maintain the product; there is no vendor to coordinate with. All online infrastructure (`eden.planetweb.com`, Dreamarena) is dead.
* **Coordinated Disclosure Proof:** N/A (no extant vendor).

---

## Vulnerability Details

### Product Overview
The Sega Dreamcast (1998–2001) shipped with a bundled **PlanetWeb Internet Browser** that turned the console into a web terminal: it dialed up via modem, rendered HTML/JPEG/GIF/PNG, ran a PersonalJava 1.1.8 VM, and connected to PlanetWeb's **"Eden"** online-service framework for downloadable services (mail, IM, content). It is an ideal Junkyard target — dead hardware, dead online services, a 1999 unauthenticated network trust model, and a full Java→native attack surface — and **native code execution on a stock Dreamcast from nothing but a network position** is a compelling demo. All research was performed on my own extracted disc image and an emulator (Flycast with an SH-4 GDB stub).

### The Full Chain at a Glance

```
  [Attacker answers DNS for eden.planetweb.com]
        │
        ▼
  (1) Eden service-subscription chain  ── plaintext HTTP, no JAR signing, no SecurityManager
        │   browser downloads + runs our JAR, FULLY PRIVILEGED Java  (HANDS-OFF, 100% reliable)
        ▼
  (2) Java→native bridge:  SystemInterface.sendMessage(100, payload)
        │   setRawDeviceID handler = memcpy(dst=0x8C29ABE6 FIXED, src=attacker[], len=attacker)  NO BOUNDS
        ▼
  (3) Fixed-address, attacker-content, unbounded overflow → plant fake IM node + SH-4 stub,
        │   corrupt IM node pointer *(0x8C29AC2C) → our fake node
        ▼
  (4) IM-object teardown runs the unlink gadget sub_8C063F38 →
        │   *( *(0x8C3402F4) + 0x3C ) = *(fakeNode+0x3C)     ← controlled value into a fixed FN-PTR field
        │   → overwrites a hot browser function pointer with our SH-4 stub
        ▼
  (5) Function pointer is invoked → NATIVE SH-4 PC under attacker control
        │   payload = in-memory DOOM (doomgeneric) reusing the browser's live framebuffer
        ▼
  [DOOM E1M1 rendering on the Dreamcast]
```

### Bug #1 — Unauthenticated, fully-privileged remote code execution via the Eden framework (design flaw; headline; 100% reliable, hands-off)

At boot the browser runs `com.planetweb.eden.client.Eden`, logs in to `eden.planetweb.com` over **plain HTTP**, and walks a discovery→subscribe flow whose responses (unsigned XML) name a **service JAR URL**. `ServiceManager.loadService(URL)` downloads that JAR over HTTP, reads its `Main-Class`, and does `JarClassLoader.loadClass(name).newInstance()` then `Service.run()`. Critically:

* **No JAR signature / certificate / checksum verification** anywhere in `ServiceManager`.
* **No `SecurityManager` is ever installed** (`java.policy` is dead config) → loaded code is fully privileged.
* The `Jar-Files` manifest attribute lets the served JAR pull **more** attacker JARs from arbitrary URLs into the same classloader.
* All transport is **plaintext HTTP** to a now-dead domain.

Anyone who answers for `eden.planetweb.com` (trivial today — dead domain; on hardware via DreamPi/rogue DNS, on emulator via DNS redirect) ships a JAR the console downloads and executes. **Reliable arbitrary Java code execution, no authentication, no memory corruption.** Implemented in `eden_mitm.py` (serves the entire conf→login→discovery→subscribe→jar chain) with payloads that hijack the browser to a full-screen "OWNED" page and leak the console's **raw device ID** — live-confirmed on the emulated Dreamcast.

### Bug #2 — Escalation to native SH-4 code execution via the Java→native bridge + a linked-list unlink

Privileged Java is still inside the VM. The single Java→native bridge is `SystemInterface.sendMessage(int cmd, Object, Object)`. Command **100 = `setRawDeviceID`** (native handler `0x8C04E0DC`, verified in IDA) performs:

```
memcpy(dst = 0x8C29ABE6 [FIXED global], src = attacker byte[], len = attacker-controlled)   // NO bounds check
```

— a **fixed-address, fully-attacker-controlled-content, unbounded overflow**, reachable directly from our Java service. Unlike the image-decoder bugs (see "Quirks"), this lets us plant **pointers, a fake object, and an SH-4 stub** at a known address. `0x8C29ABE6` is the 8-byte device-ID field; the overflow runs straight into the native Instant-Messenger / Eden object globals.

`0x8C29AC2C` (= dst + 0x46) is an **IM list-node pointer**. The object-teardown routine `sub_8C063F38` contains the unlink write at `0x8C063FA8` (`mov.l r2,@(0x3C,r3)`). Decoded precisely, with `node = *(0x8C29AC2C)`:

```
guard:  node == arg0   &&   node != 0   &&   *(0x8C3402F4) != 0
write:  *( *(0x8C3402F4) + 0x3C )  =  *( node + 0x3C )
        └── dest: FIXED IM-object field ──┘     └── value: CONTROLLED (in our payload) ──┘
```

We corrupt `*(0x8C29AC2C)` to point at a **fake node inside our own `setRawDeviceID` payload**, so `*(node+0x3C)` (the value written) is fully attacker-controlled. The destination is the IM object field `*(0x8C3402F4) + 0x3C`, which in the live-validated state is the **hot function pointer `0x8C378B84` (64 call sites)**. The write therefore overwrites that function pointer with the address of an **SH-4 stub** we planted in the same payload. When the pointer is next called → **native SH-4 PC under our control**.

> **Accuracy note / correction over earlier drafts:** the unlink destination is the *fixed* global-derived field `*(0x8C3402F4)+0x3C`, **not** `*(node+0x40)+0x3C`. The gadget is a **controlled-value → fixed-fn-ptr overwrite** (write-what / fixed-where) — the correct mental model for weaponization.

**Quirks / why the obvious paths fail.** The "expected" memory-corruption surface — the image decoders — is a red herring: the JPEG `get_dht` Huffman path is fully bounds-checked; `get_sof`/GIF/PNG bugs are heap/DoS-class with constrained writes (cannot plant a pointer). The clean native primitive is the **Java→native bridge**. Also, this Dreamcast Java runtime uses **C structs passed to fixed functions, not C++ vtables**, so there is no virtual-call gadget — the winning primitive is the **unlink write**, not a call-through.

### Stage 5 — Payload: DOOM on the Dreamcast (two deliverables)

* **Hands-off Java DOOM** — a genuine WAD + BSP engine (`org.junkyard.doom.*`: LE IWAD loader, BSP traversal, perspective-correct textured walls, span-based visplane floors/ceilings, COLORMAP lighting) written in PersonalJava-1.1-compatible bytecode (v45.3, AWT 1.1, `MemoryImageSource` blit), delivered **entirely through the Bug #1 Eden chain** (the service JAR pulls `doom.jar` + a trimmed WAD via `Jar-Files`). Renders real DOOM E1M1.
* **Native SH-4 DOOM (full id engine)** — `doomgeneric` cross-compiled to **bare-metal SH-4** (`doom.bin`, 418 KB, no KOS) with a Dreamcast platform layer that **reuses the browser's already-initialised video**: the PVR scans VRAM continuously regardless of which code owns the CPU, so DOOM just writes the live framebuffer. **Verified live (Flycast):** the engine boots its full sequence (Z_Init 6 MB zone → W_Init reading the in-RAM `doom1.wad` → R_Init/P_Init/S_Init → I_InitGraphics) and **renders E1M1 to the framebuffer at `0xA5600000`** — player view, weapon, status bar, 98-colour palette frame. See **`DOOM_E1M1_live_on_dreamcast.png`**.
  * Memory layout (16 MB, no-ASLR): WAD `0x8C010000`–`0x8C410774` (4 MB shareware `doom1.wad`), heap/zone `0x8C420000`–`0x8CC00000`, `doom.bin` @ `0x8CC00000`, stack top `0x8CFFFFF0`.
  * The native engine + a relocating loader stub (`loader.c` → `loader.bin`) are built and wired; the live boot is demonstrated via direct GDB-stub injection (`boot_doom.py`). Fully-autonomous *non-GDB* delivery of the 4.6 MB engine+WAD over the 1999 browser's I/O is a documented staging limit (see below).

---

## Validation Status (emulated Dreamcast — Flycast + SH-4 GDB stub)

| Stage | Status |
| :-- | :-- |
| (1) Eden unauthenticated Java RCE | **Fully demonstrated end-to-end** — browser downloads + runs our JAR; full-screen takeover; device-ID leak. Hands-off, deterministic. |
| (2) `setRawDeviceID` fixed-addr overflow | **Verified** (IDA handler `0x8C04E0DC`; live write to `0x8C29ABE6+`). |
| (3) Fake-node plant + IM pointer corruption | **Verified** (payload places fake node + SH-4 stub; `*(0x8C29AC2C)` → fake node). |
| (4) Unlink → fn-ptr overwrite | **Validated live** — running the *real* gadget `sub_8C063F38` against our planted fake node overwrote `0x8C378B84` (`0x8C067506 → 0x8C29ADE8`, our stub). Arbitrary write → control-flow-pointer hijack proven on (emulated) hardware. |
| (5a) SH-4 stub execution | **Validated live** — driven to its `jsr`, the stub sets up `openURL(ctx, "http://…/PWNED_NATIVE")` correctly (native code runs). |
| (5b) Native DOOM payload | **Validated live** — full SH-4 DOOM boots and renders E1M1 to the framebuffer (`DOOM_E1M1_live_on_dreamcast.png`). |

**Honest open item — the fully-autonomous native auto-fire.** Stages 2–5 are individually validated; the one piece *not* closed is making the hijacked pointer fire **unattended in steady-state browsing**. Investigation determined this precisely: the IM gadget's objects (`*(0x8C3402F4)`, `*(0x8C29AC2C)`) are populated by the browser's **connection / dial-up / registration / modal-dialog subsystem** (the writer function references `file://drmstrt.htm`, `pwreg://reg0`, and the *"Unable to contact the host"* dialog), **not** by web-page rendering. We confirmed empirically that the render loop, a multi-frame page (fully loaded), and the HTTP "unable to load document" error all leave those globals NULL — so the gadget arms only during the connection-dialog window, and the unlink fires on that dialog's teardown. Closing the auto-fire requires capturing/exercising that connection-dialog state (a cold-boot dial-up capture). The arbitrary-write → native-exec primitive itself stands as validated.

**Methodology enabler (reusable).** Flycast's dynarec ignores software breakpoints on already-compiled blocks — which blocked every prior dynamic attempt. We defeated this with **`Debug.GDBWaitForConnection = yes`**: `dc_loadstate` flushes the dynarec cache (`bm_Reset` + `ResetCache`) and then halts for the debugger, so a breakpoint set on the now-cold target compiles in fresh and fires. This is how the live gadget behaviour and stack state were captured.

---

## Steps to Reproduce
Setup (emulator; hardware is analogous via DreamPi + rogue DNS):
1. Extract the PlanetWeb Web Browser 3.0 GDI; run it in Flycast with a real Dreamcast BIOS (`dc_boot.bin`). For native-stage work, build Flycast with the GDB server (stub on `:3263`).
2. Make `eden.planetweb.com` resolve to your machine (`poc/dns_redirect.py <ip> --all`) and redirect `:80 → :8137`. Run the rogue Eden server: `python3 poc/eden_mitm.py --chain takeover` (Bug #1) or `--chain nativedoom` (Bug #2 + DOOM).
3. Boot the browser and connect online.

**Bug #1 — Unauthenticated RCE (reliable, hands-off):**
4. The browser auto-runs the Eden client → GET `/edenclient.conf` → POST `/login` → discovery → subscribe → GET `/pwn.jar`.
5. The JAR's `Service.run()` executes (fully privileged), hijacks the browser to the takeover page and leaks the device ID. **= arbitrary code execution from a network position, no auth, no memory corruption.**

**Bug #2 — Native SH-4 code execution (escalation):**
6. The delivered service calls `sendMessage(100, payload)`. The payload overflows `0x8C29ABE6`, plants a fake IM node + an SH-4 stub, and points `0x8C29AC2C` at the fake node.
7. IM-object teardown runs the unlink (`sub_8C063F38` → `0x8C063FA8`), performing the arbitrary write: `*(0x8C3402F4)+0x3C` (the fn-ptr `0x8C378B84`) ← stub address.
8. When that pointer is invoked, the stub runs `openURL("http://eden.planetweb.com/PWNED_NATIVE")` → the rogue server logs **`GET /PWNED_NATIVE`** = native SH-4 code executed.
   * Reproducible validation of steps 6–7 over the GDB stub: `poc/validate_ridexploit.py` (writes the payload, runs the real gadget, reads back the overwritten pointer). Live gadget/stack capture: `poc/r15_capture.py`.

**DOOM payload:**
9. Java DOOM: `--chain jdoom` → the Eden chain pulls `doom.jar` + `doom.wad`; DOOM renders in the browser.
10. Native DOOM: `--chain nativedoom`; `poc/boot_doom.py` injects `build/doom.bin` + `wad/doom1.wad` into free RAM via the GDB stub and jumps to `0x8CC00000` → DOOM E1M1 renders to `0xA5600000`.

---

## Additional Artifacts
All under `dc_browser_extract/poc/`:
* `eden_mitm.py` — rogue Eden/HTTP server (full unauth-RCE chain; `--chain {takeover,jdoom,nativedoom,ridexploit,…}`).
* `src/org/junkyard/TakeoverService.java` — Bug #1 payload (full-screen takeover + device-ID leak) → `pwn_takeover.jar` (v45.3).
* `src/org/junkyard/RawDeviceIDExploit.java` — Bug #2 payload (the `setRawDeviceID` overflow + fake-node unlink + embedded SH-4 `openURL` stub) → `pwn_ridexploit.jar`.
* `src/org/junkyard/NativeDoomLoader.java` — native-DOOM orchestration (overflow + fake node + embedded `loader.bin`).
* `src/org/junkyard/doom/*.java` — the hands-off Java WAD+BSP DOOM engine → `doom.jar`.
* `native_doom/` — bare-metal SH-4 DOOM: `doomgeneric_dc.c` (framebuffer/timer platform layer), `dc_syscalls.c` (newlib glue + in-RAM WAD), `startup.s`, `dc.ld`, `loader.c`, `Makefile` → `doom.bin` + `loader.bin`.
* `boot_doom.py` — native-DOOM live boot via GDB stub; `validate_ridexploit.py` / `r15_capture.py` — live validation drivers.
* `DOOM_E1M1_live_on_dreamcast.png` — **proof: native SH-4 DOOM rendering E1M1 on the (emulated) Dreamcast.**
* `crashes/NATIVE_ACE_via_setRawDeviceID.md` — full native-chain writeup; IDA helper scripts in `poc/native/`.
* `build.sh` — builds all service JARs + stages `doom.bin`/`loader.bin`.

## Appendix — Key Addresses (1ST_READ.BIN @ 0x8C010000, no-ASLR)
| Symbol | Address | Role |
| :-- | :-- | :-- |
| Eden client entry | `com.planetweb.eden.client.Eden` | boot service walk (Bug #1) |
| `sendMessage` dispatcher | `0x8C04DF80` | Java→native bridge switch |
| `setRawDeviceID` handler (cmd 100) | `0x8C04E0DC` | `memcpy` overflow primitive |
| overflow dest (device-ID field) | `0x8C29ABE6` | fixed write base |
| IM node pointer | `0x8C29AC2C` (dst+0x46) | corrupt → fake node |
| unlink routine | `0x8C063F38` | teardown gadget |
| unlink write | `0x8C063FA8` | `mov.l r2,@(0x3C,r3)` |
| unlink dest base (IM object) | `0x8C3402F4` | write goes to `*(0x8C3402F4)+0x3C` |
| validated fn-ptr target | `0x8C378B84` | hot fn-ptr (64 call sites) |
| `openURL` (native) | `0x8C043C64` | stub callee |
| framebuffer (PVR SOF) | `0xA5600000` | RGB555 640×480, DOOM output |
| native DOOM entry | `0x8CC00000` | `doom.bin` `_start` |

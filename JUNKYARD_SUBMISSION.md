<!--
  ╔══════════════════════════════════════════════════════════════════╗
  ║  D I S T R I C T C O N   ·   J U N K Y A R D   S U B M I S S I O N ║
  ║  it's the year 2001. the modem is screaming. the demon is coming. ║
  ╚══════════════════════════════════════════════════════════════════╝
-->

# 🩸 RIP AND TEAR (THROUGH THE DREAMCAST'S WEB BROWSER) 🩸
### Unauthenticated RCE → native SH-4 **DOOM** on the Sega Dreamcast PlanetWeb Internet Browser v3.0

> *"You serve the DNS for a dead domain... and the console downloads its own doom."*
> Boot it. Dial up. Open one email. The demons render at 35 FPS on hardware that's been discontinued longer than some attendees have been alive.

---

## Proof of Eligibility
* **EOL Date?** **March 31, 2001** — Sega discontinued the Dreamcast (and exited the console-hardware business). PlanetWeb, Inc. (maker of the browser) is long dissolved, and its service backbone `eden.planetweb.com` has been dark for ~two decades. **24+ years EOL.** 💀
* **EOL Confirmed by Vendor?** **Yes.** Sega publicly announced the discontinuation of the Dreamcast in early 2001; both the platform vendor (Sega) and the software vendor (PlanetWeb) ceased to exist as going concerns.
* **EOL Date Source:** `[image: sega_dreamcast_discontinued_2001.png]` — screenshot of the discontinuation announcement / platform history.
  * URL: https://en.wikipedia.org/wiki/Dreamcast ("Discontinued: … March 31, 2001 (NA)") and PlanetWeb dissolution records. (Attach a clean screenshot of the EOL line for the packet.)

---

## Presentation Details
* **Speaker Names for Display:**

| Name | Handle | Phonetic Pronunciation (optional) | Socials (X, Instagram, LinkedIn) |
| :-- | :-- | :-- | :-- |
| Christopher Hernandez | `<your handle>` | n/a | `<@x / ig / linkedin — fill in>` |

* **Speaker socials, if any:** `<fill in — or "n/a">`

* **Coverterm for talk, for display:** **"PHONE HOME, RIP AND TEAR: Native DOOM on the Dreamcast's Browser, Served From a Dead Domain"**
  * (alt cuts if you want shorter: *"It Still Runs DOOM"* · *"Dial-Up to Demons"* · *"Hang Up & Hack: Owning the Dreamcast Browser"*)

---

## Target Details
* **Target Name/Model:** Sega Dreamcast — **PlanetWeb Internet Browser** ("Web Browser for Dreamcast")
* **Target Version:** **3.0 (USA)** — GD-ROM, runs on retail Dreamcast (Game ID `T31901N`)
* **Target Category:** **other software** *(a networked browser appliance shipped on a game console; SH-4 + PersonalJava 1.1.8 + the "Eden" service framework)*

---

## Proof of Disclosure
* **CVE (optional)?:** n/a — no CVE assigned (issuing against a vendor and platform that have been dead since the first Bush administration is… aspirational).
* **Coordinated Disclosure Date:** **N/A — vendor defunct.** Sega exited console hardware in 2001 and PlanetWeb, Inc. dissolved years ago. There is **no party to coordinate with**; the update server itself is the attack surface *because* it was abandoned.
* **Coordinated Disclosure Proof:** `[image: vendor_defunct_no_disclosure_party.png]` — n/a; documented vendor/platform end-of-life in lieu of a notification thread. (The exploit literally depends on the vendor being gone — see Description.)

---

## Vulnerability Details

### Product Overview
The **PlanetWeb Internet Browser v3.0** is the official "surf the web on your Dreamcast" disc from 2000–2001: a full web browser, email client, and online-service portal running on a 200 MHz Hitachi **SH-4**, with **16 MB of RAM**, **no MMU, no ASLR, no DEP, and no Java SecurityManager**. Online features are brokered by Sega/PlanetWeb's **"Eden"** service framework over plaintext HTTP to `eden.planetweb.com`. We chose it because it's the perfect Junkyard specimen: a *networked, code-downloading appliance* whose entire trust model rests on a backend that no longer exists — and because the only acceptable proof of total ownership of a games machine is, obviously, **DOOM**.

### Description
This is a full **unauthenticated, network-only** chain: from "answer a DNS query" to **native SH-4 code execution** running real id-tech **DOOM**, live, with no physical access and no jailbreak.

**🎯 Bug #1 — Eden service-subscription RCE (design flaw, CRITICAL, unauth).**
On boot the browser logs into Eden and walks: *login → discovery URL (from server XML) → subscribe → **service-JAR URL (server-controlled)***. It downloads that JAR over **plaintext HTTP**, reads `Main-Class`, and does `JarClassLoader.loadClass().newInstance().run()` — **with no SecurityManager installed and no signature verification**. The `Jar-Files:` manifest attribute even pulls *additional* jars from arbitrary URLs. Since `eden.planetweb.com` is a **dead domain**, anyone who answers DNS for it ships code the console runs **fully privileged**. 100% reliable, zero memory corruption. This is our foothold and our data pipe.

**🎯 Bug #2 — native MIME `name=` stack overflow (HIGH, PC control).**
The mail client's attachment handler `fn_application_x_dreamcas` (`0x8C04669C`) copies a MIME part's `name=` parameter **unbounded** into a 64-byte stack buffer, smashing the saved return address → **full SH-4 PC control**. (Byte-safe: the copy terminates on `0x00/0x20/0x22`, so the payload simply avoids them.) This is the pivot off the JVM onto bare metal.

**🎯 Bonus bugs — native image-parser hangs (DoS).** An in-browser fuzzer (mutated images served at per-request unique URLs to defeat the VMU page cache) found three decoder lock-ups reachable by a *served image alone*: **GIF LZW** with min-code-size = 12 (valid 2–8), **progressive JPEG SOF2** with component count Nf = 5 (max 4), and **GIF** logical screen 65535×65535. Each freezes the browser solid; all are credible memory-corruption leads, shipped here as confirmed DoS.

**🧨 The hard part — and the story.** Overwriting PR was easy. Making it *reliable*, on a black box, was the talk:
* **The stack moves.** The stack location at trigger time varies by **~32 KB** (browser call depth/JVM state), and there's **no `jmp @r15` / pivot gadget** in the image — so a hardcoded PR → on-stack sled was a literal coin flip (`0x60036003` fault loops on the misses).
* **The fix is delicious irony.** We use Bug-#1-class control of the **`setRawDeviceID` (cmd 100) unbounded memcpy primitive** — `memcpy(dst=0x8C29ABE6 [FIXED], src=attacker bytes, len=attacker)` — to **plant our 366-byte SH-4 loader stub at a deterministic address (`0x8C29ADE8`)** *before* the overflow. The email then just sets `saved-PR = 0x8C29ADE8`. **A "bug" (no bound check) became our reliability mechanism.** No sled, no stack dependence, fires every time.
* **Don't kill the patient.** That fixed buffer overlaps an interface-manager list-head at `+0x46`; zero it and the browser crashes. `getRawDeviceID` only reads back 8 bytes, so we can't preserve it — instead we write a **harmless fake node** there (its teardown-unlink targets scratch) and plant **last** to shrink the window.
* **3.8 MB onto 16 MB.** The mail parser is O(n²), so the payload can't ride in the email. Java **stages** doom + WAD over HTTP into one heap `byte[]`; the native stub scans for a magic tag and copies it into place. The emulated link **hangs** on a single 3.4 MB read (→ "PlanetWeb offline"), and PersonalJava 1.1.8 has **no `setRequestProperty`** (HTTP Range breaks class-load) and **`close()` won't unblock a hung read** — so we download in **32 KB chunks** (`?start=N&len=M`, `URL.openStream` only) and write the magic **last** so the scanner only ever finds a *complete* blob.
* **Then make DOOM actually run.** Trim the WAD (drop audio lumps; keep PNAMES/textures/levels or `R_Init` `I_Error`s), tetris WAD/engine/heap/zone into non-overlapping RAM, **live-read `FB_R_SOF1`** for the browser's real framebuffer (hardcoding it rendered off-screen → "frozen browser"), and tick the loop off SH-4 **TMU2**.

**🔧 How we saw inside the box:** a custom **Flycast build** with a GDB stub + a patch that dumps SH-4 fault context (epc/PR/BL/r15) and DOOM's debug log on any exception, plus live guest-RAM reads via `/proc/<pid>/mem`. Every fix above came from reading the actual machine state, not guessing.

**The payoff:** DNS MITM → Eden RCE → chunked-stage → plant stub at a fixed address → one email → native DOOM, **running live and animating** on a Dreamcast browser. Reliable. Reproducible. One command.

### Steps to Reproduce
**Setup:** Flycast (with a real DC BIOS) or a real Dreamcast + DreamPi; the rogue Eden server (`eden_mitm.py`); DNS for `eden.planetweb.com` pointed at your box. `DCNet=no` (local PPP).

1. **Redirect DNS.** Answer `eden.planetweb.com` → your machine (`dns_redirect.py`, or DreamPi on hardware). Ensure traffic to it reaches `eden_mitm.py` (port 80 → 8137 if needed).
2. **Stand up the chain + browser, one shot:**
   ```
   python3 poc/run_doom.py --native     # builds doom.bin + jar + stub, starts Eden, boots the browser
   ```
   (subsequent runs: just `python3 poc/run_doom.py`)
3. **Go online** in the browser (dial up / connect) and **stay on the web-browser page**. The launcher prints a live **WAD staging progress bar**.
4. **Wait for the beep** — the launcher prints `✅ READY — OPEN THE 'DOOM-STAGE' EMAIL NOW` once the blob is staged **and** the stub is planted at `0x8C29ADE8`.
5. **Open the `DOOM-STAGE` email.** The MIME `name=` overflow fires → `saved-PR = 0x8C29ADE8` → the planted stub scans the heap for the magic blob, copies doom→`0x8CC00000` + WAD→`0x8C450000`, sets up video/timing, and **jumps into native DOOM**. 🤘

*(What's happening underneath: Eden subscription RCE loads `pwn_stagedoom.jar`; StageDoom chunked-downloads + plants; the overflow is the trigger. See the memory-map + stage-by-stage slides in the deck.)*

### Additional Artifacts
* **`poc/backups/doom_working_*.tar.gz`** — the complete, reproducible chain (8.5 MB): StageDoom.java (chunked staging + fixed-address plant), the SH-4 stub builder, `eden_mitm.py` (chunk server), the live-framebuffer `doomgeneric_dc.c`, the built `pwn_stagedoom.jar` / `doom.bin` / `stub.bin`, the trimmed `doom1_trim.wad`, and the patched Flycast `sh4_interrupts.cpp`, plus `BACKUP_README.md`.
* **`poc/run_doom.py`** — one-shot launcher (deploy → Eden → boot → watch staging → "READY" beep).
* **`poc/slides/districtcon_doom.html`** — the talk deck (self-contained), incl. the **16 MB memory map** and the **stage-by-stage memory-evolution** diagrams.
* **`poc/crashes/`** — minimal PoCs for the three parser-hang DoS bugs (e.g., 35-byte `HANG_gif_lzw_codesize12.gif`) + findings writeups.
* **Native-RE notes** — `poc/native/NATIVE_RECON.md` (full 27-code `sendCommand` map, the overflow + BSS analysis).
* **Suggested demo capture** — `[image/video: doom_running_on_dreamcast_browser.mp4]` + `[image: ready_console_banner.png]` for the packet.

---

> 🕹️ **24 years EOL. No vendor. No sandbox. No mercy.**
> *The Dreamcast said "It's Thinking." Turns out it was thinking about demons the whole time.*

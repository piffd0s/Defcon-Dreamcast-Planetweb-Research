# Native recon — PlanetWeb Dreamcast Browser v3.0 (`1ST_READ.BIN`, SH4)

Goal: reach **native** (full-speed) DOOM by turning the Java RCE into native SH4
code execution. The only Java→native gateway is
`NativeSystemInterface.sendCommand(int cmd, Object, Object)`. This is the static
+ dynamic recon of that bridge.

## Tooling (in this dir)
- **`analyze_report.py`** — scores the live `native_report.txt` sweep (from the
  `native` chain) for exploit promise: undocumented-but-live codes, type-confusion
  casts, hang/crash gaps, high-value known handlers. `--selftest` runs on synthetic data.
- **`native_recon.py`** — static SH4 RE: finds the `sendCommand` dispatcher and
  recovers the **command → handler address** map (capstone `CS_ARCH_SH`).

## Binary facts
- `1ST_READ.BIN`: 4,432,064 bytes, **unscrambled SH4**, loads at `0x8c010000`
  (opens with SH4 `nop`/SR setup). Fully disassemblable with capstone 5.x `CS_ARCH_SH`.
- Native bridge is real: embedded class `com/planetweb/eden/client/system/NativeSystemInterface$$native`
  exposes `sendCommand (ILjava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;`
  and `registerSystemListener`.

## The dispatcher — `0x8c04df80` (switch at `0x8c04dfa0`)
Small codes use `cmp/eq #imm,r0`; codes >127 use a 16-bit literal pool
(`0x8c04e070+`) with `cmp/eq r1,r0`; each match `bra`s to its handler. Recovered
map (reproduce with `python3 native_recon.py`):

| code | handler | command |
|------|---------|---------|
| 1 | `0x8c04e0c6` | sendEdenClientStarted |
| 3 | `0x8c04e626` | sendEdenClientFinishedInit |
| **100** | **`0x8c04e0dc`** | **setRawDeviceID — WRITES FLASH** |
| 101 | `0x8c04e100` | getRawDeviceID |
| 102/104 | `0x8c04e10c` | getMake / getOEM (shared) |
| 103 | `0x8c04e118` | getModel |
| 105 | `0x8c04e124` | getUserAgent |
| 106 | `0x8c04e130` | getBrowserRevision |
| 107 | `0x8c04e13c` | getDeviceRevision |
| **111** | **`0x8c04e626`** | **setSecurityFile — NATIVE PARSER of attacker byte[]** |
| 200 | `0x8c04e14a` | queryNetworkState |
| 203 | `0x8c04e158` | networkRequestConnect |
| 300 | `0x8c04e16e` | openURL |
| 301 | `0x8c04e1d0` | goBack |
| 310/312/313 | `0x8c04e1da/e1e2/e1ea` | IM notifies |
| 400 | `0x8c04e21c` | isFeatureEnabled |
| 401 | `0x8c04e25c` | setFeatureEnabled |
| 1000 | `0x8c04e308` | vmuGetAvailableStorage |
| 1001 | `0x8c04e3b8` | vmuBeginUpdate |
| **1003** | **`0x8c04e408`** | **vmuPutFile (attacker filename + bytes)** |
| 1004 | `0x8c04e55e` | vmuDeleteFile |
| 1005 | `0x8c04e60a` | vmuGetFile |
| 1006 | `0x8c04e618` | vmuFreeFile |

(`1002` resolves ambiguously to `0x8c04e094` — a dispatcher-internal label;
re-disasm to confirm. `3` and `111` share `0x8c04e626`, likely a common stub that
re-dispatches on the args — worth confirming.)

## Crown-jewel targets (next: disassemble for the overflow primitive)
1. **`111` setSecurityFile `@0x8c04e626`** — native parser of an attacker-controlled
   `byte[]`. A parser of attacker bytes is the classic memory-corruption surface;
   if it copies into a fixed buffer without bounds, that's a controllable overflow.
2. **`100` setRawDeviceID `@0x8c04e0dc`** — copies attacker bytes to FLASH;
   length handling is the thing to audit (and it's a persistence/brick primitive).
3. **`1003` vmuPutFile `@0x8c04e408`** — attacker filename + bytes → path/length bugs.
4. **`300` openURL `@0x8c04e16e`** — native URL/scheme string handling.

## Path to native DOOM
1. Run the `native` chain on Flycast → `native_report.txt`; `analyze_report.py`
   confirms which codes are live/reachable and flags undocumented ones.
2. Disassemble the crown-jewel handlers (resync capstone) to find an unbounded
   copy of the attacker `byte[]`/`String` into a fixed buffer → stack/heap overflow.
3. Build an SH4 ROP/shellcode payload (no SecurityManager; we already control the
   `byte[]` from Java) to map and jump to a **KallistiOS DOOM** binary (`/doom.bin`,
   already staged by `NativeProbe`).

Status: **dispatcher + full handler map recovered (done).** Weaponizing a specific
handler needs handler-body disasm + the live reachability map from the emulator.

---

## Handler-body analysis (`native_handlers.py`)

### `setSecurityFile` (code 111) — NOT a target (native no-op)
Code 111 (and 3) `bra` straight to `0x8c04e626`, which is just the function
**epilogue** (`mov #0,r0; lds.l/mov.l @r15+ restores; rts`). So native
`setSecurityFile` does nothing and returns null — no parser, no copy. Useful
negative result: don't spend time here.

### `setRawDeviceID` (code 100) — the overflow primitive  ✔
Handler block (`~0x8c04e0dc`):
```
mov.l  @r15, r6              ; r6 = LENGTH  (from the VM-marshalled stack arg, not an immediate)
mov.l  0x8c04e19c, r4        ; r4 = DST = 0x8c29abe6   (fixed global)
mov.l  0x8c04e1a4, r3        ; r3 = 0x8c07d680
jsr    @r3                   ; memcpy(dst, src, len)
mov    r12, r5               ; r5 = SRC = attacker byte[] data
```
- `0x8c07d680` is a generic **`memcpy(r4=dst,r5=src,r6=len)`** (alignment check,
  long/word/byte copy loops, memmove overlap handling).
- **DST `0x8c29abe6` is a fixed global**; `getRawDeviceID` (code 101) returns
  exactly **8 bytes** from it → the device-ID field is logically 8 bytes.
- **Length is a variable** (`mov.l @r15,r6`, not `mov #8,r6`) sourced from the
  VM's array marshalling → **attacker-controlled** (we call
  `setRawDeviceID(byte[])` from our privileged service with any length). No bound
  check is present in the handler.

=> **`memcpy(0x8c29abe6, attacker_bytes, attacker_len)` into an 8-byte field** =
a **linear global/BSS overflow at a fixed, known address** with attacker-controlled
length and contents.

### Overflow target layout
`0x8c29abe6` sits in a zeroed BSS region. The neighbor at **`0x8c29abee` (DST+8)**
is referenced by **12 code sites**, but all accesses are `mov.b` (byte
load/store) → it's a **state flag, not a function pointer**. So the immediate
overrun corrupts flags/state, not a code pointer. Control-flow hijack needs to
reach a **function pointer / structure further out in BSS**.

## Remaining to weaponize (next steps)
1. **Dynamic confirm** on Flycast: `setRawDeviceID(new byte[256])` then observe
   corruption at `0x8c29abe6+` (rules out any clamp in the VM marshalling stub).
2. **Map the BSS** beyond `0x8c29abe6` for the nearest function pointer / callback
   table / object with a vtable-like field reachable by a longer copy.
3. Overflow to that pointer → redirect to an SH4 stub that maps + jumps to the
   staged KallistiOS **`doom.bin`**. (We already have privileged Java exec to set
   up cache/registers and to deliver the payload bytes as the `byte[]`.)

Tools: `native_handlers.py <addr> [len]` disassembles any handler/function with
literal-load tracking + call-target resolution (capstone SH4, 2-byte resync).

---

## BSS map from the overflow → control-flow target (`native_bssmap.py`)

The overflow copies upward from `DST = 0x8c29abe6` through zeroed BSS. Mapping the
globals by how code *uses* them (BSS is zero in the image, so classify by code,
not data):

| +off | global | class | refs | meaning |
|------|--------|-------|------|---------|
| +0x00 | `0x8c29abe6` | (device-ID) | 1 | 8-byte device-ID field (the copy dst) |
| +0x08 | `0x8c29abee` | BYTE flag | 12 | state byte |
| **+0x42** | **`0x8c29ac28`** | **object ptr** | **32** | **core context/object pointer — virtual-called** |
| +0x76 | `0x8c29ac5c` | hot base | 50 | error-code switch base |
| +0x276.. | `0x8c29ae5c`+ | struct array | ~12 ea | stride-0x100 struct array (indirect) |
| +0xc7a | `0x8c29b860` | ptr table | 6 | indexed pointer table |

### Nearest control-flow primitive — `0x8c29ac28` (`DST+0x42`)
Code pattern (e.g. `0x8c01036e`): `r3 = &0x8c29ac28; r4 = *r3` → the stored
pointer is loaded and used as an object. Across its 32 sites it is:
- **virtual-called** (`obj = *V; call obj->field`) at **`0x8c032476`** and **`0x8c034b86`**
- **written-through** (`*(*V) = x`) at **`0x8c0378be`**

### Full overflow → native-exec chain
1. From our privileged Java service call
   `SystemInterface.setRawDeviceID(new byte[0x46])` — native does
   `memcpy(0x8c29abe6, bytes, 0x46)` with **no bound check**.
2. Bytes `[0x42:0x46]` land on the object pointer `0x8c29ac28`; set them to the
   address of a **fake object** in attacker-controlled memory (a pinned Java
   `byte[]` / known scratch region whose contents we also supply).
3. The fake object's method/field (at the displacement used by the call sites)
   points to our **SH4 stub**.
4. When the engine next reaches `0x8c032476` / `0x8c034b86`, it does
   `obj=*0x8c29ac28; call obj->field` → **jumps to our stub** → set up cache,
   load + run the staged KallistiOS **`doom.bin`**.

This is a fixed-address, length-controlled BSS overflow whose nearest neighbor
(+0x42) is a virtual-called object pointer → a clean control-flow hijack with a
tiny (~70-byte) overwrite. **Confirm dynamically on Flycast** (verify no clamp in
the VM array-marshalling stub, and the fake-object displacement) before relying on it.

Tools added: `native_bssmap.py [window]` — enumerates + classifies BSS globals
after `DST` and reports the nearest control primitive.



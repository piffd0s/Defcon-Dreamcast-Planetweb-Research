#!/usr/bin/env bash
# Rebuild native DOOM (doomgeneric_dc.c changed: live-read framebuffer), re-extract the
# shifted g_wad_addr/g_wad_size globals into doom_full.py, then rebuild stub + jar.
set -e
ND=/media/adversary/Storage/dc_browser_extract/poc/native_doom
POC=/media/adversary/Storage/dc_browser_extract/poc

echo "[*] building native doom.bin (sh-elf-gcc)..."
cd "$ND"
make 2>&1 | tail -4

echo "[*] re-extracting g_wad globals from doom.map -> doom_full.py..."
python3 - <<'PY'
import re
mp = open("/media/adversary/Storage/dc_browser_extract/poc/native_doom/doom.map").read()
def addr(sym):
    # find the line that names the symbol, take the 0x address on (or just above) it
    lines = mp.splitlines()
    for i, ln in enumerate(lines):
        if re.search(r"\b_?%s\b" % sym, ln):
            for cand in (ln, lines[i-1] if i else ""):
                m = re.search(r"0x([0-9a-fA-F]{6,16})", cand)
                if m:
                    a = int(m.group(1), 16) & 0xFFFFFFFF
                    if 0x8C000000 <= a < 0x8D000000: return a
    return None
gwa, gws = addr("g_wad_addr"), addr("g_wad_size")
assert gwa and gws, "could not find g_wad_addr/g_wad_size in doom.map"
print("    g_wad_addr=0x%08X  g_wad_size=0x%08X" % (gwa, gws))
df = "/media/adversary/Storage/dc_browser_extract/poc/doom_full.py"
s = open(df).read()
s2 = re.sub(r"GWA,GWS=0x[0-9A-Fa-f]+,0x[0-9A-Fa-f]+",
            "GWA,GWS=0x%08X,0x%08X" % (gwa, gws), s)
assert s2 != s, "GWA,GWS line not found/updated in doom_full.py"
open(df, "w").write(s2)
print("    doom_full.py updated")
PY

echo "[*] rebuilding jar + copying doom.bin..."
cd "$POC"
bash build.sh > /tmp/build.log 2>&1 && echo "    jar OK" || { echo "    BUILD FAILED"; tail -8 /tmp/build.log; exit 1; }
echo "[*] regenerating stub.bin + email..."
python3 build_stage_email.py
echo "[+] DONE: doom.bin=$(stat -c%s build/doom.bin)B  stub.bin=$(stat -c%s build/stub.bin)B"

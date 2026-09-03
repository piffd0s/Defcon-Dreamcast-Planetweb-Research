#!/usr/bin/env bash
# Build all DistrictCon Junkyard chains for PlanetWeb Dreamcast Browser v3.0.
# Everything compiles to PersonalJava 1.1.8 bytecode (class v45.3), linking ONLY
# against the device runtime (classes.zip) + Eden classes (planetweb.jar).
#
# Produces:
#   build/pwn_splash.jar  chain "splash"  -> browser-hijack proof
#   build/pwn_jdoom.jar   chain "jdoom"   -> real WAD/BSP DOOM (pulls doom.jar)
#   build/pwn_native.jar  chain "native"  -> sendCommand bridge recon (-> native DOOM)
#   build/doom.jar        the DOOM engine (used by the jdoom chain via Jar-Files)
set -e
cd "$(dirname "$0")"
ROOT=/media/adversary/Storage/dc_browser_extract
JAVAC="$ROOT/tools/javac8"; JART="$ROOT/tools/jar8"
BOOT="$ROOT/dc_extracted/track03_files/JAVA/CLASSES.ZIP"
EDEN="$ROOT/dc_extracted/track03_files/JAVA/PLANETWEB.JAR"
HOST="${EDEN_HOST:-eden.planetweb.com}"
FLAGS="-source 1.3 -target 1.1 -bootclasspath $BOOT"
filt(){ grep -v "warning: \[options\]" | grep -vE "^[0-9]+ warning|Note:|unchecked|recompile" || true; }

rm -rf build && mkdir -p build/svc build/doom build/meta

echo "[*] DOOM engine -> doom.jar (v45.3, AWT 1.1)"
"$JAVAC" $FLAGS -d build/doom src/org/junkyard/doom/*.java 2>&1 | filt
"$JART" cf build/doom.jar -C build/doom .

echo "[*] services -> v45.3 against device classes"
"$JAVAC" $FLAGS -classpath "$EDEN" -d build/svc \
    src/org/junkyard/Junk.java src/org/junkyard/Pwn.java \
    src/org/junkyard/SplashService.java src/org/junkyard/NativeProbe.java \
    src/org/junkyard/OverflowTest.java src/org/junkyard/FuzzNav.java src/org/junkyard/TakeoverService.java \
    src/org/junkyard/RawDeviceIDExploit.java src/org/junkyard/NativeDoomLoader.java \
    src/org/junkyard/HeapProbe.java src/org/junkyard/ArmExploit.java src/org/junkyard/LoopArm.java \
    src/org/junkyard/StageDoom.java 2>&1 | filt

mkjar(){ # name mainclass extraline serviceclass
  local jar="$1" main="$2" extra="$3" cls="$4"
  { echo "Manifest-Version: 1.0"; echo "Main-Class: $main"; [ -n "$extra" ] && echo "$extra"; } > build/meta/$jar.mf
  "$JART" cfm build/$jar.jar build/meta/$jar.mf \
      -C build/svc org/junkyard/$cls.class -C build/svc org/junkyard/Junk.class
}
mkjar pwn_splash org.junkyard.SplashService "" SplashService
mkjar pwn_jdoom  org.junkyard.Pwn "Jar-Files: http://$HOST/doom.jar" Pwn
mkjar pwn_native org.junkyard.NativeProbe "" NativeProbe
mkjar pwn_overflow org.junkyard.OverflowTest "" OverflowTest
mkjar pwn_fuzz org.junkyard.FuzzNav "" FuzzNav
mkjar pwn_takeover org.junkyard.TakeoverService "" TakeoverService
mkjar pwn_ridexploit org.junkyard.RawDeviceIDExploit "" RawDeviceIDExploit
mkjar pwn_nativedoom org.junkyard.NativeDoomLoader "" NativeDoomLoader
mkjar pwn_heapprobe org.junkyard.HeapProbe "" HeapProbe
mkjar pwn_armexploit org.junkyard.ArmExploit "" ArmExploit
mkjar pwn_looparm org.junkyard.LoopArm "" LoopArm
mkjar pwn_stagedoom org.junkyard.StageDoom "" StageDoom

echo "[*] verify class versions"
python3 - <<'PY'
import zipfile
def v(j,c):
    b=zipfile.ZipFile(j).read(c); return "%d.%d"%(b[6]<<8|b[7],b[4]<<8|b[5])
checks=[("build/pwn_splash.jar","org/junkyard/SplashService.class"),
        ("build/pwn_jdoom.jar","org/junkyard/Pwn.class"),
        ("build/pwn_native.jar","org/junkyard/NativeProbe.class"),
        ("build/doom.jar","org/junkyard/doom/DoomShell.class"),
        ("build/doom.jar","org/junkyard/doom/DoomEngine.class")]
for j,c in checks:
    ver=v(j,c); print("    %-22s %-34s v%s %s"%(j,c,ver,"OK" if ver.startswith("45") else "WRONG"))
PY
echo "[+] done. chains: splash | jdoom | native   (engine: doom.jar)"

# preserve the native in-memory-DOOM binaries (built separately in native_doom/)
[ -f native_doom/doom.bin ]   && cp native_doom/doom.bin   build/doom.bin
[ -f native_doom/loader.bin ] && cp native_doom/loader.bin build/loader.bin
echo "[*] native DOOM: build/doom.bin + build/loader.bin staged"

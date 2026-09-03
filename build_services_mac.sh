#!/bin/bash
# Mac-native rebuild of the Eden service jars. build.sh has hardcoded Linux paths
# (/media/adversary/...) and does `rm -rf build`, so it can't run here. This mirrors it
# using the Rosetta JDK 8 (same toolchain as build_calc.sh) and the local bootclasspath.
# Rebuilds doom.jar + every pwn_*.jar into build/. Does NOT touch build/pwn_calc.jar
# (run build_calc.sh for that).
set -e
ROOT="$(cd "$(dirname "$0")" && pwd)"; cd "$ROOT"
JH="tools/jdk8u502-b07/Contents/Home"
JAVAC=(arch -x86_64 "$JH/bin/javac"); JAR=(arch -x86_64 "$JH/bin/jar")
BOOT="CLASSES.ZIP"; EDEN="PLANETWEB.JAR"
HOST="${EDEN_HOST:-eden.planetweb.com}"
FLAGS=(-source 1.3 -target 1.1 -bootclasspath "$BOOT")
filt(){ grep -viE "warning: \[options\]|^[0-9]+ warning|Note:|bootstrap|obsolete|source value|target value|will not compile|To suppress" || true; }

rm -rf build/svc build/doom build/meta
mkdir -p build/svc build/doom build/meta

echo "[*] DOOM engine (java) -> doom.jar"
"${JAVAC[@]}" "${FLAGS[@]}" -d build/doom src/org/junkyard/doom/*.java 2>&1 | filt
"${JAR[@]}" cf build/doom.jar -C build/doom .

echo "[*] services -> v45.3 against device classes"
"${JAVAC[@]}" "${FLAGS[@]}" -classpath "$EDEN" -d build/svc \
    src/org/junkyard/Junk.java src/org/junkyard/Pwn.java \
    src/org/junkyard/SplashService.java src/org/junkyard/NativeProbe.java \
    src/org/junkyard/OverflowTest.java src/org/junkyard/FuzzNav.java src/org/junkyard/TakeoverService.java \
    src/org/junkyard/RawDeviceIDExploit.java src/org/junkyard/NativeDoomLoader.java \
    src/org/junkyard/HeapProbe.java src/org/junkyard/ArmExploit.java src/org/junkyard/LoopArm.java \
    src/org/junkyard/StageDoom.java 2>&1 | filt

mkjar(){ # name mainclass extraline serviceclass
  local jar="$1" main="$2" extra="$3" cls="$4"
  { echo "Manifest-Version: 1.0"; echo "Main-Class: $main"; [ -n "$extra" ] && echo "$extra"; } > build/meta/$jar.mf
  # CRITICAL: include the service class, its ANONYMOUS INNER classes ($1,$2,... -- e.g. the
  # throwaway-thread Runnables in StageDoom), and Junk (+ its inners). Missing the $N classes
  # = NoClassDefFoundError at the first `new Runnable(){}` and the service silently dies.
  local a=()
  for f in build/svc/org/junkyard/$cls.class build/svc/org/junkyard/$cls\$*.class \
           build/svc/org/junkyard/Junk.class build/svc/org/junkyard/Junk\$*.class; do
    [ -e "$f" ] && a+=(-C build/svc "org/junkyard/$(basename "$f")")
  done
  "${JAR[@]}" cfm build/$jar.jar build/meta/$jar.mf "${a[@]}"
}
mkjar pwn_splash    org.junkyard.SplashService  "" SplashService
mkjar pwn_jdoom     org.junkyard.Pwn "Jar-Files: http://$HOST/doom.jar" Pwn
mkjar pwn_native    org.junkyard.NativeProbe    "" NativeProbe
mkjar pwn_overflow  org.junkyard.OverflowTest   "" OverflowTest
mkjar pwn_fuzz      org.junkyard.FuzzNav        "" FuzzNav
mkjar pwn_takeover  org.junkyard.TakeoverService "" TakeoverService
mkjar pwn_ridexploit org.junkyard.RawDeviceIDExploit "" RawDeviceIDExploit
mkjar pwn_nativedoom org.junkyard.NativeDoomLoader "" NativeDoomLoader
mkjar pwn_heapprobe org.junkyard.HeapProbe      "" HeapProbe
mkjar pwn_armexploit org.junkyard.ArmExploit    "" ArmExploit
mkjar pwn_looparm   org.junkyard.LoopArm        "" LoopArm
mkjar pwn_stagedoom org.junkyard.StageDoom      "" StageDoom

echo "[+] built jars:"; ls -1 build/*.jar | sed 's/^/    /'

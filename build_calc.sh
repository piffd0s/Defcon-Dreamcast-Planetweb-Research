#!/usr/bin/env bash
# build_calc.sh -- build pwn_calc.jar (the Eden RCE 'calc' payload: an AWT calculator)
# to PersonalJava 1.1.8 bytecode (class v45.3) against the device runtime. Standalone;
# does NOT touch build.sh or the DOOM jars.
set -e
cd "$(dirname "$0")"
JH="$(ls -d tools/jdk8u*/Contents/Home 2>/dev/null | head -1)"
[ -n "$JH" ] || { echo "!! JDK 8 not found under tools/ -- see README (Adoptium 8 tarball)"; exit 1; }
JAVAC=(arch -x86_64 "$JH/bin/javac"); JAR=(arch -x86_64 "$JH/bin/jar")
rm -rf build/calc && mkdir -p build/calc
"${JAVAC[@]}" -source 1.3 -target 1.1 -bootclasspath CLASSES.ZIP -classpath PLANETWEB.JAR \
    -d build/calc src/org/junkyard/Junk.java src/org/junkyard/Calculator.java src/org/junkyard/CalcService.java
printf 'Manifest-Version: 1.0\nMain-Class: org.junkyard.CalcService\n' > build/calc.mf
"${JAR[@]}" cfm build/pwn_calc.jar build/calc.mf -C build/calc .
python3 - <<'PY'
import zipfile
z=zipfile.ZipFile("build/pwn_calc.jar")
bad=[n for n in z.namelist() if n.endswith(".class") and (z.read(n)[6]<<8|z.read(n)[7])!=45]
print("[+] pwn_calc.jar built, all v45.3" if not bad else "[!] WRONG class version: %s"%bad)
PY

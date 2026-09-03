#!/usr/bin/env bash
# build_flycast.sh -- build the custom Flycast (GDB stub + SH-4 fault dump) on macOS.
#
# Upstream's macOS path (shell/apple/generate_xcode_project.command) needs the full
# Xcode app and the Vulkan SDK. This builds the same thing with Command Line Tools
# + cmake/ninja + OpenGL instead, and applies the two patches this project needs.
#
#   mac/build_flycast.sh            # clone if needed, patch, configure, build, sign
#   mac/build_flycast.sh --rebuild  # skip the clone, just rebuild
set -euo pipefail
source "$(dirname "$0")/env.sh"
PATCHES="$POC/mac/patches"
export PATH="/opt/homebrew/bin:$PATH"

for t in cmake ninja git; do
  command -v "$t" >/dev/null || { echo "!! missing $t -- brew install $t" >&2; exit 1; }
done

if [ ! -d "$FLYCAST_SRC/.git" ]; then
  echo "[*] cloning flycast"
  mkdir -p "$(dirname "$FLYCAST_SRC")"
  git clone --recursive --depth 1 https://github.com/flyinghead/flycast.git "$FLYCAST_SRC"
fi

cd "$FLYCAST_SRC"

# A --recursive clone that gets interrupted leaves submodules registered but with
# empty working trees, which shows up as a confusing "does not contain a
# CMakeLists.txt" error. Fill in anything empty. oboe is Android-only: skip it,
# it is large and never compiled here.
echo "[*] checking submodules"
for p in $(git submodule status --recursive | awk '{print $2}'); do
  case "$p" in */oboe) continue ;; esac
  if [ -z "$(ls -A "$p" 2>/dev/null | grep -v '^\.git$')" ]; then
    echo "    populating $p"
    git submodule update --init --depth 1 --recursive "$p" >/dev/null 2>&1 \
      || git -C "$p" checkout -f HEAD >/dev/null 2>&1 || true
  fi
done

echo "[*] applying patches"
for p in "$PATCHES"/*.patch; do
  if git apply --reverse --check "$p" >/dev/null 2>&1; then
    echo "    already applied: $(basename "$p")"
  else
    git apply "$p" && echo "    applied: $(basename "$p")"
  fi
done

# USE_VULKAN=OFF -> OpenGL only, so no Vulkan SDK / MoltenVK needed.
# ENABLE_GDB_SERVER=ON -> the :3263 SH-4 stub (OFF upstream) that the PoC drives.
echo "[*] configuring"
cmake -B build -G Ninja \
  -DCMAKE_BUILD_TYPE=Release \
  -DCMAKE_OSX_ARCHITECTURES="$(uname -m)" \
  -DUSE_VULKAN=OFF \
  -DUSE_BREAKPAD=NO \
  -DENABLE_GDB_SERVER=ON >/dev/null

echo "[*] building (this takes a few minutes)"
cmake --build build -j "$(sysctl -n hw.ncpu)"

# Apple Silicon: without a JIT entitlement the kernel refuses the contiguous
# 512 MB reservation the ARM64 dynarec needs, and Flycast dies at startup with
# "Verify Failed : &mem_b[0] == ... driver.cpp:349". Ad-hoc signing is enough.
echo "[*] signing with JIT entitlements"
ENT="$(mktemp -t flycast_jit).entitlements"
cat > "$ENT" <<'EOF'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>com.apple.security.cs.allow-jit</key><true/>
	<key>com.apple.security.cs.allow-unsigned-executable-memory</key><true/>
	<key>com.apple.security.cs.disable-executable-page-protection</key><true/>
	<key>com.apple.security.cs.disable-library-validation</key><true/>
</dict>
</plist>
EOF
codesign --force --sign - --entitlements "$ENT" "$FLYCAST_APP"
rm -f "$ENT"

echo
echo "[+] built: $FC"
codesign -d --entitlements - "$FLYCAST_APP" 2>&1 | grep -q allow-jit && echo "[+] JIT entitlement present"
strings "$FC" | grep -q DOOMDBG && echo "[+] SH-4 fault-dump patch present"
echo "    smoke test: mac/flycast.sh --no-net"

#!/usr/bin/env bash
# deploy.sh -- rebuild the stagedoom jar + regenerate the native stub/email, in one step.
set -e
cd /media/adversary/Storage/dc_browser_extract/poc
echo "[*] building jars..."
bash build.sh > /tmp/build.log 2>&1 && echo "    jar OK" || { echo "    BUILD FAILED"; tail -5 /tmp/build.log; exit 1; }
echo "[*] regenerating stub.bin + email..."
python3 build_stage_email.py
echo "[*] stub.bin: $(stat -c%s build/stub.bin) bytes ; jar: $(stat -c%s build/pwn_stagedoom.jar) bytes"
echo "[+] deployed. eden serves the jar fresh per request -- no eden restart needed."

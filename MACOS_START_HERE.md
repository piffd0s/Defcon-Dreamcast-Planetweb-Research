# Start here (macOS)

This folder is the macOS-ported working copy of `dreamcast/`. It was created because
`~/Desktop/defcon/dreamcast` is owned by root and could not be written to.

- Full notes: **`mac/README_MACOS.md`**
- Build the emulator: `mac/build_flycast.sh` (already built — `src-build/flycast-src/build/Flycast.app`)
- Smoke test: `mac/flycast.sh --no-net`  → expect `Game ID is [T31901N]`
- Demos: `sudo mac/start_demo.sh splash|jdoom|stagedoom`, or `python3 run_doom.py`

## Relative to `dreamcast/`

Recovered from `backups/doom_working_20260617_213512.tar.gz` (missing from `dreamcast/`):
`eden_mitm.py`, `make_wad.py`, `run_full_demo.py`, `RUNBOOK.md`, `start_eden.sh`,
`fc_clean_boot.sh`, `fuzz_autorun.py`, `class_fuzz_gdb.py`, `jpeg_overflow.py`,
`sh4_stub.py`, `fc_snapshot.py`, `backup_poc.sh`, `magic.txt`, `mail_subject.txt`.

Added: `mac/` (env, build, launcher, demo runner, Flycast patches, README),
`fb_capture.py`, `src-build/flycast-src` (patched Flycast + build).

Changed: `run_doom.py` — repo-relative paths, calls the `mac/` helpers.

Everything else is byte-identical to `dreamcast/`. The originals in `dreamcast/`
were not modified.

To fold this back into `dreamcast/` once it is writable:

    sudo chown -R $(whoami):staff ~/Desktop/defcon/dreamcast
    rsync -a ~/Desktop/defcon/dreamcast-mac/ ~/Desktop/defcon/dreamcast/

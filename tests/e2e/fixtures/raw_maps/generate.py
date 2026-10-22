#!/usr/bin/env python3
"""Generate the committed raw-dump + memory-map fixture for the e2e suite.

``sample.bin`` is a flat raw dump (three 4 KiB regions back to back) and
``process_layout.maps`` its ``/proc/<pid>/maps`` listing. The map is named
UNLIKE the dump on purpose: it is not auto-detected as a sidecar, so the
wizard previews the dump as ``layout: "none"`` until the user points the
Regions step at the map.

    python tests/e2e/fixtures/raw_maps/generate.py
"""

from pathlib import Path

HERE = Path(__file__).resolve().parent
PAGE = 4096

MAPS = """\
00400000-00401000 r-xp 00000000 08:01 1234 /usr/bin/sample
01000000-01001000 rw-p 00000000 00:00 0 [heap]
7ffd0000-7ffd1000 rw-p 00000000 00:00 0 [stack]
"""


def main() -> None:
    blob = b"".join(bytes([fill]) * PAGE for fill in (0x90, 0x41, 0x53))
    (HERE / "sample.bin").write_bytes(blob)
    (HERE / "process_layout.maps").write_text(MAPS)
    print(f"wrote {HERE / 'sample.bin'} ({len(blob)} bytes) + process_layout.maps")


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""Generate the committed Android regioned-raw fixture for the e2e suite.

``app_process.bin`` is a flat one-page-per-entry raw dump of the ~60
mappings in ``tests/fixtures/android/app_process_arm64.maps``; the maps file
is copied next to it as ``app_process.maps`` so the wizard auto-detects it
as a sidecar (layout ``maps``, platform ``android``).

    python tests/e2e/fixtures/android_maps/generate.py
"""

import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[3]
sys.path.insert(0, str(REPO / "tests" / "fixtures" / "android"))

from generate_app_process_bin import write_app_process_bin  # noqa: E402


def main() -> None:
    dest = write_app_process_bin(HERE / "app_process.bin")
    print(f"wrote {dest} ({dest.stat().st_size} bytes) + {dest.with_suffix('.maps').name}")


if __name__ == "__main__":
    main()

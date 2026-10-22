"""Build the flat ``.bin`` that ``app_process_arm64.maps`` describes.

The maps fixture lists ~60 realistic arm64 Android app mappings, each one
page (4 KiB) long, so the matching gdb_raw-style ``.bin`` is just one page
per entry in maps order. Every page is filled with a byte pattern unique to
its entry; :func:`write_app_process_bin` can additionally plant a secret at
the start of the page of a named mapping (default: the zygote space).

Usage::

    python tests/fixtures/android/generate_app_process_bin.py OUT.bin
"""

from __future__ import annotations

import shutil
import sys
from pathlib import Path
from typing import List, Optional

FIXTURE_DIR = Path(__file__).resolve().parent
MAPS_PATH = FIXTURE_DIR / "app_process_arm64.maps"
PAGE_SIZE = 4096
ZYGOTE_SPACE = "[anon:dalvik-zygote space]"


def maps_entry_names(maps_path: Path = MAPS_PATH) -> List[str]:
    """Mapping name (path column, may be empty) of every maps line."""
    from memdiver.core.proc_maps_parser import parse_maps_file

    return [region.path for region in parse_maps_file(maps_path)]


def _page_for(index: int) -> bytearray:
    pattern = bytes([(index * 7 + 1) & 0xFF, index & 0xFF, 0xA5, 0x5A])
    return bytearray(pattern * (PAGE_SIZE // len(pattern)))


def write_app_process_bin(dest: Path, secret: Optional[bytes] = None,
                          secret_in: str = ZYGOTE_SPACE,
                          maps_path: Path = MAPS_PATH) -> Path:
    """Write the one-page-per-entry ``.bin`` (plus a copied ``.maps``).

    The sidecar is copied next to *dest* as ``<dest stem>.maps`` so that
    auto-detection finds it too. With *secret*, its bytes are planted at the
    start of the FIRST mapping named *secret_in*.
    """
    dest = Path(dest)
    names = maps_entry_names(maps_path)
    pages = [_page_for(i) for i in range(len(names))]
    if secret is not None:
        pages[names.index(secret_in)][:len(secret)] = secret
    dest.write_bytes(b"".join(pages))
    shutil.copyfile(maps_path, dest.with_suffix(".maps"))
    return dest


if __name__ == "__main__":
    if len(sys.argv) != 2:
        sys.exit(f"usage: {sys.argv[0]} OUT.bin")
    print(write_app_process_bin(Path(sys.argv[1])))

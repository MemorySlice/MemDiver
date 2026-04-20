"""Lazy builder for the aes_sample binary.

First call compiles `aes_sample.c` via `build_aes_sample.sh` and caches
the resulting binary next to the source. Subsequent calls reuse the
cached binary whenever its mtime is >= the source's mtime.

The compiled binary is listed in .gitignore and never shipped with the
package (tests/ is excluded from sdist/wheel).
"""
from __future__ import annotations

import shutil
import subprocess
import sys
from pathlib import Path

FIXTURES: Path = Path(__file__).resolve().parent
SOURCE: Path = FIXTURES / "aes_sample.c"
BINARY: Path = FIXTURES / "aes_sample"
BUILD_SCRIPT: Path = FIXTURES / "build_aes_sample.sh"


def ensure_built() -> Path | None:
    """Return the path to a ready-to-run aes_sample binary.

    Returns None if the C compiler (`cc`) is unavailable; callers should
    skip their test cleanly in that case.
    """
    if not SOURCE.is_file() or not BUILD_SCRIPT.is_file():
        return None

    if BINARY.is_file() and BINARY.stat().st_mtime >= SOURCE.stat().st_mtime:
        return BINARY

    if shutil.which("cc") is None:
        return None

    result = subprocess.run(
        ["bash", str(BUILD_SCRIPT)],
        cwd=FIXTURES,
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        sys.stderr.write(
            f"build_aes_sample.sh failed (rc={result.returncode}):\n"
            f"  stdout: {result.stdout}\n"
            f"  stderr: {result.stderr}\n"
        )
        return None

    return BINARY if BINARY.is_file() else None

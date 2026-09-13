#!/usr/bin/env python3
"""Generate the committed ASLR-shifted MSL fixture PAIR for the e2e suite.

Re-uses ``generate_aslr_msl_pair`` from
``tests/fixtures/generate_msl_aslr_fixtures.py`` (the single source of truth
for the ASLR pair's byte layout) and writes the two blobs next to this script.
Both files are committed so the multi-dump specs run without the private
dataset.

``extra_region=True`` is deliberate: the pair then carries TWO regions that
shift by DIFFERENT run-to-run deltas (0x1000 for the extra region, 0x10000000
for the heap). A viewer that assumes one scalar VA delta per dump cannot align
them, which is exactly the bug the side-by-side / overlay specs must catch.

Run from the repo root (or anywhere):

    python tests/e2e/fixtures/aslr_msl/generate.py
"""

import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO_ROOT = HERE.parents[3]  # .../tests/e2e/fixtures/aslr_msl -> repo root

# ``generate_msl_aslr_fixtures`` imports via the ``tests.fixtures`` package, so
# the repo root (not the fixture dir) must be importable.
sys.path.insert(0, str(REPO_ROOT))

from tests.fixtures.generate_msl_aslr_fixtures import (  # noqa: E402
    generate_aslr_msl_pair,
)

OUTPUTS = (HERE / "run_1.msl", HERE / "run_2.msl")


def main() -> None:
    blobs = generate_aslr_msl_pair(extra_region=True)
    for path, blob in zip(OUTPUTS, blobs):
        path.write_bytes(blob)
        print(f"Wrote {len(blob)} bytes to {path}")


if __name__ == "__main__":
    main()

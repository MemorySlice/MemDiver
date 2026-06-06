#!/usr/bin/env python3
"""Generate the committed synthetic MSL fixture for the Playwright e2e suite.

Re-uses ``generate_msl_file`` from ``tests/fixtures/generate_msl_fixtures.py``
(the single source of truth for synthetic MSL byte layout) and writes the
resulting blob to ``sample.msl`` next to this script. The output file is
committed so SMOKE e2e flows can run without the private dataset.

Run from the repo root (or anywhere):

    python tests/e2e/fixtures/synthetic_msl/generate.py
"""

import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO_ROOT = HERE.parents[3]  # .../tests/e2e/fixtures/synthetic_msl -> repo root
FIXTURE_DIR = REPO_ROOT / "tests" / "fixtures"

# Make generate_msl_fixtures importable regardless of cwd.
sys.path.insert(0, str(FIXTURE_DIR))

from generate_msl_fixtures import generate_msl_file  # noqa: E402

OUTPUT = HERE / "sample.msl"


def main() -> None:
    blob = generate_msl_file()
    OUTPUT.write_bytes(blob)
    print(f"Wrote {len(blob)} bytes to {OUTPUT}")


if __name__ == "__main__":
    main()

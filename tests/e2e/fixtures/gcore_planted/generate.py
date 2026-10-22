#!/usr/bin/env python3
"""Generate the gcore e2e fixture: a tiny ELF core with ``secret=ABCDEF01``.

``planted.core`` stores its two PT_LOAD bodies in reverse file order, so the
planted secret sits at a different offset in the "raw" view (file bytes) than
in the "vas" view (PT_LOADs concatenated). ``planted.json`` records both
offsets for the spec. Built by :mod:`tests.fixtures.synth_gcore_planted`, the
same builder the pytest suite uses.

    python tests/e2e/fixtures/gcore_planted/generate.py
"""

import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO_ROOT = HERE.parents[3]


def main() -> None:
    sys.path.insert(0, str(REPO_ROOT))
    from tests.fixtures.synth_gcore_planted import (
        PLANTED_SECRET,
        SECRET_REGEX,
        write_planted_core,
    )

    core = write_planted_core(HERE / "planted.core")
    (HERE / "planted.json").write_text(json.dumps({
        "raw_offset": core.raw_offset,
        "vas_offset": core.vas_offset,
        "raw_size": core.raw_size,
        "vas_size": core.vas_size,
        "secret": PLANTED_SECRET.decode("ascii"),
        "regex": SECRET_REGEX,
    }, indent=2) + "\n")
    print(f"wrote {core.path} ({core.raw_size} bytes) + planted.json")


if __name__ == "__main__":
    main()

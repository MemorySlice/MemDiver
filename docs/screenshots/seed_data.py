#!/usr/bin/env python3
"""Seed deterministic MSL fixtures for documentation screenshots.

Delegates to the six generator scripts under ``tests/fixtures/`` so that
capture.py can run against a reproducible dataset without the private
research corpus.

Usage:
    python docs/screenshots/seed_data.py --root /tmp/memdiver_docs_seed
    python docs/screenshots/seed_data.py --root /tmp/memdiver_docs_seed --verify-seed
"""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
FIXTURES = REPO_ROOT / "tests" / "fixtures"

# Generators sometimes do `from tests.fixtures.X import Y` to share helpers,
# so the repo root must be importable when this script runs as a subprocess.
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

GENERATORS = [
    ("generate_fixtures", "generate_dataset"),
    # write_msl_fixture(path) expects a file path; ensure_msl_fixtures(root)
    # is the directory-level entry point that matches the seed-driver contract.
    ("generate_msl_fixtures", "ensure_msl_fixtures"),
    ("generate_msl_aslr_fixtures", "write_aslr_msl_fixtures"),
    ("generate_aes_fixtures", "generate_dataset"),
    ("generate_aslr_fixtures", "generate_dataset"),
    ("generate_realistic_fixtures", "generate_dataset"),
]


def _load(module_name: str):
    path = FIXTURES / f"{module_name}.py"
    spec = importlib.util.spec_from_file_location(module_name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"Cannot load fixture generator: {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[module_name] = module
    spec.loader.exec_module(module)
    return module


def seed(root: Path) -> dict[str, str]:
    """Run every generator, return a manifest {path: sha256}."""
    root.mkdir(parents=True, exist_ok=True)
    manifest: dict[str, str] = {}

    for module_name, func_name in GENERATORS:
        module = _load(module_name)
        # Honor the per-module entry point declared in GENERATORS, with a
        # conventional fallback chain so fixture refactors stay tolerant.
        entry = (
            getattr(module, func_name, None)
            or getattr(module, "generate_dataset", None)
            or getattr(module, "ensure_msl_fixtures", None)
        )
        if entry is None:
            # Best-effort: invoke __main__ with seed dir as argv.
            if hasattr(module, "main"):
                saved_argv = sys.argv
                sys.argv = [module_name, "--root", str(root)]
                try:
                    module.main()
                finally:
                    sys.argv = saved_argv
            continue
        try:
            entry(root)
        except TypeError:
            # Some generators expect a positional path argument with a
            # different signature; try a keyword.
            entry(out_dir=root)

    for path in sorted(root.rglob("*")):
        if path.is_file():
            rel = path.relative_to(root).as_posix()
            manifest[rel] = hashlib.sha256(path.read_bytes()).hexdigest()
    return manifest


def verify(root: Path) -> int:
    """Spot-check the seed dataset matches expected invariants."""
    checks: list[tuple[str, bool, str]] = []

    demo = root / "msl" / "demo.msl"
    if demo.exists():
        head = demo.read_bytes()[:8]
        checks.append(("msl/demo.msl magic", head == b"MEMSLICE", head.hex()))

    aes_keylog = next((root / "aes_fixture").rglob("keylog.csv"), None)
    if aes_keylog is not None:
        checks.append(("aes_fixture/keylog.csv present", aes_keylog.is_file(), str(aes_keylog)))

    failed = [c for c in checks if not c[1]]
    for name, ok, detail in checks:
        print(f"  {'OK' if ok else 'FAIL'}  {name} — {detail}")
    return 1 if failed else 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--root", type=Path, required=True, help="Seed output directory (will be created).")
    parser.add_argument("--verify-seed", action="store_true", help="Verify a previously seeded dataset.")
    parser.add_argument("--manifest", type=Path, default=None, help="Write sha256 manifest JSON here.")
    args = parser.parse_args()

    if args.verify_seed:
        return verify(args.root)

    manifest = seed(args.root)
    if args.manifest:
        args.manifest.write_text(json.dumps(manifest, indent=2, sort_keys=True))
    print(f"Seeded {len(manifest)} files into {args.root}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

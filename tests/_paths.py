"""Portable path resolution for tests.

Tests and standalone e2e scripts import `dataset_root()` to locate the
private mempdumps dataset. Resolution order (first hit wins):

1. `--dataset-root=PATH` pytest CLI option (populated via conftest.py).
2. `MEMDIVER_DATASET_ROOT` environment variable.
3. `dataset_root` field in `config.json` (default value: ".").
4. None -> tests skip via the `requires_dataset` marker.

Also exposes `REPO_ROOT`, `FIXTURES_DIR`, and `artifacts_dir()` for
portable artifact output (screenshots, test outputs).
"""
from __future__ import annotations

import functools
import json
import os
from pathlib import Path

REPO_ROOT: Path = Path(__file__).resolve().parent.parent
TESTS_DIR: Path = Path(__file__).resolve().parent
FIXTURES_DIR: Path = TESTS_DIR / "fixtures"

_CLI_OVERRIDE: Path | None = None

SKIP_REASON: str = (
    "Dataset unavailable. Set MEMDIVER_DATASET_ROOT, pass "
    "--dataset-root=PATH, or edit config.json['dataset_root']."
)


def _set_cli_override(value: str | None) -> None:
    """Called by conftest.py during pytest_configure."""
    global _CLI_OVERRIDE
    if value:
        p = Path(value).expanduser()
        _CLI_OVERRIDE = p if p.exists() else None
    else:
        _CLI_OVERRIDE = None
    dataset_root.cache_clear()


def _load_config_dataset_root() -> Path | None:
    cfg = REPO_ROOT / "config.json"
    if not cfg.is_file():
        return None
    try:
        val = json.loads(cfg.read_text()).get("dataset_root", "")
    except (json.JSONDecodeError, OSError):
        return None
    if not val:
        return None
    p = Path(val).expanduser()
    if not p.is_absolute():
        p = (REPO_ROOT / p).resolve()
    # "." resolves to REPO_ROOT itself, which is not a real dataset root.
    if p == REPO_ROOT or not p.exists():
        return None
    return p


@functools.lru_cache(maxsize=1)
def dataset_root() -> Path | None:
    """Resolve the private mempdumps dataset path, or None if unavailable.

    Cached across calls; invalidated by `_set_cli_override`.
    """
    if _CLI_OVERRIDE is not None:
        return _CLI_OVERRIDE
    env = os.environ.get("MEMDIVER_DATASET_ROOT", "").strip()
    if env:
        p = Path(env).expanduser()
        if p.exists():
            return p
    return _load_config_dataset_root()


def artifacts_dir(subdir: str = "") -> Path:
    """Return a portable, git-ignored output directory for e2e artifacts."""
    base = TESTS_DIR / "artifacts"
    out = base / subdir if subdir else base
    out.mkdir(parents=True, exist_ok=True)
    return out

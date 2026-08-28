"""Portable path resolution for tests.

Tests and standalone e2e scripts import `dataset_root()` to locate the
private mempdumps dataset. Resolution order (first hit wins):

1. `--dataset-root=PATH` pytest CLI option (populated via conftest.py).
2. `MEMDIVER_DATASET_ROOT` environment variable.
3. `dataset_root` field in `config.json` (default value: ".").
4. The local TLS-dump corpus, via `tests.fixtures.tls_ground_truth.tls_dumps_dir()`
   (`MEMDIVER_TLS_DUMPS_DIR` or its built-in default) -- but ONLY when steps 1
   and 2 were left unset. See `_tls_corpus_fallback` for why.
5. None -> tests skip via the `requires_dataset` marker.

Step 4 exists because the repo used to carry TWO independent corpus resolvers:
this one (which gates the `requires_dataset` marker) and `tls_dumps_dir()`
(which several `requires_dataset` test BODIES actually read). With
`config.json["dataset_root"] == "."` -- correctly rejected in step 3 -- the two
disagreed, so those tests reported "no dataset" while standing on the corpus
their own bodies would have opened. Step 4 makes step 3's rejection fall
through to the resolver the bodies use instead of straight to None.

`dataset_file()` layers a per-resource HYBRID on top of that root: the real
capture where it exists, the synthetic fixture otherwise, so the returned path
always exists. Because that choice is silent, every resolution is also
available WITH ITS PROVENANCE via `resolve_dataset_file()` /
`dataset_file_source()` -- see `ResolvedDatasetPath`. A test whose assertions
mean different things against the two trees must pin (and report) that source
rather than trust a green result; `tests/test_e2e_real_dumps.py` is the worked
example.

Also exposes `REPO_ROOT`, `FIXTURES_DIR`, and `artifacts_dir()` for
portable artifact output (screenshots, test outputs).
"""
from __future__ import annotations

import functools
import json
import os
from pathlib import Path
from typing import NamedTuple

REPO_ROOT: Path = Path(__file__).resolve().parent.parent
TESTS_DIR: Path = Path(__file__).resolve().parent
FIXTURES_DIR: Path = TESTS_DIR / "fixtures"

_CLI_OVERRIDE: Path | None = None
# True once `--dataset-root=` was passed at all -- even if the path it names
# does not exist. An EXPLICIT request is honoured as given (including its
# failure), so it must never silently fall through to the corpus fallback.
_CLI_OVERRIDE_REQUESTED: bool = False

SKIP_REASON: str = (
    "Dataset unavailable. Set MEMDIVER_DATASET_ROOT or MEMDIVER_TLS_DUMPS_DIR, "
    "pass --dataset-root=PATH, or edit config.json['dataset_root']. "
    "See `make test-corpus`."
)


def _set_cli_override(value: str | None) -> None:
    """Called by conftest.py during pytest_configure."""
    global _CLI_OVERRIDE, _CLI_OVERRIDE_REQUESTED
    _CLI_OVERRIDE_REQUESTED = bool(value)
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


def _looks_like_a_corpus_root(p: Path) -> bool:
    """True if `p` is plausibly a dataset root rather than an unrelated dir.

    Mirrors the spirit of the `"."` rejection in `_load_config_dataset_root`:
    a path is only accepted as a dataset root if it is shaped like one, i.e. it
    holds at least one protocol-level directory. That keeps an empty (or
    mistyped) `MEMDIVER_TLS_DUMPS_DIR` from being promoted to "the dataset".
    """
    if not p.is_dir() or p == REPO_ROOT:
        return False
    return any(
        child.is_dir()
        and (
            child.name.startswith("TLS")
            or child.name.startswith("SSH")
            or child.name.startswith("dataset_")
        )
        for child in p.iterdir()
    )


def _tls_corpus_fallback() -> Path | None:
    """Step 4: the local TLS-dump corpus, as located by `tls_dumps_dir()`.

    Imported lazily so `tests._paths` stays importable by the standalone e2e
    scripts that do not put `tests/fixtures` on the path.
    """
    try:
        from tests.fixtures.tls_ground_truth import tls_dumps_dir
    except ImportError:  # pragma: no cover - defensive
        return None
    try:
        candidate = tls_dumps_dir().expanduser()
        return candidate if _looks_like_a_corpus_root(candidate) else None
    except OSError:  # pragma: no cover - unreadable path
        return None


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
    from_config = _load_config_dataset_root()
    if from_config is not None:
        return from_config
    # An EXPLICIT request that did not resolve means "no dataset" -- never
    # "try somewhere else". This is also how a developer (or the corpus-absent
    # verification run) simulates a machine without the corpus:
    # `MEMDIVER_DATASET_ROOT=/nonexistent pytest ...` still yields clean skips.
    if _CLI_OVERRIDE_REQUESTED or env:
        return None
    return _tls_corpus_fallback()


# --------------------------------------------------------------------------- #
# Provenance -- which tree did a resolved path actually come from?
# --------------------------------------------------------------------------- #

DATASET_SOURCE_REAL = "real"
DATASET_SOURCE_SYNTHETIC = "synthetic"


class ResolvedDatasetPath(NamedTuple):
    """A resolved dataset path together with the tree it actually came from.

    ``dataset_file()`` deliberately hides the choice between the real corpus and
    the synthetic fixtures so that callers always get an existing path. The cost
    of hiding it is that a green test proves nothing about WHICH bytes it read:
    the same test id can exercise two materially different trees on two
    machines. This tuple is the escape hatch -- resolve through
    :func:`resolve_dataset_file` and a test can assert, and print, its own
    provenance.
    """

    path: Path
    source: str  #: ``DATASET_SOURCE_REAL`` or ``DATASET_SOURCE_SYNTHETIC``
    root: Path  #: the tree ``path`` is relative to


def resolve_dataset_file(relpath: "str | Path") -> ResolvedDatasetPath:
    """Resolve a dataset resource AND report which tree supplied it.

    Hybrid resolution (first hit wins):

    1. If a real dataset root is configured (via ``--dataset-root``,
       ``MEMDIVER_DATASET_ROOT``, ``config.json`` or the ``tls_dumps_dir()``
       fallback) *and* it actually contains ``relpath``, return that real file
       with ``source == DATASET_SOURCE_REAL``.
    2. Otherwise materialise the synthetic fixture dataset on demand
       (idempotent) and return the synthetic copy with
       ``source == DATASET_SOURCE_SYNTHETIC``.

    :func:`dataset_file` is this function minus the provenance.
    """
    from tests.fixtures.synth_dataset import (
        SYNTH_DATASET_ROOT,
        ensure_synthetic_dataset,
    )

    rel = Path(relpath)
    root = dataset_root()
    if root is not None:
        candidate = root / rel
        if candidate.exists():
            return ResolvedDatasetPath(candidate, DATASET_SOURCE_REAL, root)
    ensure_synthetic_dataset()
    return ResolvedDatasetPath(
        SYNTH_DATASET_ROOT / rel, DATASET_SOURCE_SYNTHETIC, SYNTH_DATASET_ROOT
    )


def dataset_file(relpath: "str | Path") -> Path:
    """Resolve a single dataset resource, preferring the real capture.

    Thin, signature-stable wrapper over :func:`resolve_dataset_file` — see there
    for the resolution order. The returned path is guaranteed to exist as long
    as the synthetic generators cover ``relpath``, so dataset-backed tests do
    not need to skip when the private mempdumps tree is absent.

    Use :func:`resolve_dataset_file` (or :func:`dataset_file_source`) instead
    whenever the answer "real or synthetic?" changes what an assertion means.
    """
    return resolve_dataset_file(relpath).path


def dataset_file_source(relpath: "str | Path") -> str:
    """``"real"`` or ``"synthetic"`` for the tree ``relpath`` resolves against."""
    return resolve_dataset_file(relpath).source


def dataset_source_summary() -> str:
    """One-line, human-readable description of the corpus this run will use.

    Deliberately answers from :func:`dataset_root` alone so that merely printing
    the banner never materialises the synthetic fixtures.
    """
    root = dataset_root()
    if root is None:
        return (
            "no real dataset root resolved — dataset_file() will serve "
            "SYNTHETIC fixtures"
        )
    return (
        f"real dataset root: {root} — dataset_file() prefers it, "
        "synthetic fixtures fill the gaps"
    )


def artifacts_dir(subdir: str = "") -> Path:
    """Return a portable, git-ignored output directory for e2e artifacts."""
    base = TESTS_DIR / "artifacts"
    out = base / subdir if subdir else base
    out.mkdir(parents=True, exist_ok=True)
    return out

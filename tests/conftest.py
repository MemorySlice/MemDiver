"""Pytest fixtures and hooks shared across the test suite.

- Ensures REPO_ROOT is importable so test files don't need their own
  `sys.path.insert(...)` hacks.
- Registers the `--dataset-root` pytest CLI option.
- Exposes `dataset_root` and `aes_sample_binary` session fixtures.
- Registers the `requires_dataset` marker for tests that need the
  private mempdumps directory.
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

_HERE = Path(__file__).resolve().parent
_REPO_ROOT = _HERE.parent
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from tests._paths import dataset_root as _resolve_dataset_root
from tests._paths import _set_cli_override


def pytest_addoption(parser: pytest.Parser) -> None:
    parser.addoption(
        "--dataset-root",
        action="store",
        default=None,
        help="Override the private mempdumps dataset path for real-dump tests.",
    )


def pytest_configure(config: pytest.Config) -> None:
    _set_cli_override(config.getoption("--dataset-root"))
    config.addinivalue_line(
        "markers",
        "requires_dataset: mark test as requiring the private mempdumps dataset",
    )
    # Ensure the synthetic fixture dataset exists before collection.
    # generate_dataset() is idempotent — returns immediately if the
    # dataset dir is already populated. Keeps gitignored fixtures
    # re-materialisable on fresh clones and CI runners.
    from tests.fixtures.generate_fixtures import generate_dataset
    generate_dataset()


def pytest_collection_modifyitems(
    config: pytest.Config, items: list[pytest.Item]
) -> None:
    """Auto-skip tests marked requires_dataset when no dataset is resolvable."""
    if _resolve_dataset_root() is not None:
        return
    skip = pytest.mark.skip(
        reason="Dataset unavailable. Set MEMDIVER_DATASET_ROOT or --dataset-root=PATH."
    )
    for item in items:
        if "requires_dataset" in item.keywords:
            item.add_marker(skip)


@pytest.fixture(scope="session")
def dataset_root() -> Path:
    """Session fixture returning the resolved dataset root, or skipping."""
    resolved = _resolve_dataset_root()
    if resolved is None:
        pytest.skip("Dataset unavailable. Set MEMDIVER_DATASET_ROOT or --dataset-root=PATH.")
    return resolved


@pytest.fixture(scope="session")
def aes_sample_binary() -> Path:
    """Lazily build and return the compiled aes_sample binary.

    First use compiles via build_aes_sample.sh; subsequent uses reuse
    the cached binary (mtime-checked against aes_sample.c).
    Skips cleanly if no C compiler is available.
    """
    from tests.fixtures._aes_sample_builder import ensure_built

    path = ensure_built()
    if path is None:
        pytest.skip("C compiler (cc) not available to build aes_sample")
    return path

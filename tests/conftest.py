"""Pytest fixtures and hooks shared across the test suite.

- Ensures REPO_ROOT is importable so test files don't need their own
  `sys.path.insert(...)` hacks.
- Registers the `--dataset-root` pytest CLI option.
- Exposes `dataset_root` and `aes_sample_binary` session fixtures.
- Registers the `requires_dataset` marker for tests that need the
  private mempdumps directory.
"""
from __future__ import annotations

import socket
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

import pytest
from hypothesis import settings

# Hypothesis profile for the parser fuzz suite. deadline (ms) catches hangs;
# max_examples keeps the file-I/O-backed fuzz tests fast. derandomize=True gives
# a fixed per-test seed so the committed suite is DETERMINISTIC in CI — it locks
# in the currently-hardened parser boundaries as a regression guard rather than a
# flaky continuous fuzzer (which would intermittently re-discover any future
# un-hardened boundary and red the build). Registered/loaded at import time so it
# applies to the whole session.
settings.register_profile(
    "memdiver", max_examples=75, deadline=1500, derandomize=True
)
settings.load_profile("memdiver")

_HERE = Path(__file__).resolve().parent
_REPO_ROOT = _HERE.parent
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from tests._paths import REPO_ROOT
from tests._paths import dataset_root as _resolve_dataset_root
from tests._paths import _set_cli_override

# ---------------------------------------------------------------------------
# Live backend for end-to-end tests
# ---------------------------------------------------------------------------

_BACKEND_HOST = "127.0.0.1"
_BACKEND_PORT = 8080
_BACKEND_BASE_URL = f"http://{_BACKEND_HOST}:{_BACKEND_PORT}"


def _backend_listening(host: str = _BACKEND_HOST, port: int = _BACKEND_PORT) -> bool:
    """Return True if something is already accepting connections on host:port."""
    try:
        with socket.create_connection((host, port), timeout=0.5):
            return True
    except OSError:
        return False


@pytest.fixture(scope="session")
def live_backend() -> str:
    """Guarantee a reachable MemDiver backend at 127.0.0.1:8080 for e2e tests.

    Behaviour:
    - If a backend is *already* listening (e.g. a developer started one
      manually), reuse it and leave it running on teardown.
    - Otherwise spawn uvicorn via the FastAPI app factory, poll
      ``/api/notebook/status`` until healthy (~15s), yield, then terminate
      the process we started.

    Session-scoped and only instantiated when an e2e test requests it, so
    non-e2e runs never bind port 8080.
    """
    if _backend_listening():
        # Externally managed server: reuse without owning its lifecycle.
        yield _BACKEND_BASE_URL
        return

    proc = subprocess.Popen(
        [
            sys.executable, "-m", "uvicorn",
            "memdiver.api.main:create_app", "--factory",
            "--host", _BACKEND_HOST, "--port", str(_BACKEND_PORT),
        ],
        cwd=str(REPO_ROOT),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    try:
        healthy = False
        for _ in range(30):  # up to ~15s (30 * 0.5s)
            if proc.poll() is not None:
                # Process died before becoming healthy — surface its output.
                _out, err = proc.communicate()
                raise RuntimeError(
                    f"uvicorn exited early (code {proc.returncode}):\n"
                    f"{err.decode(errors='replace')}"
                )
            try:
                req = urllib.request.Request(f"{_BACKEND_BASE_URL}/api/notebook/status")
                with urllib.request.urlopen(req, timeout=2):
                    healthy = True
                    break
            except (urllib.error.URLError, ConnectionRefusedError, OSError):
                time.sleep(0.5)
        if not healthy:
            proc.kill()
            proc.wait(timeout=5)
            raise RuntimeError(
                "MemDiver backend failed to start within 15 seconds at "
                f"{_BACKEND_BASE_URL}"
            )
        yield _BACKEND_BASE_URL
    finally:
        # Only tear down a server this fixture itself started.
        if proc.poll() is None:
            proc.terminate()
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait(timeout=3)


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


@pytest.fixture(autouse=True)
def _isolate_user_structures(tmp_path_factory, monkeypatch):
    """Isolate the user-structures directory for every test.

    As of the Wave 1 extensibility work, ``get_structure_library()`` defaults to
    ``include_user=True`` and auto-merges ``~/.memdiver/structures``. Without
    isolation, a developer's (or CI runner's) real user structures would leak
    into the shared singleton and make exact-count assertions (e.g.
    ``len(list_by_protocol("TLS")) == 17``) nondeterministic. We redirect the
    directory to an empty temp dir and reset the module singleton around each
    test so the library is deterministic and rebuilt from built-ins only unless
    a test deliberately populates the dir.
    """
    from memdiver.core import structure_library, structure_loader

    empty = tmp_path_factory.mktemp("empty_user_structures")
    monkeypatch.setattr(structure_loader, "DEFAULT_USER_DIR", empty, raising=True)
    structure_library._library = None
    yield
    structure_library._library = None

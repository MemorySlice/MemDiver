"""Pytest fixtures and hooks shared across the test suite.

- Ensures REPO_ROOT is importable so test files don't need their own
  `sys.path.insert(...)` hacks.
- Registers the `--dataset-root` pytest CLI option.
- Exposes `dataset_root` and `aes_sample_binary` session fixtures.
- Registers the `requires_dataset` marker for tests that need the
  private mempdumps directory.
- Registers the `requires_vol3` marker for tests that need a real Volatility3
  launcher, and reports which one resolved.
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

from tests._paths import REPO_ROOT, SKIP_REASON, dataset_source_summary
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


#: Named so the skip line tells the reader how to turn the proof ON, rather
#: than only that it was off.
VOL3_SKIP_REASON: str = (
    "No Volatility3 launcher found. Set MEMDIVER_VOL3_BIN=/path/to/vol.py "
    "(plus MEMDIVER_VOL3_PYTHON for a checkout with its own venv), or put "
    "vol/vol.py on PATH, or `pip install \"memdiver[vol]\"`."
)


def _vol3_launcher():
    """Resolve a Volatility3 launcher, or ``None``. Never raises."""
    try:
        from memdiver.engine.vol3_subproc import find_vol3_launcher

        return find_vol3_launcher()
    except Exception:  # pragma: no cover - defensive; collection must not break
        return None


def pytest_addoption(parser: pytest.Parser) -> None:
    parser.addoption(
        "--dataset-root",
        action="store",
        default=None,
        help="Override the private mempdumps dataset path for real-dump tests.",
    )


def pytest_report_header(config: pytest.Config) -> str:
    """Print, uncaptured and on every run, WHICH tree the suite resolved.

    ``dataset_file()`` silently prefers the real corpus over the synthetic
    fixtures, so two machines can run the same test ids against materially
    different bytes. This one line makes that visible in every local run and
    every CI log without anyone having to opt into ``-s``. It answers from
    ``dataset_root()`` only, so printing it never materialises the synthetic
    dataset.
    """
    return (
        f"memdiver dataset: {dataset_source_summary()}\n"
        f"memdiver vol3 launcher: {_vol3_launcher_summary()}"
    )


def _vol3_launcher_summary() -> str:
    """Which Volatility3 launcher the ``requires_vol3`` gate resolved.

    Reported for the same reason the dataset line above is: three Volatility3
    trees routinely coexist on one machine and they disagree on version, so
    "the vol3 proof passed" is meaningless without saying which framework it
    passed against. Import is local so a broken engine module degrades to a
    header note instead of breaking collection outright.
    """
    try:
        from memdiver.engine.vol3_subproc import launcher_report

        return launcher_report()
    except Exception as exc:  # pragma: no cover - defensive; header must never fail
        return f"unavailable ({exc.__class__.__name__}: {exc})"


def pytest_configure(config: pytest.Config) -> None:
    _set_cli_override(config.getoption("--dataset-root"))
    config.addinivalue_line(
        "markers",
        "requires_dataset: mark test as requiring the private mempdumps dataset "
        "(resolved by tests/_paths.py::dataset_root, which now falls back to the "
        "local TLS corpus via tls_dumps_dir(); see `make test-corpus`)",
    )
    config.addinivalue_line(
        "markers",
        "requires_vol3: mark test as requiring a real Volatility3 launcher "
        "(MEMDIVER_VOL3_BIN, or vol/vol.py on PATH; a .py launcher also honours "
        "MEMDIVER_VOL3_PYTHON). A CONDITIONAL gate, not `slow` -- see the marker "
        "comment in pyproject.toml",
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
    """Auto-skip tests marked requires_dataset when no dataset is resolvable.

    "Resolvable" is exactly what ``tests/_paths.py::dataset_root()`` says --
    which, since the resolver reconciliation, ends at ``tls_dumps_dir()``. So a
    test gated by this marker and a test body that opens paths under
    ``tls_dumps_dir()`` can no longer disagree about whether the corpus exists.

    Auto-skip ``requires_vol3`` items too, when no ``vol``/``vol.py`` launcher
    resolves. Same shape, same reason: a conditional gate, so a machine with a
    launcher gets the real out-of-process proof from a plain ``pytest`` and a
    machine without one gets a clean, named skip.
    """
    if _resolve_dataset_root() is None:
        skip_dataset = pytest.mark.skip(reason=SKIP_REASON)
        for item in items:
            if "requires_dataset" in item.keywords:
                item.add_marker(skip_dataset)

    if _vol3_launcher() is None:
        skip_vol3 = pytest.mark.skip(reason=VOL3_SKIP_REASON)
        for item in items:
            if "requires_vol3" in item.keywords:
                item.add_marker(skip_vol3)


@pytest.fixture(scope="session")
def dataset_root() -> Path:
    """Session fixture returning the resolved dataset root, or skipping."""
    resolved = _resolve_dataset_root()
    if resolved is None:
        pytest.skip(SKIP_REASON)
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

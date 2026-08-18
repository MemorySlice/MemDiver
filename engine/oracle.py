"""BYO decryption oracle loader.

Loads a user-supplied Python file that exposes either:

    Shape 1 — stateless function:
        def verify(candidate: bytes) -> bool: ...

    Shape 2 — stateful factory (amortizes KDF/socket setup):
        def build_oracle(config: dict) -> Oracle:
            return MyOracle(config)

        class MyOracle:
            def verify(self, candidate: bytes) -> bool: ...
            def close(self): ...   # optional

Memdiver auto-detects the shape and always hands the caller a flat
``verify(bytes) -> bool`` callable.

Security: ``--oracle`` runs arbitrary Python with the caller's privileges,
equivalent to ``find -exec``. This loader prints the sha256 of the loaded
module to stderr and refuses to load oracles from world-writable paths.
"""

from __future__ import annotations

import hashlib
import importlib.util
import logging
import multiprocessing
import os
import stat
import sys
import tomllib
from pathlib import Path
from typing import Any, Callable, Protocol, runtime_checkable

from memdiver.core.artifact_util import sha256_streamed

logger = logging.getLogger("memdiver.engine.oracle")

OracleFn = Callable[[bytes], bool]

# ---------------------------------------------------------------------------
# Load-time sandbox defaults
#
# Importing an oracle and calling ``build_oracle(config)`` runs untrusted user
# code. A malicious/buggy oracle can hang or OOM the process at that point, so
# the load is first replayed in a throwaway spawned subprocess under a
# wall-clock timeout plus best-effort CPU/memory caps. The wall-clock join is
# the reliable floor on every platform; the resource caps are extra defence on
# Unix. Overridable via env for operators who need a longer/shorter budget.
# ---------------------------------------------------------------------------
_SANDBOX_TIMEOUT_S = float(os.environ.get("MEMDIVER_ORACLE_SANDBOX_TIMEOUT", "10.0"))
_SANDBOX_CPU_S = int(os.environ.get("MEMDIVER_ORACLE_SANDBOX_CPU", "10"))
_SANDBOX_MEM_BYTES = int(
    os.environ.get("MEMDIVER_ORACLE_SANDBOX_MEM", str(2 * 1024**3))
)


@runtime_checkable
class Oracle(Protocol):
    """Stateful oracle shape produced by ``build_oracle(config)``."""

    def verify(self, candidate: bytes) -> bool: ...


class OracleLoadError(RuntimeError):
    """Raised when a user oracle file cannot be loaded or validated."""


def load_oracle_config(path: Path | None) -> dict[str, Any]:
    """Load an optional TOML config file into a plain dict."""
    if path is None:
        return {}
    config_path = Path(path)
    if not config_path.is_file():
        raise OracleLoadError(f"oracle config not found: {config_path}")
    with config_path.open("rb") as fh:
        return tomllib.load(fh)


def _assert_safe_path(path: Path) -> None:
    """Refuse to load oracles from group/world-writable files or directories."""
    if not path.is_file():
        raise OracleLoadError(f"oracle file not found: {path}")
    file_mode = path.stat().st_mode
    if file_mode & (stat.S_IWOTH | stat.S_IWGRP):
        raise OracleLoadError(
            f"refusing to load group/world-writable oracle: {path} "
            f"(mode={stat.filemode(file_mode)}); tighten permissions first"
        )
    parent_mode = path.parent.stat().st_mode
    if parent_mode & (stat.S_IWOTH | stat.S_IWGRP):
        raise OracleLoadError(
            f"refusing to load oracle from group/world-writable directory: "
            f"{path.parent} (mode={stat.filemode(parent_mode)})"
        )


def _log_module_fingerprint(path: Path) -> str:
    """Emit the sha256 of the loaded file so the user can audit what ran.

    SECURITY audit trail: loading an oracle executes arbitrary user-supplied
    Python, so this notice is logged at WARNING (not INFO). The MCP server and
    non-verbose CLI default the root ``memdiver`` logger to WARNING, and an
    ``info`` record would be silently dropped on exactly the unattended paths
    that load oracle code — WARNING keeps it visible while still routing through
    the logging system (capturable to a file/SIEM) rather than a raw print.
    """
    digest = sha256_streamed(path)
    logger.warning("memdiver: loaded oracle %s sha256=%s", path, digest)
    return digest


def _import_user_module(path: Path):
    """Import the oracle file as an isolated module named ``memdiver_user_oracle``."""
    spec = importlib.util.spec_from_file_location("memdiver_user_oracle", path)
    if spec is None or spec.loader is None:
        raise OracleLoadError(f"cannot create import spec for {path}")
    module = importlib.util.module_from_spec(spec)
    try:
        spec.loader.exec_module(module)
    except Exception as exc:
        raise OracleLoadError(f"failed to import oracle {path}: {exc}") from exc
    return module


def _wrap_stateful(oracle_obj: Any, path: Path) -> OracleFn:
    """Validate a Shape-2 oracle object and return its bound verify method."""
    verify = getattr(oracle_obj, "verify", None)
    if not callable(verify):
        raise OracleLoadError(
            f"{path}: build_oracle() returned {type(oracle_obj).__name__} "
            f"with no verify() method"
        )
    return verify


def _sandbox_validate_target(
    path_str: str,
    config: dict[str, Any],
    cpu_s: int,
    mem_bytes: int,
    conn: Any,
) -> None:
    """Spawn-safe child: apply resource caps, then import + ``build_oracle``.

    Runs the untrusted load path in a throwaway process so a hang/OOM cannot
    take down the parent. Resource limits are set BEFORE any user code runs.
    Never calls ``verify()`` — that is the hot loop and out of scope, and
    skipping it avoids side effects (opening sockets, etc.).

    Communicates the outcome back over ``conn`` as ``("ok", None)`` or
    ``("err", repr(exc))``. A hang / OOM-kill / CPU-kill instead manifests as
    the process dying without sending, which the parent detects.
    """
    try:
        # Resource caps are Unix-only; on Windows the wall-clock join is the
        # sole (and reliable) floor. Each setrlimit is best-effort: macOS may
        # reject/ignore RLIMIT_AS, which is fine — the timeout still applies.
        try:
            import resource
        except ImportError:  # pragma: no cover - Windows only
            resource = None  # type: ignore[assignment]
        if resource is not None:
            try:
                resource.setrlimit(resource.RLIMIT_CPU, (cpu_s, cpu_s))
            except (ValueError, OSError):  # pragma: no cover - platform dependent
                pass
            try:
                resource.setrlimit(resource.RLIMIT_AS, (mem_bytes, mem_bytes))
            except (ValueError, OSError):  # pragma: no cover - platform dependent
                pass

        spec = importlib.util.spec_from_file_location(
            "memdiver_user_oracle_probe", path_str
        )
        if spec is None or spec.loader is None:
            conn.send(("err", f"cannot create import spec for {path_str}"))
            return
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        builder = getattr(module, "build_oracle", None)
        if callable(builder):
            builder(dict(config))
        conn.send(("ok", None))
    except Exception as exc:  # noqa: BLE001 - report any user-code failure
        try:
            # Truncate: a multi-MB repr() would exceed the pipe buffer and block
            # the send while the parent is still in proc.join() (which precedes
            # recv), starving the send until the timeout kills the child — the
            # error would then be misclassified as a "hang". A small payload
            # always fits the buffer, keeping the fast "err" path fast.
            conn.send(("err", repr(exc)[:2000]))
        except Exception:  # pragma: no cover - pipe already gone
            pass
    finally:
        try:
            conn.close()
        except Exception:  # pragma: no cover
            pass


# Memoizes SUCCESSFUL ("ok") sandbox validations for a process lifetime so the
# same unchanged oracle file isn't re-spawned on every load (the full test suite
# and the brute-force initial load both re-load oracles repeatedly). The key is
# CONTENT-ADDRESSED: it folds in the file's sha256 so a same-length content swap
# with a forged mtime (os.utime/touch -d) still misses and is re-validated —
# this closes the TOCTOU hole that a (mtime, size)-only key would leave open.
# mtime_ns + size are kept too (harmless, and let a plain touch bust it without
# a hash compare hit). Only "ok" is cached; hang/crash/err always re-probe.
# Unbounded but naturally capped by the number of distinct oracle files a
# process sees.
_SANDBOX_OK_CACHE: dict[tuple[str, int, int, str, int, int], tuple[str, None]] = {}


def _sandbox_cache_key(
    path: Path | str, cpu_s: int, mem_bytes: int
) -> tuple[str, int, int, str, int, int] | None:
    """Build the content-addressed ok-cache key, or None if unstattable.

    Reads + sha256s the file (cheap for small oracle files, reusing the same
    hashing as :func:`_log_module_fingerprint`). Returns None on any OS error
    (stat/read) so the caller skips the cache and probes normally.
    """
    resolved = Path(path).resolve()
    try:
        st = resolved.stat()
        digest = sha256_streamed(resolved)
    except OSError:
        return None
    return (str(resolved), st.st_mtime_ns, st.st_size, digest, cpu_s, mem_bytes)


def _sandbox_probe(
    path: Path | str,
    config: dict[str, Any] | None,
    timeout_s: float,
    cpu_s: int,
    mem_bytes: int,
) -> tuple[str, str | None]:
    """Classify an oracle load, reusing a cached ``ok`` for an unchanged file.

    Thin caching wrapper over :func:`_sandbox_probe_spawn`: a successful
    validation of a file whose ``(path, mtime_ns, size, cpu_s, mem_bytes)`` is
    unchanged returns the cached ``("ok", None)`` without spawning. Every other
    outcome (``err``/``hang``/``crash``) is always re-probed and never cached,
    and a changed/replaced file misses the key and re-validates. If the file
    cannot be stat'd the cache is skipped and the spawn runs normally.
    """
    key = _sandbox_cache_key(path, cpu_s, mem_bytes)
    if key is not None and key in _SANDBOX_OK_CACHE:
        return _SANDBOX_OK_CACHE[key]
    result = _sandbox_probe_spawn(path, config, timeout_s, cpu_s, mem_bytes)
    if result[0] == "ok" and key is not None:
        _SANDBOX_OK_CACHE[key] = ("ok", None)
    return result


def _sandbox_probe_spawn(
    path: Path | str,
    config: dict[str, Any] | None,
    timeout_s: float,
    cpu_s: int,
    mem_bytes: int,
) -> tuple[str, str | None]:
    """Replay the oracle load in a spawned subprocess and classify the outcome.

    Returns one of:
      * ``("ok", None)``      — imported (and ``build_oracle`` ran) cleanly.
      * ``("err", detail)``   — a normal, reproducible exception at import/build.
      * ``("hang", detail)``  — still alive after ``timeout_s`` wall-clock.
      * ``("crash", detail)`` — exited without reporting: a resource-limit kill
        (SIGKILL from RLIMIT_AS/OOM, SIGXCPU from RLIMIT_CPU → negative exitcode)
        or a hard crash.

    Never calls ``verify()``. This is the shared engine behind both
    :func:`validate_oracle_sandboxed` (strict policy) and the in-process
    :func:`load_oracle` guard (which only blocks on hang/crash and lets a
    reproducible ``err`` fall through to the readable in-process importer).
    """
    path_str = str(Path(path))
    ctx = multiprocessing.get_context("spawn")
    parent_conn, child_conn = ctx.Pipe(duplex=False)
    proc = ctx.Process(
        target=_sandbox_validate_target,
        args=(path_str, dict(config or {}), cpu_s, mem_bytes, child_conn),
    )
    proc.start()
    child_conn.close()  # parent holds only the read end
    proc.join(timeout_s)

    if proc.is_alive():
        proc.terminate()
        proc.join(1.0)
        if proc.is_alive():  # pragma: no cover - terminate almost always wins
            proc.kill()
            proc.join(1.0)
        parent_conn.close()
        return (
            "hang",
            f"oracle load exceeded {timeout_s}s wall-clock (possible hang)",
        )

    result: Any = None
    try:
        if parent_conn.poll(0.1):
            result = parent_conn.recv()
    except (EOFError, OSError):  # pragma: no cover - child died mid-send
        result = None
    finally:
        parent_conn.close()

    if result is None:
        return (
            "crash",
            f"oracle crashed during load (exit code {proc.exitcode}); likely "
            f"exceeded a resource limit (CPU {cpu_s}s / mem {mem_bytes} bytes) "
            f"or crashed",
        )
    return result


def validate_oracle_sandboxed(
    path: Path | str,
    config: dict[str, Any] | None = None,
    *,
    timeout_s: float = _SANDBOX_TIMEOUT_S,
    cpu_s: int = _SANDBOX_CPU_S,
    mem_bytes: int = _SANDBOX_MEM_BYTES,
) -> None:
    """Validate an oracle's load path in a sandboxed subprocess (strict).

    Replays ``import`` + ``build_oracle(config)`` (never ``verify()``) inside a
    spawned child under a wall-clock ``timeout_s`` plus best-effort CPU/memory
    caps, then returns ``None`` if the oracle loaded cleanly. Raises
    :class:`OracleLoadError` if the oracle hangs (wall-clock timeout), is killed
    by a resource limit / OOM (RLIMIT_CPU/RLIMIT_AS → SIGKILL/SIGXCPU), or
    raises a normal exception during import/build.

    Spawn context is used for cross-platform + macOS safety; the target is a
    module-level function so it pickles cleanly.
    """
    kind, detail = _sandbox_probe(path, config, timeout_s, cpu_s, mem_bytes)
    if kind == "ok":
        return
    if kind == "err":
        raise OracleLoadError(f"oracle failed to load: {detail}")
    # hang / crash carry a fully-formed diagnostic already.
    raise OracleLoadError(str(detail))


def load_oracle(
    path: Path | str,
    config: dict[str, Any] | None = None,
    *,
    sandbox: bool = True,
) -> OracleFn:
    """Load a user oracle script and return a flat ``verify(bytes) -> bool``.

    Auto-detects Shape 1 (``def verify(candidate)``) vs Shape 2
    (``def build_oracle(config) -> Oracle``). Shape 2 is preferred when the
    oracle needs to cache KDF state or open a network connection once; Shape 1
    is fine for hot-path-only verifiers.

    Raises OracleLoadError on missing files, unsafe permissions, import
    failures, or missing/invalid exports.

    ``sandbox`` (default True) first replays the load path (import +
    ``build_oracle``) in a resource-capped subprocess under a wall-clock
    timeout, rejecting a hanging/OOMing oracle BEFORE it runs in-process. A
    reproducible import/build exception is deliberately allowed to fall through
    to the in-process importer below, which yields the readable
    ``failed to import`` / raw-exception diagnostics; only a hang or a
    resource-limit/crash blocks here. Pass ``sandbox=False`` for
    already-validated re-loads (e.g. per-worker loads in the brute-force pool)
    so they don't each pay for a redundant validation.
    """
    oracle_path = Path(path).resolve()
    _assert_safe_path(oracle_path)
    _log_module_fingerprint(oracle_path)
    if sandbox:
        kind, detail = _sandbox_probe(
            oracle_path, config, _SANDBOX_TIMEOUT_S, _SANDBOX_CPU_S, _SANDBOX_MEM_BYTES
        )
        if kind in ("hang", "crash"):
            raise OracleLoadError(str(detail))
    module = _import_user_module(oracle_path)

    builder = getattr(module, "build_oracle", None)
    if callable(builder):
        oracle_obj = builder(dict(config or {}))
        return _wrap_stateful(oracle_obj, oracle_path)

    verify = getattr(module, "verify", None)
    if callable(verify):
        return verify

    raise OracleLoadError(
        f"{oracle_path}: must export either verify(candidate) -> bool "
        f"or build_oracle(config) -> Oracle"
    )

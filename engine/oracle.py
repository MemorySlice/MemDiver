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
import shutil
import stat
import sys
import tomllib
from pathlib import Path
from typing import Any, Callable, Mapping, Protocol, runtime_checkable

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


class OracleBuildError(OracleLoadError):
    """The oracle imported/built and raised a NORMAL, reproducible exception.

    The benign half of a sandbox rejection, split out so a caller can tell
    "this oracle disagrees with the config it was handed" (a user error the
    user can fix, e.g. a Shape-2 oracle probed before it has been configured)
    apart from "this oracle hung or was killed by a resource limit" (a hostile
    outcome that must never reach an in-process import).

    A subclass, not a replacement: every existing ``except OracleLoadError``
    still catches it and :func:`validate_oracle_sandboxed` keeps its published
    behaviour and message. Only callers that explicitly want the distinction —
    and they must opt in by naming this class — see any difference. Anything
    that raises a bare :class:`OracleLoadError` therefore still reads as
    "not known to be benign", which is the safe default for a security gate.
    """


#: MemDiver's own automation table inside an oracle's TOML config.
#:
#: A bundled example declares its autofill rules and cipher requirement under
#: ``[memdiver]`` in the same file as the oracle's config, so the two can never
#: be shipped out of sync. It is OUR metadata, not the oracle's, and is dropped
#: in :func:`_oracle_visible_config` before any user code sees it -- an oracle
#: that validates its config strictly would otherwise reject a key it never
#: declared, and only on the surfaces that read the file.
RESERVED_CONFIG_TABLE = "memdiver"


def _oracle_visible_config(config: Mapping[str, Any] | None) -> dict[str, Any]:
    """The caller's config as ``build_oracle`` should see it.

    Applied at the two places a config crosses into user code -- the sandbox
    replay and the real load -- rather than in :func:`load_oracle_config`,
    which must keep returning the whole file for the autofill loader that reads
    the reserved table. Stripping here also covers a caller that passes a dict
    directly (the web pipeline does), so every surface hands the oracle the
    same keys.
    """
    return {
        key: value
        for key, value in dict(config or {}).items()
        if key != RESERVED_CONFIG_TABLE
    }


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


def _purge_pycache(path: Path) -> None:
    """Delete the ``__pycache__/`` directory next to ``path``.

    Importing from a fresh .py file can still pick up a stale .pyc the
    attacker dropped alongside it; purging proactively avoids that
    hole. Missing or empty dirs are fine.
    """
    cache_dir = path.parent / "__pycache__"
    if cache_dir.is_dir():
        shutil.rmtree(cache_dir, ignore_errors=True)


def _import_user_module(path: Path):
    """Import the oracle file as an isolated module named ``memdiver_user_oracle``.

    Bytecode writing is suppressed for the duration of the import, and any
    ``__pycache__`` the import still managed to leave is purged.

    Here rather than only in the web registry or the sandbox child, because
    THIS is the one function every surface reaches user code through. The
    registry sets ``sys.dont_write_bytecode`` for the web server's process and
    the sandbox child sets it for its own, but a CLI ``--oracle mine.py`` run
    and any library caller of :func:`load_oracle` used to drop a ``.pyc`` next
    to the analyst's own source -- in whatever directory that happened to be,
    at whatever permissions it happened to have. A stale ``.pyc`` can then
    shadow an edited ``.py``, so what runs stops being what was hashed and
    armed; that is the whole reason :func:`_purge_pycache` exists.

    The flag is restored rather than left set: it is process-global, and
    MemDiver is importable as a library inside someone else's application.
    """
    spec = importlib.util.spec_from_file_location("memdiver_user_oracle", path)
    if spec is None or spec.loader is None:
        raise OracleLoadError(f"cannot create import spec for {path}")
    module = importlib.util.module_from_spec(spec)
    previous = sys.dont_write_bytecode
    sys.dont_write_bytecode = True
    try:
        spec.loader.exec_module(module)
    except Exception as exc:
        raise OracleLoadError(f"failed to import oracle {path}: {exc}") from exc
    finally:
        sys.dont_write_bytecode = previous
        _purge_pycache(path)
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
    # FIRST statement, before any import of user code: this is a *spawned*
    # child — a fresh interpreter that never constructs an ``OracleRegistry``,
    # so the ``sys.dont_write_bytecode = True`` the registry sets in the parent
    # does not exist here. Without this line, importing the oracle below writes
    # ``__pycache__/*.pyc`` next to it — a world-readable 0755 directory inside
    # the 0700 oracle dir, and a stale-bytecode shadowing hole where what
    # executes is not what was hashed and armed. The parent additionally exports
    # PYTHONDONTWRITEBYTECODE for the child's own stdlib/dependency imports,
    # which happen before this function is ever reached.
    sys.dont_write_bytecode = True
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
            builder(_oracle_visible_config(config))
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
    # Belt and braces for the child's bytecode writes. ``spawn`` execs a brand
    # new interpreter that inherits this process's environment, and
    # PYTHONDONTWRITEBYTECODE is read at interpreter START — early enough to
    # cover the child's own imports of multiprocessing/stdlib/deps, which run
    # before ``_sandbox_validate_target`` (and its in-function
    # ``sys.dont_write_bytecode``) is reached. The variable is only exported
    # across ``start()``, which is where the child's environment is captured,
    # and any pre-existing value is restored so we never mutate the operator's
    # environment beyond that window.
    _prev_dontwrite = os.environ.get("PYTHONDONTWRITEBYTECODE")
    os.environ["PYTHONDONTWRITEBYTECODE"] = "1"
    try:
        proc.start()
    finally:
        if _prev_dontwrite is None:
            os.environ.pop("PYTHONDONTWRITEBYTECODE", None)
        else:
            os.environ["PYTHONDONTWRITEBYTECODE"] = _prev_dontwrite
    child_conn.close()  # parent holds only the read end
    proc.join(timeout_s)

    if proc.is_alive():
        proc.terminate()
        proc.join(1.0)
        if proc.is_alive():  # pragma: no cover - terminate almost always wins
            proc.kill()
            proc.join(1.0)
        parent_conn.close()
        # Third layer: a child from an older/odd interpreter, or one that
        # imported before we could stop it, may still have left a cache behind.
        _purge_pycache(Path(path_str))
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

    # Same third layer on the non-hang paths: the probe must leave the oracle
    # directory exactly as it found it.
    _purge_pycache(Path(path_str))

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

    The normal-exception case raises the :class:`OracleBuildError` subclass, so
    a caller that wants the lenient policy can catch just that one and let the
    hostile outcomes through (:func:`assert_oracle_not_hostile` is that policy
    pre-packaged). Every existing caller, which catches
    :class:`OracleLoadError`, is unaffected.

    Spawn context is used for cross-platform + macOS safety; the target is a
    module-level function so it pickles cleanly.
    """
    kind, detail = _sandbox_probe(path, config, timeout_s, cpu_s, mem_bytes)
    if kind == "ok":
        return
    if kind == "err":
        raise OracleBuildError(f"oracle failed to load: {detail}")
    # hang / crash carry a fully-formed diagnostic already.
    raise OracleLoadError(str(detail))


def assert_oracle_not_hostile(
    path: Path | str,
    config: dict[str, Any] | None = None,
    *,
    timeout_s: float = _SANDBOX_TIMEOUT_S,
    cpu_s: int = _SANDBOX_CPU_S,
    mem_bytes: int = _SANDBOX_MEM_BYTES,
) -> None:
    """Probe an oracle's load path and block only a hang or a crash (lenient).

    The *containment* half of :func:`validate_oracle_sandboxed`, exposed as a
    public policy so callers outside this module (notably the API's oracle
    registry) never have to reach into the private :func:`_sandbox_probe`.
    Same spawned, resource-capped child, same "never calls ``verify()``"
    guarantee — only the verdict differs:

    * ``hang`` / ``crash``  -> :class:`OracleLoadError`. These are the outcomes
      that would damage the *host*: an infinite loop at import or inside
      ``build_oracle``, or a RLIMIT_AS/RLIMIT_CPU kill. They must never reach an
      in-process import.
    * ``err``               -> allowed through. A reproducible exception means
      the oracle merely disagrees with the config it was handed, which is a
      *user* problem, not a hostile one — and it is re-checked, strictly and
      with the real config, at the point of user intent.

    This is exactly the policy :func:`load_oracle`'s own guard has always
    applied (see its docstring); naming it makes the upload-time / arm-time
    split in :mod:`memdiver.api.services.oracle_registry` legible, and keeps
    the strict policy of :func:`validate_oracle_sandboxed` untouched for its
    existing callers (``engine.brute_force`` runs the strict one before any
    worker loads the oracle).

    Implemented by *narrowing* the strict validator rather than by classifying
    the probe result a second time, so the two policies are one policy by
    construction and cannot drift apart.
    """
    try:
        validate_oracle_sandboxed(
            path,
            config,
            timeout_s=timeout_s,
            cpu_s=cpu_s,
            mem_bytes=mem_bytes,
        )
    except OracleBuildError:
        return


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
        # Same probe, same verdict as before — now expressed through the named
        # policy so this guard and the registry's upload-time check cannot
        # drift apart.
        assert_oracle_not_hostile(oracle_path, config)
    module = _import_user_module(oracle_path)

    builder = getattr(module, "build_oracle", None)
    if callable(builder):
        oracle_obj = builder(_oracle_visible_config(config))
        return _wrap_stateful(oracle_obj, oracle_path)

    verify = getattr(module, "verify", None)
    if callable(verify):
        return verify

    raise OracleLoadError(
        f"{oracle_path}: must export either verify(candidate) -> bool "
        f"or build_oracle(config) -> Oracle"
    )

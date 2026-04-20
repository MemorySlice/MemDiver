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
import stat
import sys
import tomllib
from pathlib import Path
from typing import Any, Callable, Protocol, runtime_checkable

logger = logging.getLogger("memdiver.engine.oracle")

OracleFn = Callable[[bytes], bool]


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
    """Refuse to load oracles from world-writable files or directories."""
    if not path.is_file():
        raise OracleLoadError(f"oracle file not found: {path}")
    file_mode = path.stat().st_mode
    if file_mode & stat.S_IWOTH:
        raise OracleLoadError(
            f"refusing to load world-writable oracle: {path} "
            f"(mode={stat.filemode(file_mode)}); tighten permissions first"
        )
    parent_mode = path.parent.stat().st_mode
    if parent_mode & stat.S_IWOTH:
        raise OracleLoadError(
            f"refusing to load oracle from world-writable directory: "
            f"{path.parent} (mode={stat.filemode(parent_mode)})"
        )


def _log_module_fingerprint(path: Path) -> str:
    """Print the sha256 of the loaded file so the user can audit what ran."""
    digest = hashlib.sha256(path.read_bytes()).hexdigest()
    print(
        f"memdiver: loaded oracle {path} sha256={digest}",
        file=sys.stderr,
    )
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


def load_oracle(
    path: Path | str,
    config: dict[str, Any] | None = None,
) -> OracleFn:
    """Load a user oracle script and return a flat ``verify(bytes) -> bool``.

    Auto-detects Shape 1 (``def verify(candidate)``) vs Shape 2
    (``def build_oracle(config) -> Oracle``). Shape 2 is preferred when the
    oracle needs to cache KDF state or open a network connection once; Shape 1
    is fine for hot-path-only verifiers.

    Raises OracleLoadError on missing files, unsafe permissions, import
    failures, or missing/invalid exports.
    """
    oracle_path = Path(path).resolve()
    _assert_safe_path(oracle_path)
    _log_module_fingerprint(oracle_path)
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

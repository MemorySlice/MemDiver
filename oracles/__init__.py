"""Self-contained format oracles: prove a recovered key from vault files alone.

Each module in :mod:`memdiver.oracles.formats` proves a candidate key against
the on-disk artefact it protects (a vault header, one encrypted file, ...),
never against network traffic. The modules follow a paste-safe contract
(documented in ``oracles/formats/__init__.py``) so that
:mod:`memdiver.oracles.embed` can copy them verbatim into generated
single-file Volatility 3 plugins.

This package is the in-repo registry: formats are discovered by the ``KIND``
they declare, and :func:`verdict_from` turns whatever a format returns into
an :class:`OracleVerdict`. It deliberately imports nothing heavy from
MemDiver. (It is unrelated to the ``memdiver.oracles`` entry-point GROUP in
``engine/resources/builtin_oracle.py``, which only shares the name.)
"""
from __future__ import annotations

import functools
import importlib
import logging
import pkgutil
from dataclasses import dataclass, field
from types import ModuleType
from typing import Any

VERDICT_STATUSES = ("proven", "rejected", "error")

#: Names every format module must expose (``REQUIRES_PRIMITIVES`` is optional).
FORMAT_CONTRACT = (
    "KIND", "CANDIDATE_LENGTHS", "COST_US", "SAMPLE_KIND", "build_oracle", "make_sample",
)

_FORMATS_PACKAGE = f"{__name__}.formats"
_log = logging.getLogger(__name__)
#: Package holding the stdlib-only crypto primitives named by REQUIRES_PRIMITIVES
#: (``<package>/linux/secrets/<name>.py``); ``embed`` inlines them from there.
PRIMITIVES_PACKAGE = "memdiver.vol3plugins"
PRIMITIVES_SUBDIR = ("linux", "secrets")


class UnknownFormatError(KeyError):
    """No format module declares the requested ``KIND``."""


class FormatContractError(TypeError):
    """A format module declares a ``KIND`` but misses part of the contract."""


@dataclass(frozen=True)
class OracleVerdict:
    """Outcome of verifying one candidate: proven, rejected, or error (no verdict)."""

    status: str
    kind: str
    detail: str = ""
    derived: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if self.status not in VERDICT_STATUSES:
            raise ValueError(f"status must be one of {VERDICT_STATUSES}, not {self.status!r}")

    @property
    def proven(self) -> bool:
        return self.status == "proven"


def verdict_from(obj: Any, kind: str = "") -> OracleVerdict:
    """Normalise a format module's return value into an :class:`OracleVerdict`.

    Accepts an ``OracleVerdict``, the contract's plain dict, or a legacy bool
    (``True`` -> proven). Anything malformed becomes an ``error`` verdict
    rather than an exception, so one broken oracle cannot abort a sweep.
    """
    if isinstance(obj, OracleVerdict):
        return obj
    if isinstance(obj, bool):
        return OracleVerdict("proven" if obj else "rejected", kind, "boolean oracle result")
    if isinstance(obj, dict):
        return _verdict_from_dict(obj, kind)
    return OracleVerdict("error", kind, f"unrecognised oracle result {type(obj).__name__}")


def _verdict_from_dict(obj: dict, kind: str) -> OracleVerdict:
    status, derived = obj.get("status"), obj.get("derived") or {}
    verdict_kind = str(obj.get("kind") or kind)
    if status not in VERDICT_STATUSES:
        return OracleVerdict("error", verdict_kind, f"malformed verdict: status={status!r}")
    if not isinstance(derived, dict):
        return OracleVerdict("error", verdict_kind, "malformed verdict: derived is not a dict")
    return OracleVerdict(status, verdict_kind, str(obj.get("detail") or ""), dict(derived))


@functools.lru_cache(maxsize=1)
def _discover() -> dict[str, ModuleType]:
    """Import every public module under ``formats/`` and index it by ``KIND``."""
    package = importlib.import_module(_FORMATS_PACKAGE)
    found: dict[str, ModuleType] = {}
    for info in sorted(pkgutil.iter_modules(package.__path__), key=lambda i: i.name):
        if info.name.startswith("_"):
            continue
        module = importlib.import_module(f"{_FORMATS_PACKAGE}.{info.name}")
        kind = getattr(module, "KIND", None)
        if not isinstance(kind, str):
            continue
        if kind in found:
            raise FormatContractError(
                f"KIND {kind!r} declared by both {found[kind].__name__} and {module.__name__}"
            )
        bind_primitives(module)
        found[kind] = module
    return found


def bind_primitives(module: ModuleType) -> None:
    """Bind each primitive in ``module.REQUIRES_PRIMITIVES`` as a global of ``module``.

    The in-repository twin of ``_inline_runtime.load_inlined``, which binds the
    INLINED copies inside a generated plugin: a format module only ever looks
    its primitives up with ``globals().get(name)``. A primitive that cannot be
    imported (for ANY reason: one broken primitive must not take down discovery of
    every format) is logged and left unbound, as the inline loader leaves an absent one.
    """
    prefix = ".".join((PRIMITIVES_PACKAGE,) + PRIMITIVES_SUBDIR)
    for name in getattr(module, "REQUIRES_PRIMITIVES", ()):
        if getattr(module, name, None) is not None:
            continue
        try:
            setattr(module, name, importlib.import_module(f"{prefix}.{name}"))
        except Exception as exc:  # ImportError, or a primitive that fails at import time
            _log.warning("primitive %s for %s left unbound: %r", name, module.__name__, exc)


def list_formats() -> list[str]:
    """Sorted ``KIND`` of every discovered format module."""
    return sorted(_discover())


def missing_contract(module: ModuleType) -> list[str]:
    """Contract names ``module`` does not expose (empty when it complies)."""
    return [name for name in FORMAT_CONTRACT if not hasattr(module, name)]


def get_format(kind: str) -> ModuleType:
    """The format module declaring ``KIND == kind``, checked against the contract."""
    formats = _discover()
    if kind not in formats:
        raise UnknownFormatError(f"no oracle format {kind!r}; known: {sorted(formats)}")
    module = formats[kind]
    missing = missing_contract(module)
    if missing:
        raise FormatContractError(f"{module.__name__} misses contract names {missing}")
    return module

"""Bridge the self-contained format oracles into MemDiver's BYO-oracle stage.

The format oracles in :mod:`memdiver.oracles.formats` (``gocryptfs-gcm``,
``luks``, ``xts-fsmagic``, ...) return a rich verdict dict from
``verify(candidate, ctx)``. The brute-force loop, the oracle registry's
arm / dry-run / smoke-test and the pipeline worker all speak the engine's
Shape-2 contract instead: ``build_oracle(config)`` returning an object with a
boolean ``verify(candidate)``. :class:`FormatOracleAdapter` is the one place
that translation happens, so every caller sees the same semantics:

* ``True`` only for a ``proven`` verdict; ``rejected`` and ``error`` are both
  ``False`` for the hot loop, and :attr:`FormatOracleAdapter.last_verdict`
  keeps the distinction for a caller that grades (an ``error`` means "no
  verdict", never "this is not the key").
* the format's optional ``prefilter`` runs first, exactly as a generated
  Volatility 3 plugin runs it, so a cheap structural rejection never pays for
  a KDF.

Resources are named ``format:<KIND>`` (see
:func:`memdiver.engine.resources.builtin_oracle.build_oracle`). Their config:

    resource_type = "format:luks"
    sample_b64 = "<base64 of the sample blob>"   # or:
    sample_path = "/path/to/header-or-sample"     # packed by load_format_sample
    params = { ... }                              # optional, per format
    ctx = { ... }                                 # optional static verify ctx

This module imports nothing heavy at import time: the format registry is
loaded on first use.
"""

from __future__ import annotations

import base64
import binascii
from pathlib import Path
from typing import Any, Dict, Optional, Tuple

#: Resource-type prefix under which every format oracle is registered.
FORMAT_RESOURCE_PREFIX = "format:"

#: Largest artefact read to build a sample. Samples are <= 8 KiB, but the
#: artefact they are packed from (a gocryptfs content file, a LUKS2 header with
#: its JSON area) can be larger; anything beyond this is not a sample source.
MAX_SAMPLE_SOURCE_BYTES = 64 * 1024 * 1024

_LUKS_MAGIC = b"LUKS\xba\xbe"
_GOCRYPTFS_CONF = "gocryptfs.conf"
#: How many parent directories a gocryptfs content file may sit below its
#: vault root (where gocryptfs.conf lives).
_MAX_VAULT_DEPTH = 16


def resource_type_for(kind: str) -> str:
    """The ``resource_type`` naming format oracle *kind*."""
    return f"{FORMAT_RESOURCE_PREFIX}{kind}"


def kind_of(resource_type: str) -> Optional[str]:
    """The format KIND of a ``format:<kind>`` resource type, else ``None``."""
    if isinstance(resource_type, str) and resource_type.startswith(FORMAT_RESOURCE_PREFIX):
        return resource_type[len(FORMAT_RESOURCE_PREFIX):] or None
    return None


def format_module(kind: str) -> Any:
    """The format module for *kind*; ``ValueError`` naming the known kinds."""
    from memdiver import oracles

    try:
        return oracles.get_format(kind)
    except oracles.UnknownFormatError as exc:
        raise ValueError(str(exc.args[0] if exc.args else exc)) from None


def module_is_unique(module: Any) -> bool:
    """Whether the format's built oracle declares ``unique`` (one key per sample).

    ``unique`` is an attribute of the BUILT oracle (see the format contract);
    every in-repo format sets it as a class attribute, so the module's classes
    answer it without building anything.
    """
    return any(
        isinstance(obj, type) and getattr(obj, "unique", False) is True
        for obj in vars(module).values()
    )


def describe_format(kind: str) -> Dict[str, Any]:
    """Static facts about one format: lengths, cost, evidence, uniqueness."""
    module = format_module(kind)
    return {
        "kind": kind,
        "resource_type": resource_type_for(kind),
        "candidate_lengths": [int(n) for n in module.CANDIDATE_LENGTHS],
        "cost_us": module.COST_US,
        "sample_kind": str(module.SAMPLE_KIND),
        "unique": module_is_unique(module),
    }


def list_format_kinds() -> Tuple[str, ...]:
    """Every format KIND the registry discovers, sorted."""
    from memdiver import oracles

    return tuple(oracles.list_formats())


class FormatOracleAdapter:
    """A format oracle behind the engine's Shape-2 ``verify(bytes) -> bool``."""

    def __init__(
        self,
        kind: str,
        params: Optional[Dict[str, Any]] = None,
        sample: bytes = b"",
        *,
        ctx: Optional[Dict[str, Any]] = None,
    ) -> None:
        from memdiver.oracles import OracleVerdict

        module = format_module(kind)
        if params is not None and not isinstance(params, dict):
            raise ValueError(f"params must be a mapping, not {type(params).__name__}")
        self.kind = kind
        self._verdict_type = OracleVerdict
        self._oracle = module.build_oracle(dict(params or {}), bytes(sample))
        self._ctx = dict(ctx or {})
        self.candidate_lengths = tuple(
            getattr(self._oracle, "candidate_lengths", None) or module.CANDIDATE_LENGTHS
        )
        self.cost_us = getattr(self._oracle, "cost_us", module.COST_US)
        self.unique = bool(getattr(self._oracle, "unique", False))
        self.sample_size = len(sample)
        self.last_verdict: Any = None

    def verify(self, candidate: bytes) -> bool:
        """``True`` only for a ``proven`` verdict; :attr:`last_verdict` keeps the rest."""
        verdict = self._judge(candidate)
        self.last_verdict = verdict
        return verdict.proven

    def _judge(self, candidate: Any) -> Any:
        from memdiver.oracles import verdict_from

        try:
            data = bytes(candidate)
        except (TypeError, ValueError):
            return self._verdict_type("error", self.kind, "candidate is not bytes-like")
        reason = self._prefilter(data)
        if reason:
            return self._verdict_type("rejected", self.kind, f"prefilter: {reason}")
        try:
            return verdict_from(self._oracle.verify(data, dict(self._ctx)), self.kind)
        except Exception as exc:  # noqa: BLE001 - the contract says never raise; enforce it
            return self._verdict_type("error", self.kind, f"verify raised {exc!r}")

    def _prefilter(self, data: bytes) -> Optional[str]:
        prefilter = getattr(self._oracle, "prefilter", None)
        if not callable(prefilter):
            return None
        try:
            reason = prefilter(data)
        except Exception:  # noqa: BLE001 - the contract: an exception means "no opinion"
            return None
        return str(reason) if reason else None

    def close(self) -> None:
        closer = getattr(self._oracle, "close", None)
        if callable(closer):
            closer()


# -- samples --------------------------------------------------------------


def decode_sample_b64(value: str) -> bytes:
    """Strictly decode a base64 sample; ``ValueError`` on anything malformed."""
    try:
        sample = base64.b64decode(str(value), validate=True)
    except (binascii.Error, ValueError) as exc:
        raise ValueError(f"sample_b64 is not valid base64: {exc}") from None
    if not sample:
        raise ValueError("sample_b64 decodes to zero bytes")
    return sample


def _read_capped(path: Path) -> bytes:
    size = path.stat().st_size
    if size > MAX_SAMPLE_SOURCE_BYTES:
        raise ValueError(
            f"{path} is {size} bytes; a sample source must be at most "
            f"{MAX_SAMPLE_SOURCE_BYTES} bytes"
        )
    return path.read_bytes()


def _vault_root_of(content_file: Path) -> Optional[Path]:
    """The nearest ancestor holding gocryptfs.conf, or ``None``."""
    for parent in list(content_file.parents)[:_MAX_VAULT_DEPTH]:
        if (parent / _GOCRYPTFS_CONF).is_file():
            return parent
    return None


def _gocryptfs_sample(module: Any, path: Path) -> bytes:
    if path.is_dir():
        # The format's own vault reader: the smallest content file whose
        # block 0 is not a sparse hole, packed with the vault's conf.
        return module.sample_from_vault(str(path))
    raw = _read_capped(path)
    if raw.startswith(module.SAMPLE_MAGIC):
        return raw
    root = _vault_root_of(path)
    conf = (root / _GOCRYPTFS_CONF).read_bytes() if root is not None else None
    return module.make_sample(raw, conf=conf)


def _luks_sample(module: Any, path: Path) -> bytes:
    raw = _read_capped(path)
    if raw[:6] == _LUKS_MAGIC:
        return module.make_sample(raw)
    return raw


def load_format_sample(kind: str, sample_path: "str | Path") -> bytes:
    """Read *sample_path* as the evidence for format *kind*.

    A path holding a ready ``make_sample`` blob is used as is. For two formats
    the natural artefact is packed here so nobody has to run ``make_sample`` by
    hand: a gocryptfs vault directory or content file (``gocryptfs.conf`` found
    in the vault root), and a raw LUKS1/LUKS2 header. Every other format's
    sample is the file's bytes.
    """
    module = format_module(kind)
    path = Path(sample_path).expanduser()
    if not path.exists():
        raise ValueError(f"sample path {str(sample_path)!r} does not exist")
    if kind == "gocryptfs-gcm":
        return _gocryptfs_sample(module, path)
    if path.is_dir():
        raise ValueError(f"sample path {str(sample_path)!r} is a directory")
    if kind == "luks":
        return _luks_sample(module, path)
    return _read_capped(path)


def sample_from_config(kind: str, config: Dict[str, Any]) -> bytes:
    """The sample named by a resource config: ``sample_b64`` wins over ``sample_path``."""
    if config.get("sample_b64"):
        return decode_sample_b64(config["sample_b64"])
    if config.get("sample_path"):
        return load_format_sample(kind, config["sample_path"])
    return b""


def format_resource_factory(kind: str):
    """A ``build_resource`` factory building :class:`FormatOracleAdapter` for *kind*."""

    def _factory(config: Dict[str, Any]) -> FormatOracleAdapter:
        params = config.get("params")
        ctx = config.get("ctx")
        if ctx is not None and not isinstance(ctx, dict):
            raise ValueError("ctx must be a mapping")
        return FormatOracleAdapter(kind, params, sample_from_config(kind, config), ctx=ctx)

    _factory.__name__ = f"format_resource_factory[{kind}]"
    return _factory


def format_oracle_config(
    kind: str,
    *,
    params: Optional[Dict[str, Any]] = None,
    sample_path: Optional[str] = None,
    sample_b64: Optional[str] = None,
) -> Tuple[Dict[str, Any], FormatOracleAdapter]:
    """Build and VALIDATE the Shape-2 config of a format oracle.

    The sample is resolved once (a path is read and packed now) and stored as
    ``sample_b64``, so the config is self-contained: arming, a dry run and a
    pipeline worker replaying it later all see the same bytes, even if the file
    moves. Returns the config and the adapter it built (close it when done).
    """
    if sample_b64 and sample_path:
        raise ValueError("give sample_path or sample_b64, not both")
    if sample_b64:
        sample = decode_sample_b64(sample_b64)
    elif sample_path:
        sample = load_format_sample(kind, sample_path)
    else:
        sample = b""
    adapter = FormatOracleAdapter(kind, params, sample)
    config: Dict[str, Any] = {"resource_type": resource_type_for(kind)}
    if sample:
        config["sample_b64"] = base64.b64encode(sample).decode("ascii")
    if params:
        config["params"] = dict(params)
    if sample_path:
        config["sample_source"] = str(Path(sample_path).expanduser())
    return config, adapter

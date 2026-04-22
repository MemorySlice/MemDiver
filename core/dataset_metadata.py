"""Per-run ``meta.json`` ingestion for MemDiver dataset scans.

Each run directory in the *dataset_memory_slice* corpus carries a
``meta.json`` describing the cipher, the plaintext password, the
master-key (hex), the recorded ASLR base, the target PID, and the
paths+sizes of every produced dump flavour. This module parses that
file into a strongly-typed :class:`DatasetMeta` consumed by
:mod:`core.discovery` and the ``/api/dataset/runs`` endpoint.

Unknown fields are ignored so the format can evolve without breaking
downstream callers. ``load_run_meta`` returns ``None`` when no
``meta.json`` is present — scans treat that as "legacy-style run".
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, Optional

logger = logging.getLogger("memdiver.core.dataset_metadata")

META_FILENAME = "meta.json"

# Canonical dump-kind keys used across discovery, dispatcher, and the API.
_DUMP_KIND_ALIASES = {
    "gcore": "gcore",
    "gdb_raw": "gdb_raw",
    "lldb_raw": "lldb_raw",
    "memslicer": "msl",
    "msl": "msl",
}


@dataclass
class DumpRef:
    """A single dump file declared by ``meta.json``."""

    path: Path
    size: int


@dataclass
class DatasetMeta:
    """Parsed ``meta.json`` payload for one run directory."""

    run_id: str
    cipher: str
    password: str
    master_key_hex: str
    master_key: bytes
    aslr_base: int
    pid: int
    dumps: Dict[str, DumpRef] = field(default_factory=dict)
    source_path: Path = field(default_factory=Path)

    def dump(self, kind: str) -> Optional[DumpRef]:
        """Convenience lookup by canonical kind (``gcore``/``gdb_raw``/...)."""
        return self.dumps.get(kind)


def load_run_meta(run_dir: Path) -> Optional[DatasetMeta]:
    """Parse ``run_dir/meta.json`` into a :class:`DatasetMeta`.

    Returns ``None`` when the file is missing. Returns ``None`` with a
    warning log on malformed JSON rather than raising; scan paths must
    tolerate partial datasets.
    """
    run_dir = Path(run_dir)
    meta_path = run_dir / META_FILENAME
    if not meta_path.is_file():
        return None

    try:
        with meta_path.open("rb") as f:
            payload = json.load(f)
    except (OSError, json.JSONDecodeError) as exc:
        logger.warning("Failed to read meta.json at %s: %s", meta_path, exc)
        return None

    try:
        return _build_meta(payload, run_dir, meta_path)
    except (KeyError, TypeError, ValueError) as exc:
        logger.warning("Malformed meta.json at %s: %s", meta_path, exc)
        return None


# -- Internals ----------------------------------------------------------------


def _build_meta(
    payload: dict,
    run_dir: Path,
    source_path: Path,
) -> DatasetMeta:
    """Convert a decoded ``meta.json`` mapping into a :class:`DatasetMeta`."""
    run_id = str(payload.get("run_id", run_dir.name))
    cipher = str(payload.get("cipher", ""))
    password = str(payload.get("password", ""))
    master_key_hex = str(payload.get("master_key_hex", ""))
    master_key = _decode_hex(master_key_hex)
    aslr_base = _parse_int(payload.get("aslr_base", 0))
    pid = int(payload.get("pid", 0))
    dumps = _parse_dumps(payload.get("dumps", {}), run_dir)

    return DatasetMeta(
        run_id=run_id,
        cipher=cipher,
        password=password,
        master_key_hex=master_key_hex,
        master_key=master_key,
        aslr_base=aslr_base,
        pid=pid,
        dumps=dumps,
        source_path=source_path,
    )


def _decode_hex(value: str) -> bytes:
    """Decode a hex string tolerating ``0x`` prefixes and odd lengths."""
    if not value:
        return b""
    clean = value.lower()
    if clean.startswith("0x"):
        clean = clean[2:]
    if len(clean) % 2:
        clean = "0" + clean
    try:
        return bytes.fromhex(clean)
    except ValueError:
        return b""


def _parse_int(value) -> int:
    """Accept ``"0x400000"``, ``"4194304"``, or a raw ``int``."""
    if isinstance(value, int):
        return value
    if isinstance(value, str) and value:
        try:
            return int(value, 0)
        except ValueError:
            return 0
    return 0


def _parse_dumps(raw: dict, run_dir: Path) -> Dict[str, DumpRef]:
    """Map the ``dumps`` subtree into ``{kind: DumpRef}`` with canonical keys."""
    result: Dict[str, DumpRef] = {}
    if not isinstance(raw, dict):
        return result
    dataset_root = _infer_dataset_root(run_dir)
    for raw_key, entry in raw.items():
        if not isinstance(entry, dict):
            continue
        kind = _DUMP_KIND_ALIASES.get(raw_key, raw_key)
        rel_path = entry.get("path", "")
        size = int(entry.get("size", 0))
        resolved = _resolve_dump_path(rel_path, run_dir, dataset_root)
        result[kind] = DumpRef(path=resolved, size=size)
    return result


def _infer_dataset_root(run_dir: Path) -> Path:
    """The ``meta.json`` paths are written relative to the dataset root.

    They look like ``run_0001/gcore.core`` so the root is one level up
    from the run directory.
    """
    return run_dir.parent


def _resolve_dump_path(rel: str, run_dir: Path, dataset_root: Path) -> Path:
    """Resolve a ``meta.json`` dump path against the run + dataset directories."""
    if not rel:
        return run_dir
    candidate = Path(rel)
    if candidate.is_absolute():
        return candidate
    # Most meta.json files express paths as ``run_0001/gcore.core``.
    rooted = dataset_root / candidate
    if rooted.exists():
        return rooted
    # Fallback: treat the tail as a filename inside run_dir.
    return run_dir / candidate.name

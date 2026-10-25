"""Stable ``capture_id`` for a capture file, without re-hashing what is stored.

* ``.mdview`` -> the descriptor's ``image_sha256`` (the image it views).
* ``.msl``    -> the End-of-Capture block's file hash, already in the file.
* anything else (or an ``.msl`` without a recorded hash) -> ``file_sha256``.

The result is lowercase hex, so it satisfies the analysis-record capture_id
pattern ``^[A-Za-z0-9_.\\-:]{1,128}$``.
"""

from __future__ import annotations

from pathlib import Path
from typing import Optional, Union

_ZERO_HASH = bytes(32)


def capture_id_for(path: Union[str, Path]) -> str:
    """The ``capture_id`` of the capture file at ``path``."""
    path = Path(path)
    suffix = path.suffix.lower()
    if suffix == ".mdview":
        return _descriptor_capture_id(path)
    if suffix == ".msl":
        stored = _msl_stored_hash(path)
        if stored is not None:
            return stored
    return _hash_capture_id(path)


def _descriptor_capture_id(path: Path) -> str:
    from memdiver.core.image.view_descriptor import ViewDescriptor

    return ViewDescriptor.read(path).capture_id


def _msl_stored_hash(path: Path) -> Optional[str]:
    """Hex of the EoC file hash, or ``None`` when absent or unrecorded."""
    from memdiver.msl.reader import MslReader

    with MslReader(path) as reader:
        blocks = reader.collect_end_of_capture()
    if not blocks or blocks[-1].file_hash in (b"", _ZERO_HASH):
        return None
    return blocks[-1].file_hash.hex()


def _hash_capture_id(path: Path) -> str:
    from memdiver.core.image.context import file_sha256

    return file_sha256(path)

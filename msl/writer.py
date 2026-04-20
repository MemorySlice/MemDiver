"""MSL file writer for producing valid Memory Slice binary files.

All struct layouts must match the corresponding decoders.py decoder
for roundtrip compatibility via MslReader.
"""

import logging
import struct
import time
from pathlib import Path
from typing import List, Optional, Tuple
from uuid import UUID, uuid4

from .enums import (BLOCK_HEADER_SIZE, BLOCK_MAGIC, BlockType, Endianness,
                    FILE_HEADER_SIZE, FILE_MAGIC, HeaderFlag, OSType, ArchType)
from .hashing import hash_bytes, hash_file, hash_stream

logger = logging.getLogger("memdiver.msl.writer")

_ZERO_HASH = b"\x00" * 32


def _pad8(n: int) -> int:
    return (n + 7) & ~7


def _pack_padded_str(s: str) -> bytes:
    raw = s.encode("utf-8") + b"\x00"
    return raw.ljust(_pad8(len(raw)), b"\x00")


def _file_digest_or_zero(path: Optional[Path]) -> bytes:
    """Return BLAKE3 digest of *path* via streamed reads, or zeros if missing.

    Handles the TOCTOU-safe path: we attempt the read directly and swallow
    FileNotFoundError rather than pre-checking with .exists().
    """
    if path is None:
        return _ZERO_HASH
    try:
        return hash_file(Path(path))
    except (FileNotFoundError, IsADirectoryError):
        return _ZERO_HASH


class MslWriter:
    """Accumulate blocks and write a valid MSL file."""

    def __init__(self, path: Path, pid: int = 0,
                 os_type: int = OSType.UNKNOWN,
                 arch_type: int = ArchType.UNKNOWN,
                 imported: bool = True):
        self._path = Path(path)
        self._pid = pid
        self._os_type = os_type
        self._arch_type = arch_type
        self._imported = imported
        self._dump_uuid = uuid4()
        self._blocks: List[Tuple[int, bytes, UUID]] = []

    @property
    def dump_uuid(self) -> UUID:
        return self._dump_uuid

    def add_memory_region(self, base_addr: int, data: bytes,
                          protection: int = 0x03, region_type: int = 0x05,
                          page_size_log2: int = 12,
                          timestamp_ns: int = 0) -> UUID:
        """Add a memory region block. Returns block UUID."""
        page_size = 1 << page_size_log2
        num_pages = (len(data) + page_size - 1) // page_size
        psm_padded = _pad8((num_pages * 2 + 7) // 8)
        page_state_map = b"\x00" * psm_padded  # all CAPTURED
        payload = struct.pack("<QQBBB5xQ", base_addr, len(data),
                              protection, region_type, page_size_log2,
                              timestamp_ns)
        payload += page_state_map + data
        block_uuid = uuid4()
        self._blocks.append((BlockType.MEMORY_REGION, payload, block_uuid))
        return block_uuid

    def add_key_hint(self, region_uuid: UUID, offset: int,
                     key_length: int, key_type: int, protocol: int,
                     confidence: int = 0x01, key_state: int = 0,
                     note: str = "") -> None:
        """Add a key hint block referencing a memory region."""
        note_bytes = _pack_padded_str(note) if note else b""
        note_raw_len = (len(note.encode("utf-8")) + 1) if note else 0
        payload = struct.pack("<16sQIHHBB2xI4x", region_uuid.bytes, offset,
                              key_length, key_type, protocol,
                              confidence, key_state, note_raw_len)
        payload += note_bytes
        self._blocks.append((BlockType.KEY_HINT, payload, uuid4()))

    def add_import_provenance(self, source_format: int, tool_name: str,
                              orig_file_size: int, note: str = "",
                              source_path: Optional[Path] = None) -> None:
        """Add an import provenance block.

        When *source_path* is provided and readable, its BLAKE3 digest
        is computed and written as `source_hash`. Otherwise source_hash
        is 32 zero bytes.
        """
        tool_bytes = _pack_padded_str(tool_name)
        tool_raw_len = len(tool_name.encode("utf-8")) + 1
        note_bytes = _pack_padded_str(note) if note else b""
        note_raw_len = (len(note.encode("utf-8")) + 1) if note else 0
        payload = struct.pack("<H2xIQQI4x", source_format, tool_raw_len,
                              int(time.time() * 1e9), orig_file_size,
                              note_raw_len)
        payload += tool_bytes + note_bytes
        payload += _file_digest_or_zero(source_path)
        self._blocks.append((BlockType.IMPORT_PROVENANCE, payload, uuid4()))

    def add_related_dump(self, related_uuid: UUID, related_pid: int,
                         relationship: int,
                         target_path: Optional[Path] = None) -> None:
        """Add a RELATED_DUMP block (type 0x0041).

        When *target_path* is provided and readable, its BLAKE3 digest
        is computed and written as `target_hash`, pinning the
        cross-reference. Otherwise target_hash is 32 zero bytes.
        """
        payload = struct.pack("<16sIH2x", related_uuid.bytes,
                              related_pid, relationship)
        payload += _file_digest_or_zero(target_path)
        self._blocks.append((BlockType.RELATED_DUMP, payload, uuid4()))

    def add_end_of_capture(self, reason: int = 0) -> None:
        """Add an end-of-capture block.

        The 32-byte file_hash slot is left as zeros here; `write()`
        finalizes it with a digest covering the file header and every
        preceding encoded block.
        """
        payload = struct.pack("<32sQ", b"\x00" * 32, int(time.time() * 1e9))
        self._blocks.append((BlockType.END_OF_CAPTURE, payload, uuid4()))

    def write(self) -> None:
        """Write all accumulated blocks to the output file.

        END_OF_CAPTURE blocks have their `file_hash` finalized over the
        file header plus every prior encoded block, so the EoC pins the
        full file contents.
        """
        file_header = self._encode_file_header()
        encoded_blocks: List[Optional[bytes]] = []
        prev_hash = _ZERO_HASH
        eoc_index: Optional[int] = None

        for idx, (block_type, payload, block_uuid) in enumerate(self._blocks):
            if block_type == BlockType.END_OF_CAPTURE:
                eoc_index = idx
                encoded_blocks.append(None)
                continue
            block_data = self._encode_block(block_type, payload,
                                             block_uuid, prev_hash)
            encoded_blocks.append(block_data)
            prev_hash = hash_bytes(block_data)

        if eoc_index is not None:
            self._finalize_end_of_capture(
                encoded_blocks, file_header, eoc_index, prev_hash,
            )

        self._path.parent.mkdir(parents=True, exist_ok=True)
        with open(self._path, "wb") as f:
            f.write(file_header)
            for block in encoded_blocks:
                if block is not None:
                    f.write(block)
        logger.info("Wrote MSL file: %s (%d blocks)",
                    self._path, len(self._blocks))

    def _finalize_end_of_capture(
        self,
        encoded_blocks: List[Optional[bytes]],
        file_header: bytes,
        eoc_index: int,
        prev_hash: bytes,
    ) -> None:
        """Fill in the EoC block's `file_hash` with a streaming digest.

        Streams the file header and all prior encoded blocks through the
        hasher to avoid materializing a concatenated digest input — MSL
        files can easily reach multi-GB when memory regions are included.
        """
        file_hash = hash_stream(
            (file_header, *(b for b in encoded_blocks if b is not None))
        )
        _, eoc_payload_stub, eoc_uuid = self._blocks[eoc_index]
        acq_end_ns = struct.unpack_from("<Q", eoc_payload_stub, 32)[0]
        new_eoc_payload = file_hash + struct.pack("<Q", acq_end_ns)
        encoded_blocks[eoc_index] = self._encode_block(
            BlockType.END_OF_CAPTURE, new_eoc_payload, eoc_uuid, prev_hash,
        )

    def _encode_file_header(self) -> bytes:
        version = (1 << 8) | 1  # v1.1
        return struct.pack(
            "<8sBBHIQ16sQHHIB7x",
            FILE_MAGIC, Endianness.LITTLE, FILE_HEADER_SIZE, version,
            HeaderFlag.IMPORTED if self._imported else 0,
            0, self._dump_uuid.bytes,
            int(time.time() * 1e9), self._os_type, self._arch_type,
            self._pid, 0,
        )

    def _encode_block(self, block_type: int, payload: bytes,
                      block_uuid: UUID, prev_hash: bytes) -> bytes:
        total_len = BLOCK_HEADER_SIZE + len(payload)
        header = struct.pack(
            "<4sHHIH2x16s16s32s",
            BLOCK_MAGIC, block_type, 0, total_len, 1,
            block_uuid.bytes, b"\x00" * 16, prev_hash,
        )
        return header + payload

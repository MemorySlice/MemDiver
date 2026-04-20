"""MSL file reader with mmap-backed, endianness-aware parsing."""

import logging
import mmap
import struct
from pathlib import Path
from typing import Iterator, List, Optional, Tuple
from uuid import UUID

from .block_iter import merge_continuations as _merge_cont
from .compress import decompress
from .decoders import (decode_connection_table, decode_connectivity_table,
                       decode_end_of_capture, decode_handle_table,
                       decode_import_provenance, decode_key_hint,
                       decode_memory_region, decode_module_entry,
                       decode_module_list_index, decode_process_identity,
                       decode_process_table, decode_related_dump,
                       decode_vas_map)
from .decoders_ext import (decode_environment_block, decode_file_descriptor,
                           decode_network_connection, decode_security_token,
                           decode_system_context, decode_thread_context)
from .enums import (BLOCK_HEADER_SIZE, BLOCK_MAGIC, BlockType, Endianness,
                    FILE_HEADER_SIZE, FILE_MAGIC)
from .types import (MslBlockHeader, MslConnectionTable, MslConnectivityTable,
                    MslEncryptedError, MslEndOfCapture, MslFileHeader,
                    MslHandleTable, MslImportProvenance, MslKeyHint,
                    MslMemoryRegion, MslModuleEntry, MslModuleListIndex,
                    MslParseError, MslProcessIdentity, MslProcessTable,
                    MslRelatedDump, MslVasMap)

logger = logging.getLogger("memdiver.msl.reader")


class MslReader:
    """Memory-mapped MSL file reader (context manager)."""

    _CACHE_ATTRS = ("_regions_cache", "_hints_cache", "_modules_cache",
                    "_process_identity_cache", "_vas_cache",
                    "_related_dumps_cache", "_end_of_capture_cache",
                    "_import_provenance_cache",
                    # New spec-defined table decoders (Phase MSL-Decoders-02)
                    "_module_list_index_cache", "_processes_cache",
                    "_connections_cache", "_handles_cache",
                    "_connectivity_tables_cache",
                    # Ext decoders (wired but speculative layouts; see decoders_ext.py)
                    "_thread_contexts_cache", "_file_descriptors_cache",
                    "_network_connections_cache", "_environment_blocks_cache",
                    "_security_tokens_cache", "_system_context_cache")

    def __init__(self, path: Path):
        self.path = path
        self._file = None
        self._mmap: Optional[mmap.mmap] = None
        self._file_header: Optional[MslFileHeader] = None
        self._byte_order: str = "<"
        for attr in self._CACHE_ATTRS:
            setattr(self, attr, None)

    def open(self) -> None:
        self._file = open(self.path, "rb")
        size = self.path.stat().st_size
        if size < FILE_HEADER_SIZE:
            raise MslParseError(f"File too small: {size} bytes")
        self._mmap = mmap.mmap(self._file.fileno(), 0, access=mmap.ACCESS_READ)
        self._file_header = self._parse_file_header()

    def close(self) -> None:
        for attr in self._CACHE_ATTRS:
            setattr(self, attr, None)
        if self._mmap:
            self._mmap.close()
            self._mmap = None
        if self._file:
            self._file.close()
            self._file = None

    def __enter__(self):
        self.open()
        return self

    def __exit__(self, *args):
        self.close()

    @property
    def file_header(self) -> MslFileHeader:
        if self._file_header is None:
            raise MslParseError("Reader not opened")
        return self._file_header

    def _parse_file_header(self) -> MslFileHeader:
        buf = self._mmap
        if buf[0:8] != FILE_MAGIC:
            raise MslParseError(f"Bad magic: {bytes(buf[0:8])!r}")
        endianness = buf[8]
        if endianness not in (Endianness.LITTLE, Endianness.BIG):
            raise MslParseError(f"Invalid endianness: 0x{endianness:02X}")
        self._byte_order = "<" if endianness == Endianness.LITTLE else ">"
        bo = self._byte_order
        header_size = buf[9]
        version = struct.unpack_from(f"{bo}H", buf, 0x0A)[0]
        flags = struct.unpack_from(f"{bo}I", buf, 0x0C)[0]
        cap_bitmap = struct.unpack_from(f"{bo}Q", buf, 0x10)[0]
        dump_uuid = UUID(bytes=bytes(buf[0x18:0x28]))
        timestamp_ns = struct.unpack_from(f"{bo}Q", buf, 0x28)[0]
        os_type = struct.unpack_from(f"{bo}H", buf, 0x30)[0]
        arch_type = struct.unpack_from(f"{bo}H", buf, 0x32)[0]
        pid = struct.unpack_from(f"{bo}I", buf, 0x34)[0]
        clock_source = buf[0x38]
        hdr = MslFileHeader(
            endianness=endianness, header_size=header_size,
            version_major=(version >> 8) & 0xFF,
            version_minor=version & 0xFF,
            flags=flags, cap_bitmap=cap_bitmap,
            dump_uuid=dump_uuid, timestamp_ns=timestamp_ns,
            os_type=os_type, arch_type=arch_type,
            pid=pid, clock_source=clock_source,
        )
        if hdr.encrypted:
            raise MslEncryptedError(
                "Encrypted MSL files not supported. Decrypt first."
            )
        return hdr

    def _parse_block_header(self, offset: int) -> MslBlockHeader:
        buf = self._mmap
        if buf[offset:offset + 4] != BLOCK_MAGIC:
            raise MslParseError(f"Bad block magic at 0x{offset:X}")
        bo = self._byte_order
        return MslBlockHeader(
            block_type=struct.unpack_from(f"{bo}H", buf, offset + 4)[0],
            flags=struct.unpack_from(f"{bo}H", buf, offset + 6)[0],
            block_length=struct.unpack_from(f"{bo}I", buf, offset + 8)[0],
            payload_version=struct.unpack_from(f"{bo}H", buf, offset + 0x0C)[0],
            block_uuid=UUID(bytes=bytes(buf[offset + 0x10:offset + 0x20])),
            parent_uuid=UUID(bytes=bytes(buf[offset + 0x20:offset + 0x30])),
            prev_hash=bytes(buf[offset + 0x30:offset + 0x50]),
            file_offset=offset,
            payload_offset=offset + BLOCK_HEADER_SIZE,
        )

    def _iter_raw_blocks(self) -> Iterator[Tuple[MslBlockHeader, bytes]]:
        """Iterate all blocks without continuation merging."""
        buf = self._mmap
        offset = self.file_header.header_size
        file_size = len(buf)
        while offset + BLOCK_HEADER_SIZE <= file_size:
            if buf[offset:offset + 4] != BLOCK_MAGIC:
                break
            hdr = self._parse_block_header(offset)
            if hdr.block_length < BLOCK_HEADER_SIZE:
                raise MslParseError(f"Invalid block length at 0x{offset:X}")
            end = offset + hdr.block_length
            if end > file_size:
                logger.warning("Truncated block at 0x%X", offset)
                break
            raw = bytes(buf[hdr.payload_offset:end])
            if hdr.compressed:
                raw = decompress(raw, hdr.comp_algo)
            yield hdr, raw
            offset = end

    def iter_blocks(self, merge_cont: bool = True) -> Iterator[Tuple[MslBlockHeader, bytes]]:
        """Iterate blocks; merges continuation blocks when *merge_cont* is True."""
        raw = self._iter_raw_blocks()
        return _merge_cont(raw) if merge_cont else raw

    def read_bytes(self, offset: int, length: int) -> bytes:
        """Read raw bytes from the mmap at given offset."""
        if self._mmap is None:
            return b""
        end = min(offset + length, len(self._mmap))
        return bytes(self._mmap[offset:end])

    def read_block_payload(self, hdr: MslBlockHeader) -> bytes:
        """Read and decompress a block's payload bytes."""
        if self._mmap is None:
            return b""
        end = min(hdr.file_offset + hdr.block_length, len(self._mmap))
        raw = bytes(self._mmap[hdr.payload_offset:end])
        if hdr.compressed:
            raw = decompress(raw, hdr.comp_algo)
        return raw

    def _collect(self, block_type, decoder, cache_attr):
        cached = getattr(self, cache_attr)
        if cached is None:
            cached = [decoder(h, p, self._byte_order)
                      for h, p in self.iter_blocks() if h.block_type == block_type]
            setattr(self, cache_attr, cached)
        return cached

    def collect_regions(self) -> List[MslMemoryRegion]:
        return self._collect(BlockType.MEMORY_REGION, decode_memory_region, "_regions_cache")

    def collect_key_hints(self) -> List[MslKeyHint]:
        return self._collect(BlockType.KEY_HINT, decode_key_hint, "_hints_cache")

    def collect_modules(self) -> List[MslModuleEntry]:
        return self._collect(BlockType.MODULE_ENTRY, decode_module_entry, "_modules_cache")

    def collect_process_identity(self) -> List[MslProcessIdentity]:
        return self._collect(BlockType.PROCESS_IDENTITY, decode_process_identity, "_process_identity_cache")

    def collect_vas_map(self) -> List[MslVasMap]:
        return self._collect(BlockType.VAS_MAP, decode_vas_map, "_vas_cache")

    def collect_related_dumps(self) -> List[MslRelatedDump]:
        return self._collect(BlockType.RELATED_DUMP, decode_related_dump, "_related_dumps_cache")

    def collect_end_of_capture(self) -> List[MslEndOfCapture]:
        return self._collect(BlockType.END_OF_CAPTURE, decode_end_of_capture, "_end_of_capture_cache")

    def collect_import_provenance(self) -> List[MslImportProvenance]:
        return self._collect(BlockType.IMPORT_PROVENANCE, decode_import_provenance, "_import_provenance_cache")

    # -- New spec-defined table block collectors --

    def collect_module_list_index(self) -> List[MslModuleListIndex]:
        return self._collect(BlockType.MODULE_LIST_INDEX, decode_module_list_index, "_module_list_index_cache")

    def collect_processes(self) -> List[MslProcessTable]:
        return self._collect(BlockType.PROCESS_TABLE, decode_process_table, "_processes_cache")

    def collect_connections(self) -> List[MslConnectionTable]:
        return self._collect(BlockType.CONNECTION_TABLE, decode_connection_table, "_connections_cache")

    def collect_handles(self) -> List[MslHandleTable]:
        return self._collect(BlockType.HANDLE_TABLE, decode_handle_table, "_handles_cache")

    def collect_connectivity_tables(self) -> List[MslConnectivityTable]:
        return self._collect(
            BlockType.CONNECTIVITY_TABLE,
            decode_connectivity_table,
            "_connectivity_tables_cache",
        )

    # -- Ext decoder collectors (speculative layouts; see decoders_ext.py) --

    def collect_thread_contexts(self) -> list:
        return self._collect(BlockType.THREAD_CONTEXT, decode_thread_context, "_thread_contexts_cache")

    def collect_file_descriptors(self) -> list:
        return self._collect(BlockType.FILE_DESCRIPTOR, decode_file_descriptor, "_file_descriptors_cache")

    def collect_network_connections(self) -> list:
        return self._collect(BlockType.NETWORK_CONNECTION, decode_network_connection, "_network_connections_cache")

    def collect_environment_blocks(self) -> list:
        return self._collect(BlockType.ENVIRONMENT_BLOCK, decode_environment_block, "_environment_blocks_cache")

    def collect_security_tokens(self) -> list:
        return self._collect(BlockType.SECURITY_TOKEN, decode_security_token, "_security_tokens_cache")

    def collect_system_context(self) -> list:
        """Collect SYSTEM_CONTEXT (0x0050) blocks per spec §6.2 Table 20."""
        return self._collect(BlockType.SYSTEM_CONTEXT, decode_system_context, "_system_context_cache")

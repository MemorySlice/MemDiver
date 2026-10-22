"""Region-filtered rewrite ("materialize") of an existing ``.msl``.

:func:`materialize_msl` copies an open ``.msl`` into a new file that holds
only the MEMORY_REGION blocks a selection keeps. An encrypted source (opened
with its key material) yields a copy re-encrypted under the same key wrapping
with a fresh nonce, or — explicit opt-in — a plaintext copy. Everything else
survives:

* file header identity — ``dump_uuid``, timestamp, clock source, os/arch/pid
  and the IMPORTED / INVESTIGATION flags are kept as in the source (a live
  capture stays a live capture; the rewrite is recorded in provenance, not by
  flipping IMPORTED);
* every non-region block is copied as stored on disk (payload, flags, block
  UUID and parent UUID), so parent references between copied blocks
  (Module Entry -> Module List Index, tables -> System Context, continuation
  -> parent) stay valid without remapping;
* KEY_HINT blocks are re-created against the new region UUIDs (located by
  virtual address); hints into excluded regions are dropped and counted;
* a fresh, complete VAS_MAP replaces any source VAS_MAP (source entries plus
  every source region, kept or excluded); when the source's mapping names
  are trusted the copy's note carries ``region_names=1`` so they stay so
  (a live memslicer capture gains provenance here, see
  :func:`import_preview.msl_classification_context`);
* one IMPORT_PROVENANCE records the rewrite (see :func:`_provenance_note`);
* END_OF_CAPTURE is recomputed by the writer; a post-EoC appendix (e.g.
  POINTER_GRAPH) is copied verbatim.

Region bytes are streamed from the source mmap; a compressed (or
continuation-merged) source region is decoded one block at a time.
"""

import logging
from dataclasses import dataclass
from pathlib import Path
from typing import List, Optional, Sequence

from .decoders import (decode_end_of_capture, decode_import_provenance,
                       decode_key_hint, decode_memory_region, decode_vas_map)
from .enums import BlockFlag, BlockType, HeaderFlag, SourceFormat, TagStatus
from .import_preview import (_module_for, _msl_modules,
                             msl_classification_context, msl_region_infos)
from .page_map import count_captured_pages
from .region_select import (DROPPED_KEY_HINTS_KEY, MATERIALIZED_KEY,
                            ORIG_EOC_HASH_KEY, REGION_NAMES_NOTE, RegionInfo,
                            join_provenance_note)
from .types import (MslBlockHeader, MslEndOfCapture, MslImportProvenance,
                    MslMemoryRegion, MslParseError, MslVasEntry)
from .writer import (CapBit, MslEncryptionConfig, MslWriter,
                     build_import_provenance_payload)

logger = logging.getLogger("memdiver.msl.materialize")

_DECODE_ERRORS = (MslParseError, ValueError, IndexError, OverflowError)
# Capability bits the writer recomputes from what it actually emits.
_RECOMPUTED_CAPS = CapBit.MEMORY_REGIONS | CapBit.CRYPTO_HINTS
# Blocks the rewrite re-creates instead of copying.
_RECREATED_TYPES = frozenset({BlockType.KEY_HINT, BlockType.VAS_MAP,
                              BlockType.IMPORT_PROVENANCE,
                              BlockType.END_OF_CAPTURE})


@dataclass
class StoredRegion:
    """One MEMORY_REGION block of a source ``.msl`` plus its classification."""

    header: MslBlockHeader
    region: MslMemoryRegion
    info: RegionInfo


@dataclass
class MaterializeStats:
    """What :func:`materialize_msl` wrote."""

    regions_written: int = 0
    key_hints_written: int = 0
    dropped_key_hints: int = 0


def stored_regions(reader, source_format: Optional[int]) -> List[StoredRegion]:
    """Every decodable MEMORY_REGION block, classified like the preview does.

    Mirrors :meth:`MslReader.iter_region_headers` (continuations skipped,
    malformed blocks skipped), so the order and the classification match
    :func:`import_preview.preview_import` for the same file (trusted VAS_MAP
    names included, see :func:`import_preview.msl_classification_context`).
    """
    modules = _msl_modules(reader)
    _, names, _ = msl_classification_context(reader)
    out: List[StoredRegion] = []
    for hdr in reader._iter_raw_block_headers():
        if not _is_region_head(hdr):
            continue
        try:
            region = decode_memory_region(hdr, reader._region_head(hdr),
                                          reader._byte_order)
        except _DECODE_ERRORS:
            continue
        captured = count_captured_pages(region.page_intervals) * region.page_size
        raw = (region.base_addr, region.region_size, region.protection,
               region.region_type, captured,
               _module_for(region.base_addr, region.region_size, modules))
        (info,) = msl_region_infos([raw], source_format, names)
        out.append(StoredRegion(hdr, region, info))
    return out


def _is_region_head(hdr: MslBlockHeader) -> bool:
    return (hdr.block_type == BlockType.MEMORY_REGION
            and not hdr.flags & BlockFlag.CONTINUATION)


class _RegionByteSource:
    """``read_chunk`` for one source region's captured-byte stream.

    An uncompressed, self-contained block is served straight from the reader
    buffer (mmap) without copying. A compressed or continued block has no
    random access: its full payload is decoded on first read and released
    after the last byte is served, so at most one such block is resident.
    """

    def __init__(self, reader, stored: StoredRegion):
        self._reader = reader
        self._hdr = stored.header
        region = stored.region
        map_bytes = ((region.num_pages + 3) // 4 + 7) & ~7
        self._data_start = 0x20 + map_bytes
        self.data_len = count_captured_pages(region.page_intervals) * region.page_size
        self._payload: Optional[bytes] = None

    @property
    def _random_access(self) -> bool:
        return not (self._hdr.compressed or self._hdr.flags & BlockFlag.HAS_CHILDREN)

    def __call__(self, offset: int, length: int):
        if self._random_access:
            return self._reader.read_view(
                self._hdr.payload_offset + self._data_start + offset, length)
        if self._payload is None:
            self._payload = self._decoded_payload()
        start = self._data_start + offset
        piece = memoryview(self._payload)[start:start + length]
        if offset + length >= self.data_len:
            self._payload = None  # done with this block
        return piece

    def _decoded_payload(self) -> bytes:
        if not self._hdr.flags & BlockFlag.HAS_CHILDREN:
            return self._reader.read_block_payload(self._hdr)
        for hdr, payload in self._reader.iter_blocks():
            if hdr.block_uuid == self._hdr.block_uuid:
                return payload
        raise ValueError(f"region block {self._hdr.block_uuid} vanished")


class _Materializer:
    """Single-use rewrite of one source ``.msl`` (see module docstring)."""

    def __init__(self, reader, src_path: Path, output_path: Path,
                 regions: Sequence[StoredRegion], keep: Sequence[bool],
                 selection_note: str,
                 encryption: Optional[MslEncryptionConfig] = None):
        self._reader = reader
        self._src_path = Path(src_path)
        self._selection_note = selection_note
        self._regions = list(regions)
        self._keep_by_offset = {r.header.file_offset: k
                                for r, k in zip(self._regions, keep)}
        self._region_by_uuid = {r.header.block_uuid: (r, k)
                                for r, k in zip(self._regions, keep)}
        fh = reader.file_header
        self._header = fh
        self._writer = MslWriter(
            output_path, pid=fh.pid, os_type=fh.os_type,
            arch_type=fh.arch_type,
            imported=bool(fh.flags & HeaderFlag.IMPORTED),
            investigation=bool(fh.flags & HeaderFlag.INVESTIGATION),
            dump_uuid=fh.dump_uuid, timestamp_ns=fh.timestamp_ns,
            clock_source=fh.clock_source, encryption=encryption,
        )
        self._writer.add_capabilities(fh.cap_bitmap & ~_RECOMPUTED_CAPS)
        self._hint_headers: List[MslBlockHeader] = []
        self._vas_entries: List[MslVasEntry] = []
        self._provenance: Optional[MslImportProvenance] = None
        self._eoc: Optional[MslEndOfCapture] = None
        # Source names trusted -> the copy keeps them trusted (marker).
        self._names_trusted = msl_classification_context(reader)[1] is not None
        self.stats = MaterializeStats()

    # -- block walk ---------------------------------------------------------

    def run(self) -> MaterializeStats:
        for hdr in self._reader._iter_raw_block_headers():
            self._route(hdr)
        self._add_key_hints()
        self._add_vas_map()
        self._add_provenance()
        self._add_end_and_appendix()
        self._writer.write()
        return self.stats

    def _route(self, hdr: MslBlockHeader) -> None:
        if hdr.block_type == BlockType.MEMORY_REGION:
            self._route_region(hdr)
        elif hdr.block_type in _RECREATED_TYPES:
            self._collect_recreated(hdr)
        else:
            self._copy_raw(hdr)

    def _route_region(self, hdr: MslBlockHeader) -> None:
        if hdr.flags & BlockFlag.CONTINUATION:
            # Merged into its kept parent, or dropped with its excluded one.
            if hdr.parent_uuid not in self._region_by_uuid:
                self._copy_raw(hdr)
            return
        keep = self._keep_by_offset.get(hdr.file_offset)
        if keep is None:
            logger.warning("copying undecodable MEMORY_REGION block at 0x%X "
                           "verbatim", hdr.file_offset)
            self._copy_raw(hdr)
        elif keep:
            self._add_region(self._region_by_uuid[hdr.block_uuid][0])

    def _add_region(self, stored: StoredRegion) -> None:
        region = stored.region
        source = _RegionByteSource(self._reader, stored)
        new_uuid = self._writer.add_memory_region_source(
            region.base_addr, region.region_size, source,
            protection=region.protection, region_type=region.region_type,
            page_size_log2=region.page_size_log2,
            timestamp_ns=region.timestamp_ns,
            page_states=[int(s) for s in region.page_states])
        logger.debug("region 0x%X: %s -> %s", region.base_addr,
                     stored.header.block_uuid, new_uuid)
        self.stats.regions_written += 1

    def _collect_recreated(self, hdr: MslBlockHeader) -> None:
        if hdr.block_type == BlockType.KEY_HINT:
            self._hint_headers.append(hdr)
            return
        payload = self._reader.read_block_payload(hdr)
        bo = self._reader._byte_order
        try:
            if hdr.block_type == BlockType.VAS_MAP:
                self._vas_entries.extend(decode_vas_map(hdr, payload, bo).entries)
            elif hdr.block_type == BlockType.IMPORT_PROVENANCE:
                if self._provenance is None:
                    self._provenance = decode_import_provenance(hdr, payload, bo)
            elif hdr.block_type == BlockType.END_OF_CAPTURE:
                self._eoc = decode_end_of_capture(hdr, payload, bo)
        except _DECODE_ERRORS as exc:
            logger.warning("dropping malformed %s block at 0x%X: %s",
                           BlockType(hdr.block_type).name, hdr.file_offset, exc)

    def _copy_raw(self, hdr: MslBlockHeader) -> None:
        payload = self._reader.read_bytes(hdr.payload_offset, hdr.payload_length)
        parent = hdr.parent_uuid if hdr.parent_uuid.int else None
        self._writer.add_raw_block(hdr.block_type, payload,
                                   block_uuid=hdr.block_uuid,
                                   parent_uuid=parent, flags=hdr.flags)

    # -- re-created blocks --------------------------------------------------

    def _add_key_hints(self) -> None:
        for hdr in self._hint_headers:
            self._add_key_hint(hdr)
        if self.stats.dropped_key_hints:
            logger.warning("%d key hint(s) referenced excluded regions and "
                           "were dropped", self.stats.dropped_key_hints)

    def _add_key_hint(self, hdr: MslBlockHeader) -> None:
        try:
            hint = decode_key_hint(hdr, self._reader.read_block_payload(hdr),
                                   self._reader._byte_order)
        except _DECODE_ERRORS:
            self._copy_raw_hint(hdr)
            return
        owner = self._region_by_uuid.get(hint.region_uuid)
        if owner is None:
            self._copy_raw_hint(hdr)  # dangling in the source already
            return
        stored, kept = owner
        located = self._writer.region_for_va(
            stored.region.base_addr + hint.region_offset) if kept else None
        if located is None:
            self.stats.dropped_key_hints += 1
            return
        new_uuid, offset = located
        self._writer.add_key_hint(new_uuid, offset, hint.key_length,
                                  hint.key_type, hint.protocol,
                                  confidence=hint.confidence,
                                  key_state=hint.key_state, note=hint.note)
        self.stats.key_hints_written += 1

    def _copy_raw_hint(self, hdr: MslBlockHeader) -> None:
        self._copy_raw(hdr)
        self._writer.add_capabilities(CapBit.CRYPTO_HINTS)
        self.stats.key_hints_written += 1

    def _add_vas_map(self) -> None:
        """Source VAS entries plus every source region not already covered."""
        entries = list(self._vas_entries)
        for stored in self._regions:
            info = stored.info
            if not any(e.base_addr <= info.base_addr < e.base_addr + e.region_size
                       for e in entries):
                entries.append(MslVasEntry(
                    base_addr=info.base_addr, region_size=info.size,
                    protection=info.protection, region_type=info.region_type,
                    mapped_path=info.name or info.module_path or ""))
        self._writer.add_vas_map(sorted(entries, key=lambda e: e.base_addr))

    def _add_provenance(self) -> None:
        prov = self._provenance
        # Keep the original source_format: stored-region classification
        # depends on it (RAW_DUMP regions stay UNCLASSIFIED).
        source_format = prov.source_format if prov else SourceFormat.MSL
        args = dict(source_format=source_format, tool_name="memdiver",
                    orig_file_size=self._src_path.stat().st_size,
                    note=self._provenance_note(), source_path=self._src_path)
        if self._header.flags & HeaderFlag.IMPORTED:
            self._writer.add_import_provenance(**args)
        else:
            # Live capture: Block 0 stays Process Identity, IMPORTED stays
            # clear; the provenance rides along as an ordinary block.
            self._writer.add_raw_block(BlockType.IMPORT_PROVENANCE,
                                       build_import_provenance_payload(**args))

    def _provenance_note(self) -> str:
        """``<orig note>; source_format=msl;...; <selection note>`` (last)."""
        parts = ["source_format=msl", f"{MATERIALIZED_KEY}=1",
                 f"{DROPPED_KEY_HINTS_KEY}={self.stats.dropped_key_hints}"]
        if self._names_trusted:
            parts.append(REGION_NAMES_NOTE)
        if self._eoc is not None and any(self._eoc.file_hash):
            parts.append(f"{ORIG_EOC_HASH_KEY}={self._eoc.file_hash.hex()}")
        base = join_provenance_note(self._provenance.note if self._provenance
                                    else "", ";".join(parts))
        return join_provenance_note(base, self._selection_note)

    def _add_end_and_appendix(self) -> None:
        acq_end = self._eoc.acq_end_ns if self._eoc is not None else None
        self._writer.add_end_of_capture(acq_end_ns=acq_end)
        start = self._reader._appendix_offset()
        if start is not None:
            self._writer.add_raw_appendix(self._reader.read_bytes(
                start, self._reader.buffer_length - start))


def require_decrypted(reader, name: str) -> None:
    """Raise ``ValueError`` unless *reader* is plaintext or tag-verified."""
    status = reader.tag_status
    if status in (TagStatus.NOT_ENCRYPTED, TagStatus.VALID):
        return
    if status is TagStatus.CORRUPTED:
        raise ValueError(
            f"cannot materialize encrypted .msl {name}: decryption failed "
            f"(wrong key material or tampered file)")
    raise ValueError(
        f"cannot materialize encrypted .msl {name}: key material required "
        f"(key file, passphrase or KEM private key); import without "
        f"materialize to stage it verbatim")


def output_encryption(reader, decrypt_output: bool
                      ) -> Optional[MslEncryptionConfig]:
    """Encryption for the copy: re-wrap an encrypted source unless opted out."""
    if not reader.file_header.encrypted or decrypt_output:
        return None
    return MslEncryptionConfig.rewrap(reader._rewrap_material())


def materialize_msl(reader, src_path: Path, output_path: Path,
                    regions: Sequence[StoredRegion], keep: Sequence[bool],
                    selection_note: str,
                    decrypt_output: bool = False) -> MaterializeStats:
    """Write *output_path*: *reader*'s ``.msl`` with only the kept regions.

    *regions* comes from :func:`stored_regions` on the same reader and *keep*
    is parallel to it. *selection_note* (``selection_provenance_note``) is
    appended last to the provenance note. The reader must stay open (region
    bytes are streamed from it).

    An encrypted source must have been opened with valid key material. The
    copy is then RE-ENCRYPTED with the same content key and key wrapping and
    a fresh nonce, so the same key / passphrase / private key opens it.
    *decrypt_output* (explicit opt-in) writes a plaintext copy instead.
    """
    require_decrypted(reader, Path(src_path).name)
    encryption = output_encryption(reader, decrypt_output)
    return _Materializer(reader, src_path, output_path, regions, keep,
                         selection_note, encryption).run()

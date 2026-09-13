"""MSL file reader with mmap-backed, endianness-aware parsing."""

import logging
import mmap
import struct
from pathlib import Path
from typing import Iterator, List, NamedTuple, Optional, Tuple
from uuid import UUID

from .block_iter import merge_continuations as _merge_cont
from .compress import decompress
from .crypto import aead_decrypt, derive_cek_consumer, nonce_for_cipher
from .decoders import (decode_connection_table, decode_connectivity_table,
                       decode_end_of_capture, decode_handle_table,
                       decode_import_provenance, decode_key_hint,
                       decode_memory_region, decode_module_entry,
                       decode_module_list_index, decode_process_identity,
                       decode_process_table, decode_related_dump,
                       decode_vas_map)
from .decoders_ext import (decode_environment_block, decode_file_descriptor,
                           decode_network_connection, decode_pointer_graph,
                           decode_security_token, decode_system_context,
                           decode_thread_context)
from .enums import (BLOCK_HEADER_SIZE, BLOCK_MAGIC, ENC_EXT_OFFSET,
                    FILE_HEADER_ENC_SIZE, FILE_HEADER_SIZE, FILE_MAGIC,
                    BlockType, EncAlgo, Endianness, KdfType, KeyEncap,
                    TagStatus)
from .types import (MslAuthError, MslBlockHeader, MslConnectionTable,
                    MslConnectivityTable, MslCryptoError,
                    MslEncryptionParams, MslEndOfCapture, MslFileHeader,
                    MslHandleTable, MslImportProvenance, MslKeyHint,
                    MslMemoryRegion, MslModuleEntry, MslModuleListIndex,
                    MslParseError, MslPointerGraph, MslProcessIdentity,
                    MslProcessTable, MslRelatedDump, MslVasMap)

logger = logging.getLogger("memdiver.msl.reader")


class CapturedRun(NamedTuple):
    """One contiguous run of CAPTURED pages, located in the block buffer.

    The unit of :meth:`MslReader.captured_run_index`. Everything a reader of
    ``.msl`` bytes needs in order to serve a window WITHOUT walking the
    container: where the run lives in virtual address space, where it lives in
    the flat ``"vas"`` stream, and where its bytes are in the buffer.

    ``length`` is the run's NOMINAL size (``pages * page_size``); ``avail`` is
    how many of those bytes the buffer actually holds. The two differ only for
    a container truncated mid-payload, and keeping them apart is what lets a
    caller report the run's true extent while copying only real bytes.
    """

    va_start: int
    length: int
    buf_offset: int
    avail: int
    vas_offset: int


class CapturedRunIndex(NamedTuple):
    """:class:`CapturedRun` runs plus the keys a read path bisects them by.

    ``runs`` is in ``vas_offset`` order — the order
    :meth:`MslDumpSource.iter_ranges` yields in, which is what makes
    ``vas_offset`` the flat ``"vas"`` stream offset. ``by_va`` is the same runs
    ordered by virtual address, because a ``"va"`` window has to find the runs
    that overlap an address and region base addresses are not guaranteed to
    arrive in VA order.

    The two ``*_starts`` tuples are the bisect keys for their respective
    orderings, materialized once so a lookup never rebuilds them.
    """

    runs: Tuple[CapturedRun, ...]
    by_va: Tuple[CapturedRun, ...]
    va_starts: Tuple[int, ...]
    vas_starts: Tuple[int, ...]


def _captured_page_runs(region) -> List[Tuple[int, int]]:
    """``[(start_page, page_count)]`` for the CAPTURED runs of one region.

    Accepts either representation a decoded region can carry — the per-page
    ``page_states`` list or the run-length ``page_intervals`` — because both
    are produced from the same PageStateMap and callers construct regions
    either way. ``page_states`` is consulted first: it is the input
    ``MslDumpSource.iter_ranges`` has always used, so the runs derived here are
    the same runs by construction rather than by coincidence.
    """
    from .page_map import PageInterval, PageState

    states = getattr(region, "page_states", None) or getattr(
        region, "page_intervals", None,
    )
    if not states:
        return []
    if isinstance(states[0], PageInterval):
        return [
            (int(iv.start_page), int(iv.count))
            for iv in states
            if iv.state == PageState.CAPTURED and iv.count > 0
        ]
    runs: List[Tuple[int, int]] = []
    run_start = 0
    for i in range(1, len(states) + 1):
        if i < len(states) and states[i] == states[run_start]:
            continue
        if states[run_start] == PageState.CAPTURED:
            runs.append((run_start, i - run_start))
        run_start = i
    return runs


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
                    "_security_tokens_cache", "_system_context_cache",
                    # POINTER_GRAPH appendix (MemDiver extension; lives after EoC)
                    "_pointer_graphs_cache")

    def __init__(self, path: Path, *,
                 key: Optional[bytes] = None,
                 passphrase: Optional[bytes] = None,
                 kem_private_key: Optional[bytes] = None):
        self.path = path
        self._file = None
        self._mmap: Optional[mmap.mmap] = None
        self._file_header: Optional[MslFileHeader] = None
        self._byte_order: str = "<"
        # Encryption (spec §10). Key material is supplied at construction;
        # tag_status communicates the decryption outcome to the caller.
        self._key = key
        self._passphrase = passphrase
        self._kem_private = kem_private_key
        self._enc_params: Optional[MslEncryptionParams] = None
        self._plaintext: Optional[bytes] = None   # decrypted block stream
        self.tag_status: TagStatus = TagStatus.NOT_ENCRYPTED
        # Block-region source: for plaintext files the mmap (blocks start at
        # header_size); for decrypted files the plaintext buffer (base 0).
        self._buf = None
        self._buf_base: int = 0
        # Derived from the region table AND the buffer, so it is NOT a
        # _CACHE_ATTRS block cache (those pair one-for-one with a collect_*
        # method). Reset alongside them wherever they are reset: a reopened
        # reader must never serve buffer offsets from the previous mapping.
        self._captured_runs_cache: Optional[CapturedRunIndex] = None
        for attr in self._CACHE_ATTRS:
            setattr(self, attr, None)

    def open(self) -> None:
        self._file = open(self.path, "rb")
        size = self.path.stat().st_size
        if size < FILE_HEADER_SIZE:
            raise MslParseError(f"File too small: {size} bytes")
        self._mmap = mmap.mmap(self._file.fileno(), 0, access=mmap.ACCESS_READ)
        self._file_header = self._parse_file_header()
        if self._file_header.encrypted:
            self._setup_decryption()  # sets tag_status, _plaintext, _buf
        else:
            self.tag_status = TagStatus.NOT_ENCRYPTED
            self._buf = self._mmap
            self._buf_base = self._file_header.header_size

    def close(self) -> None:
        for attr in self._CACHE_ATTRS:
            setattr(self, attr, None)
        self._captured_runs_cache = None
        self._plaintext = None
        self._buf = None
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

    # MSL Specification v1.0.0 (binary format 1.x). Reader rejects unknown
    # major versions per spec §3.4 ("Unknown major version: SHOULD reject").
    SUPPORTED_MAJOR_VERSION = 1
    KNOWN_MAX_MINOR_VERSION = 1

    def _parse_file_header(self) -> MslFileHeader:
        buf = self._mmap
        if buf[0:8] != FILE_MAGIC:
            raise MslParseError(f"Bad magic: {bytes(buf[0:8])!r}")
        endianness = buf[8]
        # Spec §3.1: "v1.1: MUST be 0x01. Other values MUST cause rejection."
        if endianness != Endianness.LITTLE:
            raise MslParseError(
                f"Invalid Endianness 0x{endianness:02X}; MSL Specification "
                f"v1.0.0 requires 0x01 (little-endian)"
            )
        self._byte_order = "<"
        bo = self._byte_order
        header_size = buf[9]
        version = struct.unpack_from(f"{bo}H", buf, 0x0A)[0]
        version_major = (version >> 8) & 0xFF
        version_minor = version & 0xFF
        # Spec §3.4: reject unknown major version; warn (don't reject) on
        # unknown minor of known major.
        if version_major != self.SUPPORTED_MAJOR_VERSION:
            raise MslParseError(
                f"Unsupported MSL major version {version_major}; this build "
                f"supports major version {self.SUPPORTED_MAJOR_VERSION} "
                f"(MSL Specification v1.0.0, binary format 1.x)"
            )
        if version_minor > self.KNOWN_MAX_MINOR_VERSION:
            logger.warning(
                "MSL minor version %d is newer than the highest known minor "
                "(%d); parsing best-effort per spec §3.4 forward-compat rule",
                version_minor, self.KNOWN_MAX_MINOR_VERSION,
            )
        flags = struct.unpack_from(f"{bo}I", buf, 0x0C)[0]
        cap_bitmap = struct.unpack_from(f"{bo}Q", buf, 0x10)[0]
        dump_uuid = UUID(bytes=bytes(buf[0x18:0x28]))
        timestamp_ns = struct.unpack_from(f"{bo}Q", buf, 0x28)[0]
        os_type = struct.unpack_from(f"{bo}H", buf, 0x30)[0]
        arch_type = struct.unpack_from(f"{bo}H", buf, 0x32)[0]
        pid = struct.unpack_from(f"{bo}I", buf, 0x34)[0]
        clock_source = buf[0x38]
        # Spec Table 3: BlockCount (0x39, u32) and HashAlgo (0x3D, u8).
        block_count = struct.unpack_from(f"{bo}I", buf, 0x39)[0]
        hash_algo = buf[0x3D]
        return MslFileHeader(
            endianness=endianness, header_size=header_size,
            version_major=version_major,
            version_minor=version_minor,
            flags=flags, cap_bitmap=cap_bitmap,
            dump_uuid=dump_uuid, timestamp_ns=timestamp_ns,
            os_type=os_type, arch_type=arch_type,
            pid=pid, clock_source=clock_source,
            block_count=block_count, hash_algo=hash_algo,
        )

    def _parse_enc_extension(self) -> MslEncryptionParams:
        """Parse the 64-byte encryption extension (spec Table 5, 0x40-0x7F)."""
        buf = self._mmap
        bo = self._byte_order
        off = ENC_EXT_OFFSET
        enc_algo = buf[off + 0x00]
        kdf_type = buf[off + 0x01]
        key_encap = buf[off + 0x02]
        # +0x03 reserved
        kdf_time = struct.unpack_from(f"{bo}I", buf, off + 0x04)[0]
        kdf_memory = struct.unpack_from(f"{bo}I", buf, off + 0x08)[0]
        kdf_lanes = buf[off + 0x0C]
        # +0x0D reserved2
        kem_ct_len = struct.unpack_from(f"{bo}H", buf, off + 0x0E)[0]
        nonce = bytes(buf[off + 0x10:off + 0x28])   # 24 bytes
        kdf_salt = bytes(buf[off + 0x28:off + 0x38])  # 16 bytes
        return MslEncryptionParams(
            enc_algo=enc_algo, kdf_type=kdf_type, key_encap=key_encap,
            kdf_time=kdf_time, kdf_memory=kdf_memory, kdf_lanes=kdf_lanes,
            kem_ct_len=kem_ct_len, nonce=nonce, kdf_salt=kdf_salt,
        )

    def _has_key_material(self, ep: MslEncryptionParams) -> bool:
        if ep.key_encap == KeyEncap.NONE:
            if ep.kdf_type == KdfType.NONE:
                return self._key is not None
            if ep.kdf_type == KdfType.ARGON2ID:
                return self._passphrase is not None
            return False
        return self._kem_private is not None

    def _setup_decryption(self) -> None:
        """Parse the encryption extension and attempt to decrypt the block
        stream (spec §10). Sets ``tag_status`` and, on success, populates the
        decrypted ``_buf`` that all block iteration reads from."""
        hs = self._file_header.header_size
        # Spec §14.2 rule 15: an encrypted file MUST declare HeaderSize=128.
        if hs != FILE_HEADER_ENC_SIZE:
            raise MslParseError(
                f"Encrypted MSL file must have HeaderSize=128, got {hs} "
                f"(MSL Specification v1.0.0 §3.2, §14.2)"
            )
        if self._mmap is None or len(self._mmap) < FILE_HEADER_ENC_SIZE:
            raise MslParseError("Encrypted MSL file truncated before extension header")
        ep = self._parse_enc_extension()
        self._enc_params = ep
        buf = self._mmap
        kem_ct = bytes(buf[hs:hs + ep.kem_ct_len])
        ciphertext_and_tag = bytes(buf[hs + ep.kem_ct_len:])

        if not self._has_key_material(ep):
            self.tag_status = TagStatus.MISSING_KEY
            return

        try:
            cek = derive_cek_consumer(
                key_encap=KeyEncap(ep.key_encap), kdf_type=KdfType(ep.kdf_type),
                dump_uuid_bytes=self._file_header.dump_uuid.bytes,
                raw_key=self._key, passphrase=self._passphrase,
                kdf_salt=ep.kdf_salt, kdf_time=ep.kdf_time,
                kdf_memory=ep.kdf_memory, kdf_lanes=ep.kdf_lanes,
                recipient_private=self._kem_private, kem_ciphertext=kem_ct,
            )
            aad = bytes(buf[0:hs]) + kem_ct
            nonce = nonce_for_cipher(EncAlgo(ep.enc_algo), ep.nonce)
            self._plaintext = aead_decrypt(
                EncAlgo(ep.enc_algo), cek, nonce, aad, ciphertext_and_tag,
            )
            self.tag_status = TagStatus.VALID
            self._buf = self._plaintext
            self._buf_base = 0
        # NOTE: MslAuthError and MslCryptoError both subclass ValueError, so
        # they MUST be caught before the bare ValueError clause. On any
        # failure path no plaintext is exposed (_buf/_plaintext stay None).
        except MslAuthError:
            # Wrong key or tampered ciphertext.
            self.tag_status = TagStatus.CORRUPTED
            self._plaintext = self._buf = None
        except MslCryptoError:
            # Unsupported algorithm or missing optional library (e.g. ML-KEM).
            self.tag_status = TagStatus.MISSING_KEY
            self._plaintext = self._buf = None
        except ValueError:
            # Malformed header declaring an unknown cipher/KEM/KDF code
            # (attacker-supplied bytes through KeyEncap()/KdfType()/EncAlgo()).
            self.tag_status = TagStatus.CORRUPTED
            self._plaintext = self._buf = None

    def _parse_block_header(self, offset: int) -> MslBlockHeader:
        buf = self._buf
        # Defensive bound check: every field below (UUIDs, prev_hash, struct
        # fields) assumes a full BLOCK_HEADER_SIZE-byte header is available.
        # All current callers guard the length, but protect future callers
        # from silently reading short/truncated slices.
        if offset < 0 or offset + BLOCK_HEADER_SIZE > len(buf):
            raise MslParseError(
                f"Truncated block header at 0x{offset:X}: need "
                f"{BLOCK_HEADER_SIZE} bytes, have {max(0, len(buf) - offset)}"
            )
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
        """Iterate in-chain blocks without continuation merging.

        Stops *after* yielding the End-of-Capture block: per spec, EoC is
        the last in-chain block, and anything past it is a MemDiver
        appendix (e.g., POINTER_GRAPH 0x1003) that lives outside the
        BLAKE3 prev_hash chain. The appendix is reachable via
        ``_iter_appendix_blocks()``.

        Reads from ``_buf``: the mmap (plaintext files) or the decrypted
        block stream (encrypted files). ``_buf`` is None for an encrypted
        file opened without a usable key, in which case nothing is yielded.
        """
        for hdr in self._iter_raw_block_headers():
            raw = bytes(self._buf[hdr.payload_offset:hdr.file_offset + hdr.block_length])
            if hdr.compressed:
                raw = decompress(raw, hdr.comp_algo)
            yield hdr, raw

    def _iter_raw_block_headers(self) -> Iterator[MslBlockHeader]:
        """Iterate in-chain block headers WITHOUT decompressing payloads.

        Shares the walk/validation logic with ``_iter_raw_blocks`` but
        yields only the parsed header, so callers that need just the
        framing (offset/length/type) avoid decompressing every payload.
        Stops *after* yielding the End-of-Capture header (see
        ``_iter_raw_blocks`` for the chain/appendix rationale).
        """
        buf = self._buf
        if buf is None:
            return
        offset = self._buf_base
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
            yield hdr
            offset = end
            if hdr.block_type == BlockType.END_OF_CAPTURE:
                break

    def _appendix_offset(self) -> Optional[int]:
        """Return the file offset where any appendix region begins, or None.

        Walks ``_iter_raw_block_headers`` (header-only, no payload
        decompression) and records the byte just past the last in-chain
        block. Returns None when the file has no EoC, no bytes follow EoC,
        or block parsing fails before EoC is reached.
        """
        if self._buf is None:
            return None
        end_offset: Optional[int] = None
        saw_eoc = False
        try:
            for hdr in self._iter_raw_block_headers():
                end_offset = hdr.file_offset + hdr.block_length
                if hdr.block_type == BlockType.END_OF_CAPTURE:
                    saw_eoc = True
                    break
        except MslParseError:
            return None
        if not saw_eoc or end_offset is None:
            return None
        return end_offset if end_offset < len(self._buf) else None

    def _iter_appendix_blocks(self) -> Iterator[Tuple[MslBlockHeader, bytes]]:
        """Iterate blocks in the post-EoC appendix region.

        Yields raw (header, payload) tuples. Appendix blocks live outside
        the BLAKE3 chain: their `prev_hash` is zero, and they are not
        considered when verifying integrity via ``verify_chain``. For
        encrypted files this reads the decrypted block stream, so the
        appendix is recovered transparently from inside the AEAD envelope.
        """
        buf = self._buf
        if buf is None:
            return
        appendix_start = self._appendix_offset()
        if appendix_start is None:
            return
        offset = appendix_start
        file_size = len(buf)
        while offset + BLOCK_HEADER_SIZE <= file_size:
            if buf[offset:offset + 4] != BLOCK_MAGIC:
                break
            hdr = self._parse_block_header(offset)
            if hdr.block_length < BLOCK_HEADER_SIZE:
                logger.warning("Invalid appendix block length at 0x%X", offset)
                break
            end = offset + hdr.block_length
            if end > file_size:
                logger.warning("Truncated appendix block at 0x%X", offset)
                break
            raw = bytes(buf[hdr.payload_offset:end])
            yield hdr, raw
            offset = end

    def iter_blocks(self, merge_cont: bool = True) -> Iterator[Tuple[MslBlockHeader, bytes]]:
        """Iterate blocks; merges continuation blocks when *merge_cont* is True."""
        raw = self._iter_raw_blocks()
        return _merge_cont(raw) if merge_cont else raw

    def read_bytes(self, offset: int, length: int) -> bytes:
        """Read raw bytes from the block region at the given offset.

        Offsets are relative to the same buffer block offsets use: the mmap
        for plaintext files, the decrypted stream for encrypted files."""
        if self._buf is None:
            return b""
        end = min(offset + length, len(self._buf))
        return bytes(self._buf[offset:end])

    @property
    def buffer_length(self) -> int:
        """Bytes addressable by :meth:`read_bytes` / :meth:`read_view`.

        Zero when the reader is closed. Exposed so a caller can decide how much
        of a block's declared payload a truncated container actually holds
        WITHOUT reading the payload to find out.
        """
        return 0 if self._buf is None else len(self._buf)

    def read_view(self, offset: int, length: int) -> memoryview:
        """:meth:`read_bytes` without the copy.

        Returns a memoryview over the same bytes and with the same clamping.
        A window read that used to copy a whole region to slice a page out of
        it can slice first and copy only what it returns.
        """
        if self._buf is None:
            return memoryview(b"")
        end = min(offset + length, len(self._buf))
        return memoryview(self._buf)[offset:end]

    def read_block_payload(self, hdr: MslBlockHeader) -> bytes:
        """Read and decompress a block's payload bytes."""
        if self._buf is None:
            return b""
        end = min(hdr.file_offset + hdr.block_length, len(self._buf))
        raw = bytes(self._buf[hdr.payload_offset:end])
        if hdr.compressed:
            raw = decompress(raw, hdr.comp_algo)
        return raw

    def _collect(self, block_type, decoder, cache_attr):
        cached = getattr(self, cache_attr)
        if cached is None:
            decoded = []
            for h, p in self.iter_blocks():
                if h.block_type != block_type:
                    continue
                # A single non-conformant block (e.g. a real-world capture
                # with an out-of-spec PageSizeLog2) must not abort the whole
                # collection and take unrelated blocks / consumers down with
                # it. Skip the offending block with a warning and continue;
                # decoders remain strict when called directly.
                try:
                    decoded.append(decoder(h, p, self._byte_order))
                except (MslParseError, struct.error, IndexError, OverflowError) as exc:
                    logger.warning(
                        "Skipping malformed %s block at 0x%X: %s",
                        block_type.name, h.file_offset, exc,
                    )
            cached = decoded
            setattr(self, cache_attr, cached)
        return cached

    def collect_regions(self) -> List[MslMemoryRegion]:
        return self._collect(BlockType.MEMORY_REGION, decode_memory_region, "_regions_cache")

    def captured_run_index(self) -> CapturedRunIndex:
        """Every CAPTURED run in the container, indexed for lookup (cached).

        The read path's map. Without it, answering "give me the 4 KiB at this
        virtual address" meant restarting a walk over the region table from
        region 0 and COPYING every region's page data on the way past — a
        measured 846 MB copied to deliver 16 KiB. With it, a read is a bisect
        plus one slice.

        Ordering is region base address, then page order within a region, which
        is exactly the order :meth:`MslDumpSource.iter_ranges` yields in — so
        ``vas_offset`` is the run's offset in the flat ``"vas"`` stream, not a
        second opinion about it.

        Buffer offsets are computed the same way the old per-region read
        computed them (payload start, past the 0x20 header and the 8-byte
        padded PageStateMap), so an index lookup and a region read land on the
        same byte. Cached on the READER, which the dump-source pool keeps
        alive, rather than on a per-request source view that would rebuild it
        every request; :data:`_CACHE_ATTRS` drops it on ``close()``.
        """
        cached = self._captured_runs_cache
        if cached is not None:
            return cached
        from .page_map import count_captured_pages

        buf_len = self.buffer_length
        runs: List[CapturedRun] = []
        vas_offset = 0
        for region in sorted(self.collect_regions(), key=lambda r: r.base_addr):
            page_size = int(region.page_size)
            map_bytes = ((int(region.num_pages) + 3) // 4 + 7) & ~7
            base = int(region.block_header.payload_offset) + 0x20 + map_bytes
            region_avail = max(
                0,
                min(count_captured_pages(region.page_states) * page_size,
                    buf_len - base),
            )
            data_offset = 0
            for start_page, page_count in _captured_page_runs(region):
                length = page_count * page_size
                runs.append(CapturedRun(
                    va_start=int(region.base_addr) + start_page * page_size,
                    length=length,
                    buf_offset=base + data_offset,
                    avail=max(0, min(length, region_avail - data_offset)),
                    vas_offset=vas_offset,
                ))
                data_offset += length
                vas_offset += length
        by_va = tuple(sorted(runs, key=lambda run: run.va_start))
        index = CapturedRunIndex(
            runs=tuple(runs),
            by_va=by_va,
            va_starts=tuple(run.va_start for run in by_va),
            vas_starts=tuple(run.vas_offset for run in runs),
        )
        self._captured_runs_cache = index
        return index

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

    # -- POINTER_GRAPH appendix collector (MemDiver extension) --

    def collect_pointer_graphs(self) -> List[MslPointerGraph]:
        """Collect POINTER_GRAPH appendix blocks (0x1003).

        These blocks live OUTSIDE the in-chain region (after EoC, and in
        Phase C after the AEAD Tag), so they are decoded from the
        post-EoC iterator rather than ``iter_blocks()``. Returns an empty
        list when no appendix is present — the common case for files
        produced before the extension landed.
        """
        if self._pointer_graphs_cache is not None:
            return self._pointer_graphs_cache
        cached = [
            decode_pointer_graph(h, p, self._byte_order)
            for h, p in self._iter_appendix_blocks()
            if h.block_type == BlockType.POINTER_GRAPH
        ]
        self._pointer_graphs_cache = cached
        return cached

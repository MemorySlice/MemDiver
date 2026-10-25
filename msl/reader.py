"""MSL file reader with mmap-backed, endianness-aware parsing."""

import logging
import mmap
import struct
from pathlib import Path
from typing import Iterator, List, NamedTuple, Optional, Tuple
from uuid import UUID

from .block_iter import merge_continuations as _merge_cont
from .aead_seek import (TAG_LEN, DecryptedView, FileGuard, FileIdentity,
                        SeekableDecryptor, oneshot_requested,
                        verify_tag_streaming)
from .compress import decompress
from .crypto import (RewrapMaterial, aead_decrypt, argon2id_below_minimum,
                     derive_cek_consumer, encryption_aad, nonce_for_cipher)
from .decoders import (decode_connection_table, decode_connectivity_table,
                       decode_end_of_capture, decode_end_of_extension,
                       decode_handle_table,
                       decode_import_provenance, decode_key_hint,
                       decode_memory_region, decode_module_entry,
                       decode_module_list_index, decode_process_identity,
                       decode_physical_memory_map,
                       decode_process_table, decode_related_dump,
                       decode_vas_map)
from .decoders_ext import (decode_environment_block, decode_file_descriptor,
                           decode_network_connection, decode_pointer_graph,
                           decode_security_token, decode_system_context,
                           decode_thread_context)
from .enums import (BLOCK_HEADER_SIZE, BLOCK_MAGIC, ENC_EXT_OFFSET,
                    FILE_HEADER_ENC_SIZE, FILE_HEADER_SIZE, FILE_MAGIC,
                    BlockFlag, BlockType, EncAlgo, Endianness, KdfType, KeyEncap,
                    TagStatus)
from .types import (ExtensionSegment, MslAuthError, MslBlockHeader,
                    MslConnectionTable, MslConnectivityTable, MslCryptoError,
                    MslEncryptionParams, MslEndOfCapture, MslEndOfExtension,
                    MslFileHeader,
                    MslHandleTable, MslImportProvenance, MslKeyHint,
                    MslMemoryRegion, MslModuleEntry, MslModuleListIndex,
                    MslParseError, MslPhysicalMemoryMap, MslPointerGraph, MslProcessIdentity,
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

    ``block`` is ``None`` for an uncompressed region: ``buf_offset`` is then
    an offset into the reader's block buffer (mmap / decrypted stream). For a
    COMPRESSED region block it is that block's header, and ``buf_offset`` is
    an offset into the block's DECOMPRESSED payload — the on-disk bytes are
    codec output, not memory. Read run bytes through
    :meth:`MslReader.run_view` / :meth:`MslReader.iter_find_run`, which
    handle both cases.
    """

    va_start: int
    length: int
    buf_offset: int
    avail: int
    vas_offset: int
    block: Optional[MslBlockHeader] = None


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


#: Window for searching a buffer that has no ``find`` (the lazily decrypted
#: view): the most plaintext one search step holds at a time.
FIND_WINDOW = 8 * 1024 * 1024


def _iter_find_windowed(read, needle: bytes, start: int, end: int,
                        window: int = FIND_WINDOW) -> Iterator[int]:
    """Yield offsets of *needle* in ``[start, end)`` via bounded ``read`` calls.

    ``read(offset, length) -> bytes``. Consecutive windows overlap by
    ``len(needle) - 1`` bytes, so every match that fits in the range fits
    wholly inside some window; a match seen in two windows is reported once
    (offsets are ascending, so anything below the last reported offset + 1
    was already yielded). The window is never smaller than ``2 * len(needle)``
    so the walk always advances.
    """
    n = len(needle)
    if n == 0 or start >= end:
        return
    window = max(window, 2 * n)
    step = window - (n - 1)
    next_min = start
    pos = start
    while pos < end:
        take = min(window, end - pos)
        data = read(pos, take)
        at = data.find(needle)
        while at >= 0:
            hit = pos + at
            if hit >= next_min:
                yield hit
                next_min = hit + 1
            at = data.find(needle, at + 1)
        if pos + take >= end:
            return
        pos += step


class MslReader:
    """Memory-mapped MSL file reader (context manager)."""

    _CACHE_ATTRS = ("_regions_cache", "_hints_cache", "_modules_cache",
                    "_process_identity_cache", "_vas_cache",
                    "_related_dumps_cache", "_end_of_capture_cache",
                    "_import_provenance_cache",
                    # New spec-defined table decoders (Phase MSL-Decoders-02)
                    "_module_list_index_cache", "_processes_cache",
                    "_connections_cache", "_handles_cache",
                    "_connectivity_tables_cache", "_physical_memory_map_cache",
                    # Ext decoders (0x0011 per spec 5.7; the rest speculative)
                    "_thread_contexts_cache", "_file_descriptors_cache",
                    "_network_connections_cache", "_environment_blocks_cache",
                    "_security_tokens_cache", "_system_context_cache",
                    # Extension-segment collectors (spec 4.6); the segment
                    # scan / verification caches they build on are reset
                    # with them in _reset_segment_caches().
                    "_end_of_extension_cache", "_pointer_graphs_cache",
                    "_extension_vas_cache")

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
        # Decrypted block stream: a lazily decrypted DecryptedView after a
        # streamed tag verification (default), or the whole plaintext as
        # bytes when MEMDIVER_MSL_DECRYPT_ONESHOT=1 selects the legacy path.
        self._plaintext = None
        # Re-wrap handle (CEK + key-wrapping header fields), set only after a
        # tag-verified decrypt; wiped on close. See _rewrap_material().
        self._rewrap: Optional[RewrapMaterial] = None
        self.tag_status: TagStatus = TagStatus.NOT_ENCRYPTED
        # First byte after the primary AEAD tag (spec 1.1.1 §10.2), set once
        # the tag verifies: where sealed extension segments (§10.8) and then
        # trailing data begin. None for plaintext / unverified files.
        self._post_tag_offset: Optional[int] = None
        # Block-region source: for plaintext files the mmap (blocks start at
        # header_size); for decrypted files the plaintext buffer (base 0).
        self._buf = None
        self._buf_base: int = 0
        # Derived from the region table AND the buffer, so it is NOT a
        # _CACHE_ATTRS block cache (those pair one-for-one with a collect_*
        # method). Reset alongside them wherever they are reset: a reopened
        # reader must never serve buffer offsets from the previous mapping.
        self._captured_runs_cache: Optional[CapturedRunIndex] = None
        # Compressed region blocks: decompressed payload length per block
        # file offset (recorded while collect_regions decodes them), and a
        # ONE-entry cache of the most recently decompressed payload, so at
        # most one decompressed block (<= the 1 GiB region block cap) is
        # held at a time. Both reset with the other caches.
        self._decompressed_lengths: dict = {}
        self._payload_cache: Optional[Tuple[int, bytes]] = None
        for attr in self._CACHE_ATTRS:
            setattr(self, attr, None)
        # Extension segments (spec 4.6): header-only framing and the
        # per-segment verification reports; not block caches, so they are
        # kept out of _CACHE_ATTRS and reset alongside it.
        self._extension_segments_cache: Optional[List[ExtensionSegment]] = None
        self._segment_reports_cache = None
        # Sealed extension segments after the primary tag (spec 10.8):
        # (verified segments, trailing offset); opened lazily, reset on close.
        self._sealed_cache = None

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
        self._extension_segments_cache = None
        self._segment_reports_cache = None
        self._sealed_cache = None
        self._decompressed_lengths = {}
        self._payload_cache = None
        if isinstance(self._plaintext, DecryptedView):
            self._plaintext.close()  # releases its mmap view before the close
        self._plaintext = None
        self._buf = None
        self._post_tag_offset = None
        if self._rewrap is not None:
            self._rewrap.wipe()
            self._rewrap = None
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
        # +0x38 CipherLen (spec 1.1.1; formerly Reserved3), u64
        cipher_len = struct.unpack_from(f"{bo}Q", buf, off + 0x38)[0]
        return MslEncryptionParams(
            enc_algo=enc_algo, kdf_type=kdf_type, key_encap=key_encap,
            kdf_time=kdf_time, kdf_memory=kdf_memory, kdf_lanes=kdf_lanes,
            kem_ct_len=kem_ct_len, nonce=nonce, kdf_salt=kdf_salt,
            cipher_len=cipher_len,
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

        if not self._has_key_material(ep):
            self.tag_status = TagStatus.MISSING_KEY
            return

        try:
            cek = self._derive_cek(ep, kem_ct, enforce_minimum=False)
            try:
                self._decrypt_with_cek(ep, cek, kem_ct)
            except MslAuthError:
                if not self._weak_argon2id_params(ep):
                    raise
                # Backward compatibility: earlier MemDiver writers stored the
                # configured (weak) Argon2id params in the header but derived
                # the CEK with params clamped to the spec minimum. Retry once
                # with the clamped params before reporting CORRUPTED.
                self._drop_decryption_state()
                cek = self._derive_cek(ep, kem_ct, enforce_minimum=True)
                self._decrypt_with_cek(ep, cek, kem_ct)
                logger.warning(
                    "%s: decrypted with Argon2id params clamped to the spec "
                    "minimum (legacy MemDiver file; header stores weaker ones)",
                    self.path)
            self.tag_status = TagStatus.VALID
            self._post_tag_offset = self._ciphertext_end() + TAG_LEN
            self._buf = self._plaintext
            self._buf_base = 0
            if self._rewrap is None:
                self._rewrap = self._build_rewrap(ep, cek, kem_ct)
        # NOTE: MslAuthError and MslCryptoError both subclass ValueError, so
        # they MUST be caught before the bare ValueError clause. On any
        # failure path no plaintext is exposed (_buf/_plaintext stay None).
        except MslAuthError:
            # Wrong key or tampered ciphertext.
            self.tag_status = TagStatus.CORRUPTED
            self._drop_decryption_state()
        except MslCryptoError:
            # Unsupported algorithm or missing optional library (e.g. ML-KEM).
            self.tag_status = TagStatus.MISSING_KEY
            self._drop_decryption_state()
        except ValueError:
            # Malformed header declaring an unknown cipher/KEM/KDF code
            # (attacker-supplied bytes through KeyEncap()/KdfType()/EncAlgo()).
            self.tag_status = TagStatus.CORRUPTED
            self._drop_decryption_state()

    def _derive_cek(self, ep: MslEncryptionParams, kem_ct: bytes, *,
                    enforce_minimum: bool) -> bytes:
        """Derive the CEK from the header params (exactly, unless clamped)."""
        return derive_cek_consumer(
            key_encap=KeyEncap(ep.key_encap), kdf_type=KdfType(ep.kdf_type),
            dump_uuid_bytes=self._file_header.dump_uuid.bytes,
            raw_key=self._key, passphrase=self._passphrase,
            kdf_salt=ep.kdf_salt, kdf_time=ep.kdf_time,
            kdf_memory=ep.kdf_memory, kdf_lanes=ep.kdf_lanes,
            recipient_private=self._kem_private, kem_ciphertext=kem_ct,
            enforce_minimum=enforce_minimum,
        )

    def _decrypt_with_cek(self, ep: MslEncryptionParams, cek: bytes,
                          kem_ct: bytes) -> None:
        """Verify the AEAD tag with *cek*; raises MslAuthError on mismatch."""
        hs = self._file_header.header_size
        aad = encryption_aad(bytes(self._mmap[0:hs]), kem_ct)
        algo = EncAlgo(ep.enc_algo)
        nonce = nonce_for_cipher(algo, ep.nonce)
        if oneshot_requested():
            self._decrypt_oneshot(algo, cek, nonce, aad)
        else:
            self._verify_and_seek(algo, cek, nonce, aad, kem_ct)

    @staticmethod
    def _weak_argon2id_params(ep: MslEncryptionParams) -> bool:
        """True for a passphrase container whose header params are below
        the spec minimum (candidate for the legacy clamped-params retry)."""
        return (ep.key_encap == KeyEncap.NONE
                and ep.kdf_type == KdfType.ARGON2ID
                and argon2id_below_minimum(ep.kdf_time, ep.kdf_memory,
                                           ep.kdf_lanes))

    def _ciphertext_start(self) -> int:
        return self._file_header.header_size + self._enc_params.kem_ct_len

    def _ciphertext_end(self) -> int:
        """End of the primary ciphertext == offset of its 16-byte tag.

        Spec 1.1.1 §10.2 "Locating the tag": ``CipherLen=0`` puts the tag in
        the final 16 bytes; otherwise it follows ``CipherLen`` ciphertext
        bytes. Raises :class:`MslAuthError` (-> CORRUPTED) when the tag
        cannot fit, including ``CipherLen > size - HeaderSize - KEMCtLen - 16``.
        """
        start = self._ciphertext_start()
        room = len(self._mmap) - start - TAG_LEN
        cipher_len = self._enc_params.cipher_len
        if room < 0:
            raise MslAuthError("AEAD tag missing (container truncated)")
        if cipher_len > room:
            raise MslAuthError(
                f"CipherLen {cipher_len} exceeds the {room} ciphertext bytes "
                "available before a 16-byte tag (truncated or corrupt)")
        return start + (cipher_len if cipher_len else room)

    @property
    def post_tag_offset(self) -> Optional[int]:
        """File offset just past the verified primary AEAD tag, else None."""
        return self._post_tag_offset

    def _decrypt_oneshot(self, algo: EncAlgo, cek: bytes, nonce: bytes,
                         aad: bytes) -> None:
        """Legacy path (``MEMDIVER_MSL_DECRYPT_ONESHOT=1``): whole plaintext.

        Zero-copy view of the ciphertext for AES-GCM (cryptography accepts any
        buffer), so peak RAM is ~1x the block stream, not 2x. PyNaCl demands
        ``bytes``, so XChaCha20 still copies. Released in finally.
        """
        tag_end = self._ciphertext_end() + TAG_LEN
        ct_view = memoryview(self._mmap)[self._ciphertext_start():tag_end]
        try:
            ciphertext_and_tag = (ct_view if algo == EncAlgo.AES_256_GCM
                                  else bytes(ct_view))
            self._plaintext = aead_decrypt(algo, cek, nonce, aad,
                                           ciphertext_and_tag)
        finally:
            ct_view.release()

    def _verify_and_seek(self, algo: EncAlgo, cek: bytes, nonce: bytes,
                         aad: bytes, kem_ct: bytes) -> None:
        """Default path: verify the tag in one bounded streamed pass, then
        serve plaintext through a lazily decrypting :class:`DecryptedView`.

        The file identity is captured BEFORE the pass, so a change during
        verification is caught by the first read. The content key is held in
        the re-wrap material's ``bytearray`` and wiped with it on close.
        """
        identity = FileIdentity.of_fd(self._file.fileno())
        start = self._ciphertext_start()
        end = self._ciphertext_end()
        tag = bytes(self._mmap[end:end + TAG_LEN])
        ct_view = memoryview(self._mmap)[start:end]
        try:
            verify_tag_streaming(algo, cek, nonce, aad, ct_view, tag)
            self._rewrap = self._build_rewrap(self._enc_params, cek, kem_ct)
            decryptor = SeekableDecryptor(algo, self._rewrap._cek, nonce)
            guard = FileGuard(self._file.fileno(), identity, self.path)
            self._plaintext = DecryptedView(ct_view, decryptor, guard)
            guard.check()  # the verified bytes are the bytes we will serve
            ct_view = None  # owned by the view now
        finally:
            if ct_view is not None:
                ct_view.release()

    def _drop_decryption_state(self) -> None:
        if isinstance(self._plaintext, DecryptedView):
            self._plaintext.close()
        self._plaintext = self._buf = None
        if self._rewrap is not None:
            self._rewrap.wipe()
            self._rewrap = None

    def _build_rewrap(self, ep: MslEncryptionParams, cek: bytes,
                      kem_ct: bytes) -> RewrapMaterial:
        return RewrapMaterial(
            enc_algo=EncAlgo(ep.enc_algo), kdf_type=KdfType(ep.kdf_type),
            key_encap=KeyEncap(ep.key_encap), kdf_time=ep.kdf_time,
            kdf_memory=ep.kdf_memory, kdf_lanes=ep.kdf_lanes,
            kdf_salt=ep.kdf_salt, kem_ciphertext=kem_ct,
            source_nonce=ep.nonce,
            dump_uuid_bytes=self._file_header.dump_uuid.bytes,
            _cek=bytearray(cek))

    def _rewrap_material(self) -> RewrapMaterial:
        """Key-wrapping handle for re-encrypting a derived copy.

        Narrow, private API used only by :mod:`memdiver.msl.materialize`.
        Available only while the reader is open and only after the AEAD tag
        verified (``tag_status is VALID``); raises ``MslCryptoError`` otherwise.
        The returned object is a request-scoped secret (redacted ``repr``,
        wiped on :meth:`close`) — never cache or log it.
        """
        if self.tag_status is not TagStatus.VALID or self._rewrap is None:
            raise MslCryptoError(
                f"no verified key material to re-wrap "
                f"(tag_status={self.tag_status.value})")
        return self._rewrap

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
        # One bounded copy of the header: works for the mmap and for the
        # lazily decrypted view alike (which has no buffer protocol).
        raw = bytes(buf[offset:offset + BLOCK_HEADER_SIZE])
        if raw[0:4] != BLOCK_MAGIC:
            raise MslParseError(f"Bad block magic at 0x{offset:X}")
        bo = self._byte_order
        return MslBlockHeader(
            block_type=struct.unpack_from(f"{bo}H", raw, 4)[0],
            flags=struct.unpack_from(f"{bo}H", raw, 6)[0],
            block_length=struct.unpack_from(f"{bo}I", raw, 8)[0],
            payload_version=struct.unpack_from(f"{bo}H", raw, 0x0C)[0],
            block_uuid=UUID(bytes=raw[0x10:0x20]),
            parent_uuid=UUID(bytes=raw[0x20:0x30]),
            prev_hash=raw[0x30:0x50],
            file_offset=offset,
            payload_offset=offset + BLOCK_HEADER_SIZE,
        )

    def _iter_raw_blocks(self) -> Iterator[Tuple[MslBlockHeader, bytes]]:
        """Iterate in-chain blocks without continuation merging.

        Stops *after* yielding the End-of-Capture block: per spec, EoC is
        the last capture-segment block; extension segments after it (spec
        4.6, e.g. a POINTER_GRAPH 0x1003) are reachable via
        ``iter_extension_blocks()``.

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
        ``_iter_raw_blocks``; extension segments follow the EoC).
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

    # -- Extension segments (spec 4.6) --------------------------------------

    def _extension_start(self) -> Optional[int]:
        """Buffer offset just past the End-of-Capture block, or None.

        None only when the file has no EoC (or block framing fails before
        it is reached); it may equal ``buffer_length`` when nothing follows
        the EoC. Header-only walk, no payload decompression.
        """
        if self._buf is None:
            return None
        try:
            for hdr in self._iter_raw_block_headers():
                if hdr.block_type == BlockType.END_OF_CAPTURE:
                    return hdr.file_offset + hdr.block_length
        except MslParseError:
            return None
        return None

    def scan_extension_segments(self) -> List[ExtensionSegment]:
        """Frame the extension segments after the EoC (header-only, cached).

        Walks blocks from :meth:`_extension_start`; each run up to and
        including an End-of-Extension block is one segment. A run that
        hits EOF, non-magic bytes or a block that fails framing before a
        terminator is returned as an unterminated segment (``terminator``
        None) and ends the scan — everything from there on is trailing
        data. No verification happens here (see
        :func:`integrity.verify_extension_segments`).
        """
        if self._extension_segments_cache is not None:
            return self._extension_segments_cache
        segments: List[ExtensionSegment] = []
        start = self._extension_start()
        if start is not None:
            offset = start
            while offset < len(self._buf):
                seg = self._frame_segment(len(segments), offset)
                if seg is None:
                    break
                segments.append(seg)
                offset = seg.end
                if not seg.terminated:
                    break
        self._extension_segments_cache = segments
        return segments

    def _frame_segment(self, index: int, start: int) -> Optional[ExtensionSegment]:
        """One segment starting at *start*; None when no block frames there."""
        buf = self._buf
        headers: List[MslBlockHeader] = []
        offset = start
        terminator: Optional[MslEndOfExtension] = None
        while offset + BLOCK_HEADER_SIZE <= len(buf):
            if buf[offset:offset + 4] != BLOCK_MAGIC:
                break
            hdr = self._parse_block_header(offset)
            end = offset + hdr.block_length
            if hdr.block_length < BLOCK_HEADER_SIZE or end > len(buf):
                logger.warning("Extension block at 0x%X fails framing", offset)
                break
            headers.append(hdr)
            offset = end
            if hdr.block_type == BlockType.END_OF_EXTENSION:
                terminator = self._decode_terminator(hdr)
                if terminator is None:
                    headers.pop()
                    offset = hdr.file_offset
                break
        if not headers:
            return None
        return ExtensionSegment(index, start, offset, tuple(headers), terminator)

    def _decode_terminator(self, hdr: MslBlockHeader) -> Optional[MslEndOfExtension]:
        try:
            return decode_end_of_extension(hdr, self.read_block_payload(hdr),
                                           self._byte_order)
        except (MslParseError, struct.error, IndexError, ValueError) as exc:
            logger.warning("Malformed End-of-Extension at 0x%X: %s",
                           hdr.file_offset, exc)
            return None

    def _segment_reports(self):
        """Per-segment verification (cached); see integrity.verify_extension_segments."""
        if self._segment_reports_cache is None:
            from .integrity import verify_extension_segments
            self._segment_reports_cache = verify_extension_segments(self)
        return self._segment_reports_cache

    def iter_extension_blocks(self, include_unverified: bool = False
                              ) -> Iterator[Tuple[MslBlockHeader, bytes]]:
        """Iterate ``(header, payload)`` over the extension segments' blocks.

        Terminator blocks are included. By default only *verified* segments
        (chain continuity for plaintext files, SegmentHash, BlockCount —
        spec consumer rule 23) are yielded; *include_unverified* also walks
        unterminated or failing segments, whose blocks MUST NOT be presented
        as verified. Payloads are decompressed like ``iter_blocks``.
        Blocks of verified sealed segments (spec 10.8, encrypted files)
        follow, in SegIndex order, with ``hdr.seal_index`` set; sealed
        segments that fail are never yielded, not even when unverified
        segments are requested.
        """
        reports, _ = self._segment_reports()
        verified = {r.index for r in reports if r.verified}
        for seg in self.scan_extension_segments():
            if seg.index not in verified and not include_unverified:
                continue
            for hdr in seg.headers:
                raw = bytes(self._buf[hdr.payload_offset:
                                      hdr.file_offset + hdr.block_length])
                if hdr.compressed:
                    raw = decompress(raw, hdr.comp_algo)
                yield hdr, raw
        for sealed in self.sealed_segments():
            for hdr in sealed.segment.headers:
                yield hdr, self.read_block_payload(hdr)

    # -- Sealed extension segments (spec 10.8) -------------------------------

    def sealed_segments(self) -> list:
        """Verified sealed segments after the primary AEAD tag (cached).

        Only for a tag-verified container with ``CipherLen != 0``; empty
        otherwise. Each is a :class:`memdiver.msl.sealed.SealedSegment`
        whose tag and plaintext segment both verified; their blocks follow
        the in-stream segments' in :meth:`iter_extension_blocks`.
        """
        return self._open_sealed()[0]

    @property
    def sealed_trailing_bytes(self) -> int:
        """Bytes after the primary tag not covered by a verified sealed segment."""
        if self._post_tag_offset is None or self._mmap is None:
            return 0
        return len(self._mmap) - self._open_sealed()[1]

    def _open_sealed(self):
        if self._sealed_cache is None:
            self._sealed_cache = self._compute_sealed()
        return self._sealed_cache

    def _compute_sealed(self):
        start = self._post_tag_offset
        if (start is None or self._rewrap is None
                or not self._enc_params.cipher_len):
            return [], start or 0
        from .sealed import open_sealed_segments
        return open_sealed_segments(self._seal_context(), self._mmap, start,
                                    len(self.scan_extension_segments()))

    def _seal_context(self):
        from .sealed import SealContext
        hs = self._file_header.header_size
        tag_end = self._post_tag_offset
        return SealContext(
            algo=EncAlgo(self._enc_params.enc_algo),
            cek=bytes(self._rewrap._cek), header=bytes(self._mmap[0:hs]),
            kem_ct=bytes(self._mmap[hs:self._ciphertext_start()]),
            primary_tag=bytes(self._mmap[tag_end - TAG_LEN:tag_end]),
            hash_algo=self._file_header.hash_algo, byte_order=self._byte_order)

    @property
    def trailing_bytes(self) -> int:
        """Bytes after the last verified segment (0 when none), spec rule 14."""
        if self._buf is None:
            return 0
        if self._extension_start() is None:
            return 0
        return self._segment_reports()[1]

    def _appendix_offset(self) -> Optional[int]:
        """Deprecated: pre-1.1 appendix locator, now a thin wrapper.

        Returns :meth:`_extension_start` when bytes follow the EoC, else None.
        """
        start = self._extension_start()
        if start is None or self._buf is None or start >= len(self._buf):
            return None
        return start

    def _iter_appendix_blocks(self) -> Iterator[Tuple[MslBlockHeader, bytes]]:
        """Deprecated: pre-1.1 appendix walk, now
        ``iter_extension_blocks(include_unverified=True)``."""
        return self.iter_extension_blocks(include_unverified=True)

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
        if isinstance(self._buf, DecryptedView):
            # Encrypted files: a view over a freshly decrypted copy.
            return memoryview(self._buf.read(offset, end - offset))
        return memoryview(self._buf)[offset:end]

    def iter_find(self, needle: bytes, offset: int, length: int) -> Iterator[int]:
        """Yield buffer offsets of *needle* inside ``[offset, offset+length)``.

        Matches must lie wholly inside the (buffer-clamped) range; overlapping
        matches are all reported, ascending — the same answer as
        ``find_all_offsets(read_bytes(offset, length), needle)`` shifted by
        ``offset``, without the copy. Plaintext buffers (the mmap, or the
        one-shot plaintext ``bytes``) are searched in place with bounded
        ``find(needle, start, end)``; a lazily decrypted view has no ``find``,
        so it is decrypted in bounded windows (:func:`_iter_find_windowed`).
        An empty needle yields nothing (see ``core.dump_io.find_all_offsets``
        for why that guard is load-bearing on an mmap).
        """
        buf = self._buf
        if buf is None or not needle or length <= 0:
            return
        end = min(offset + length, len(buf))
        if offset < 0 or offset >= end:
            return
        if isinstance(buf, DecryptedView):
            yield from _iter_find_windowed(buf.read, needle, offset, end)
            return
        start = offset
        while True:
            at = buf.find(needle, start, end)
            if at < 0:
                return
            yield at
            start = at + 1

    def _decompressed_length(self, hdr: MslBlockHeader) -> int:
        """Decompressed payload length of a compressed block (cached)."""
        size = self._decompressed_lengths.get(hdr.file_offset)
        if size is None:
            size = len(self.decompressed_payload(hdr))
            self._decompressed_lengths[hdr.file_offset] = size
        return size

    def decompressed_payload(self, hdr: MslBlockHeader) -> bytes:
        """:meth:`read_block_payload`, keeping the LAST result only.

        Run reads on a compressed region hit the same block many times in a
        row (hex-viewer windows, a search walking its runs), so the most
        recent decompressed payload is kept — one block at a time, bounded by
        the writer's region block cap (1 GiB), released on ``close()``.
        """
        cached = self._payload_cache
        if cached is not None and cached[0] == hdr.file_offset:
            return cached[1]
        payload = self.read_block_payload(hdr)
        self._payload_cache = (hdr.file_offset, payload)
        return payload

    def run_span(self, run: CapturedRun) -> int:
        """Bytes of *run* that can actually be read (``read_view`` clamping)."""
        if run.block is not None:
            return max(0, run.avail)
        return max(0, min(run.buf_offset + run.avail, self.buffer_length)
                   - run.buf_offset)

    def run_view(self, run: CapturedRun, begin: int, length: int) -> memoryview:
        """``length`` bytes of *run* starting ``begin`` bytes into it.

        Uncompressed runs: :meth:`read_view` (zero-copy on an mmap).
        Compressed runs: a view into the block's decompressed payload.
        """
        if run.block is None:
            return self.read_view(run.buf_offset + begin, length)
        if self._buf is None or length <= 0:
            return memoryview(b"")
        payload = self.decompressed_payload(run.block)
        start = run.buf_offset + begin
        return memoryview(payload)[start:min(start + length, len(payload))]

    def iter_find_run(self, run: CapturedRun, needle: bytes) -> Iterator[int]:
        """Run-relative offsets of *needle* inside *run*'s readable bytes.

        Same answer as ``find_all_offsets(run_view(run, 0, run_span(run)),
        needle)`` without copying the run: an uncompressed run is searched in
        place (:meth:`iter_find`), a compressed one inside its cached
        decompressed payload with bounded ``find(needle, start, end)``.
        """
        span = self.run_span(run)
        if not needle or span <= 0 or self._buf is None:
            return
        if run.block is None:
            for hit in self.iter_find(needle, run.buf_offset, span):
                yield hit - run.buf_offset
            return
        payload = self.decompressed_payload(run.block)
        lo = run.buf_offset
        hi = min(lo + span, len(payload))
        at = payload.find(needle, lo, hi)
        while at >= 0:
            yield at - lo
            at = payload.find(needle, at + 1, hi)

    def read_block_payload(self, hdr: MslBlockHeader) -> bytes:
        """Read and decompress a block's payload bytes.

        A block of a sealed segment (``hdr.seal_index``) is read from that
        segment's verified plaintext.
        """
        buf = self._block_buffer(hdr)
        if buf is None:
            return b""
        end = min(hdr.file_offset + hdr.block_length, len(buf))
        raw = bytes(buf[hdr.payload_offset:end])
        if hdr.compressed:
            raw = decompress(raw, hdr.comp_algo)
        return raw

    def _block_buffer(self, hdr: MslBlockHeader):
        """The buffer *hdr*'s offsets refer to (reader buffer or sealed plaintext)."""
        if not hdr.seal_index:
            return self._buf
        sealed = self.sealed_segments()
        if hdr.seal_index > len(sealed):
            return None
        return sealed[hdr.seal_index - 1].plaintext

    def iter_blocks_of_type(self, *block_types) -> Iterator[Tuple[MslBlockHeader, bytes]]:
        """Like :meth:`iter_blocks`, but reads payloads only for *block_types*.

        Every other block is skipped at the header level, so asking for the
        (small) module tables never copies or decompresses region payloads.
        Continuations of a wanted type are merged as in :meth:`iter_blocks`.
        """
        wanted = {int(t) for t in block_types}
        raw = ((hdr, self.read_block_payload(hdr))
               for hdr in self._iter_raw_block_headers()
               if hdr.block_type in wanted)
        return _merge_cont(raw)

    def iter_region_headers(self) -> Iterator[MslMemoryRegion]:
        """Decode every MEMORY_REGION from its 0x20 header + page map only.

        Uncompressed blocks are read with two bounded views (fixed header,
        then header + PageStateMap); page data is never touched. A compressed
        block has no random access, so its payload is decompressed one block
        at a time and dropped after decoding (never cached). Continuation
        blocks are skipped: the fixed header and page map live in the parent.
        Malformed blocks are skipped with a warning, as in ``_collect``.
        Yields nothing for an encrypted file opened without key material.
        """
        for hdr in self._iter_raw_block_headers():
            if (hdr.block_type != BlockType.MEMORY_REGION
                    or hdr.flags & BlockFlag.CONTINUATION):
                continue
            try:
                yield decode_memory_region(
                    hdr, self._region_head(hdr), self._byte_order)
            except (MslParseError, struct.error, IndexError, OverflowError) as exc:
                logger.warning("Skipping malformed MEMORY_REGION block at "
                               "0x%X: %s", hdr.file_offset, exc)

    def _region_head(self, hdr: MslBlockHeader) -> bytes:
        """The fixed region header plus its padded page-state map."""
        if hdr.compressed:
            return self.read_block_payload(hdr)
        avail = max(0, min(hdr.payload_length,
                           len(self._buf) - hdr.payload_offset))
        head = self.read_bytes(hdr.payload_offset, min(avail, 0x20))
        if len(head) < 0x20:
            return head  # decoder raises MslParseError on the short header
        region_size = struct.unpack_from(f"{self._byte_order}Q", head, 8)[0]
        log2 = head[0x12]
        num_pages = region_size >> log2 if 10 <= log2 <= 40 else 0
        map_bytes = ((num_pages + 3) // 4 + 7) & ~7
        return self.read_bytes(hdr.payload_offset,
                               min(avail, 0x20 + map_bytes))

    def _collect(self, block_type, decoder, cache_attr):
        cached = getattr(self, cache_attr)
        if cached is None:
            decoded = []
            # Payloads are read only for *block_type*: walking iter_blocks()
            # here copied every region payload in the container to find a
            # few small table blocks.
            for h, p in self.iter_blocks_of_type(block_type):
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
        """Every MEMORY_REGION, decoded from its header + page map (cached).

        Decoded from :meth:`_region_head` rather than the full payload: a
        region's decoded form never contains page data, so copying every
        payload (up to 1 GiB per block) just to read its first few KiB was
        pure waste — and on a 4 GiB container it was most of the anonymous
        memory a first search allocated. Order is the order the old
        ``iter_blocks()`` walk produced (see :meth:`_region_heads_in_merge_order`),
        so callers that zip this list against another walk keep lining up.
        """
        cached = self._regions_cache
        if cached is None:
            cached = []
            for hdr in self._region_heads_in_merge_order():
                try:
                    head = self._region_head(hdr)
                    if hdr.compressed:  # head is the whole decompressed payload
                        self._decompressed_lengths[hdr.file_offset] = len(head)
                    cached.append(decode_memory_region(
                        hdr, head, self._byte_order))
                except (MslParseError, struct.error, IndexError, OverflowError) as exc:
                    logger.warning("Skipping malformed MEMORY_REGION block at "
                                   "0x%X: %s", hdr.file_offset, exc)
            self._regions_cache = cached
        return cached

    def _region_heads_in_merge_order(self) -> List[MslBlockHeader]:
        """MEMORY_REGION block headers in ``merge_continuations`` output order.

        Replays :func:`msl.block_iter.merge_continuations` on HEADERS only:
        leaf blocks and orphaned continuations are emitted where they occur,
        a ``HAS_CHILDREN`` parent is held back until end-of-stream (or until a
        later parent reuses its uuid), and a continuation of a pending parent
        is absorbed. Only MEMORY_REGION headers are returned, but parents of
        every type are tracked, exactly as the payload walk tracks them.
        """
        out: List[MslBlockHeader] = []
        pending: dict = {}  # parent uuid -> header (insertion ordered)
        for hdr in self._iter_raw_block_headers():
            if hdr.flags & BlockFlag.CONTINUATION:
                if hdr.parent_uuid not in pending:
                    out.append(hdr)  # orphan: emitted as-is, like the merge
            elif hdr.flags & BlockFlag.HAS_CHILDREN:
                if hdr.block_uuid in pending:
                    out.append(pending.pop(hdr.block_uuid))
                pending[hdr.block_uuid] = hdr
            else:
                out.append(hdr)
        out.extend(pending.values())
        return [h for h in out if h.block_type == BlockType.MEMORY_REGION]

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

        Built from :meth:`collect_regions`, which decodes each region from its
        header + page map only (:meth:`_region_head`), so building the index
        never copies page data.

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
            hdr = region.block_header
            block = hdr if hdr.compressed else None
            if block is None:
                base = int(hdr.payload_offset) + 0x20 + map_bytes
                held = buf_len - base
            else:
                base = 0x20 + map_bytes
                held = self._decompressed_length(hdr) - base
            region_avail = max(
                0,
                min(count_captured_pages(region.page_states) * page_size, held),
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
                    block=block,
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
        """Capture-segment VAS_MAP blocks, raw and in file order.

        For the map the file actually asserts (last one wins, extension
        segments included — spec 5.8) use :meth:`effective_vas_map`.
        """
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

    def collect_physical_memory_map(self) -> List[MslPhysicalMemoryMap]:
        """Physical Memory Map (0x0059) blocks, in file order (spec 5.9)."""
        return self._collect(BlockType.PHYSICAL_MEMORY_MAP, decode_physical_memory_map,
                             "_physical_memory_map_cache")

    # -- Ext decoder collectors (0x0011 is spec-defined; the rest speculative) --

    def collect_thread_contexts(self) -> list:
        """THREAD_CONTEXT (0x0011) blocks per spec 5.7 (``MslThreadContext``;
        a malformed one decodes to ``MslGenericBlock``)."""
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

    # -- Extension-segment collectors (spec 4.6) --

    def collect_end_of_extension(self) -> List[MslEndOfExtension]:
        """Decoded End-of-Extension blocks of every *verified* segment."""
        if self._end_of_extension_cache is None:
            self._end_of_extension_cache = [
                decode_end_of_extension(h, p, self._byte_order)
                for h, p in self.iter_extension_blocks()
                if h.block_type == BlockType.END_OF_EXTENSION
            ]
        return self._end_of_extension_cache

    def collect_pointer_graphs(self) -> List[MslPointerGraph]:
        """Collect POINTER_GRAPH blocks (0x1003) from verified extension segments.

        The block lives after the EoC (inside the AEAD stream when
        encrypted), so it comes from ``iter_extension_blocks()`` rather than
        ``iter_blocks()``. Returns an empty list when the file has no
        verified segment carrying one — the common case.
        """
        if self._pointer_graphs_cache is not None:
            return self._pointer_graphs_cache
        cached = [
            decode_pointer_graph(h, p, self._byte_order)
            for h, p in self.iter_extension_blocks()
            if h.block_type == BlockType.POINTER_GRAPH
        ]
        self._pointer_graphs_cache = cached
        return cached

    def collect_extension_vas_maps(self) -> List[MslVasMap]:
        """Collect VAS_MAP blocks (0x1001) from verified extension segments.

        In-stream segments then verified sealed ones, in file order (via
        ``iter_extension_blocks()``). A malformed block is skipped with a
        warning, as in :meth:`_collect`.
        """
        if self._extension_vas_cache is not None:
            return self._extension_vas_cache
        cached: List[MslVasMap] = []
        for h, p in self.iter_extension_blocks():
            if h.block_type != BlockType.VAS_MAP:
                continue
            try:
                cached.append(decode_vas_map(h, p, self._byte_order))
            except (MslParseError, struct.error, IndexError, OverflowError) as exc:
                logger.warning("Skipping malformed segment VAS_MAP block at 0x%X: %s",
                               h.file_offset, exc)
        self._extension_vas_cache = cached
        return cached

    def effective_vas_map(self) -> Optional[MslVasMap]:
        """The VAS map the file says applies, or ``None`` when it has none.

        Spec 5.8 / consumer rule 25: the LAST VAS map in file order
        supersedes earlier ones, including maps in verified extension
        (4.6) and sealed (10.8) segments. Segment maps always follow
        capture-segment ones, so the result came from a segment exactly
        when :meth:`collect_extension_vas_maps` is non-empty.
        """
        maps = self.collect_vas_map() + self.collect_extension_vas_maps()
        return maps[-1] if maps else None

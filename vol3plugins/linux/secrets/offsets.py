"""Offset tables for the dm-crypt structures that are NOT in a vmlinux ISF.

``struct crypt_config`` lives in the ``dm_crypt`` module, so a symbol table built from
``vmlinux`` debug info never describes it.  The ``linux.dmcrypt`` plugin therefore reads it
through this table (or a user-supplied ``--offsets`` JSON) and treats every entry as a
*hypothesis*: the plugin's self-validating locator rejects a ``crypt_config`` whose fields do
not make sense (cipher string, key size, key parts, tfm pointer back to a crypto_alg whose
``cra_name`` matches the cipher string), so a wrong table entry yields no rows, never a wrong
key.

Stdlib only (``tests/test_vol3plugins_import_rules.py``).

Entry provenance
----------------
``("aarch64", "6.8.0-136-generic")`` -- the Ubuntu 24.04 arm64 kernel of the MemDiver
acquired-secrets capture.  Seeded from the capture sidecar's ``btf_offsets.crypt_config``
(``bpftool``/``pahole`` over ``/sys/kernel/btf/dm_crypt``) and checked member-by-member
against ``pahole_crypt_config.txt`` from the sidecar tarball (size 888, ``key[]`` at 888).
The ``flags`` / ``cipher_flags`` bit numbers are the enumerator order of ``enum flags`` /
``enum cipher_flags`` in the same BTF blob (6.8 has no ``DM_CRYPT_HIGH_PRIORITY``).

``("x86_64", "6.8.0-136-generic")`` -- the x86_64 capture of the same kernel release: its
sidecar ``btf_offsets``, ``pahole_crypt_config.txt`` and ``btf_dm_crypt.bin`` enum order are
identical to the aarch64 entry (``crypt_config`` has no arch-dependent members).

``--offsets`` JSON accepted shapes
----------------------------------
* the MemDiver ground-truth sidecar (``*.secrets.json``): ``{"btf_offsets": {"crypt_config":
  {"members": {"dev": {"offset": 0, ...}, ...}}}}``;
* a bare ``btf_offsets`` object: ``{"crypt_config": {"members": {...}}}``;
* a flat table: ``{"crypt_config": {"dev": 0, "cipher_string": 96, ...},
  "flag_bits": {"DM_CRYPT_SAME_CPU": 2, ...}, "cipher_flag_bits": {...},
  "dm_core": {"hash_cell.name": 56, ..., "sizeof(dm_target)": 80}}``.

Only the members the plugin reads are required (``REQUIRED_MEMBERS`` plus one of
``TAG_SIZE_MEMBERS``).  ``on_disk_tag_size`` was renamed ``used_tag_size`` in v6.11 by
commit 6a6c56130aaa ("dm-crypt: support for per-sector NVMe metadata"; checked against
``drivers/md/dm-crypt.c`` at v6.10 and v6.11), so both spellings are accepted.  Without
``flag_bits`` the loader picks the ``enum flags`` numbering by kernel release:
``DM_CRYPT_HIGH_PRIORITY`` was inserted after ``DM_CRYPT_SAME_CPU`` in v6.10 by commit
5268de78e1e6 ("dm-crypt: add the optional "high_priority" flag").

``dm_core`` (optional) supplies the device-mapper core offsets (``hash_cell``,
``mapped_device``, ``dm_table``, ``dm_target``, ``target_type``, ``dm_dev``) for kernels where
``dm_mod`` is a loadable module and the vmlinux ISF therefore lacks those types (RHEL/Alma).
Keys are ``"type.member"`` offsets plus ``"sizeof(dm_target)"``.
"""

import json
import logging
import os
from dataclasses import dataclass, field
from typing import Any, Dict, Optional, Tuple

__all__ = [
    "REQUIRED_MEMBERS",
    "TAG_SIZE_MEMBERS",
    "DmCryptOffsets",
    "DM_CRYPT_OFFSETS",
    "AES_CTX_LAYOUTS",
    "lookup_offsets",
    "load_offsets_json",
]

# The crypt_config members the plugin reads.  ``key`` is the flexible array at the tail.
REQUIRED_MEMBERS = (
    "dev", "start", "cipher_string", "cipher_auth", "key_string", "iv_offset",
    "sector_size", "cipher_tfm", "tfms_count", "cipher_flags", "flags", "key_size",
    "key_parts", "key",
)
# One of these must be present: v6.11 (commit 6a6c56130aaa) renamed the first spelling.
TAG_SIZE_MEMBERS = ("on_disk_tag_size", "used_tag_size")

_OFFSETS_FLAG_BITS_6_8 = {
    "DM_CRYPT_SUSPENDED": 0, "DM_CRYPT_KEY_VALID": 1, "DM_CRYPT_SAME_CPU": 2,
    "DM_CRYPT_NO_OFFLOAD": 3, "DM_CRYPT_NO_READ_WORKQUEUE": 4,
    "DM_CRYPT_NO_WRITE_WORKQUEUE": 5, "DM_CRYPT_WRITE_INLINE": 6,
}
_OFFSETS_FLAG_BITS_6_10 = {  # commit 5268de78e1e6 (v6.10) inserted HIGH_PRIORITY
    "DM_CRYPT_SUSPENDED": 0, "DM_CRYPT_KEY_VALID": 1, "DM_CRYPT_SAME_CPU": 2,
    "DM_CRYPT_HIGH_PRIORITY": 3, "DM_CRYPT_NO_OFFLOAD": 4, "DM_CRYPT_NO_READ_WORKQUEUE": 5,
    "DM_CRYPT_NO_WRITE_WORKQUEUE": 6, "DM_CRYPT_WRITE_INLINE": 7,
}
_OFFSETS_CIPHER_FLAG_BITS_6_8 = {
    "CRYPT_MODE_INTEGRITY_AEAD": 0, "CRYPT_IV_LARGE_SECTORS": 1, "CRYPT_ENCRYPT_PREPROCESS": 2,
}
_OFFSETS_CRYPT_CONFIG_6_8 = {
    "dev": 0, "start": 8, "n_allocated_pages": 16, "io_queue": 56, "crypt_queue": 64,
    "write_thread_lock": 72, "write_thread": 80, "write_tree": 88, "cipher_string": 96,
    "cipher_auth": 104, "key_string": 112, "iv_gen_ops": 120, "iv_gen_private": 128,
    "iv_offset": 152, "iv_size": 160, "sector_size": 164, "sector_shift": 166,
    "cipher_tfm": 168, "tfms_count": 176, "cipher_flags": 184, "dmreq_start": 192,
    "per_bio_data_size": 196, "flags": 200, "key_size": 208, "key_parts": 212,
    "key_extra_size": 216, "key_mac_size": 220, "integrity_tag_size": 224,
    "integrity_iv_size": 228, "on_disk_tag_size": 232, "tag_pool_max_sectors": 236,
    "tag_pool": 240, "req_pool": 312, "page_pool": 384, "bs": 456, "bio_alloc_lock": 848,
    "authenc_key": 880, "key": 888,
}


# dm core offsets of the same aarch64 6.8.0-136 kernel, read from its vmlinux ISF (dm core is
# built in there); only consulted when an ISF lacks these types.
_OFFSETS_DM_CORE_6_8 = {
    "rb_node.rb_right": 8, "rb_node.rb_left": 16,
    "hash_cell.name_node": 0, "hash_cell.name": 56, "hash_cell.uuid": 64, "hash_cell.md": 72,
    "mapped_device.map": 80, "mapped_device.name": 168, "mapped_device.disk": 184,
    "mapped_device.interface_ptr": 352, "dm_table.num_targets": 208, "dm_table.targets": 224,
    "dm_target.type": 8, "dm_target.begin": 16, "dm_target.len": 24,
    "dm_target.num_discard_bios": 40, "dm_target.private": 56, "target_type.name": 8,
    "dm_dev.bdev": 0, "dm_dev.name": 28, "sizeof(dm_target)": 80,
}


@dataclass(frozen=True)
class DmCryptOffsets:
    """``crypt_config`` member offsets plus the ``flags``/``cipher_flags`` bit numbers."""

    crypt_config: Dict[str, int]
    flag_bits: Dict[str, int] = field(default_factory=dict)
    cipher_flag_bits: Dict[str, int] = field(default_factory=dict)
    source: str = "table"
    dm_core: Dict[str, int] = field(default_factory=dict)

    def tag_size_member(self) -> Optional[str]:
        return next((m for m in TAG_SIZE_MEMBERS if m in self.crypt_config), None)

    def missing(self) -> Tuple[str, ...]:
        absent = [m for m in REQUIRED_MEMBERS if m not in self.crypt_config]
        if self.tag_size_member() is None:
            absent.append("|".join(TAG_SIZE_MEMBERS))
        return tuple(absent)


DM_CRYPT_OFFSETS: Dict[Tuple[str, str], DmCryptOffsets] = {
    ("aarch64", "6.8.0-136-generic"): DmCryptOffsets(
        dict(_OFFSETS_CRYPT_CONFIG_6_8), dict(_OFFSETS_FLAG_BITS_6_8), dict(_OFFSETS_CIPHER_FLAG_BITS_6_8),
        source="btf:dm_crypt aarch64 6.8.0-136-generic (pahole-verified)",
        dm_core=dict(_OFFSETS_DM_CORE_6_8)),
    # x86_64 capture of the same Ubuntu 24.04 kernel: its sidecar btf_offsets, pahole text and
    # btf_dm_crypt.bin enum order are identical to the aarch64 entry; its vmlinux ISF carries the
    # same dm core offsets (dm core is built in on Ubuntu).
    ("x86_64", "6.8.0-136-generic"): DmCryptOffsets(
        dict(_OFFSETS_CRYPT_CONFIG_6_8), dict(_OFFSETS_FLAG_BITS_6_8), dict(_OFFSETS_CIPHER_FLAG_BITS_6_8),
        source="btf:dm_crypt x86_64 6.8.0-136-generic (pahole-verified)",
        dm_core=dict(_OFFSETS_DM_CORE_6_8)),
}

# Where the kernel's crypto drivers keep their ``struct crypto_aes_ctx`` copies inside the
# transform context: driver name -> (context alignment, ((role, offset), ...)).  Roles:
# ``data`` (the bulk/XTS data key), ``tweak`` (the XTS tweak key), ``essiv`` (the AES key
# derived as hash(data key) for ESSIV).  Drivers not listed fall back to a schedule scan.
AES_CTX_LAYOUTS: Dict[str, Tuple[int, Tuple[Tuple[str, int], ...]]] = {
    # arch/arm64/crypto/aes-glue.c: crypto_aes_xts_ctx{key1; key2 __aligned(8)}
    "xts-aes-ce": (1, (("data", 0), ("tweak", 488))),
    "xts-aes-neon": (1, (("data", 0), ("tweak", 488))),
    # crypto_aes_essiv_cbc_ctx{key1; key2 __aligned(8); hash}
    "essiv-cbc-aes-sha256-ce": (1, (("data", 0), ("essiv", 488))),
    "essiv-cbc-aes-sha256-neon": (1, (("data", 0), ("essiv", 488))),
    "cbc-aes-ce": (1, (("data", 0),)),
    "cbc-aes-neon": (1, (("data", 0),)),
    "ecb-aes-ce": (1, (("data", 0),)),
    "aes-ce": (1, (("data", 0),)),
    "aes-arm64": (1, (("data", 0),)),
    "aes-generic": (1, (("data", 0),)),
    # arch/x86/crypto/aesni-intel_glue.c (v6.8, checked; layout holds to <= v6.9):
    # aesni_xts_ctx{tweak_ctx AESNI_ALIGN_ATTR; crypt_ctx AESNI_ALIGN_ATTR}, and every AES-NI
    # ctx is reached through aes_align_addr() = PTR_ALIGN(raw ctx, 16).  dm-crypt holds the
    # simd wrappers (xts-aes-aesni, cbc-aes-aesni) that point through cryptd to these; the
    # generic essiv(cbc-aes-aesni,sha256-ni) template keeps its IV key in an "aes-aesni" cipher.
    "__xts-aes-aesni": (16, (("tweak", 0), ("data", 496))),
    "__cbc-aes-aesni": (16, (("data", 0),)),
    "__ecb-aes-aesni": (16, (("data", 0),)),
    "aes-aesni": (16, (("data", 0),)),
}


def _offsets_kernel_series(kver: str) -> str:
    parts = kver.split("-")[0].split(".")
    return ".".join(parts[:2])


def lookup_offsets(arch: str, kver: str) -> Optional[DmCryptOffsets]:
    """Exact ``(arch, kver)`` entry, else same arch and series, else any LP64 same series."""
    hidden = _offsets_table_hidden()
    if (arch, kver) in DM_CRYPT_OFFSETS and not hidden:
        return DM_CRYPT_OFFSETS[(arch, kver)]
    series = _offsets_kernel_series(kver)
    for wanted_arch in (arch, None):
        for (entry_arch, entry_kver), entry in sorted(DM_CRYPT_OFFSETS.items()):
            if wanted_arch is not None and entry_arch != wanted_arch:
                continue
            if hidden and entry_kver == kver:
                continue
            if _offsets_kernel_series(entry_kver) == series:
                return DmCryptOffsets(entry.crypt_config, entry.flag_bits, entry.cipher_flag_bits,
                                      source="nearest(%s %s): %s" % (entry_arch, entry_kver, entry.source))
    return None


def _offsets_members(table: Any) -> Dict[str, int]:
    """``{"members": {name: {"offset": n}}}`` or a flat ``{name: n}`` -> ``{name: n}``."""
    if not isinstance(table, dict):
        raise ValueError("crypt_config entry must be an object")
    members = table.get("members", table)
    result = {}
    for name, value in members.items():
        offset = value.get("offset") if isinstance(value, dict) else value
        if isinstance(offset, int) and not isinstance(offset, bool) and 0 <= offset < 1 << 16:
            result[str(name)] = offset
    return result


def _offsets_default_flag_bits(kver: str) -> Dict[str, int]:
    try:
        major, minor = (int(x) for x in _offsets_kernel_series(kver).split("."))
    except ValueError:
        return dict(_OFFSETS_FLAG_BITS_6_8)
    return dict(_OFFSETS_FLAG_BITS_6_10 if (major, minor) >= (6, 10) else _OFFSETS_FLAG_BITS_6_8)


def _offsets_int_map(value: Any) -> Dict[str, int]:
    if not isinstance(value, dict):
        return {}
    return {str(k): v for k, v in value.items() if isinstance(v, int) and 0 <= v < 64}


def load_offsets_json(text: str, source: str = "--offsets", kver: str = "") -> DmCryptOffsets:
    """Parse an ``--offsets`` document (see module doc); raises ``ValueError`` when unusable.

    ``kver`` (the image's kernel release) picks the default ``enum flags`` numbering when the
    document has no ``flag_bits``.
    """
    document = json.loads(text)
    if not isinstance(document, dict):
        raise ValueError("offsets JSON must be an object")
    document = document.get("btf_offsets", document)
    if "crypt_config" not in document:
        raise ValueError("offsets JSON has no crypt_config entry")
    offsets = DmCryptOffsets(
        _offsets_members(document["crypt_config"]),
        _offsets_int_map(document.get("flag_bits")) or _offsets_default_flag_bits(kver),
        _offsets_int_map(document.get("cipher_flag_bits")) or dict(_OFFSETS_CIPHER_FLAG_BITS_6_8),
        source=source,
        dm_core=_offsets_members(document["dm_core"]) if isinstance(document.get("dm_core"), dict) else {},
    )
    if offsets.missing():
        raise ValueError("offsets JSON lacks crypt_config members: %s" % ", ".join(offsets.missing()))
    return offsets


# --------------------------------------------------------------------------- in-memory BTF

# TEST-ONLY switch: ``MEMDIVER_TEST_HIDE_OFFSET_TABLE=1`` makes ``lookup_offsets`` ignore every entry of
# the image's own kernel release.  Read at call time.
OFFSETS_HIDE_TABLE_ENV = "MEMDIVER_TEST_HIDE_OFFSET_TABLE"
MEMORY_SOURCE_PREFIX = "btf-memory"
# ``enum flags`` / ``enum cipher_flags`` enumerators that must be present for a usable recovery.
_OFFSETS_REQUIRED_FLAGS = ("DM_CRYPT_SAME_CPU", "DM_CRYPT_NO_OFFLOAD")
_OFFSETS_REQUIRED_CIPHER_FLAGS = ("CRYPT_IV_LARGE_SECTORS",)


_OFFSETS_TABLE_HIDDEN_WARNED = []


def _offsets_table_hidden() -> bool:
    """True when the test-only switch is set; logs one WARNING the first time it is seen."""
    hidden = os.environ.get(OFFSETS_HIDE_TABLE_ENV, "") not in ("", "0")
    if hidden and not _OFFSETS_TABLE_HIDDEN_WARNED:
        _OFFSETS_TABLE_HIDDEN_WARNED.append(True)
        logging.getLogger(__name__).warning(
            "%s is set (TEST ONLY): built-in offset entries of the image's kernel release are ignored", OFFSETS_HIDE_TABLE_ENV)
    return hidden


def from_memory(crypt_config: Dict[str, int], flag_bits: Dict[str, int], cipher_flag_bits: Dict[str, int],
                source: str, dm_core: Optional[Dict[str, int]] = None) -> Optional[DmCryptOffsets]:
    """``DmCryptOffsets`` from the image's own dm_crypt BTF (a TRUSTED recovery), else None.

    ``crypt_config`` is ``{member: offset}``; ``flag_bits`` / ``cipher_flag_bits`` are the
    ``enum flags`` / ``enum cipher_flags`` enumerators read from the same module BTF.  Partial
    data (a required member or enumerator missing) returns None: never half-trusted.
    """
    offsets = DmCryptOffsets(dict(crypt_config), dict(flag_bits), dict(cipher_flag_bits),
                             source=source, dm_core=dict(dm_core or {}))
    if offsets.missing() or any(f not in flag_bits for f in _OFFSETS_REQUIRED_FLAGS) or \
            any(f not in cipher_flag_bits for f in _OFFSETS_REQUIRED_CIPHER_FLAGS):
        return None
    if any(not 0 <= bit < 64 for bit in list(flag_bits.values()) + list(cipher_flag_bits.values())):
        return None  # a flag bit outside an unsigned long: not the enum the plugin needs
    return offsets


def is_memory_source(offsets: Optional[DmCryptOffsets]) -> bool:
    return offsets is not None and offsets.source.startswith(MEMORY_SOURCE_PREFIX)


def differences(memory: DmCryptOffsets, table: Optional[DmCryptOffsets]) -> Tuple[str, ...]:
    """Members / flag bits on which a memory recovery and a table entry disagree."""
    if table is None:
        return ()
    found = []
    for label, mine, theirs in (("crypt_config", memory.crypt_config, table.crypt_config),
                                ("flags", memory.flag_bits, table.flag_bits),
                                ("cipher_flags", memory.cipher_flag_bits, table.cipher_flag_bits)):
        for key in sorted(set(mine) & set(theirs)):
            if mine[key] != theirs[key]:
                found.append("%s.%s: memory %d != table %d" % (label, key, mine[key], theirs[key]))
    return tuple(found)

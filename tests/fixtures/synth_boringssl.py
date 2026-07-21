"""Synthetic BoringSSL TLS 1.3 ``.dump`` tree builder.

``build(root)`` materialises the two BoringSSL TLS 1.3 scenario trees consumed
by ``tests/test_e2e_real_dumps.py`` and ``tests/test_kaitai_and_features.py``:

* ``TLS13/100_iterations_Abort_KeyUpdate/boringssl/`` — ``boringssl_run_13_1``
  and ``boringssl_run_13_2`` are *full* runs (multi-phase ELF dumps + keylog
  with all five TLS 1.3 secret types, per-run-unique key material). Runs
  ``3 .. 100`` are *lightweight* (one tiny ELF dump each) so ``DatasetScanner``
  counts ``total_runs >= 100`` while keeping disk usage sane.
* ``TLS13/20_iterations_Abort_KeyUpdate/boringssl/boringssl_run_13_10/`` —
  a single valid ELF64 dump named ``*_pre_server_key_update.dump`` used by the
  Kaitai format-detection / structure-apply / custom-pattern tests.

Design decisions, cross-referenced against the pipeline mechanics:

* Hits come from ``SearchCorrelator.search_all`` which is a raw byte search of
  each keylog secret's ``secret_value`` over the dump bytes. So a secret is
  "present" in a phase iff its 32-byte value is embedded in that phase's dump.
* Derived key expansion (``expand_keys=True``) runs the real TLS13 HKDF
  (``DerivedKeyExpander``) over the traffic secrets and then searches the dump
  for the derived key/IV bytes. To make ``expand_keys=True`` surface a
  ``*_KEY_*`` / ``*_IV`` hit, we embed those derived bytes into the
  ``pre_server_key_update`` dump; ``expand_keys=False`` never searches for them.
* Per-run key uniqueness reuses ``generate_fixtures._xor_secret`` (byte delta of
  128 between runs), so run 1 and run 2 key sets are disjoint and run 1 keys do
  not appear in run 2 dumps.

The builder is idempotent: it returns early once the last run directory exists.
"""
from __future__ import annotations

import struct
from pathlib import Path
from typing import Dict, List, Tuple

from tests.fixtures import generate_fixtures as gf

# --- Layout constants -------------------------------------------------------

_SCENARIO_100 = "100_iterations_Abort_KeyUpdate"
_SCENARIO_20 = "20_iterations_Abort_KeyUpdate"
_N_RUNS = 100          # total run dirs in the 100_iterations scenario
_FULL_RUNS = (1, 2)    # deeply-analysed runs (multi-phase + full keylog)

# The ``pre_abort`` dump in a full run must be > 1 MB and < 100 MB, and support
# ``seek(100_000); read(4096)``. ~1.5 MB satisfies both while staying tiny.
_PRE_ABORT_SIZE = 1_500_000
# Other analysed phase dumps only need to hold the embedded secrets.
_SMALL_DUMP_SIZE = 8_192
# Lightweight runs just need to exist and look like a run.
_LIGHT_DUMP_SIZE = 256
# The run_13_10 ELF dump must be big enough that ``structure-apply`` does not
# report "extends beyond file boundary" (which would be HTTP 400).
_ELF10_DUMP_SIZE = 65_536

# Full-run phase specs: (timestamp, prefix, name) -> full_phase "prefix_name".
# NOTE: ``generate_fixtures._TLS13_PHASES`` has no ``pre_server_key_update``
# phase; we add it here as required by the e2e tests.
_FULL_PHASES: List[Tuple[str, str, str]] = [
    ("20251013_131441_000001", "pre", "abort"),
    ("20251013_131442_000002", "post", "abort"),
    ("20251013_131451_383028", "pre", "server_key_update"),
]

# The exact filename test_kaitai_and_features.py expects for run_13_10.
_RUN10_DUMP_NAME = "20251013_131451_383028_pre_server_key_update.dump"

# TLS 1.3 handshake secret types — deliberately never embedded in the
# post-handshake phases so they read as "absent" (BoringSSL zeroes them).
_HANDSHAKE_TYPES = {
    "CLIENT_HANDSHAKE_TRAFFIC_SECRET",
    "SERVER_HANDSHAKE_TRAFFIC_SECRET",
}
_NON_HANDSHAKE_TYPES = [
    "CLIENT_TRAFFIC_SECRET_0",
    "SERVER_TRAFFIC_SECRET_0",
    "EXPORTER_SECRET",
]


# --- Byte helpers -----------------------------------------------------------

def _elf64_header() -> bytes:
    """Minimal, valid ELF64 LE header (64 bytes, no program/section headers).

    Mirrors ``tests/test_kaitai_and_features.py::_make_elf64_le`` so the Kaitai
    ELF parser walks fields cleanly and ``detect_format`` classifies ``elf64``.
    """
    buf = bytearray(64)
    buf[0:4] = b"\x7fELF"
    buf[4] = 2       # ELFCLASS64
    buf[5] = 1       # ELFDATA2LSB
    buf[6] = 1       # EV_CURRENT
    buf[7] = 0       # ELFOSABI_NONE
    struct.pack_into("<H", buf, 16, 3)      # e_type = ET_DYN
    struct.pack_into("<H", buf, 18, 0x3E)   # e_machine = EM_X86_64
    struct.pack_into("<I", buf, 20, 1)      # e_version
    struct.pack_into("<Q", buf, 24, 0)      # e_entry
    struct.pack_into("<Q", buf, 32, 0)      # e_phoff
    struct.pack_into("<Q", buf, 40, 0)      # e_shoff
    struct.pack_into("<I", buf, 48, 0)      # e_flags
    struct.pack_into("<H", buf, 52, 64)     # e_ehsize
    struct.pack_into("<H", buf, 54, 0)      # e_phentsize
    struct.pack_into("<H", buf, 56, 0)      # e_phnum
    struct.pack_into("<H", buf, 58, 0)      # e_shentsize
    struct.pack_into("<H", buf, 60, 0)      # e_shnum
    struct.pack_into("<H", buf, 62, 0)      # e_shstrndx
    return bytes(buf)


def _build_dump(size: int, pad: int, values: List[bytes]) -> bytes:
    """ELF-headed dump: ``pad`` everywhere, ELF64 header at 0, values embedded.

    Values are placed at fixed offsets starting well past the 256-byte header
    window so the first 256 bytes stay low-entropy (header + padding only).
    """
    data = bytearray([pad] * size)
    data[0:64] = _elf64_header()
    off = 512
    for value in values:
        end = off + len(value)
        if end > size:
            raise ValueError(
                f"value at offset {off} (len {len(value)}) overruns dump size {size}"
            )
        data[off:end] = value
        off = end + 128
    return bytes(data)


# --- Per-run key material ---------------------------------------------------

def _run_secret_values(run_num: int) -> Dict[str, bytes]:
    """All five TLS 1.3 secret values for *run_num* (per-run-unique via XOR)."""
    return {
        st: gf._xor_secret(gf.TLS13_SECRET_VALUES[st], run_num)
        for st in gf.TLS13_SECRET_TYPES
    }


def _keylog_entries(run_num: int) -> List[Tuple[str, bytes]]:
    """(secret_type, value) pairs for the run's keylog — all five types."""
    vals = _run_secret_values(run_num)
    return [(st, vals[st]) for st in gf.TLS13_SECRET_TYPES]


def _derived_values(run_num: int) -> List[bytes]:
    """Derived key/IV byte-strings the real HKDF produces for the traffic0 secrets.

    Uses the same expander the pipeline uses (default key lengths / hash), so the
    bytes we embed match what ``expand_keys=True`` will search for.
    """
    from memdiver.core.models import CryptoSecret
    from memdiver.engine.derived_keys import DerivedKeyExpander

    vals = _run_secret_values(run_num)
    seeds = [
        CryptoSecret("CLIENT_TRAFFIC_SECRET_0", gf.TLS13_IDENTIFIER,
                     vals["CLIENT_TRAFFIC_SECRET_0"]),
        CryptoSecret("SERVER_TRAFFIC_SECRET_0", gf.TLS13_IDENTIFIER,
                     vals["SERVER_TRAFFIC_SECRET_0"]),
    ]
    derived = DerivedKeyExpander().expand_secrets(seeds)
    return [d.secret_value for d in derived]


def _phase_values(phase_full: str, run_num: int) -> List[bytes]:
    """Secret byte-strings to embed for a given full-phase name."""
    vals = _run_secret_values(run_num)
    if phase_full in ("pre_abort", "post_abort"):
        # Non-handshake secrets persist; handshake secrets are gone (absent).
        return [vals[st] for st in _NON_HANDSHAKE_TYPES]
    if phase_full == "pre_server_key_update":
        # Traffic0 + exporter still live, plus the derived AEAD keys/IVs so
        # expand_keys=True finds a *_KEY_* / *_IV hit.
        originals = [vals[st] for st in _NON_HANDSHAKE_TYPES]
        return originals + _derived_values(run_num)
    return []


# --- Tree builders ----------------------------------------------------------

def _write_full_run(lib_dir: Path, run_num: int) -> None:
    """Write a deeply-analysed run: multi-phase ELF dumps + full keylog."""
    run_dir = lib_dir / f"boringssl_run_13_{run_num}"
    run_dir.mkdir(parents=True, exist_ok=True)
    pad = 0x00 if run_num == 1 else 0xFE
    for ts, prefix, name in _FULL_PHASES:
        phase_full = f"{prefix}_{name}"
        size = _PRE_ABORT_SIZE if phase_full == "pre_abort" else _SMALL_DUMP_SIZE
        dump = _build_dump(size, pad, _phase_values(phase_full, run_num))
        (run_dir / f"{ts}_{prefix}_{name}.dump").write_bytes(dump)
    gf._write_keylog(run_dir, _keylog_entries(run_num), gf.TLS13_IDENTIFIER)


def _write_light_run(lib_dir: Path, run_num: int) -> None:
    """Write a lightweight run: one tiny ELF dump so it counts as a run."""
    run_dir = lib_dir / f"boringssl_run_13_{run_num}"
    run_dir.mkdir(parents=True, exist_ok=True)
    dump = _build_dump(_LIGHT_DUMP_SIZE, 0x00, [])
    (run_dir / "20251013_131441_000001_pre_abort.dump").write_bytes(dump)


def _build_scenario_100(root: Path) -> None:
    lib_dir = root / "TLS13" / _SCENARIO_100 / "boringssl"
    for run_num in range(1, _N_RUNS + 1):
        if run_num in _FULL_RUNS:
            _write_full_run(lib_dir, run_num)
        else:
            _write_light_run(lib_dir, run_num)


def _build_scenario_20(root: Path) -> None:
    run_dir = root / "TLS13" / _SCENARIO_20 / "boringssl" / "boringssl_run_13_10"
    run_dir.mkdir(parents=True, exist_ok=True)
    dump = _build_dump(_ELF10_DUMP_SIZE, 0x00, [])
    (run_dir / _RUN10_DUMP_NAME).write_bytes(dump)


def build(root: Path) -> Path:
    """Materialise the BoringSSL TLS 1.3 trees under *root* (idempotent).

    *root* is the synthetic dataset root (``tests/fixtures/dataset``); the trees
    are created under ``root/TLS13/...``. Returns *root*.
    """
    root = Path(root)
    sentinel_100 = (
        root / "TLS13" / _SCENARIO_100 / "boringssl" / f"boringssl_run_13_{_N_RUNS}"
    )
    sentinel_20 = (
        root / "TLS13" / _SCENARIO_20 / "boringssl" / "boringssl_run_13_10"
        / _RUN10_DUMP_NAME
    )
    if sentinel_100.is_dir() and sentinel_20.is_file():
        return root

    _build_scenario_100(root)
    _build_scenario_20(root)
    return root

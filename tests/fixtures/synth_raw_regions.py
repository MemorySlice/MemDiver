"""Synthetic gdb_raw / lldb_raw region-dump builder.

Produces ``gdb_raw.bin`` + ``gdb_raw.maps`` and ``lldb_raw.bin`` +
``lldb_raw.maps`` pairs in the layout consumed by
``tests/test_regioned_raw_source.py`` and ``tests/test_proc_maps_parser.py``.

Layout invariants required by those tests:

* The ``.maps`` sidecar has >10 regions and includes at least one HEAP
  (``[heap]``) and one IMAGE (shared-library path) region — see
  ``core.proc_maps_parser.classify_region``.
* The ``.bin`` is the byte-wise concatenation of every region's bytes, so its
  size equals the sum of region sizes (``padding_bytes == 0`` in the
  ``_RegionedRawSource`` metadata). Regions use non-adjacent virtual addresses
  so ``va_to_file_offset(first_start - 1)`` is ``None``.
"""
from __future__ import annotations

from pathlib import Path

# (relative_start, size, perms, path) — path drives RegionType classification.
# Non-adjacent VAs (0x10000 stride, 0x1000 regions) keep gaps between regions.
_REGION_SPECS = [
    (0x00400000, 0x1000, "r-xp", "/usr/lib/x86_64-linux-gnu/libc.so.6"),
    (0x00410000, 0x1000, "r--p", "/usr/lib/x86_64-linux-gnu/libc.so.6"),
    (0x00420000, 0x1000, "r-xp", "/usr/lib/x86_64-linux-gnu/libssl.so.3"),
    (0x00430000, 0x1000, "r-xp", "/usr/lib/x86_64-linux-gnu/libcrypto.so.3"),
    (0x00440000, 0x1000, "r-xp", "/usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2"),
    (0x00450000, 0x2000, "rw-p", "[heap]"),
    (0x00470000, 0x1000, "rw-p", ""),                # anonymous
    (0x00480000, 0x1000, "r--p", "/usr/bin/gocryptfs"),
    (0x00490000, 0x1000, "r-xp", "/usr/bin/gocryptfs"),
    (0x004A0000, 0x1000, "rw-p", "[stack]"),
    (0x004B0000, 0x1000, "r--p", "[vvar]"),
    (0x004C0000, 0x1000, "r-xp", "[vdso]"),
    (0x004D0000, 0x2000, "rw-p", ""),                # anonymous
]


def _build_maps_text() -> str:
    lines = []
    for start, size, perms, path in _REGION_SPECS:
        end = start + size
        tail = f" {path}" if path else ""
        lines.append(f"{start:08x}-{end:08x} {perms} 00000000 08:01 12345{tail}")
    return "\n".join(lines) + "\n"


def _build_bin_bytes() -> bytes:
    """Concatenate each region's bytes; give each region a recognisable fill."""
    blob = bytearray()
    for idx, (_start, size, _perms, _path) in enumerate(_REGION_SPECS):
        # Distinct low-entropy fill per region, plus a 16-byte marker so reads
        # are verifiable; region 0 starts at bin offset 0.
        fill = bytes([(idx * 7) & 0xFF]) * size
        marker = bytes([0xA0 + (idx & 0x0F)]) * 16
        region = bytearray(fill)
        region[0:16] = marker
        blob.extend(region)
    return bytes(blob)


def _build_pair(run_dir: Path, flavour: str) -> None:
    bin_path = run_dir / f"{flavour}.bin"
    maps_path = run_dir / f"{flavour}.maps"
    if bin_path.exists() and maps_path.exists():
        return
    run_dir.mkdir(parents=True, exist_ok=True)
    bin_path.write_bytes(_build_bin_bytes())
    maps_path.write_text(_build_maps_text())


def build(run_dir: Path) -> Path:
    """Materialise gdb_raw + lldb_raw pairs under ``run_dir`` (idempotent)."""
    run_dir = Path(run_dir)
    _build_pair(run_dir, "gdb_raw")
    _build_pair(run_dir, "lldb_raw")
    return run_dir


if __name__ == "__main__":
    out = build(Path(__file__).resolve().parent / "datasets" / "gocryptfs" / "run_0001")
    print(f"Synthetic raw region dumps written under: {out}")

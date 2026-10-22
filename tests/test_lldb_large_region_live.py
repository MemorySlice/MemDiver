"""LIVE lldb capture of a >100 MB region (opt-in: MEMDIVER_LIVE_LLDB=1).

Spawns its own python target holding a 160 MiB bytearray with a marker
113 MiB in (past the historic 100 MB lldb limit), captures it with the lldb
backend, imports the bin + .maps and checks the marker sits at its real VA.
Writes ~1 GB to tmp_path on macOS, hence opt-in.
"""

import os
import shutil
import subprocess
import sys
import textwrap

import pytest

pytestmark = pytest.mark.skipif(
    os.environ.get("MEMDIVER_LIVE_LLDB") != "1" or shutil.which("lldb") is None,
    reason="live lldb test: set MEMDIVER_LIVE_LLDB=1 (needs lldb)")

MARKER = b"MEMDIVER_BIG_REGION_MARKER_7f3a9c"
_TARGET = textwrap.dedent(f"""
    import ctypes, os, time
    SIZE, OFF = 160 * 1024 * 1024, 113 * 1024 * 1024 + 0x1234
    buf = bytearray(SIZE)
    for i in range(0, SIZE, 4096):
        buf[i] = 1
    buf[OFF:OFF + {len(MARKER)}] = {MARKER!r}
    base = ctypes.addressof((ctypes.c_char * SIZE).from_buffer(buf))
    print(base + OFF, flush=True)
    time.sleep(300)
""")


def test_marker_beyond_100mb_captured_at_real_va(tmp_path):
    from memdiver.core.capture_target import CaptureTarget
    from memdiver.core.dump_driver import DumpOrchestrator, maps_sidecar_path
    from memdiver.msl.importer import import_regioned_raw
    from memdiver.core.dump_source import open_dump

    proc = subprocess.Popen([sys.executable, "-c", _TARGET], stdout=subprocess.PIPE,
                            text=True)
    try:
        marker_va = int(proc.stdout.readline())
        out = tmp_path / "big.lldb_raw.bin"
        report = DumpOrchestrator(tools=["lldb"]).capture(
            CaptureTarget(pid=proc.pid), out, "lldb")
    finally:
        proc.kill()
    assert report.ok, report.error
    big = [r for r in report.skipped if r.base <= marker_va < r.base + r.size]
    assert not big, f"marker region was skipped: {big}"
    msl = tmp_path / "big.msl"
    import_regioned_raw(out, maps_sidecar_path(out), msl)
    with open_dump(msl) as src:
        vas_off = src.va_to_vas_offset(marker_va)
        assert vas_off is not None
        assert src.read_range(vas_off, len(MARKER), view="vas") == MARKER

if __name__ == "__main__":
    sys.exit(pytest.main([__file__, "-q"]))

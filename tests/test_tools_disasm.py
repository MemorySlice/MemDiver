"""disasm_result: captured-stretch disassembly, gaps, truncation, case table, real kernel."""

import json
import os
from pathlib import Path
from types import SimpleNamespace

import pytest

pytest.importorskip("capstone")

from memdiver.app.tools_disasm import disasm_result
from memdiver.core.location import (
    AddressSpace, Coverage, CoverageGap, GapReason, Location, ReadResult)
from memdiver.core.service_errors import CapabilityError, ErrorCategory

X64 = bytes.fromhex("554889e5c3")
A64 = bytes.fromhex("fd7bbfa9c0035fd6")
BASE = 0xFFFFFFFF81000000


class FakeView:
    """An image-view-shaped source over {va: bytes} stretches; the rest is a gap."""
    format_name = "image_view"

    def __init__(self, stretches, arch=None, profile=True):
        self.stretches = stretches
        paging = SimpleNamespace(arch=arch) if arch else None
        self.descriptor = SimpleNamespace(paging=paging, image_sha256="ab" * 32,
                                          profile="isf" if profile else None)

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return None

    def location(self, address):
        return Location(AddressSpace.KERNEL_VA, address, capture_id="cap")

    def read_location(self, address, length):
        buf, gaps, cursor = bytearray(length), [], address
        for start in sorted(self.stretches):
            data = self.stretches[start]
            lo, hi = max(start, address), min(start + len(data), address + length)
            if hi <= lo:
                continue
            if lo > cursor:
                gaps.append(CoverageGap(cursor, lo - cursor, GapReason.UNMAPPED))
            buf[lo - address:hi - address] = data[lo - start:hi - start]
            cursor = hi
        if cursor < address + length:
            gaps.append(CoverageGap(cursor, address + length - cursor, GapReason.UNMAPPED))
        cov = Coverage.from_gaps(address, length, gaps)
        return ReadResult(self.location(address), bytes(buf), cov)


@pytest.fixture
def dump(tmp_path):
    f = tmp_path / "x.mdview"
    f.write_bytes(b"x")
    return str(f)


@pytest.fixture(autouse=True)
def _profiled_arch(monkeypatch):
    """A profiled FakeView has no vol3 context: stand in for the paging-layer lookup."""
    monkeypatch.setattr("memdiver.app.tools_disasm._arch_of_profiled_view",
                        lambda source: "x86_64")


@pytest.fixture
def use(monkeypatch):
    def _use(source):
        monkeypatch.setattr("memdiver.core.dump_source.open_dump", lambda p: source)
    return _use


def test_x86_64_known_bytes(dump, use):
    use(FakeView({BASE: X64}))
    p = disasm_result(dump, BASE, 5).payload
    assert [r["mnemonic"] for r in p["rows"]] == ["push", "mov", "ret"]
    assert p["rows"][1]["op_str"] == "rbp, rsp" and p["rows"][1]["bytes"] == "4889e5"
    assert p["rows"][0]["addr"] == hex(BASE) and p["rows"][0]["size"] == 1
    assert p["rows"][0]["location"]["space"] == "kernel_va"
    assert p["arch"] == "x86_64" and p["space"] == "kernel_va"
    assert not p["truncated"] and p["coverage"]["complete"]


def test_aarch64_known_bytes(dump, use):
    use(FakeView({0x1000: A64}, arch="aarch64"))
    p = disasm_result(dump, 0x1000, 8).payload
    assert [r["mnemonic"] for r in p["rows"]] == ["stp", "ret"]
    assert p["arch"] == "aarch64"


def test_explicit_arch_overrides_and_thumb_mode(dump, use):
    use(FakeView({0: bytes.fromhex("7047")}, profile=False))
    p = disasm_result(dump, 0, 2, arch="arm", mode="thumb").payload
    assert p["rows"][0]["mnemonic"] == "bx" and p["mode"] == "thumb"


def test_unknown_arch_lists_choices(dump, use):
    use(FakeView({0: b"\x90"}, profile=False))
    with pytest.raises(CapabilityError) as e:
        disasm_result(dump, 0, 1)
    assert e.value.category is ErrorCategory.INVALID_INPUT and "x86_64" in str(e.value)
    with pytest.raises(CapabilityError) as e:
        disasm_result(dump, 0, 1, arch="sparc")
    assert "mipsel" in str(e.value)


def test_gap_is_reported_and_never_zero_filled(dump, use):
    use(FakeView({BASE: b"\x55\x48", BASE + 6: X64}))
    p = disasm_result(dump, BASE, 11).payload
    # 55 | 48 (dangling prefix, undecodable alone) ... gap 2..6 ... 55 48 89 e5 c3
    addrs = [int(r["addr"], 16) - BASE for r in p["rows"]]
    assert all(not (2 <= a < 6) for a in addrs)
    assert p["coverage"]["gaps"] == [{"start": BASE + 2, "length": 4, "reason": "unmapped",
                                         "start_hex": hex(BASE + 2)}]
    assert p["coverage"]["captured"] == 7 and not p["coverage"]["complete"]
    assert [r["mnemonic"] for r in p["rows"]][-3:] == ["push", "mov", "ret"]
    assert "00" not in {r["bytes"] for r in p["rows"]}


def test_undecodable_bytes_become_byte_rows_and_stops(dump, use):
    use(FakeView({0x10: bytes.fromhex("06") + X64}))   # 0x06 invalid in 64-bit mode
    p = disasm_result(dump, 0x10, 6, arch="x86_64").payload
    assert p["rows"][0]["mnemonic"] == ".byte"
    assert p["rows"][0]["stop_reason"] == "undecodable"
    assert p["stops"] == [{"addr": "0x10", "offset": 0, "stop_reason": "undecodable"}]
    assert [r["mnemonic"] for r in p["rows"][1:]] == ["push", "mov", "ret"]


def test_max_insns_truncates(dump, use):
    use(FakeView({0: b"\x90" * 50}))
    p = disasm_result(dump, 0, 50, arch="x86_64", max_insns=7).payload
    assert p["row_count"] == 7 and p["truncated"] is True
    q = disasm_result(dump, 0, 50, arch="x86_64", max_insns=50).payload
    assert q["row_count"] == 50 and q["truncated"] is False


def test_missing_capstone_gives_install_hint(dump, use, monkeypatch):
    import builtins

    real = builtins.__import__

    def fake(name, *a, **k):
        if name == "capstone":
            raise ImportError("no capstone")
        return real(name, *a, **k)

    use(FakeView({0: b"\x90"}))
    monkeypatch.setattr(builtins, "__import__", fake)
    with pytest.raises(CapabilityError) as e:
        disasm_result(dump, 0, 1, arch="x86_64")
    assert 'pip install "memdiver[disasm]"' in str(e.value)
    assert e.value.code == "disasm.capstone_missing"


def test_raw_file_uses_file_offsets(tmp_path):
    f = tmp_path / "blob.bin"
    f.write_bytes(b"\x00\x00" + X64)
    p = disasm_result(str(f), 2, 5, arch="x86_64").payload
    assert p["space"] == "file_offset" and [r["mnemonic"] for r in p["rows"]] == ["push", "mov", "ret"]


def test_case_table_written(dump, use, tmp_path, monkeypatch):
    from memdiver.analysis.case import Case

    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "home"))
    case_dir = tmp_path / "case"
    Case.init(case_dir)
    use(FakeView({BASE: X64}))
    p = disasm_result(dump, BASE, 5, case_dir=str(case_dir)).payload
    assert p["case"]["table"] == "disasm" and p["case"]["rows"] == 3
    rows = Case.open(case_dir).query(
        "SELECT addr, size, space, mnemonic, op_str FROM disasm ORDER BY addr").table.to_pylist()
    assert [r["mnemonic"] for r in rows] == ["push", "mov", "ret"]
    assert rows[0]["addr"] == BASE and rows[0]["space"] == "kernel_va"


# -- real kernel image ------------------------------------------------------------

_ROOT = os.environ.get("MEMDIVER_IMAGE_CORPUS", "")
_STEM = "arista-eos-4.36.1F_5.10.165.Ar-48367454.4361F"
_CORPUS = Path(_ROOT) if _ROOT else None


@pytest.mark.skipif(
    _CORPUS is None or not all((_CORPUS / f"{_STEM}{e}").is_file() for e in (".lime", ".isf.json")),
    reason="set MEMDIVER_IMAGE_CORPUS to a dir with the arista .lime + .isf.json")
def test_real_kernel_start_kernel_disassembles(tmp_path, monkeypatch):
    from memdiver.core.dump_source import open_dump
    from memdiver.core.image.view_descriptor import ProfileRef, ViewDescriptor, ViewKind

    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "home"))
    isf = _CORPUS / f"{_STEM}.isf.json"
    sha = "5a" * 32
    desc = ViewDescriptor(str(_CORPUS / f"{_STEM}.lime"), sha, ViewKind.KERNEL,
                          profile=ProfileRef(str(isf), sha256=sha, origin="pakunoda"))
    path = desc.write(tmp_path / "arista.mdview")
    with open_dump(path) as src:
        shift = src.metadata()["layer"]["kernel"]["aslr_shift"]
    symbols = json.loads(isf.read_text())["symbols"]
    va = symbols["start_kernel"]["address"] + shift
    p = disasm_result(str(path), va, 64).payload
    assert p["arch"] == "x86_64" and p["space"] == "kernel_va"
    assert p["row_count"] >= 5 and p["rows"][0]["mnemonic"] != ".byte"
    # start_kernel lives in .init.text, which the kernel frees after boot, so its
    # bytes are poison that happens to decode. do_syscall_64 is live code.
    live = disasm_result(str(path), symbols["do_syscall_64"]["address"] + shift, 32).payload
    assert [r["mnemonic"] for r in live["rows"][:3]] == ["push", "mov", "push"]
    assert live["rows"][1]["op_str"] == "rbp, rsp"

"""Tests for core.dump_driver -- mock-based, no real dumps."""

import pytest
from unittest.mock import patch, MagicMock
from memdiver.core.dump_driver import (
    DumpOrchestrator,
    DumpToolInfo,
    TargetProcess,
    ExperimentResult,
)


class TestDumpToolInfo:
    def test_dataclass_fields(self):
        info = DumpToolInfo(name="test", available=True, extension="bin")
        assert info.name == "test"
        assert info.available is True
        assert info.extension == "bin"

    def test_equality(self):
        a = DumpToolInfo(name="lldb", available=True, extension="dump")
        b = DumpToolInfo(name="lldb", available=True, extension="dump")
        assert a == b


class TestTargetProcess:
    def test_dataclass_fields(self):
        proc = MagicMock()
        tp = TargetProcess(pid=123, key_hex="aa" * 32, iv_hex="bb" * 16, process=proc)
        assert tp.pid == 123
        assert len(tp.key_hex) == 64
        assert len(tp.iv_hex) == 32
        assert tp.process is proc


class TestExperimentResult:
    def test_defaults(self, tmp_path):
        result = ExperimentResult(
            output_dir=tmp_path,
            tool_dirs={},
            num_runs=5,
            tools_used=["lldb"],
        )
        assert result.metadata == {}
        assert result.num_runs == 5


class TestDetectTools:
    def test_returns_three_tools(self):
        tools = DumpOrchestrator._detect_tools()
        assert isinstance(tools, list)
        assert len(tools) == 3

    def test_tool_names(self):
        tools = DumpOrchestrator._detect_tools()
        names = {t.name for t in tools}
        assert names == {"memslicer", "lldb", "fridump"}

    def test_extensions(self):
        tools = DumpOrchestrator._detect_tools()
        by_name = {t.name: t for t in tools}
        assert by_name["memslicer"].extension == "msl"
        assert by_name["lldb"].extension == "dump"
        assert by_name["fridump"].extension == "dump"

    @patch("memdiver.core.dump_driver.shutil.which", return_value="/usr/bin/fake")
    def test_all_available_when_which_succeeds(self, mock_which):
        tools = DumpOrchestrator._detect_tools()
        # memslicer and lldb use shutil.which; fridump checks which first
        for t in tools:
            if t.name in ("memslicer", "lldb"):
                assert t.available is True

    @patch("memdiver.core.dump_driver.shutil.which", return_value=None)
    def test_none_available_when_which_fails(self, mock_which):
        tools = DumpOrchestrator._detect_tools()
        for t in tools:
            assert t.available is False


class TestOrchestratorInit:
    @patch("memdiver.core.dump_driver.shutil.which", return_value=None)
    def test_filter_by_name(self, mock_which):
        orch = DumpOrchestrator(tools=["lldb"])
        names = {t.name for t in orch._tools}
        assert names == {"lldb"}

    @patch("memdiver.core.dump_driver.shutil.which", return_value=None)
    def test_no_tools_available(self, mock_which):
        orch = DumpOrchestrator()
        assert orch.available_tools == []

    @patch("memdiver.core.dump_driver.shutil.which", return_value="/usr/bin/fake")
    def test_available_tools_property(self, mock_which):
        orch = DumpOrchestrator()
        available = orch.available_tools
        assert len(available) >= 2  # memslicer + lldb at minimum


class TestDump:
    @patch("memdiver.core.dump_driver.shutil.which", return_value=None)
    def test_unknown_tool_returns_false(self, mock_which):
        orch = DumpOrchestrator()
        from pathlib import Path
        assert orch.dump(123, Path("/tmp/test.bin"), "nonexistent") is False

    @patch("memdiver.core.dump_driver.subprocess.run")
    @patch("memdiver.core.dump_driver.shutil.which", return_value="/usr/bin/fake")
    def test_memslicer_success(self, mock_which, mock_run, tmp_path):
        dump_path = tmp_path / "out.msl"
        dump_path.write_bytes(b"\x00" * 100)
        mock_run.return_value = MagicMock(returncode=0)
        orch = DumpOrchestrator(tools=["memslicer"])
        result = orch.dump(999, dump_path, "memslicer")
        assert result is True

    @patch("memdiver.core.dump_driver.subprocess.run")
    @patch("memdiver.core.dump_driver.shutil.which", return_value="/usr/bin/fake")
    def test_memslicer_failure(self, mock_which, mock_run, tmp_path):
        dump_path = tmp_path / "out.msl"
        mock_run.return_value = MagicMock(returncode=1)
        orch = DumpOrchestrator(tools=["memslicer"])
        result = orch.dump(999, dump_path, "memslicer")
        assert result is False

    @patch("memdiver.core.dump_driver.shutil.which", return_value="/usr/bin/fake")
    def test_dump_exception_returns_false(self, mock_which, tmp_path):
        orch = DumpOrchestrator(tools=["memslicer"])
        # dump() routes through capture() -> _capture_memslicer (never run the
        # real tool against an arbitrary pid).
        with patch.object(orch, "_capture_memslicer", side_effect=OSError("fail")):
            result = orch.dump(999, tmp_path / "out.msl", "memslicer")
            assert result is False


class TestStartTargetTimeout:
    @patch("memdiver.core.dump_driver.shutil.which", return_value=None)
    def test_timeout_fires_when_target_emits_no_newline(self, mock_which, tmp_path):
        """A target that opens stdout but never emits a newline must still
        time out. Regression: the deadline was only checked inside
        ``for line in proc.stdout``, which blocks forever with no newline."""
        script = tmp_path / "hang.py"
        # Write a partial line (no newline) then sleep well past the timeout.
        script.write_text(
            "import sys, time\n"
            "sys.stdout.write('partial-no-newline')\n"
            "sys.stdout.flush()\n"
            "time.sleep(30)\n"
        )
        orch = DumpOrchestrator()
        import time as _t
        start = _t.monotonic()
        with pytest.raises(TimeoutError):
            orch.start_target(script, timeout=1.0)
        # Must return promptly around the timeout, not block on the sleep(30).
        assert _t.monotonic() - start < 10.0

    @patch("memdiver.core.dump_driver.shutil.which", return_value=None)
    def test_success_path_reads_pid_key_iv(self, mock_which, tmp_path):
        """The MEMDIVER_READY success path must still work end-to-end."""
        script = tmp_path / "ready.py"
        script.write_text(
            "import sys, time\n"
            "print('MEMDIVER_PID=4321')\n"
            "print('MEMDIVER_KEY=' + 'ab' * 32)\n"
            "print('MEMDIVER_IV=' + 'cd' * 16)\n"
            "print('MEMDIVER_READY=1')\n"
            "sys.stdout.flush()\n"
            "time.sleep(30)\n"
        )
        orch = DumpOrchestrator()
        target = orch.start_target(script, timeout=10.0)
        try:
            assert target.pid == 4321
            assert target.key_hex == "ab" * 32
            assert target.iv_hex == "cd" * 16
        finally:
            target.process.kill()

    @patch("memdiver.core.dump_driver.shutil.which", return_value=None)
    def test_eof_without_ready_raises_runtime_error(self, mock_which, tmp_path):
        """A target that exits before providing PID/KEY raises RuntimeError."""
        script = tmp_path / "exit.py"
        script.write_text("print('nothing useful')\n")
        orch = DumpOrchestrator()
        with pytest.raises(RuntimeError):
            orch.start_target(script, timeout=5.0)


class TestRunExperimentKeylog:
    def _orch_with_one_tool(self):
        with patch("memdiver.core.dump_driver.shutil.which", return_value="/usr/bin/fake"):
            orch = DumpOrchestrator(tools=["memslicer"])
        return orch

    def test_keylog_uses_protocol_label_and_iv(self, tmp_path):
        """The keylog line must derive its label from the protocol and use
        the target's IV as the identifier — not a hardcoded AES256 / zero
        identifier."""
        orch = self._orch_with_one_tool()
        target = TargetProcess(
            pid=111, key_hex="11" * 32, iv_hex="ab" * 16, process=MagicMock()
        )
        with patch.object(orch, "start_target", return_value=target), \
                patch.object(orch, "dump", return_value=True), \
                patch.object(orch, "kill_target"), \
                patch("memdiver.core.dump_driver.time.sleep"):
            result = orch.run_experiment(
                tmp_path / "target.py", num_runs=1, output_dir=tmp_path,
                protocol="CHACHA20", scenario="scn", delay=0.0,
            )
        run_dir = result.tool_dirs["memslicer"] / "memslicer_run_256_1"
        keylog = (run_dir / "keylog.csv").read_text()
        assert "CHACHA20_KEY" in keylog
        assert ("ab" * 16) in keylog
        assert ("11" * 32) in keylog
        # The old hardcoded 32-byte zero identifier must be gone.
        assert ("00" * 32) not in keylog

    def test_keylog_falls_back_to_zero_iv_when_absent(self, tmp_path):
        orch = self._orch_with_one_tool()
        target = TargetProcess(
            pid=222, key_hex="22" * 32, iv_hex="", process=MagicMock()
        )
        with patch.object(orch, "start_target", return_value=target), \
                patch.object(orch, "dump", return_value=True), \
                patch.object(orch, "kill_target"), \
                patch("memdiver.core.dump_driver.time.sleep"):
            result = orch.run_experiment(
                tmp_path / "target.py", num_runs=1, output_dir=tmp_path,
                protocol="AES256", scenario="scn", delay=0.0,
            )
        run_dir = result.tool_dirs["memslicer"] / "memslicer_run_256_1"
        keylog = (run_dir / "keylog.csv").read_text()
        assert "AES256_KEY" in keylog
        assert ("00" * 16) in keylog  # zero IV fallback (16 bytes, not 32)


class TestKillTarget:
    @patch("memdiver.core.dump_driver.os.kill")
    @patch("memdiver.core.dump_driver.shutil.which", return_value=None)
    def test_kill_sends_sigterm(self, mock_which, mock_kill):
        proc = MagicMock()
        proc.wait.return_value = None
        target = TargetProcess(pid=42, key_hex="aa", iv_hex="bb", process=proc)
        orch = DumpOrchestrator()
        orch.kill_target(target)
        mock_kill.assert_called_once_with(42, 15)  # SIGTERM = 15

    @patch("memdiver.core.dump_driver.os.kill")
    @patch("memdiver.core.dump_driver.shutil.which", return_value=None)
    def test_kill_escalates_to_sigkill(self, mock_which, mock_kill):
        import subprocess as sp
        proc = MagicMock()
        proc.wait.side_effect = sp.TimeoutExpired("cmd", 5)
        target = TargetProcess(pid=42, key_hex="aa", iv_hex="bb", process=proc)
        orch = DumpOrchestrator()
        orch.kill_target(target)
        # Second call should be SIGKILL
        calls = mock_kill.call_args_list
        assert len(calls) == 2
        assert calls[1][0] == (42, 9)  # SIGKILL = 9

    @patch("memdiver.core.dump_driver.os.kill", side_effect=ProcessLookupError)
    @patch("memdiver.core.dump_driver.shutil.which", return_value=None)
    def test_kill_already_dead(self, mock_which, mock_kill):
        proc = MagicMock()
        target = TargetProcess(pid=42, key_hex="aa", iv_hex="bb", process=proc)
        orch = DumpOrchestrator()
        # Should not raise
        orch.kill_target(target)


# ---------------------------------------------------------------------------
# Layout-preserving producers: lldb + fridump .maps sidecars
# ---------------------------------------------------------------------------

import sys as _sys
import types as _types
from pathlib import Path

from memdiver.core import dump_driver as _dd
from memdiver.core.proc_maps_parser import parse_maps_text


class _FakeRegionInfo:
    """Minimal stand-in for ``lldb.SBMemoryRegionInfo``."""

    def __init__(self):
        self.base, self.end, self.perm, self.name = 0, 0, "---", None

    def IsReadable(self): return "r" in self.perm
    def IsWritable(self): return "w" in self.perm
    def IsExecutable(self): return "x" in self.perm
    def GetRegionBase(self): return self.base
    def GetRegionEnd(self): return self.end
    def GetName(self): return self.name


class _FakeError:
    def __init__(self): self.ok = True
    def Success(self): return self.ok


class _FakeRegionInfoList:
    """Minimal stand-in for ``lldb.SBMemoryRegionInfoList``."""

    def __init__(self, regions):
        self.regions = regions

    def GetSize(self): return len(self.regions)

    def GetMemoryRegionAtIndex(self, i, info):
        info.base, info.end, info.perm, info.name, _ = self.regions[i]
        return True


class _FakeFileSpec:
    """Stand-in for ``lldb.SBFileSpec`` (``fullpath`` is a real SWIG property)."""

    def __init__(self, fullpath): self.fullpath = fullpath


class _FakeSection:
    """Stand-in for ``lldb.SBSection``; ``load`` None means not loaded."""

    def __init__(self, load, size, subsections=()):
        self.load, self.size, self.subsections = load, size, list(subsections)

    def GetLoadAddress(self, target):
        return _dd.LLDB_INVALID_ADDRESS if self.load is None else self.load

    def GetByteSize(self): return self.size
    def GetNumSubSections(self): return len(self.subsections)
    def GetSubSectionAtIndex(self, i): return self.subsections[i]


class _FakeModule:
    """Stand-in for ``lldb.SBModule``."""

    def __init__(self, path, sections):
        self.path, self.sections = path, sections

    def GetFileSpec(self): return _FakeFileSpec(self.path)
    def GetNumSections(self): return len(self.sections)
    def GetSectionAtIndex(self, i): return self.sections[i]


class _FakeTarget:
    """Stand-in for ``lldb.SBTarget``."""

    def __init__(self, modules=()): self.modules = list(modules)
    def GetNumModules(self): return len(self.modules)
    def GetModuleAtIndex(self, i): return self.modules[i]


class _FakeFrame:
    def __init__(self, sp): self.sp = sp
    def GetSP(self): return self.sp


class _FakeThread:
    """Stand-in for ``lldb.SBThread``."""

    def __init__(self, tid, sp): self.tid, self.sp = tid, sp
    def GetThreadID(self): return self.tid
    def GetFrameAtIndex(self, i): return _FakeFrame(self.sp)


class _FakeProcess:
    """Regions: list of (base, end, perm, name, data_or_None_for_failure).

    Mirrors the real ``lldb.SBProcess`` surface: regions are only reachable
    through ``GetMemoryRegions()`` (SBProcess has no GetNumMemoryRegions).
    """

    def __init__(self, regions, modules=(), threads=()):
        self.regions = regions
        self.target = _FakeTarget(modules)
        self.threads = list(threads)

    def GetMemoryRegions(self): return _FakeRegionInfoList(self.regions)
    def GetTarget(self): return self.target
    def GetNumThreads(self): return len(self.threads)
    def GetThreadAtIndex(self, i): return self.threads[i]

    def ReadMemory(self, base, size, err):
        for b, _e, _p, _n, data in self.regions:
            if b == base:
                if data is None:
                    err.ok = False
                    return None
                return data[:size]
        err.ok = False
        return None


def _fake_lldb_module(process=None):
    mod = _types.SimpleNamespace(SBMemoryRegionInfo=_FakeRegionInfo, SBError=_FakeError)
    if process is not None:
        target = MagicMock()
        target.GetProcess.return_value = process
        mod.debugger = MagicMock()
        mod.debugger.GetSelectedTarget.return_value = target
    return mod


_LLDB_REGIONS = [
    (0x1000, 0x1010, "r-x", "/usr/lib/libc.so.6", b"A" * 16),
    (0x2000, 0x2008, "---", None, b"N" * 8),           # unreadable -> skipped
    (0x3000, 0x3010, "rw-", "", b"B" * 8),               # short read: 8 of 16
    (0x4000, 0x4010, "rw-", "[heap]", None),             # read failure -> skipped
    (0x5000, 0x5000, "rw-", None, b""),                  # zero size -> skipped
    (0x6000, 0x6004, "rwx", "[stack]", b"C" * 4),
]


class TestFormatMapsLine:
    def test_without_path_parses(self):
        line = _dd.format_maps_line(0x1000, 0x2000, "r--p")
        assert line == "1000-2000 r--p 00000000 00:00 0"
        (region,) = parse_maps_text(line)
        assert (region.start, region.end, region.perm, region.path) == (0x1000, 0x2000, "r--p", "")

    def test_with_path_parses(self):
        line = _dd.format_maps_line(0x10, 0x20, "rw-p", "/opt/my lib.so")
        (region,) = parse_maps_text(line)
        assert region.path == "/opt/my lib.so"

    def test_sidecar_path(self, tmp_path):
        assert _dd.maps_sidecar_path(tmp_path / "x.lldb_raw.bin").name == "x.lldb_raw.maps"
        assert _dd.maps_sidecar_path(tmp_path / "x_pre_snapshot.dump").name == "x_pre_snapshot.maps"


class TestLldbRegionHelpers:
    def test_perm(self):
        info = _FakeRegionInfo()
        info.perm = "r-x"
        assert _dd.lldb_region_perm(info) == "r-xp"
        info.perm = ""
        assert _dd.lldb_region_perm(info) == "---p"

    def test_name_empty_is_none(self):
        info = _FakeRegionInfo()
        info.name = ""
        assert _dd.lldb_region_name(info) is None
        info.name = "[heap]"
        assert _dd.lldb_region_name(info) == "[heap]"


class TestLldbWriteRegions:
    def _run(self, tmp_path, max_size=_dd.LLDB_MAX_REGION_SIZE):
        bin_path = tmp_path / "t.lldb_raw.bin"
        maps_path = _dd.maps_sidecar_path(bin_path)
        with open(bin_path, "wb") as b, open(maps_path, "w") as m:
            n = _dd.lldb_write_regions(_fake_lldb_module(), _FakeProcess(_LLDB_REGIONS),
                                       b, m, max_size)
        return n, bin_path.read_bytes(), parse_maps_text(maps_path.read_text())

    def test_maps_match_written_regions(self, tmp_path):
        n, data, regions = self._run(tmp_path)
        assert n == 3
        assert [(r.start, r.end) for r in regions] == [
            (0x1000, 0x1010), (0x3000, 0x3008), (0x6000, 0x6004)]
        assert [r.perm for r in regions] == ["r-xp", "rw-p", "rwxp"]
        assert [r.path for r in regions] == ["/usr/lib/libc.so.6", "", "[stack]"]
        assert sum(r.size for r in regions) == len(data)
        assert data == b"A" * 16 + b"B" * 8 + b"C" * 4

    def test_oversized_regions_skipped(self, tmp_path):
        _n, data, regions = self._run(tmp_path, max_size=16)
        assert [r.start for r in regions] == [0x6000]
        assert sum(r.size for r in regions) == len(data)

    def test_uses_only_real_sb_api(self):
        """Regression: SBProcess has no GetNumMemoryRegions; must use GetMemoryRegions()."""
        src = _dd.inspect.getsource(_dd.lldb_write_regions)
        assert "GetNumMemoryRegions" not in src
        lldb = _real_lldb_module()
        if lldb is None:
            pytest.skip("lldb Python module not available")
        assert hasattr(lldb.SBProcess, "GetMemoryRegions")
        assert not hasattr(lldb.SBProcess, "GetNumMemoryRegions")
        for name in ("GetSize", "GetMemoryRegionAtIndex"):
            assert hasattr(lldb.SBMemoryRegionInfoList, name)

    def test_every_sb_call_in_script_helpers_exists(self):
        """Every ``.GetX(``/``.IsX(`` call the lldb script makes is a real SB method."""
        import re as _re
        src = "\n".join(_dd.inspect.getsource(f) for f in _dd._LLDB_SCRIPT_HELPERS)
        called = set(_re.findall(r"\.((?:Get|Is)[A-Z]\w*)\(", src))
        assert {"GetNumModules", "GetSectionAtIndex", "GetSP", "GetThreadAtIndex"} <= called
        lldb = _real_lldb_module()
        if lldb is None:
            pytest.skip("lldb Python module not available")
        sb_classes = (lldb.SBProcess, lldb.SBTarget, lldb.SBModule, lldb.SBSection,
                      lldb.SBThread, lldb.SBFrame, lldb.SBMemoryRegionInfo,
                      lldb.SBMemoryRegionInfoList, lldb.SBDebugger, lldb.SBError)
        missing = {n for n in called if not any(hasattr(c, n) for c in sb_classes)}
        assert not missing
        for cls, name in ((lldb.SBProcess, "GetTarget"), (lldb.SBProcess, "GetNumThreads"),
                          (lldb.SBTarget, "GetModuleAtIndex"), (lldb.SBModule, "GetFileSpec"),
                          (lldb.SBModule, "GetNumSections"), (lldb.SBSection, "GetLoadAddress"),
                          (lldb.SBSection, "GetNumSubSections"),
                          (lldb.SBSection, "GetSubSectionAtIndex"),
                          (lldb.SBThread, "GetFrameAtIndex"), (lldb.SBThread, "GetThreadID"),
                          (lldb.SBFileSpec, "fullpath")):
            assert hasattr(cls, name), f"{cls.__name__}.{name}"
        assert lldb.LLDB_INVALID_ADDRESS == _dd.LLDB_INVALID_ADDRESS


_UNNAMED_REGIONS = [  # macOS-style: lldb reports no region names
    (0x10000, 0x14000, "r-x", None, b"T" * 0x4000),   # main binary __TEXT
    (0x14000, 0x18000, "rw-", None, b"D" * 0x4000),   # main binary __DATA
    (0x20000, 0x21000, "r--", None, b"L" * 0x1000),   # dylib, partly covered
    (0x30000, 0x31000, "rw-", None, b"H" * 0x1000),   # malloc heap
    (0x40000, 0x48000, "rw-", None, b"S" * 0x8000),   # main thread stack
    (0x50000, 0x51000, "rw-", None, b"s" * 0x1000),   # secondary thread stack
    (0x60000, 0x61000, "rw-", "[heap]", b"N" * 0x1000),  # lldb name wins
]
_MODULES = [
    _FakeModule("/tmp/app/target", [
        _FakeSection(None, 0x10000),                   # __PAGEZERO-like, not loaded
        _FakeSection(0x10000, 0x4000, [_FakeSection(0x10100, 0x100)]),
        _FakeSection(0x14000, 0x4000),
    ]),
    _FakeModule("/usr/lib/libSystem.B.dylib", [_FakeSection(0x20800, 0x2000)]),
    _FakeModule("/usr/lib/heapshadow.dylib", [_FakeSection(0x60000, 0x1000)]),
    _FakeModule(None, [_FakeSection(0x30000, 0x1000)]),  # pathless -> ignored
]
_THREADS = [_FakeThread(101, 0x47f00), _FakeThread(202, 0x50800), _FakeThread(303, 0)]


class TestLldbRegionNaming:
    def _paths(self, tmp_path):
        bin_path = tmp_path / "n.bin"
        process = _FakeProcess(_UNNAMED_REGIONS, _MODULES, _THREADS)
        with open(bin_path, "wb") as b, open(_dd.maps_sidecar_path(bin_path), "w") as m:
            _dd.lldb_write_regions(_fake_lldb_module(), process, b, m)
        return [r.path for r in parse_maps_text(_dd.maps_sidecar_path(bin_path).read_text())]

    def test_regions_named_from_modules_and_stacks(self, tmp_path):
        assert self._paths(tmp_path) == [
            "/tmp/app/target", "/tmp/app/target", "/usr/lib/libSystem.B.dylib",
            "", "[stack]", "[stack:202]", "[heap]"]

    def test_module_intervals_recurse_and_skip_unloaded(self):
        intervals = _dd.lldb_module_intervals(_FakeTarget(_MODULES[:1]))
        assert intervals == [(0x10000, 0x14000, "/tmp/app/target"),
                             (0x10100, 0x10200, "/tmp/app/target"),
                             (0x14000, 0x18000, "/tmp/app/target")]

    def test_module_for_range_prefers_start_then_largest_overlap(self):
        intervals = [(0x100, 0x180, "a"), (0x180, 0x200, "b"), (0x0, 0x110, "c")]
        assert _dd.lldb_module_for_range(0x100, 0x200, intervals) == "a"
        assert _dd.lldb_module_for_range(0x120, 0x200, intervals[1:]) == "b"
        assert _dd.lldb_module_for_range(0x300, 0x400, intervals) is None

    def test_stack_pointers_skip_threads_without_sp(self):
        assert _dd.lldb_stack_pointers(_FakeProcess([], threads=_THREADS)) == [
            (0x47f00, "[stack]"), (0x50800, "[stack:202]")]


def _real_lldb_module():
    """Import lldb's Python bindings via ``lldb -P``; None when unavailable."""
    import shutil as _shutil
    import subprocess as _subprocess
    if _shutil.which("lldb") is None:
        return None
    try:
        path = _subprocess.run(["lldb", "-P"], capture_output=True, text=True,
                               timeout=10).stdout.strip()
        if path and path not in _sys.path:
            _sys.path.append(path)
        import lldb  # noqa: WPS433
        return lldb
    except Exception:  # noqa: BLE001 - any import/ABI failure means "unavailable"
        return None


class TestLldbDumpScript:
    def test_script_is_self_contained_and_writes_sidecar(self, tmp_path, monkeypatch):
        out = tmp_path / "run_pre_snapshot.dump"
        script = _dd.build_lldb_dump_script(out)
        monkeypatch.setitem(_sys.modules, "lldb",
                            _fake_lldb_module(_FakeProcess(_LLDB_REGIONS)))
        exec(compile(script, "<lldb-script>", "exec"), {"__name__": "__lldb__"})
        regions = parse_maps_text(_dd.maps_sidecar_path(out).read_text())
        assert len(regions) == 3
        assert sum(r.size for r in regions) == out.stat().st_size

    @patch("memdiver.core.dump_driver.subprocess.run")
    def test_dump_lldb_invokes_script_and_cleans_up(self, mock_run, tmp_path):
        out = tmp_path / "run.dump"

        def fake_run(cmd, **_kw):
            script_cmd = cmd[cmd.index("-o") + 1]
            assert script_cmd.startswith("script exec(open(")
            out.write_bytes(b"x")
            return MagicMock(returncode=0)

        mock_run.side_effect = fake_run
        assert _dd.DumpOrchestrator._dump_lldb(1234, out) is True
        assert not out.with_suffix(".lldb_script.py").exists()


class TestFridumpBaseAddress:
    @pytest.mark.parametrize("name,expected", [
        ("0x7f12a000_dump.data", 0x7f12a000),
        ("0x00009000_dump.data", 0x9000),
        ("7f12a000_dump.data", 0x7f12a000),
        ("0X10000.data", None),  # uppercase prefix not a fridump convention
        ("0x10000.data", 0x10000),
        ("dump_foo.data", None),
        ("strings.data", None),
    ])
    def test_parse(self, name, expected):
        assert _dd.fridump_base_address(name) == expected


def _write_chunks(directory, chunks):
    directory.mkdir(exist_ok=True)
    paths = []
    for name, data in chunks:
        p = directory / name
        p.write_bytes(data)
        paths.append(p)
    return paths


class TestAssembleFridumpOutput:
    def test_numeric_order_and_maps(self, tmp_path):
        files = _write_chunks(tmp_path / "chunks", [
            ("0x10000_dump.data", b"\x02" * 32),
            ("0x9000_dump.data", b"\x01" * 16),
            ("0x7f0000000000_dump.data", b"\x03" * 8),
        ])
        out = tmp_path / "snap.dump"
        assert _dd.assemble_fridump_output(files, out) is True
        regions = parse_maps_text(_dd.maps_sidecar_path(out).read_text())
        assert [(r.start, r.size) for r in regions] == [
            (0x9000, 16), (0x10000, 32), (0x7f0000000000, 8)]
        assert all(r.perm == _dd.FRIDUMP_DEFAULT_PERM and r.path == "" for r in regions)
        assert sum(r.size for r in regions) == out.stat().st_size
        assert out.read_bytes() == b"\x01" * 16 + b"\x02" * 32 + b"\x03" * 8

    def test_unparsable_name_skips_maps(self, tmp_path):
        files = _write_chunks(tmp_path / "chunks", [
            ("region_dump.data", b"B"), ("0x9000_dump.data", b"A")])
        out = tmp_path / "snap.dump"
        assert _dd.assemble_fridump_output(files, out) is False
        assert not _dd.maps_sidecar_path(out).exists()
        assert out.read_bytes() == b"AB"  # lexicographic fallback ("0x9000" < "region")

    @patch("memdiver.core.dump_driver.collect_target_spans",
           return_value=([], "none"))  # no real Frida attach to pid 1
    @patch("memdiver.core.dump_driver.subprocess.run")
    def test_dump_fridump_end_to_end(self, mock_run, _mock_spans, tmp_path):
        out = tmp_path / "snap.dump"

        def fake_run(cmd, **_kw):
            tmp_dir = Path(cmd[cmd.index("-o") + 1])
            _write_chunks(tmp_dir, [("0x10000_dump.data", b"Y" * 4),
                                    ("0x9000_dump.data", b"X" * 2)])
            return MagicMock(returncode=0)

        mock_run.side_effect = fake_run
        assert _dd.DumpOrchestrator._dump_fridump(1, out) is True
        assert out.read_bytes() == b"XXYYYY"
        regions = parse_maps_text(_dd.maps_sidecar_path(out).read_text())
        assert [(r.start, r.end) for r in regions] == [(0x9000, 0x9002), (0x10000, 0x10004)]
        assert not (tmp_path / "_fridump_tmp").exists()

"""Capture backends: device/target selection, chunked lldb reads, reported
skips, fridump naming, and the ``capture`` capability on every surface.

Mock-based: no real debugger, Frida session or device is touched here (the
real lldb run lives in ``tests/test_lldb_large_region_live.py``).
"""

import json
import sys
import types
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from memdiver.core import capture_manifest as cm
from memdiver.core import dump_driver as dd
from memdiver.core import fridump_names as fn
from memdiver.core.capture_target import (CaptureDevice, CaptureTarget,
                                          UnsupportedCaptureTarget,
                                          fridump_device_args,
                                          memslicer_acquire_args,
                                          memslicer_device_args,
                                          parse_device_spec, parse_target,
                                          require_local)
from memdiver.core.proc_maps_parser import parse_maps_file, parse_maps_text
from memdiver.msl.import_regioned import plan_regioned_raw

PAGE = dd.LLDB_PAGE_SIZE


# -- device / target ------------------------------------------------------------


class TestDeviceSpec:
    @pytest.mark.parametrize("spec,expected", [
        (None, CaptureDevice()),
        ("", CaptureDevice()),
        ("local", CaptureDevice()),
        ("USB", CaptureDevice("usb")),
        ("usb:emulator-5554", CaptureDevice("usb", device_id="emulator-5554")),
        ("remote:10.0.0.2", CaptureDevice("remote", remote_addr="10.0.0.2")),
        ("remote:10.0.0.2:27042", CaptureDevice("remote", remote_addr="10.0.0.2:27042")),
    ])
    def test_parse(self, spec, expected):
        assert parse_device_spec(spec) == expected

    @pytest.mark.parametrize("spec", ["bogus", "remote", "remote:", "local:x",
                                      "remote:host:0", "remote:host:abc"])
    def test_invalid(self, spec):
        with pytest.raises(ValueError):
            parse_device_spec(spec)

    @pytest.mark.parametrize("spec", ["local", "usb", "usb:emulator-5556",
                                      "remote:h:1234"])
    def test_round_trip(self, spec):
        assert parse_device_spec(spec).to_spec() == spec

    def test_target_pid_or_name(self):
        assert parse_target("1234").pid == 1234
        assert parse_target(77).pid == 77
        t = parse_target("com.example.app", "usb")
        assert (t.pid, t.name, t.device.kind) == (None, "com.example.app", "usb")
        assert t.to_dict() == {"pid": None, "name": "com.example.app", "device": "usb"}
        with pytest.raises(ValueError):
            CaptureTarget()
        with pytest.raises(ValueError):
            CaptureTarget(pid=0)

    def test_memslicer_args(self):
        assert memslicer_device_args(CaptureDevice()) == []
        assert memslicer_device_args(CaptureDevice("usb")) == ["-U"]
        assert memslicer_device_args(CaptureDevice("usb", device_id="e-1")) == ["-D", "e-1"]
        assert memslicer_device_args(CaptureDevice("remote", remote_addr="h:1")) == ["-R", "h:1"]
        argv = memslicer_acquire_args(parse_target("com.app", "usb:e-1"), "/o.msl", 1024)
        assert argv == ["memslicer", "acquire", "com.app", "-o", "/o.msl",
                        "-D", "e-1", "--max-region-size", "1024"]

    def test_fridump_args(self):
        assert fridump_device_args(CaptureDevice()) == []
        assert fridump_device_args(CaptureDevice("usb")) == ["-U"]
        for dev in (CaptureDevice("usb", device_id="x"),
                    CaptureDevice("remote", remote_addr="h")):
            with pytest.raises(UnsupportedCaptureTarget):
                fridump_device_args(dev)

    def test_require_local(self):
        require_local(CaptureDevice(), "lldb")
        with pytest.raises(UnsupportedCaptureTarget):
            require_local(CaptureDevice("usb"), "lldb")


# -- manifest -------------------------------------------------------------------


class TestManifest:
    def _report(self, tmp_path):
        rep = cm.CaptureReport(ok=True, tool="lldb", output_path=str(tmp_path / "a.bin"),
                               names=cm.NAMES_NONE)
        rep.skip(0x1000, 0x2000, cm.REASON_READ_FAILED)
        rep.skip(0x9000, 0x1000, cm.REASON_UNREADABLE)
        return rep

    def test_to_dict_lists_skips(self, tmp_path):
        d = self._report(tmp_path).to_dict()
        assert d["skipped"][0] == {"base": 0x1000, "base_hex": "0x1000",
                                   "size": 0x2000, "reason": "read_failed"}
        assert d["skipped_bytes"] == 0x3000
        assert d["summary_warnings"][0].startswith("2 region(s) / 12288 bytes")
        assert any("0x1000-0x3000" in w for w in d["summary_warnings"])
        assert any("names unavailable" in w for w in d["summary_warnings"])

    def test_digest_caps_listed_examples(self):
        skipped = [cm.SkippedRegion(i * PAGE, PAGE, "unreadable") for i in range(9)]
        lines = cm.skipped_warnings(skipped)
        assert len(lines) == 1 + 5 and "unreadable=9" in lines[0]

    def test_write_read_and_import_warnings(self, tmp_path):
        rep = self._report(tmp_path)
        path = cm.write_manifest(rep)
        assert path.name == "a.capture.json"
        assert cm.read_manifest(tmp_path / "a.bin")["schema"] == cm.MANIFEST_SCHEMA
        warnings = cm.manifest_warnings(tmp_path / "a.bin")
        assert warnings[0].startswith("2 region(s)") and "anonymous" in warnings[-1]

    def test_missing_or_corrupt_manifest(self, tmp_path):
        assert cm.manifest_warnings(tmp_path / "x.bin") == []
        (tmp_path / "x.capture.json").write_text("{not json")
        assert cm.manifest_warnings(tmp_path / "x.bin") == []

    def test_partial_names_warning(self):
        assert "partial" in cm.names_warnings(cm.NAMES_FRIDA_RANGES)[0]
        assert cm.names_warnings(cm.NAMES_PROC_MAPS) == []


# -- chunked lldb reads ------------------------------------------------------------


class _Err:
    def __init__(self): self.ok = True
    def Success(self): return self.ok


class _Info:
    def __init__(self): self.base = self.end = 0; self.perm = "---"; self.name = None
    def IsReadable(self): return "r" in self.perm
    def IsWritable(self): return "w" in self.perm
    def IsExecutable(self): return "x" in self.perm
    def GetRegionBase(self): return self.base
    def GetRegionEnd(self): return self.end
    def GetName(self): return self.name


class _Regions:
    def __init__(self, regions): self.regions = regions
    def GetSize(self): return len(self.regions)

    def GetMemoryRegionAtIndex(self, i, info):
        info.base, info.end, info.perm, info.name = self.regions[i][:4]
        return True


class _Target:
    def GetNumModules(self): return 0


class _Proc:
    """Byte-addressable fake SBProcess: reads anywhere inside a region; pages
    listed in ``bad`` fail; records every request size."""

    def __init__(self, regions, bad=()):
        self.regions = regions  # (base, end, perm, name, fill_byte)
        self.bad = set(bad)
        self.requests = []

    def GetMemoryRegions(self): return _Regions(self.regions)
    def GetTarget(self): return _Target()
    def GetNumThreads(self): return 0

    def ReadMemory(self, addr, size, err):
        self.requests.append(size)
        out = bytearray()
        for page_addr in range(addr, addr + size):
            if page_addr // PAGE * PAGE in self.bad:
                break
            region = next((r for r in self.regions if r[0] <= page_addr < r[1]), None)
            if region is None:
                break
            out.append((page_addr - region[0]) % 251)
        if not out:
            err.ok = False
            return None
        return bytes(out)


_LLDB = types.SimpleNamespace(SBMemoryRegionInfo=_Info, SBError=_Err)


def _expected(base, start, end):
    return bytes((a - base) % 251 for a in range(start, end))


def _write(tmp_path, proc, **kw):
    bin_path = tmp_path / "t.bin"
    events = []
    with open(bin_path, "wb") as b, open(dd.maps_sidecar_path(bin_path), "w") as m:
        n = dd.lldb_write_regions(_LLDB, proc, b, m,
                                  on_event=lambda *e: events.append(e), **kw)
    regions = parse_maps_file(dd.maps_sidecar_path(bin_path))
    return n, bin_path, regions, events


class TestLldbChunkedRead:
    def test_large_region_streamed_in_bounded_chunks(self, tmp_path):
        base, size = 0x100000, 40 * PAGE + 123          # > several chunks
        proc = _Proc([(base, base + size, "rw-", None, 0)])
        n, bin_path, regions, events = _write(tmp_path, proc, chunk_size=8 * PAGE)
        assert n == 1 and [(r.start, r.end) for r in regions] == [(base, base + size)]
        assert bin_path.read_bytes() == _expected(base, base, base + size)
        assert max(proc.requests) <= 8 * PAGE           # memory stays bounded
        assert [e[0] for e in events] == ["begin"]

    def test_bad_pages_split_region_and_are_reported(self, tmp_path):
        base = 0x200000
        size = 32 * PAGE
        bad = {base + 9 * PAGE, base + 10 * PAGE, base + 20 * PAGE}
        proc = _Proc([(base, base + size, "rw-", "[heap]", 0)], bad=bad)
        n, bin_path, regions, events = _write(tmp_path, proc, chunk_size=8 * PAGE)
        assert [(r.start, r.end) for r in regions] == [
            (base, base + 9 * PAGE), (base + 11 * PAGE, base + 20 * PAGE),
            (base + 21 * PAGE, base + size)]
        assert all(r.path == "[heap]" and r.perm == "rw-p" for r in regions)
        skips = [e for e in events if e[0] == "skip"]
        assert skips == [("skip", base + 9 * PAGE, 2 * PAGE, "read_failed"),
                         ("skip", base + 20 * PAGE, PAGE, "read_failed")]
        expected = b"".join(_expected(base, r.start, r.end) for r in regions)
        assert bin_path.read_bytes() == expected
        plan, why = plan_regioned_raw(bin_path, dd.maps_sidecar_path(bin_path))
        assert why is None and [e.base_addr for e in plan.entries] == [
            r.start for r in regions]

    def test_skip_reasons_reported_not_silent(self, tmp_path):
        big = dd.LLDB_LARGE_READONLY_SIZE
        proc = _Proc([
            (0x10000, 0x11000, "---", None, 0),                  # guard page
            (0x20000, 0x20000 + 4 * PAGE, "rw-", None, 0),       # captured
            (0x100000000, 0x100000000 + big, "r-x", None, 0),    # shared cache
            (0x200000000, 0x200000000 + big + PAGE, "rw-", None, 0),  # over cap
        ])
        _n, _b, regions, events = _write(
            tmp_path, proc, max_size=big + PAGE, readonly_cap=big)
        assert [r.start for r in regions] == [0x20000]
        assert [e for e in events if e[0] == "skip"] == [
            ("skip", 0x10000, 0x1000, "unreadable"),
            ("skip", 0x100000000, big, "large_readonly"),
            ("skip", 0x200000000, big + PAGE, "size_cap")]

    def test_no_default_size_limit(self, tmp_path):
        """Writable regions above the historic 100 MB limit are read (lazily
        faked: only the request sizes are inspected)."""
        info = _Info()
        info.perm = "rw-"
        size = dd.LLDB_MAX_REGION_SIZE + PAGE
        assert dd.lldb_skip_reason(info, size) is None
        assert dd.lldb_skip_reason(info, size, readonly_cap=dd.LLDB_LARGE_READONLY_SIZE) is None
        info.perm = "r--"
        assert dd.lldb_skip_reason(info, size, readonly_cap=size) == "large_readonly"


class TestLldbScriptAndReconcile:
    def _exec_script(self, tmp_path, monkeypatch, proc, **kw):
        out = tmp_path / "snap.lldb_raw.bin"
        script = dd.build_lldb_dump_script(out, **kw)
        target = MagicMock()
        target.GetProcess.return_value = proc
        lldb = types.SimpleNamespace(SBMemoryRegionInfo=_Info, SBError=_Err,
                                     debugger=MagicMock())
        lldb.debugger.GetSelectedTarget.return_value = target
        monkeypatch.setitem(sys.modules, "lldb", lldb)
        exec(compile(script, "<lldb-script>", "exec"), {"__name__": "__lldb__"})
        return out

    def test_script_reports_skips_through_event_log(self, tmp_path, monkeypatch):
        base = 0x300000
        proc = _Proc([(0x1000, 0x2000, "---", None, 0),
                      (base, base + 4 * PAGE, "rw-", None, 0)], bad={base + PAGE})
        out = self._exec_script(tmp_path, monkeypatch, proc, chunk_size=2 * PAGE)
        report = cm.CaptureReport(ok=False, tool="lldb", output_path=str(out))
        dd.reconcile_lldb_output(out, report, timed_out=False, timeout=1)
        assert not dd.lldb_events_path(out).exists()
        assert [(s.base, s.size, s.reason) for s in report.skipped] == [
            (0x1000, 0x1000, "unreadable"), (base + PAGE, PAGE, "read_failed")]
        assert report.regions_captured == 2 and report.bytes_captured == 3 * PAGE
        assert report.names == cm.NAMES_LLDB

    def test_timeout_truncates_unlisted_tail_and_reports_region(self, tmp_path):
        out = tmp_path / "t.bin"
        out.write_bytes(b"A" * PAGE + b"B" * 100)   # 100 bytes of a torn region
        dd.maps_sidecar_path(out).write_text(dd.format_maps_line(0x1000, 0x2000, "rw-p") + "\n")
        dd.lldb_events_path(out).write_text(
            '{"event": "begin", "base": 4096, "size": 4096}\n'
            '{"event": "begin", "base": 65536, "size": 8192}\n{"event": "sk')
        report = cm.CaptureReport(ok=False, tool="lldb", output_path=str(out))
        dd.reconcile_lldb_output(out, report, timed_out=True, timeout=5)
        assert out.stat().st_size == PAGE
        assert [(s.base, s.size, s.reason) for s in report.skipped] == [
            (65536, 8192, "timeout")]
        assert report.error and "timed out" in report.warnings[0]
        plan, why = plan_regioned_raw(out, dd.maps_sidecar_path(out))
        assert why is None


# -- orchestrator backends -------------------------------------------------------


def _orch(tools):
    with patch("memdiver.core.dump_driver.shutil.which", return_value="/usr/bin/fake"):
        return dd.DumpOrchestrator(tools=tools)


class TestCaptureBackends:
    @patch("memdiver.core.dump_driver.subprocess.run")
    def test_memslicer_usb_by_name(self, mock_run, tmp_path):
        out = tmp_path / "app.msl"

        def fake(cmd, **_kw):
            out.write_bytes(b"MSL")
            return MagicMock(returncode=0, stdout="", stderr="")

        mock_run.side_effect = fake
        rep = _orch(["memslicer"]).capture(
            parse_target("com.android.settings", "usb:emulator-5556"), out, "memslicer")
        assert rep.ok and rep.bytes_captured == 3
        assert mock_run.call_args[0][0] == [
            "memslicer", "acquire", "com.android.settings", "-o", str(out),
            "-D", "emulator-5556"]
        assert cm.read_manifest(out)["target"]["device"] == "usb:emulator-5556"

    @patch("memdiver.core.dump_driver.subprocess.run")
    def test_memslicer_failure_carries_stderr(self, mock_run, tmp_path):
        mock_run.return_value = MagicMock(returncode=2, stdout="", stderr="no device\n")
        rep = _orch(["memslicer"]).capture(parse_target("1", "usb"), tmp_path / "x.msl",
                                           "memslicer")
        assert not rep.ok and rep.error == "no device"

    @patch("memdiver.core.dump_driver.subprocess.run")
    def test_lldb_rejects_devices_and_attaches_by_name(self, mock_run, tmp_path):
        orch = _orch(["lldb"])
        rep = orch.capture(parse_target("1", "usb"), tmp_path / "a.bin", "lldb")
        assert not rep.ok and "local processes only" in rep.error
        mock_run.assert_not_called()
        mock_run.return_value = MagicMock(returncode=0, stderr="")
        orch.capture(parse_target("python3"), tmp_path / "b.bin", "lldb")
        cmd = mock_run.call_args[0][0]
        assert cmd[:3] == ["lldb", "-n", "python3"]

    @patch("memdiver.core.dump_driver.subprocess.run",
           side_effect=dd.subprocess.TimeoutExpired("lldb", 1))
    def test_lldb_timeout_is_reported(self, _run, tmp_path):
        rep = _orch(["lldb"]).capture(parse_target("123"), tmp_path / "a.bin", "lldb",
                                      dd.CaptureOptions(timeout=1))
        assert not rep.ok and "timed out" in rep.error

    def test_lldb_options_reach_script(self, tmp_path):
        script = dd.build_lldb_dump_script(tmp_path / "a.bin", max_size=4096,
                                           readonly_cap=None, chunk_size=8192)
        assert "_event, 8192, None)" in script and "_m, 4096," in script

    def test_dump_keeps_last_report(self, tmp_path):
        orch = _orch(["memslicer"])
        with patch.object(orch, "_capture_memslicer") as backend:
            backend.side_effect = lambda t, o, report, opts: setattr(report, "ok", True)
            assert orch.dump(5, tmp_path / "a.msl", "memslicer") is True
        assert orch.last_report.target["pid"] == 5

    def _fridump_run(self, chunks):
        def fake(cmd, **_kw):
            tmp_dir = Path(cmd[cmd.index("-o") + 1])
            for name, data in chunks:
                (tmp_dir / name).write_bytes(data)
            return MagicMock(returncode=0)
        return fake

    @patch("memdiver.core.dump_driver.subprocess.run")
    def test_fridump_names_and_perms_from_target_maps(self, mock_run, tmp_path):
        mock_run.side_effect = self._fridump_run([
            ("0x10000_dump.data", b"A" * 0x2000), ("0x40000_dump.data", b"B" * 0x1000)])
        maps = ("10000-11000 r-xp 00000000 00:00 0 /system/lib64/libc.so\n"
                "11000-12000 rw-p 00000000 00:00 0 [anon:scudo:primary]\n"
                "40000-41000 rw-p 00000000 00:00 0 [stack]\n")
        spans = (fn.spans_from_maps_text(maps), cm.NAMES_PROC_MAPS)
        out = tmp_path / "f.dump"
        with patch("memdiver.core.dump_driver.collect_target_spans", return_value=spans):
            rep = _orch(["fridump"]).capture(parse_target("com.app", "usb"), out, "fridump")
        assert rep.ok and rep.names == cm.NAMES_PROC_MAPS and rep.regions_captured == 3
        regions = parse_maps_file(dd.maps_sidecar_path(out))
        assert [(r.start, r.perm, r.path) for r in regions] == [
            (0x10000, "r-xp", "/system/lib64/libc.so"),
            (0x11000, "rw-p", "[anon:scudo:primary]"), (0x40000, "rw-p", "[stack]")]
        cmd = mock_run.call_args[0][0]
        assert "-U" in cmd and "com.app" in cmd and "-a" not in cmd

    @patch("memdiver.core.dump_driver.subprocess.run")
    def test_fridump_without_names_marks_manifest(self, mock_run, tmp_path):
        mock_run.side_effect = self._fridump_run([("0x9000_dump.data", b"X" * 16)])
        out = tmp_path / "f.dump"
        with patch("memdiver.core.dump_driver.collect_target_spans",
                   return_value=([], cm.NAMES_NONE)):
            rep = _orch(["fridump"]).capture(parse_target("42"), out, "fridump")
        assert rep.ok and rep.names == cm.NAMES_NONE
        assert any("names unavailable" in w for w in cm.manifest_warnings(out))
        (region,) = parse_maps_file(dd.maps_sidecar_path(out))
        assert region.perm == dd.FRIDUMP_DEFAULT_PERM and region.path == ""
        assert mock_run.call_args[0][0][3:5] == ["-a", "42"]

    def test_fridump_remote_unsupported(self, tmp_path):
        rep = _orch(["fridump"]).capture(parse_target("1", "remote:h"), tmp_path / "f.dump",
                                         "fridump")
        assert not rep.ok and "memslicer" in rep.error

    def test_experiment_records_capture_reports(self, tmp_path):
        orch = _orch(["memslicer"])
        target = dd.TargetProcess(pid=9, key_hex="11" * 32, iv_hex="", process=MagicMock())

        def backend(t, o, report, opts):
            report.ok = True
            report.skip(0x1000, 0x1000, cm.REASON_UNREADABLE)

        with patch.object(orch, "start_target", return_value=target), \
                patch.object(orch, "kill_target"), \
                patch.object(orch, "_capture_memslicer", side_effect=backend), \
                patch("memdiver.core.dump_driver.time.sleep"):
            exp = orch.run_experiment(tmp_path / "t.py", 1, tmp_path, delay=0)
        reports = exp.metadata["runs"][0]["capture_reports"]
        assert reports["memslicer"]["skipped"][0]["reason"] == "unreadable"
        from memdiver.app.experiment_orchestration import _experiment_capture_warnings
        assert _experiment_capture_warnings(exp.metadata)[0].startswith(
            "run 1 [memslicer]: 1 region(s)")


# -- fridump naming helpers ---------------------------------------------------------


class TestFridumpNames:
    SPANS = [fn.NamedSpan(0x1000, 0x2000, "r-xp", "/lib/a.so"),
             fn.NamedSpan(0x3000, 0x5000, "rw-p", "[heap]")]

    def test_annotate_splits_at_mapping_boundaries_and_tiles(self):
        pieces = fn.annotate_chunk(0x1800, 0x3000, self.SPANS, "r--p")
        assert pieces == [(0x1800, 0x2000, "r-xp", "/lib/a.so"),
                          (0x2000, 0x3000, "r--p", ""),
                          (0x3000, 0x4800, "rw-p", "[heap]")]
        assert sum(e - s for s, e, _p, _n in pieces) == 0x3000

    def test_annotate_outside_and_empty(self):
        assert fn.annotate_chunk(0x9000, 0x10, self.SPANS, "r--p") == [
            (0x9000, 0x9010, "r--p", "")]
        assert fn.annotate_chunk(0x0, 0x10, [], "r--p") == [(0x0, 0x10, "r--p", "")]

    def test_frida_ranges(self):
        spans = fn.spans_from_frida_ranges([["0x3000", 4096, "rw-", ""],
                                            ["0x1000", 4096, "r-x", "/a"]])
        assert spans == [fn.NamedSpan(0x1000, 0x2000, "r-xp", "/a"),
                         fn.NamedSpan(0x3000, 0x4000, "rw-p", "")]

    def test_collect_prefers_local_proc_maps(self, monkeypatch):
        monkeypatch.setattr(fn, "read_local_proc_maps",
                            lambda pid: "1000-2000 rw-p 00000000 00:00 0 [heap]\n")
        monkeypatch.setattr(fn, "frida_target_spans",
                            lambda t: pytest.fail("frida must not be used"))
        spans, source = fn.collect_target_spans(parse_target("7"))
        assert source == cm.NAMES_PROC_MAPS and spans[0].name == "[heap]"

    def test_collect_frida_failure_is_none(self, monkeypatch):
        def boom(_t):
            raise RuntimeError("unable to attach")
        monkeypatch.setattr(fn, "frida_target_spans", boom)
        assert fn.collect_target_spans(parse_target("app", "usb")) == ([], cm.NAMES_NONE)

    def test_frida_session_maps_then_ranges(self, monkeypatch):
        exports = MagicMock()
        exports.read_maps.return_value = ""
        exports.ranges.return_value = [["0x1000", 4096, "rw-", "/x"]]
        session = MagicMock()
        session.create_script.return_value.exports_sync = exports
        device = MagicMock()
        device.attach.return_value = session
        monkeypatch.setattr(fn, "frida_device", lambda d: device)
        spans, source = fn.frida_target_spans(parse_target("com.app", "usb"))
        device.attach.assert_called_once_with("com.app")
        assert source == cm.NAMES_FRIDA_RANGES and spans[0].name == "/x"
        session.detach.assert_called_once()
        exports.read_maps.return_value = "1000-2000 rw-p 00000000 00:00 0 [stack]\n"
        assert fn.frida_target_spans(parse_target("5"))[1] == cm.NAMES_PROC_MAPS


# -- capability surfaces -----------------------------------------------------------


class TestCaptureCapability:
    def test_invalid_input(self, tmp_path):
        from memdiver.app.experiment_orchestration import capture_result
        from memdiver.core.service_errors import CapabilityError, ErrorCategory
        for kwargs in ({"tool": "gdb"}, {"device": "bogus"},
                       {"max_region_size": 0}, {"timeout": -1}):
            with pytest.raises(CapabilityError) as exc:
                capture_result("1", str(tmp_path / "a.msl"), **kwargs)
            assert exc.value.category is ErrorCategory.INVALID_INPUT

    def test_missing_backend(self, tmp_path):
        from memdiver.app.experiment_orchestration import capture_result
        from memdiver.core.service_errors import CapabilityError
        with patch("memdiver.core.dump_driver.shutil.which", return_value=None):
            with pytest.raises(CapabilityError) as exc:
                capture_result("1", str(tmp_path / "a.bin"), tool="lldb")
        assert exc.value.code == "missing_backend"

    def test_producer_threads_options(self, tmp_path):
        from memdiver.app.experiment_orchestration import capture_result
        seen = {}

        def fake_capture(self, target, output_path, tool, options=None):
            seen.update(target=target, tool=tool, options=options, out=output_path)
            return cm.CaptureReport(ok=True, tool=tool, output_path=str(output_path))

        with patch("memdiver.core.dump_driver.shutil.which", return_value="/x"), \
                patch.object(dd.DumpOrchestrator, "capture", fake_capture):
            out = capture_result("com.app", str(tmp_path / "sub" / "a.msl"),
                                 device="usb:emulator-5554", max_region_size=99,
                                 timeout=7)
        assert out["ok"] and seen["target"].device.device_id == "emulator-5554"
        assert seen["options"] == dd.CaptureOptions(max_region_size=99, timeout=7)
        assert (tmp_path / "sub").is_dir()

    def test_cli(self, tmp_path, capsys):
        from memdiver.cli.main import main
        report = cm.CaptureReport(ok=True, tool="lldb", output_path="x")
        report.skip(0x1000, 0x1000, "unreadable")
        with patch("memdiver.app.experiment_orchestration.capture_result",
                   return_value=report.to_dict()) as producer, \
                patch.object(sys, "argv", ["memdiver", "capture", "1234", "o.bin",
                                           "--tool", "lldb", "--device", "local",
                                           "--max-region-size", "4096",
                                           "--include-large-readonly"]):
            with pytest.raises(SystemExit) as exc:
                main()
        assert exc.value.code in (0, None)
        kwargs = producer.call_args.kwargs
        assert kwargs["max_region_size"] == 4096 and kwargs["include_large_readonly"]
        captured = capsys.readouterr()
        assert "WARNING" in captured.err and json.loads(captured.out)["ok"]

    def test_rest(self, tmp_path, monkeypatch):
        from fastapi.testclient import TestClient
        from memdiver.api.config import get_settings
        from memdiver.api.main import create_app
        monkeypatch.setenv("MEMDIVER_TASK_ROOT", str(tmp_path / "tasks"))
        monkeypatch.setenv("MEMDIVER_ORACLE_DIR", str(tmp_path / "oracles"))
        monkeypatch.setenv("MEMDIVER_PIPELINE_MAX_WORKERS", "1")
        get_settings.cache_clear()
        seen = {}

        def fake(**kwargs):
            seen.update(kwargs)
            return {"ok": True, "output_path": kwargs["output"], "skipped": []}

        try:
            with patch("memdiver.app.experiment_orchestration.capture_result", fake), \
                    TestClient(create_app()) as client:
                r = client.post("/api/experiment/capture",
                                json={"target": "com.app", "device": "usb"})
                assert r.status_code == 200, r.text
                assert "/captures/com.app_memslicer_" in seen["output"]
                assert seen["device"] == "usb"
                bad = client.post("/api/experiment/capture",
                                  json={"target": "1", "device": "bogus"})
                assert bad.status_code == 200  # fake producer: no validation
                real = client.post("/api/experiment/capture",
                                   json={"target": " "})
                assert real.status_code == 400
        finally:
            get_settings.cache_clear()

    def test_rest_invalid_device_is_400(self, tmp_path, monkeypatch):
        from fastapi.testclient import TestClient
        from memdiver.api.config import get_settings
        from memdiver.api.main import create_app
        monkeypatch.setenv("MEMDIVER_TASK_ROOT", str(tmp_path / "tasks"))
        monkeypatch.setenv("MEMDIVER_ORACLE_DIR", str(tmp_path / "oracles"))
        get_settings.cache_clear()
        try:
            with TestClient(create_app()) as client:
                r = client.post("/api/experiment/capture",
                                json={"target": "1", "device": "bogus",
                                      "output": str(tmp_path / "a.msl")})
            assert r.status_code == 400
        finally:
            get_settings.cache_clear()


class TestImportWarnsFromManifest:
    def _dump(self, tmp_path):
        out = tmp_path / "f.dump"
        out.write_bytes(b"\x00" * PAGE)
        dd.maps_sidecar_path(out).write_text(dd.format_maps_line(0x1000, 0x2000, "r--p") + "\n")
        rep = cm.CaptureReport(ok=True, tool="fridump", output_path=str(out),
                               names=cm.NAMES_NONE)
        rep.skip(0x8000, PAGE, "read_failed")
        cm.write_manifest(rep)
        return out

    def test_preview_notes(self, tmp_path):
        from memdiver.msl.import_preview import preview_import
        preview = preview_import(self._dump(tmp_path))
        assert preview.layout == "maps"
        assert any("names unavailable" in n for n in preview.notes)
        assert any("not captured" in n for n in preview.notes)

    def test_import_result_warnings(self, tmp_path):
        from memdiver.msl.importer import import_regioned_raw
        out = self._dump(tmp_path)
        result = import_regioned_raw(out, dd.maps_sidecar_path(out), tmp_path / "f.msl")
        assert any("names unavailable" in w for w in result.warnings)


def test_manifest_written_next_to_raw_dump(tmp_path):
    rep = cm.CaptureReport(ok=True, tool="lldb", output_path=str(tmp_path / "a.lldb_raw.bin"))
    dd._write_manifest_quietly(rep)
    assert (tmp_path / "a.lldb_raw.capture.json").is_file()
    assert parse_maps_text("") == []


if __name__ == "__main__":
    sys.exit(pytest.main([__file__, "-q"]))

"""Tests for core.dump_driver -- mock-based, no real dumps."""

import pytest
from unittest.mock import patch, MagicMock
from core.dump_driver import (
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

    @patch("core.dump_driver.shutil.which", return_value="/usr/bin/fake")
    def test_all_available_when_which_succeeds(self, mock_which):
        tools = DumpOrchestrator._detect_tools()
        # memslicer and lldb use shutil.which; fridump checks which first
        for t in tools:
            if t.name in ("memslicer", "lldb"):
                assert t.available is True

    @patch("core.dump_driver.shutil.which", return_value=None)
    def test_none_available_when_which_fails(self, mock_which):
        tools = DumpOrchestrator._detect_tools()
        for t in tools:
            assert t.available is False


class TestOrchestratorInit:
    @patch("core.dump_driver.shutil.which", return_value=None)
    def test_filter_by_name(self, mock_which):
        orch = DumpOrchestrator(tools=["lldb"])
        names = {t.name for t in orch._tools}
        assert names == {"lldb"}

    @patch("core.dump_driver.shutil.which", return_value=None)
    def test_no_tools_available(self, mock_which):
        orch = DumpOrchestrator()
        assert orch.available_tools == []

    @patch("core.dump_driver.shutil.which", return_value="/usr/bin/fake")
    def test_available_tools_property(self, mock_which):
        orch = DumpOrchestrator()
        available = orch.available_tools
        assert len(available) >= 2  # memslicer + lldb at minimum


class TestDump:
    @patch("core.dump_driver.shutil.which", return_value=None)
    def test_unknown_tool_returns_false(self, mock_which):
        orch = DumpOrchestrator()
        from pathlib import Path
        assert orch.dump(123, Path("/tmp/test.bin"), "nonexistent") is False

    @patch("core.dump_driver.subprocess.run")
    @patch("core.dump_driver.shutil.which", return_value="/usr/bin/fake")
    def test_memslicer_success(self, mock_which, mock_run, tmp_path):
        dump_path = tmp_path / "out.msl"
        dump_path.write_bytes(b"\x00" * 100)
        mock_run.return_value = MagicMock(returncode=0)
        orch = DumpOrchestrator(tools=["memslicer"])
        result = orch.dump(999, dump_path, "memslicer")
        assert result is True

    @patch("core.dump_driver.subprocess.run")
    @patch("core.dump_driver.shutil.which", return_value="/usr/bin/fake")
    def test_memslicer_failure(self, mock_which, mock_run, tmp_path):
        dump_path = tmp_path / "out.msl"
        mock_run.return_value = MagicMock(returncode=1)
        orch = DumpOrchestrator(tools=["memslicer"])
        result = orch.dump(999, dump_path, "memslicer")
        assert result is False

    @patch("core.dump_driver.shutil.which", return_value="/usr/bin/fake")
    def test_dump_exception_returns_false(self, mock_which, tmp_path):
        orch = DumpOrchestrator(tools=["memslicer"])
        with patch.object(orch, "_dump_memslicer", side_effect=OSError("fail")):
            result = orch.dump(999, tmp_path / "out.msl", "memslicer")
            assert result is False


class TestStartTargetTimeout:
    @patch("core.dump_driver.shutil.which", return_value=None)
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

    @patch("core.dump_driver.shutil.which", return_value=None)
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

    @patch("core.dump_driver.shutil.which", return_value=None)
    def test_eof_without_ready_raises_runtime_error(self, mock_which, tmp_path):
        """A target that exits before providing PID/KEY raises RuntimeError."""
        script = tmp_path / "exit.py"
        script.write_text("print('nothing useful')\n")
        orch = DumpOrchestrator()
        with pytest.raises(RuntimeError):
            orch.start_target(script, timeout=5.0)


class TestRunExperimentKeylog:
    def _orch_with_one_tool(self):
        with patch("core.dump_driver.shutil.which", return_value="/usr/bin/fake"):
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
                patch("core.dump_driver.time.sleep"):
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
                patch("core.dump_driver.time.sleep"):
            result = orch.run_experiment(
                tmp_path / "target.py", num_runs=1, output_dir=tmp_path,
                protocol="AES256", scenario="scn", delay=0.0,
            )
        run_dir = result.tool_dirs["memslicer"] / "memslicer_run_256_1"
        keylog = (run_dir / "keylog.csv").read_text()
        assert "AES256_KEY" in keylog
        assert ("00" * 16) in keylog  # zero IV fallback (16 bytes, not 32)


class TestKillTarget:
    @patch("core.dump_driver.os.kill")
    @patch("core.dump_driver.shutil.which", return_value=None)
    def test_kill_sends_sigterm(self, mock_which, mock_kill):
        proc = MagicMock()
        proc.wait.return_value = None
        target = TargetProcess(pid=42, key_hex="aa", iv_hex="bb", process=proc)
        orch = DumpOrchestrator()
        orch.kill_target(target)
        mock_kill.assert_called_once_with(42, 15)  # SIGTERM = 15

    @patch("core.dump_driver.os.kill")
    @patch("core.dump_driver.shutil.which", return_value=None)
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

    @patch("core.dump_driver.os.kill", side_effect=ProcessLookupError)
    @patch("core.dump_driver.shutil.which", return_value=None)
    def test_kill_already_dead(self, mock_which, mock_kill):
        proc = MagicMock()
        target = TargetProcess(pid=42, key_hex="aa", iv_hex="bb", process=proc)
        orch = DumpOrchestrator()
        # Should not raise
        orch.kill_target(target)

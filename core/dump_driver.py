"""Memory dump orchestrator -- spawn target, dump via available tools."""
import datetime
import logging
import os
import shlex
import shutil
import signal
import subprocess
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path

logger = logging.getLogger("memdiver.core.dump_driver")


@dataclass
class DumpToolInfo:
    """Information about a dump tool."""
    name: str
    available: bool
    extension: str  # "msl" or "dump"


@dataclass
class TargetProcess:
    """A running target process with known key material."""
    pid: int
    key_hex: str
    iv_hex: str
    process: subprocess.Popen


@dataclass
class ExperimentResult:
    """Result of a full experiment run."""
    output_dir: Path
    tool_dirs: dict  # tool_name -> directory with runs
    num_runs: int
    tools_used: list
    metadata: dict = field(default_factory=dict)


class DumpOrchestrator:
    """Manage target processes and dump tool execution."""

    def __init__(self, tools: list | None = None):
        self._all_tools = self._detect_tools()
        if tools:
            self._tools = [t for t in self._all_tools if t.name in tools]
        else:
            self._tools = [t for t in self._all_tools if t.available]

    @property
    def available_tools(self) -> list:
        return [t for t in self._tools if t.available]

    @staticmethod
    def _detect_tools() -> list:
        """Detect which dump tools are installed."""
        tools = [
            DumpToolInfo("memslicer", shutil.which("memslicer") is not None, "msl"),
            DumpToolInfo("lldb", shutil.which("lldb") is not None, "dump"),
        ]
        fridump_ok = shutil.which("fridump") is not None
        if not fridump_ok:
            try:
                import importlib
                importlib.import_module("fridump")
                fridump_ok = True
            except ImportError:
                pass
        tools.append(DumpToolInfo("fridump", fridump_ok, "dump"))
        return tools

    def start_target(self, script_path: Path, timeout: float = 10.0) -> TargetProcess:
        """Start target process; it must print MEMDIVER_PID/KEY/IV/READY lines."""
        proc = subprocess.Popen(
            [sys.executable, str(script_path)],
            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True,
        )
        pid, key_hex, iv_hex = None, None, None
        deadline = time.monotonic() + timeout
        for line in proc.stdout:
            line = line.strip()
            if line.startswith("MEMDIVER_PID="):
                pid = int(line.split("=", 1)[1])
            elif line.startswith("MEMDIVER_KEY="):
                key_hex = line.split("=", 1)[1]
            elif line.startswith("MEMDIVER_IV="):
                iv_hex = line.split("=", 1)[1]
            elif line.startswith("MEMDIVER_READY="):
                break
            if time.monotonic() > deadline:
                proc.kill()
                raise TimeoutError("Target process did not become ready")
        if pid is None or key_hex is None:
            proc.kill()
            raise RuntimeError("Target process did not provide PID/KEY")
        return TargetProcess(pid=pid, key_hex=key_hex, iv_hex=iv_hex or "", process=proc)

    def dump(self, pid: int, output_path: Path, tool: str) -> bool:
        """Dump process memory using the specified tool."""
        dispatch = {"memslicer": self._dump_memslicer, "lldb": self._dump_lldb,
                     "fridump": self._dump_fridump}
        fn = dispatch.get(tool)
        if fn is None:
            logger.error("Unknown tool: %s", tool)
            return False
        try:
            return fn(pid, output_path)
        except Exception as exc:
            logger.error("Dump failed (%s): %s", tool, exc)
            return False

    def kill_target(self, target: TargetProcess) -> None:
        """Kill a target process (SIGTERM then SIGKILL)."""
        try:
            os.kill(target.pid, signal.SIGTERM)
            target.process.wait(timeout=5)
        except (ProcessLookupError, subprocess.TimeoutExpired):
            try:
                os.kill(target.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass

    def run_experiment(
        self, script_path: Path, num_runs: int, output_dir: Path,
        protocol: str = "AES256", scenario: str = "aes_key_in_memory",
        delay: float = 1.0,
    ) -> ExperimentResult:
        """Run N iterations: start process, dump with each tool, kill."""
        base_dir = output_dir / protocol / scenario
        tool_dirs = {i.name: base_dir / i.name for i in self.available_tools}
        metadata = {"script": str(script_path), "num_runs": num_runs,
                     "tools": [t.name for t in self.available_tools], "runs": []}
        for run_idx in range(1, num_runs + 1):
            target = self.start_target(script_path)
            time.sleep(delay)
            run_meta = {"run": run_idx, "key_hex": target.key_hex,
                        "iv_hex": target.iv_hex, "tool_results": {}}
            for info in self.available_tools:
                run_dir = tool_dirs[info.name] / f"{info.name}_run_256_{run_idx}"
                run_dir.mkdir(parents=True, exist_ok=True)
                ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S_%f")
                dump_path = run_dir / f"{ts}_pre_snapshot.{info.extension}"
                ok = self.dump(target.pid, dump_path, info.name)
                run_meta["tool_results"][info.name] = ok
                if ok:
                    keylog = f"line\nAES256_KEY {'00' * 32} {target.key_hex}\n"
                    (run_dir / "keylog.csv").write_text(keylog)
                    logger.info("Run %d/%d [%s]: OK", run_idx, num_runs, info.name)
                else:
                    logger.warning("Run %d/%d [%s]: FAIL", run_idx, num_runs, info.name)
            self.kill_target(target)
            metadata["runs"].append(run_meta)
        return ExperimentResult(
            output_dir=output_dir, tool_dirs=tool_dirs, num_runs=num_runs,
            tools_used=[t.name for t in self.available_tools], metadata=metadata)

    @staticmethod
    def _dump_memslicer(pid: int, output_path: Path) -> bool:
        r = subprocess.run(["memslicer", "capture", str(pid), str(output_path)],
                           capture_output=True, timeout=30)
        return r.returncode == 0 and output_path.exists()

    @staticmethod
    def _dump_lldb(pid: int, output_path: Path) -> bool:
        script = (
            'import lldb; t=lldb.debugger.GetSelectedTarget(); p=t.GetProcess()\n'
            f'f=open({shlex.quote(str(output_path))},"wb")\n'
            'for i in range(p.GetNumMemoryRegions()):\n'
            ' info=lldb.SBMemoryRegionInfo(); p.GetMemoryRegionAtIndex(i,info)\n'
            ' if info.IsReadable():\n'
            '  sz=info.GetRegionEnd()-info.GetRegionBase()\n'
            '  if 0<sz<100*1024*1024:\n'
            '   err=lldb.SBError(); d=p.ReadMemory(info.GetRegionBase(),sz,err)\n'
            '   if err.Success() and d: f.write(d)\n'
            'f.close()\n')
        result = subprocess.run(["lldb", "-p", str(pid), "-o", f"script {script}",
                                 "-o", "detach", "-o", "quit"],
                                capture_output=True, text=True, timeout=60)
        if result.returncode != 0:
            logger.error("lldb subprocess failed: %s", result.stderr)
            return False
        return output_path.exists() and output_path.stat().st_size > 0

    @staticmethod
    def _dump_fridump(pid: int, output_path: Path) -> bool:
        tmp_dir = output_path.parent / "_fridump_tmp"
        tmp_dir.mkdir(exist_ok=True)
        r = subprocess.run([sys.executable, "-m", "fridump", "-a", str(pid),
                            "-o", str(tmp_dir), "-r"],
                           capture_output=True, timeout=60)
        if r.returncode != 0:
            return False
        data_files = sorted(tmp_dir.glob("*.data"))
        if not data_files:
            return False
        with open(output_path, "wb") as out:
            for f in data_files:
                out.write(f.read_bytes())
        shutil.rmtree(tmp_dir, ignore_errors=True)
        return output_path.exists()

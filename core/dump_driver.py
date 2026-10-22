"""Memory dump orchestrator -- spawn target, dump via available tools."""
import datetime
import inspect
import json
import logging
import os
import re
import select
import shlex
import shutil
import signal
import subprocess
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path

from memdiver.core.capture_manifest import (NAMES_LLDB, NAMES_NONE, CaptureReport,
                                            write_manifest)
from memdiver.core.capture_target import (CaptureTarget, UnsupportedCaptureTarget,
                                          fridump_device_args, memslicer_acquire_args,
                                          require_local)
from memdiver.core.fridump_names import annotate_chunk, collect_target_spans

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
        self.last_report: "CaptureReport | None" = None
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
        stdout_fd = proc.stdout.fileno()
        # Read the raw fd via select() so the deadline still fires when the
        # target opens but never emits a newline. Iterating ``for line in
        # proc.stdout`` (or readline) blocks indefinitely on such a target.
        # We read bytes directly from the fd and split lines ourselves to
        # avoid the TextIOWrapper buffering data that select() can't see.
        buf = ""
        ready = False

        def _consume(text_line: str) -> bool:
            nonlocal pid, key_hex, iv_hex
            text_line = text_line.strip()
            if text_line.startswith("MEMDIVER_PID="):
                pid = int(text_line.split("=", 1)[1])
            elif text_line.startswith("MEMDIVER_KEY="):
                key_hex = text_line.split("=", 1)[1]
            elif text_line.startswith("MEMDIVER_IV="):
                iv_hex = text_line.split("=", 1)[1]
            elif text_line.startswith("MEMDIVER_READY="):
                return True
            return False

        while not ready:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                proc.kill()
                raise TimeoutError("Target process did not become ready")
            readable, _, _ = select.select([stdout_fd], [], [], remaining)
            if not readable:
                # Timed out waiting for output; loop re-checks the deadline.
                continue
            chunk = os.read(stdout_fd, 65536)
            if not chunk:
                # EOF: target exited/closed stdout without becoming ready.
                break
            buf += chunk.decode("utf-8", "replace")
            while "\n" in buf:
                line, buf = buf.split("\n", 1)
                if _consume(line):
                    ready = True
                    break
        if pid is None or key_hex is None:
            proc.kill()
            raise RuntimeError("Target process did not provide PID/KEY")
        return TargetProcess(pid=pid, key_hex=key_hex, iv_hex=iv_hex or "", process=proc)

    def dump(self, pid: int, output_path: Path, tool: str) -> bool:
        """Dump process memory using the specified tool (local pid; bool result).

        Thin wrapper over :meth:`capture`; the full :class:`CaptureReport`
        (skipped regions, names source, warnings) is kept in ``last_report``.
        """
        self.last_report = None
        if tool not in _BACKENDS:
            logger.error("Unknown tool: %s", tool)
            return False
        self.last_report = self.capture(CaptureTarget(pid=pid), output_path, tool)
        return self.last_report.ok

    def capture(self, target: CaptureTarget, output_path: Path, tool: str,
                options: "CaptureOptions | None" = None) -> CaptureReport:
        """Capture *target* with *tool*; never raises, never drops a region silently.

        Writes the dump, its ``.maps`` sidecar (raw backends) and a
        ``.capture.json`` manifest listing every skipped region.
        """
        output_path = Path(output_path)
        report = CaptureReport(ok=False, tool=tool, output_path=str(output_path),
                               target=target.to_dict())
        backend = _BACKENDS.get(tool)
        if backend is None:
            report.error = f"unknown dump tool: {tool}"
            return report
        try:
            getattr(self, backend)(target, output_path, report,
                                   options or CaptureOptions())
        except UnsupportedCaptureTarget as exc:
            report.ok, report.error = False, str(exc)
        except Exception as exc:  # noqa: BLE001 - surface every backend failure
            logger.error("Dump failed (%s): %s", tool, exc)
            report.ok, report.error = False, str(exc)
        _write_manifest_quietly(report)
        return report

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
                report = getattr(self, "last_report", None)
                if report is not None:
                    run_meta.setdefault("capture_reports", {})[info.name] = (
                        report.to_dict())
                if ok:
                    # Derive the keylog label from the experiment protocol and
                    # use the target's IV as the identifier when one is known
                    # (falls back to all-zero IV for IV-less protocols), rather
                    # than hardcoding AES256 / a zero identifier.
                    label = f"{protocol}_KEY"
                    identifier = target.iv_hex or ("00" * 16)
                    keylog = f"line\n{label} {identifier} {target.key_hex}\n"
                    (run_dir / "keylog.csv").write_text(keylog)
                    logger.info("Run %d/%d [%s]: OK", run_idx, num_runs, info.name)
                else:
                    logger.warning("Run %d/%d [%s]: FAIL", run_idx, num_runs, info.name)
            self.kill_target(target)
            metadata["runs"].append(run_meta)
        return ExperimentResult(
            output_dir=output_dir, tool_dirs=tool_dirs, num_runs=num_runs,
            tools_used=[t.name for t in self.available_tools], metadata=metadata)

    # -- backends: fill ``report`` in place ------------------------------------

    @staticmethod
    def _capture_memslicer(target: CaptureTarget, output_path: Path,
                           report: CaptureReport, options: "CaptureOptions") -> None:
        """``memslicer acquire <pid|name> -o <out> [-U | -D id | -R host:port]``."""
        cmd = memslicer_acquire_args(target, str(output_path), options.max_region_size)
        r = subprocess.run(cmd, capture_output=True, text=True,
                           timeout=options.timeout or MEMSLICER_TIMEOUT)
        report.ok = r.returncode == 0 and output_path.exists()
        if report.ok:
            report.bytes_captured = output_path.stat().st_size
            if options.max_region_size:
                report.warnings.append(
                    f"memslicer skipped regions larger than {options.max_region_size} "
                    "bytes (recorded in the .msl)")
        else:
            report.error = _tail(r.stderr) or _tail(r.stdout) or (
                f"memslicer exited with {r.returncode}")

    @staticmethod
    def _capture_lldb(target: CaptureTarget, output_path: Path,
                      report: CaptureReport, options: "CaptureOptions") -> None:
        """Chunked lldb capture into ``output_path`` + ``.maps`` sidecar."""
        require_local(target.device, "lldb")
        attach = (["-p", str(target.pid)] if target.pid is not None
                  else ["-n", str(target.name)])
        script_path = output_path.with_suffix(".lldb_script.py")
        script_path.write_text(build_lldb_dump_script(
            output_path, max_size=options.max_region_size,
            readonly_cap=None if options.include_large_readonly
            else LLDB_LARGE_READONLY_SIZE))
        timeout = options.timeout or LLDB_TIMEOUT
        timed_out, result = False, None
        try:
            result = subprocess.run(
                ["lldb", *attach,
                 "-o", f"script exec(open({str(script_path)!r}).read())",
                 "-o", "detach", "-o", "quit"],
                capture_output=True, text=True, timeout=timeout)
        except subprocess.TimeoutExpired:
            timed_out = True
        finally:
            script_path.unlink(missing_ok=True)
        reconcile_lldb_output(output_path, report, timed_out, timeout)
        if result is not None and result.returncode != 0:
            logger.error("lldb subprocess failed: %s", result.stderr)
            report.ok, report.error = False, _tail(result.stderr) or "lldb failed"
            return
        report.ok = (not timed_out and output_path.exists()
                     and output_path.stat().st_size > 0)

    @staticmethod
    def _capture_fridump(target: CaptureTarget, output_path: Path,
                         report: CaptureReport, options: "CaptureOptions") -> None:
        """fridump chunks -> address-ordered bin + named ``.maps`` (best effort)."""
        device_args = fridump_device_args(target.device)
        process_args = (["-a", str(target.pid)] if target.pid is not None
                        else [str(target.name)])
        if options.max_region_size:
            report.warnings.append("fridump has no region size cap; "
                                   "max_region_size ignored")
        tmp_dir = output_path.parent / "_fridump_tmp"
        tmp_dir.mkdir(exist_ok=True)
        try:
            r = subprocess.run([sys.executable, "-m", "fridump", *device_args,
                                *process_args, "-o", str(tmp_dir), "-r"],
                               capture_output=True, timeout=options.timeout
                               or FRIDUMP_TIMEOUT)
            data_files = list(tmp_dir.glob("*.data"))
            if r.returncode != 0 or not data_files:
                report.error = f"fridump failed (exit {r.returncode}, " \
                               f"{len(data_files)} chunks)"
                return
            spans, names = collect_target_spans(target)
            assemble_fridump_output(data_files, output_path, spans=spans or None,
                                    report=report)
            report.names = names if spans else NAMES_NONE
        finally:
            shutil.rmtree(tmp_dir, ignore_errors=True)
        report.ok = output_path.exists()

    # -- back-compat bool wrappers (pid only, local) --------------------------

    @staticmethod
    def _dump_memslicer(pid: int, output_path: Path) -> bool:
        return _run_backend("_capture_memslicer", pid, output_path)

    @staticmethod
    def _dump_lldb(pid: int, output_path: Path) -> bool:
        """Dump readable regions via lldb into ``output_path`` plus a ``.maps`` sidecar."""
        return _run_backend("_capture_lldb", pid, output_path)

    @staticmethod
    def _dump_fridump(pid: int, output_path: Path) -> bool:
        """Dump via fridump, concatenating chunks in address order with a ``.maps`` sidecar."""
        return _run_backend("_capture_fridump", pid, output_path)


@dataclass(frozen=True)
class CaptureOptions:
    """Per-capture knobs shared by all backends.

    ``max_region_size``: explicit user cap -- regions at or above it are
    skipped *and reported* (``None`` = no cap). ``include_large_readonly``:
    lldb also captures non-writable regions >= ``LLDB_LARGE_READONLY_SIZE``
    (macOS dyld shared cache: several GB per process). ``timeout``: seconds
    for the backend subprocess (``None`` = per-backend default).
    """

    max_region_size: "int | None" = None
    include_large_readonly: bool = False
    timeout: "float | None" = None


#: tool name -> DumpOrchestrator backend method.
_BACKENDS = {"memslicer": "_capture_memslicer", "lldb": "_capture_lldb",
             "fridump": "_capture_fridump"}

MEMSLICER_TIMEOUT = 300.0
LLDB_TIMEOUT = 600.0
FRIDUMP_TIMEOUT = 300.0


def _run_backend(method: str, pid: int, output_path: Path) -> bool:
    report = CaptureReport(ok=False, tool=method, output_path=str(output_path))
    getattr(DumpOrchestrator, method)(CaptureTarget(pid=pid), Path(output_path),
                                      report, CaptureOptions())
    return report.ok


def _tail(text, limit: int = 500) -> str:
    """Last *limit* chars of subprocess output ('' for non-text, e.g. mocks)."""
    return text.strip()[-limit:] if isinstance(text, str) else ""


def _write_manifest_quietly(report: CaptureReport) -> None:
    if not Path(report.output_path).parent.is_dir():
        return
    try:
        write_manifest(report)
    except OSError as exc:
        report.warnings.append(f"capture manifest not written: {exc}")


# ---------------------------------------------------------------------------
# Layout-preserving helpers (pure / side-effect-light, unit tested)
# ---------------------------------------------------------------------------

#: Historic lldb size limit (regions at or above it used to be dropped
#: silently). It is now only the default threshold for *non-writable*
#: regions (:data:`LLDB_LARGE_READONLY_SIZE`); writable regions of any size
#: are captured in bounded chunks, and every skip is reported.
LLDB_MAX_REGION_SIZE = 100 * 1024 * 1024

#: Non-writable regions at or above this size (the multi-GB macOS dyld shared
#: cache) are skipped *and reported* unless ``include_large_readonly`` is set.
LLDB_LARGE_READONLY_SIZE = LLDB_MAX_REGION_SIZE

#: Bytes per ``ReadMemory`` call: bounds lldb's and the script's memory use.
LLDB_READ_CHUNK = 8 * 1024 * 1024

#: Granularity used to isolate unreadable pages inside a readable region.
LLDB_PAGE_SIZE = 4096

_FRIDUMP_ADDRESS_RE = re.compile(r"^(?:0x)?([0-9a-fA-F]+)(?:[_.]|$)")


def maps_sidecar_path(bin_path: Path) -> Path:
    """Return the ``.maps`` sidecar path for a raw dump (``foo.bin`` -> ``foo.maps``)."""
    return Path(bin_path).with_suffix(".maps")


def format_maps_line(start: int, end: int, perm: str, path: "str | None" = None) -> str:
    """Format one ``/proc/<pid>/maps`` line (no trailing newline)."""
    line = f"{start:x}-{end:x} {perm} 00000000 00:00 0"
    return f"{line} {path}" if path else line


def maps_perm(readable: bool, writable: bool, executable: bool) -> str:
    """Build a 4-char private ``/proc/<pid>/maps`` perm string."""
    r = "r" if readable else "-"
    w = "w" if writable else "-"
    x = "x" if executable else "-"
    return f"{r}{w}{x}p"


#: fridump records no protections; every dumped chunk was readable, so the
#: honest, conservative description is read-only private.
FRIDUMP_DEFAULT_PERM = maps_perm(readable=True, writable=False, executable=False)


def lldb_region_perm(info) -> str:
    """Build a 4-char perm string from an ``SBMemoryRegionInfo``-like object."""
    return maps_perm(info.IsReadable(), info.IsWritable(), info.IsExecutable())


def lldb_region_name(info) -> "str | None":
    """Return the region's mapped name, or None when lldb reports none."""
    getter = getattr(info, "GetName", None)
    name = getter() if getter is not None else None
    return name or None


#: ``lldb.LLDB_INVALID_ADDRESS`` (sections that are not loaded report this).
LLDB_INVALID_ADDRESS = 0xFFFFFFFFFFFFFFFF


def lldb_section_intervals(target, section, path, out) -> None:
    """Append ``(start, end, path)`` for a loaded ``SBSection`` and its subsections."""
    start = section.GetLoadAddress(target)
    size = section.GetByteSize()
    if size > 0 and start != LLDB_INVALID_ADDRESS:
        out.append((start, start + size, path))
    for i in range(section.GetNumSubSections()):
        lldb_section_intervals(target, section.GetSubSectionAtIndex(i), path, out)


def lldb_module_intervals(target) -> list:
    """Return ``(start, end, module_path)`` for every loaded section of every module."""
    intervals = []
    for m in range(target.GetNumModules()):
        module = target.GetModuleAtIndex(m)
        path = module.GetFileSpec().fullpath
        if not path:
            continue
        for s in range(module.GetNumSections()):
            lldb_section_intervals(target, module.GetSectionAtIndex(s), path, intervals)
    return intervals


def lldb_stack_pointers(process) -> list:
    """Return ``(sp, name)`` per thread: ``[stack]`` for the first, ``[stack:<tid>]`` after."""
    stacks = []
    for i in range(process.GetNumThreads()):
        thread = process.GetThreadAtIndex(i)
        sp = thread.GetFrameAtIndex(0).GetSP()
        if not sp or sp == LLDB_INVALID_ADDRESS:
            continue
        name = "[stack]" if not stacks else f"[stack:{thread.GetThreadID()}]"
        stacks.append((sp, name))
    return stacks


def lldb_module_for_range(base: int, end: int, intervals) -> "str | None":
    """Module path covering ``base``, else the one with the largest overlap."""
    best_path, best_overlap = None, 0
    for lo, hi, path in intervals:
        if lo <= base < hi:
            return path
        overlap = min(hi, end) - max(lo, base)
        if overlap > best_overlap:
            best_path, best_overlap = path, overlap
    return best_path


def lldb_region_label(info, base: int, end: int, intervals, stacks) -> "str | None":
    """Name a region: lldb's own name, else a thread stack, else a module path."""
    name = lldb_region_name(info)
    if name:
        return name
    for sp, stack_name in stacks:
        if base <= sp < end:
            return stack_name
    return lldb_module_for_range(base, end, intervals)


def lldb_skip_reason(info, size, max_size=None, readonly_cap=None):
    """Why a region is not read at all, or None to read it."""
    if not info.IsReadable():
        return "unreadable"
    if max_size is not None and size >= max_size:
        return "size_cap"
    if readonly_cap is not None and not info.IsWritable() and size >= readonly_cap:
        return "large_readonly"
    return None


def lldb_read_region(lldb, process, base, size, bin_file, on_event,
                     chunk_size=LLDB_READ_CHUNK, page_size=LLDB_PAGE_SIZE):
    """Stream ``[base, base+size)`` to ``bin_file`` in bounded chunks.

    Returns the contiguous ``(start, end)`` runs actually written. A failed
    chunk is retried page by page so a guard page only costs its own page;
    every unread span is reported once via ``on_event("skip", ...)``
    (adjacent failures coalesced).
    """
    end = base + size
    runs, pending = [], []          # pending: [start, end, reason] failure
    run_start = pos = base
    step = chunk_size

    def flush_failure():
        if pending:
            on_event("skip", pending[0], pending[1] - pending[0], pending[2])
            del pending[:]

    while pos < end:
        want = min(step, end - pos)
        err = lldb.SBError()
        data = process.ReadMemory(pos, want, err)
        got = min(len(data), want) if (err.Success() and data) else 0
        if got:
            bin_file.write(data[:got])
            pos += got
        if got == want:
            step = chunk_size
            continue
        if step > page_size:              # isolate the bad page(s)
            step = page_size
            continue
        if pos > run_start:
            runs.append((run_start, pos))
        fail_end = min(end, (pos // page_size + 1) * page_size)
        reason = "short_read" if got else "read_failed"
        if pending and pending[1] == pos and pending[2] == reason:
            pending[1] = fail_end
        else:
            flush_failure()
            pending[:] = [pos, fail_end, reason]
        pos = run_start = fail_end
    flush_failure()
    if pos > run_start:
        runs.append((run_start, pos))
    return runs


def lldb_write_regions(lldb, process, bin_file, maps_file, max_size=None,
                       on_event=None, chunk_size=LLDB_READ_CHUNK, readonly_cap=None):
    """Write readable regions of ``process`` to ``bin_file`` and matching maps lines.

    Only bytes actually returned by ``ReadMemory`` are written; each maps line
    covers exactly one written run, so the sum of map sizes equals the bin
    size. Regions of any size are streamed in ``chunk_size`` reads. Regions
    lldb leaves unnamed (macOS) are named from module sections and thread
    stack pointers. Every region (or span) not written is reported through
    ``on_event("skip", base, size, reason)``; ``on_event("begin", base, size)``
    precedes each read so a timed-out capture can name the region it lost.
    ``max_size`` / ``readonly_cap``: see :func:`lldb_skip_reason`. Returns the
    number of maps lines written.
    """
    def _ignore(*_args):
        return None

    log = on_event or _ignore
    written = 0
    intervals = lldb_module_intervals(process.GetTarget())
    stacks = lldb_stack_pointers(process)
    regions = process.GetMemoryRegions()  # SBMemoryRegionInfoList
    for i in range(regions.GetSize()):
        info = lldb.SBMemoryRegionInfo()
        if not regions.GetMemoryRegionAtIndex(i, info):
            continue
        base = info.GetRegionBase()
        size = info.GetRegionEnd() - base
        if size <= 0:
            continue
        reason = lldb_skip_reason(info, size, max_size, readonly_cap)
        if reason:
            log("skip", base, size, reason)
            continue
        log("begin", base, size)
        runs = lldb_read_region(lldb, process, base, size, bin_file, log, chunk_size)
        if not runs:
            continue
        bin_file.flush()   # bin bytes land before the maps line that describes them
        label = lldb_region_label(info, base, base + size, intervals, stacks)
        perm = lldb_region_perm(info)
        for start, end in runs:
            maps_file.write(format_maps_line(start, end, perm, label) + "\n")
        maps_file.flush()
        written += len(runs)
    return written


_LLDB_SCRIPT_HELPERS = (format_maps_line, maps_perm, lldb_region_perm,
                        lldb_region_name, lldb_section_intervals, lldb_module_intervals,
                        lldb_stack_pointers, lldb_module_for_range, lldb_region_label,
                        lldb_skip_reason, lldb_read_region, lldb_write_regions)


def lldb_events_path(output_path: Path) -> Path:
    """JSON-lines event log the lldb script writes beside the bin."""
    return Path(output_path).with_suffix(".lldb_events.jsonl")


def build_lldb_dump_script(output_path: Path, max_size=None,
                           readonly_cap=LLDB_LARGE_READONLY_SIZE,
                           chunk_size=LLDB_READ_CHUNK) -> str:
    """Return a self-contained Python script for lldb's embedded interpreter.

    The helpers above are inlined via their source so the script does not
    need ``memdiver`` importable inside lldb's Python. Skip/begin events are
    flushed line by line to :func:`lldb_events_path` so they survive a kill.
    """
    helpers = "\n\n".join(inspect.getsource(fn) for fn in _LLDB_SCRIPT_HELPERS)
    bin_path = str(output_path)
    maps_path = str(maps_sidecar_path(output_path))
    events_path = str(lldb_events_path(output_path))
    return (
        f"LLDB_MAX_REGION_SIZE = {LLDB_MAX_REGION_SIZE}\n"
        f"LLDB_READ_CHUNK = {LLDB_READ_CHUNK}\n"
        f"LLDB_PAGE_SIZE = {LLDB_PAGE_SIZE}\n"
        f"LLDB_INVALID_ADDRESS = {LLDB_INVALID_ADDRESS}\n\n{helpers}\n\n"
        "import json\n"
        "import lldb\n"
        "_p = lldb.debugger.GetSelectedTarget().GetProcess()\n"
        f"with open({bin_path!r}, 'wb') as _b, open({maps_path!r}, 'w') as _m, "
        f"open({events_path!r}, 'w') as _k:\n"
        "    def _event(kind, base, size, reason=None):\n"
        "        _k.write(json.dumps({'event': kind, 'base': base, 'size': size,\n"
        "                             'reason': reason}) + '\\n')\n"
        "        _k.flush()\n"
        f"    lldb_write_regions(lldb, _p, _b, _m, {max_size!r}, _event, "
        f"{int(chunk_size)}, {readonly_cap!r})\n")


def read_lldb_events(path: Path) -> list:
    """Parse the lldb event log (tolerates a torn last line after a kill)."""
    events = []
    try:
        lines = Path(path).read_text(encoding="utf-8").splitlines()
    except OSError:
        return events
    for line in lines:
        try:
            events.append(json.loads(line))
        except ValueError:
            continue
    return events


def reconcile_lldb_output(output_path: Path, report: CaptureReport,
                          timed_out: bool, timeout: float) -> None:
    """Make bin + maps consistent after lldb exits (or is killed) and fill *report*.

    The script writes bin bytes before the maps line describing them, so a
    kill can only leave *unlisted trailing* bytes: they are truncated so the
    sidecar still describes the bin exactly. Skip events become
    ``report.skipped``; on timeout the region being read is reported too.
    """
    from memdiver.core.proc_maps_parser import parse_maps_file

    events_path = lldb_events_path(output_path)
    events = read_lldb_events(events_path)
    events_path.unlink(missing_ok=True)
    for ev in events:
        if ev.get("event") == "skip":
            report.skip(ev["base"], ev["size"], ev.get("reason") or "unknown")
    report.names = NAMES_LLDB
    maps_path = maps_sidecar_path(output_path)
    if not (output_path.exists() and maps_path.exists()):
        if output_path.exists():
            report.bytes_captured = output_path.stat().st_size
        if timed_out:
            _report_lldb_timeout(report, events, [], timeout)
        return
    regions = parse_maps_file(maps_path)
    listed = sum(r.size for r in regions)
    if output_path.stat().st_size > listed:
        with open(output_path, "r+b") as fh:
            fh.truncate(listed)
    report.maps_path = str(maps_path)
    report.regions_captured = len(regions)
    report.bytes_captured = listed
    if timed_out:
        _report_lldb_timeout(report, events, regions, timeout)


def _report_lldb_timeout(report: CaptureReport, events: list, regions, timeout) -> None:
    listed_end = regions[-1].end if regions else 0
    begins = [ev for ev in events if ev.get("event") == "begin"]
    if begins and begins[-1]["base"] + begins[-1]["size"] > listed_end:
        last = begins[-1]
        start = max(last["base"], listed_end)
        report.skip(start, last["base"] + last["size"] - start, "timeout")
    report.error = f"lldb timed out after {timeout:g}s"
    report.warnings.append(
        f"lldb timed out after {timeout:g}s: capture stopped at {listed_end:#x}; "
        "later regions were not captured (raise the timeout)")


def fridump_base_address(name: str) -> "int | None":
    """Parse the base address from a fridump chunk name (e.g. ``0x7f12a000_dump.data``).

    Accepts hex with or without ``0x`` and with any zero padding. Returns
    None when the name carries no parsable address.
    """
    match = _FRIDUMP_ADDRESS_RE.match(Path(name).name)
    return int(match.group(1), 16) if match else None


def order_fridump_files(files) -> "tuple[list, list | None]":
    """Order fridump chunks numerically by base address.

    Returns ``(ordered_files, bases)``. When any name lacks an address,
    falls back to lexicographic order and ``bases`` is None (no maps).
    """
    files = list(files)
    bases = [fridump_base_address(f.name) for f in files]
    if any(b is None for b in bases):
        return sorted(files), None
    pairs = sorted(zip(bases, files), key=lambda bf: (bf[0], bf[1].name))
    return [f for _, f in pairs], [b for b, _ in pairs]


def assemble_fridump_output(data_files, output_path: Path, spans=None,
                            report: "CaptureReport | None" = None) -> bool:
    """Concatenate fridump chunks into ``output_path`` and write a ``.maps`` sidecar.

    ``spans`` (sorted :class:`core.fridump_names.NamedSpan`) gives each chunk
    its real perms/names, split at mapping boundaries; without it every chunk
    is the conservative unnamed read-only private perm. Returns True when the sidecar was
    written. If any chunk name has no parsable address the old lexicographic
    behaviour is kept and no sidecar is written (a warning is logged).
    """
    ordered, bases = order_fridump_files(data_files)
    lines, total = [], 0
    with open(output_path, "wb") as out:
        for idx, f in enumerate(ordered):
            data = f.read_bytes()
            out.write(data)
            total += len(data)
            if bases is not None and data:
                lines.extend(_fridump_chunk_lines(bases[idx], len(data), spans))
    if report is not None:
        report.bytes_captured = total
    if bases is None:
        logger.warning("fridump chunk names lack base addresses; no .maps written for %s",
                       output_path)
        if report is not None:
            report.warnings.append("fridump chunk names lack base addresses; "
                                   "no .maps sidecar written")
        return False
    maps_path = maps_sidecar_path(output_path)
    maps_path.write_text("".join(l + "\n" for l in lines))
    if report is not None:
        report.maps_path, report.regions_captured = str(maps_path), len(lines)
    return True


def _fridump_chunk_lines(base: int, size: int, spans) -> list:
    if not spans:
        return [format_maps_line(base, base + size, FRIDUMP_DEFAULT_PERM)]
    return [format_maps_line(start, end, perm, name or None)
            for start, end, perm, name in annotate_chunk(base, size, spans,
                                                         FRIDUMP_DEFAULT_PERM)]

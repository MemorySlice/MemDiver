"""Run a MemDiver-emitted Volatility3 plugin through a REAL ``vol`` launcher.

The out-of-process twin of ``engine/vol3_verify.py``. That module proves the
emitted plugin works against the framework *this* interpreter imports; this one
proves it works the way a user actually runs it -- ``vol -p <dir> -f <dump>
<module>.<Class>`` -- against whichever Volatility3 checkout the user has, which
is frequently not the one MemDiver's own environment holds.

**No ``volatility3`` import lives here, by design.** Only the standard library
(``subprocess``, ``json``, ``shutil.which``, ``os``, ``signal``, ...) and
``engine.progress.Cancelled``. That keeps this module free of any
install-contract obligation (``tests/test_install_contract.py`` scans
module-level import probes) and, more importantly, keeps it honest: the point
is to interrogate a *foreign* installation, and importing one into this process
would answer a different question.

**The hazard this module's ``cwd`` discipline exists for.** A Volatility3 source
checkout can hold an *editable* install in its own venv whose registered
version and whose importable code disagree. Measured on the tree the author
runs::

    cd <checkout> && env/bin/python vol.py ...     -> framework 2.27.1
    env/bin/python -c "import volatility3"          -> framework 2.28.2
    env/bin/pip show volatility3                    -> 2.27.1

The script's own directory (or the cwd) shadows the editable finder, so *which*
framework you get depends on how you invoke it. Therefore: always invoke
``vol.py`` as a script with an explicit ``cwd`` set to the launcher's own
directory, never rely on a bare import, and always log the version actually
resolved -- :func:`probe_version` is not a nicety.

**A note on what a zero-row result used to mean, and why it no longer does.**
``vol`` runs its ``LayerStacker`` automagic, and MemDiver's flat dumps carry an
ELF header (``7f 45 4c 46``, ``e_type = ET_DYN``), so the stacker wraps the dump
in an ``Elf64Layer`` whose sections have no size ("Scan Failure: Sections have no
size, nothing to scan"). Until B5.2 the emitted plugin bound its scan to
``primary`` -- that empty layer -- and reported nothing for a dump whose key an
in-process flat ``FileLayer`` finds immediately. B5.2 made the emitted plugin
walk ``layer.dependencies`` down to the lowest (file) layer by default, and the
real ``vol`` now finds the key: measured 1 row at ``KeyOffset 370672`` on the
ground-truth dump, framework 2.27.0, where the same invocation previously
returned ``[]``. So an empty list from :func:`run_plugin` is once again a
statement about the *pattern*, not about layer selection.

Layering: ``engine`` may import ``core``; never ``app``/``presentation``. No
``print``/stdout -- ``logger`` only.
"""

from __future__ import annotations

import json
import logging
import os
import re
import shutil
import signal
# The safe no-shell form throughout (fixed argv, no user-supplied string is
# ever handed to a shell); see the [tool.bandit] notes in pyproject.toml.
import subprocess  # nosec B404
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, List, Optional, Sequence, Tuple, Union

logger = logging.getLogger("memdiver.engine.vol3_subproc")

#: Explicit path to a ``vol``/``vol.py`` launcher. Checked first so a developer
#: with three Volatility3 trees can say which one the proof runs against.
VOL3_BIN_ENV = "MEMDIVER_VOL3_BIN"

#: Interpreter to run a ``vol.py`` *script* with. Required when the launcher is
#: a ``.py`` file belonging to a checkout with its own venv (the common case),
#: because that venv -- not MemDiver's -- carries the framework being tested.
VOL3_PYTHON_ENV = "MEMDIVER_VOL3_PYTHON"

#: Default wall-clock ceiling for one plugin run, in seconds.
DEFAULT_TIMEOUT_SECONDS = 900

#: Parses the framework banner ``vol`` prints on stdout before its results
#: ("Volatility 3 Framework 2.27.1").
_BANNER_VERSION = re.compile(r"Volatility\s+3\s+Framework\s+(\d+)\.(\d+)\.(\d+)")

#: One-liner used to ask a checkout's own interpreter for its version. Run WITH
#: ``cwd`` set to the checkout, so the local package shadows any editable
#: install pointing elsewhere.
_VERSION_SNIPPET = (
    "import volatility3.framework.constants as c;"
    "print(c.VERSION_MAJOR, c.VERSION_MINOR, c.VERSION_PATCH)"
)


@dataclass(frozen=True)
class Vol3Launcher:
    """How to invoke a foreign Volatility3, and from where.

    ``argv`` is the command prefix (``[python, vol.py]`` for a checkout,
    ``[vol]`` for a console script). ``cwd`` is the directory every invocation
    runs from and is never optional -- see the module docstring.
    """

    argv: Tuple[str, ...]
    cwd: Path
    #: The interpreter that owns this launcher's Volatility3, when it is
    #: knowable: ``MEMDIVER_VOL3_PYTHON``, else the venv python a ``vol.py`` is
    #: run under, else the interpreter named in a console script's shebang. Used
    #: to run a ``.py`` launcher AND, for either kind, to ask the installation
    #: its version -- which is the only reliable way to get one out of a
    #: release that has no ``--version`` flag (2.27.1 does not).
    python: Optional[str]
    source: str  # which resolution rule produced this launcher

    def describe(self) -> str:
        return f"{' '.join(self.argv)} (cwd={self.cwd}, via {self.source})"


def _shebang_interpreter(path: Path) -> Optional[str]:
    """The python named in *path*'s shebang, when there is one.

    A pip-installed ``vol`` console script starts ``#!/…/bin/python``, which
    names the very environment whose ``volatility3`` it will import. That is the
    only way to version-probe such a launcher on a release with no
    ``--version`` flag. The interpreter must look like a python (``#!/bin/sh``
    wrappers and ``#!/usr/bin/env python`` indirection are both rejected) so a
    guess is never passed off as a resolution.
    """
    try:
        first = path.open("rb").readline(256).decode("utf-8", "replace").strip()
    except OSError:
        return None
    if not first.startswith("#!"):
        return None
    candidate = first[2:].split()[0] if first[2:].split() else ""
    if not candidate or "python" not in Path(candidate).name:
        return None
    return candidate if Path(candidate).is_file() else None


#: Seconds ``pyenv which`` may take before the shim is kept as-is.
_PYENV_WHICH_TIMEOUT = 5

_PYENV_SHIM_EXEC = re.compile(r'exec\s+"?([^"\s]*pyenv)"?\s+exec\b')


def _script_head(path: Path) -> str:
    try:
        with path.open("rb") as handle:
            return handle.read(2048).decode("utf-8", "replace")
    except OSError:
        return ""


def _is_pyenv_shim(path: Path) -> bool:
    """Whether *path* is a pyenv shim: under a ``shims`` dir or a ``pyenv exec`` wrapper."""
    if path.parent.name == "shims" and path.parent.parent.name == ".pyenv":
        return True
    root = os.environ.get("PYENV_ROOT")
    if root and path.parent == Path(root).expanduser() / "shims":
        return True
    head = _script_head(path)
    return head.startswith("#!") and bool(_PYENV_SHIM_EXEC.search(head))


def _pyenv_executables(shim: Path) -> List[str]:
    found: List[str] = []
    match = _PYENV_SHIM_EXEC.search(_script_head(shim))
    if match:
        found.append(match.group(1))
    root = os.environ.get("PYENV_ROOT")
    for candidate in (root and str(Path(root).expanduser() / "bin" / "pyenv"),
                      shutil.which("pyenv")):
        if candidate:
            found.append(candidate)
    return [exe for exe in dict.fromkeys(found) if Path(exe).is_file()]


def _resolve_pyenv_shim(path: Path) -> Path:
    """The real executable behind a pyenv shim, or *path* itself.

    A shim is a bash wrapper (``exec pyenv exec "$program"``): it has no python
    shebang to probe and ``vol --version`` through it exits non-zero, so the
    launcher would resolve with no version. ``pyenv which <name>`` names the
    real console script. ANY failure (no pyenv, timeout, non-zero exit, answer
    that is missing or itself a shim) keeps the shim -- never a guess.
    """
    if not _is_pyenv_shim(path):
        return path
    for exe in _pyenv_executables(path):
        try:
            done = subprocess.run(  # nosec B603
                [exe, "which", path.name], capture_output=True, text=True,
                timeout=_PYENV_WHICH_TIMEOUT, check=False,
            )
        except (OSError, subprocess.SubprocessError):
            continue
        answer = Path(done.stdout.strip()) if done.returncode == 0 else None
        if answer and answer.is_file() and not _is_pyenv_shim(answer):
            logger.info("vol3 launcher %s is a pyenv shim; resolved to %s", path, answer)
            return answer
    return path


def _launcher_for_path(
    path: Path, source: str, *, python_override: Optional[str] = None,
) -> Optional[Vol3Launcher]:
    path = path.expanduser()
    if not path.is_file():
        logger.warning("vol3 launcher %s does not exist", path)
        return None
    path = _resolve_pyenv_shim(path)
    cwd = path.parent.resolve()
    # *python_override* is an explicit PARAMETER beating the env var, not a
    # replacement for it: env-only configuration is unreachable from the web
    # and MCP surfaces (nobody sets an environment variable through an HTTP
    # body), so a producer parameter has to be able to say which interpreter
    # owns the framework under test. ``None`` keeps the historical env-var
    # behaviour byte-for-byte.
    configured = python_override or os.environ.get(VOL3_PYTHON_ENV)
    if path.suffix == ".py":
        # A checkout's vol.py belongs to that checkout's venv; falling back to
        # OUR interpreter is a last resort and is worth being loud about,
        # because it silently changes which framework is under test.
        python = configured or sys.executable
        if not configured:
            logger.warning(
                "%s is unset; running %s under this interpreter (%s), which may "
                "not be the environment that owns its volatility3",
                VOL3_PYTHON_ENV, path, sys.executable,
            )
        return Vol3Launcher(
            argv=(python, str(path.resolve())), cwd=cwd, python=python, source=source,
        )
    return Vol3Launcher(
        argv=(str(path.resolve()),), cwd=cwd,
        python=configured or _shebang_interpreter(path), source=source,
    )


#: :attr:`Vol3Launcher.source` for a launcher named by the ``vol_bin=``
#: PARAMETER rather than by the environment. Distinct from
#: :data:`VOL3_BIN_ENV` on purpose: "which rule produced this launcher" is part
#: of every verification report, and "the caller told us" and "the environment
#: told us" are different provenance.
VOL3_BIN_PARAM = "vol_bin="


def find_vol3_launcher(
    *, python_override: Optional[str] = None,
) -> Optional[Vol3Launcher]:
    """Resolve a usable ``vol`` launcher, or ``None``.

    Order: :data:`VOL3_BIN_ENV`, then ``which("vol")``, then ``which("vol.py")``.
    The env var wins so that a machine holding several Volatility3 trees --
    which is the normal state of a forensics workstation -- can pin the proof to
    a chosen one instead of whichever ``PATH`` happens to expose.

    *python_override* pins the INTERPRETER without pinning the launcher, for a
    caller that found ``vol`` on ``PATH`` but knows which venv owns its
    framework. ``None`` (the default) is the historical behaviour exactly.
    """
    explicit = os.environ.get(VOL3_BIN_ENV)
    if explicit:
        return _launcher_for_path(
            Path(explicit), source=VOL3_BIN_ENV, python_override=python_override,
        )
    for name in ("vol", "vol.py"):
        found = shutil.which(name)
        if found:
            return _launcher_for_path(
                Path(found), source=f'which("{name}")',
                python_override=python_override,
            )
    return None


def resolve_launcher(
    *, vol_bin: Optional[str] = None, vol_python: Optional[str] = None,
) -> Optional[Vol3Launcher]:
    """The launcher for an explicit request, falling back to the environment.

    The parameter form of :func:`find_vol3_launcher`, and the entry point every
    surface uses. *vol_bin* / *vol_python* are the first-class equivalents of
    :data:`VOL3_BIN_ENV` / :data:`VOL3_PYTHON_ENV` and BEAT them, because an
    environment variable is not a channel a web request or an MCP tool call
    has: leaving launcher selection env-only would mean the "point me at my own
    vol.py" requirement was satisfiable from the shell alone.

    An explicit *vol_bin* that does not exist resolves to ``None`` rather than
    falling back to ``PATH`` -- honouring a request INCLUDING its failure is
    what keeps a report header truthful, exactly as
    :func:`find_vol3_launcher` already does for the env var.
    """
    if vol_bin:
        return _launcher_for_path(
            Path(vol_bin), source=VOL3_BIN_PARAM, python_override=vol_python,
        )
    return find_vol3_launcher(python_override=vol_python)


def _run(
    argv: Sequence[str], cwd: Path, timeout: int,
    cancel: Optional[Callable[[], bool]] = None,
) -> subprocess.CompletedProcess:
    """``vol`` with captured text output, through :func:`run_cancellable`.

    Answers like ``subprocess.run(..., capture_output=True, text=True)``; the
    run is stoppable through *cancel* (default: never) and always killed as a
    whole process group on timeout or when this process goes.
    """
    logger.debug("vol3 subprocess: %s (cwd=%s)", " ".join(argv), cwd)
    return run_cancellable(argv, cwd, timeout=timeout, cancel=cancel,
                           stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)


# ---------------------------------------------------------------------------
# Cancellable runs (every ``vol`` this module starts)
# ---------------------------------------------------------------------------
#
# A job worker (``app/pipeline/vol3_synth_task_runner.py``) can run ``vol`` over
# a multi-GB image for up to an hour. ``subprocess.run(timeout=)`` cannot be
# stopped early and kills only the direct child, so a cancelled job held the
# TaskManager's one-job gate until vol finished on its own, and a worker killed
# at shutdown left vol running to its timeout. Hence:
#
# * the child runs in its OWN session (``start_new_session``), so one
#   ``killpg`` reaches vol and anything it spawned;
# * the parent polls ``cancel`` and the deadline every ``CANCEL_POLL_S``;
# * every exit path -- cancel, timeout, or any exception unwinding through the
#   wait (``KeyboardInterrupt`` from a terminal Ctrl-C included) -- SIGKILLs the
#   group and reaps it before returning.
#
# The own session also means a terminal Ctrl-C no longer reaches vol directly;
# the exception it raises in the parent is what kills the group instead.
#
# None of that helps when the PARENT goes without unwinding (SIGTERM, SIGKILL,
# OOM / jetsam, the orphan watchdog's ``os._exit``, the TaskManager's
# SIGTERM/SIGKILL escalation): nothing in it runs, and vol -- in its own
# session -- would run on to its timeout. macOS has no PR_SET_PDEATHSIG, so the
# group carries its own LIFELINE, the one mechanism for all of those: vol is
# started by a tiny watchdog (:data:`_LIFELINE_SCRIPT`), the group leader, which
# holds the read end of a pipe whose only write end lives in the parent. The
# parent's death -- by any means -- closes that end; the watchdog reads EOF
# within :data:`LIFELINE_POLL_S` and SIGKILLs the group. It also enforces the
# deadline itself (+ :data:`LIFELINE_GRACE_S`), so a group can never outlive
# its budget even if the parent is wedged.

#: How often a cancellable run polls ``cancel`` and its deadline, in seconds.
#: Bounds how long a cancelled ``vol`` keeps running.
CANCEL_POLL_S = 0.25

#: How often the lifeline watchdog checks for its parent's death, in seconds.
#: Bounds how long vol outlives a parent that died without unwinding.
LIFELINE_POLL_S = 0.05

#: How long to wait for a SIGKILLed process group's leader to be reaped.
_REAP_TIMEOUT_S = 5.0

#: Slack the lifeline watchdog adds to the run's own timeout before it kills
#: the group by itself (the parent normally does it first, on time).
LIFELINE_GRACE_S = 5.0

#: The group leader of a cancellable run: ``<lifeline fd> <poll s> <budget s> <argv...>``.
#: Starts vol, then waits for whichever comes first: vol exits (its status is
#: passed on, a signal death included), the lifeline reads EOF (the parent is
#: gone), or the budget runs out -- the last two SIGKILL the whole group.
#: Standard library only, run with ``-I -S``; it writes nothing itself.
_LIFELINE_SCRIPT = """
import os, select, signal, subprocess, sys, time
fd, poll_s = int(sys.argv[1]), float(sys.argv[2])
deadline = time.monotonic() + float(sys.argv[3])
child = subprocess.Popen(sys.argv[4:])
while True:
    ready = select.select([fd], [], [], poll_s)[0]
    if (ready and not os.read(fd, 64)) or time.monotonic() > deadline:
        os.killpg(0, signal.SIGKILL)
    rc = child.poll()
    if rc is not None:
        if rc < 0:
            try:  # SIGKILL / SIGSTOP (an OOM-killed vol) cannot take a handler
                signal.signal(-rc, signal.SIG_DFL)
            except (OSError, ValueError):
                pass
            os.kill(os.getpid(), -rc)
        sys.exit(rc)
"""


def _never() -> bool:
    """The *cancel* of a run nobody can cancel."""
    return False


def _kill_group(proc: "subprocess.Popen[Any]") -> None:
    """SIGKILL *proc*'s whole process group (its own session), then reap the leader."""
    try:
        os.killpg(proc.pid, signal.SIGKILL)
    except (ProcessLookupError, PermissionError):
        pass
    try:
        proc.wait(timeout=_REAP_TIMEOUT_S)
    except subprocess.TimeoutExpired:  # pragma: no cover - SIGKILL cannot be ignored
        logger.warning("vol process group %s not reaped after SIGKILL", proc.pid)


def _wait_or_stop(proc: "subprocess.Popen[Any]", timeout: float,
                  cancel: Callable[[], bool], argv: List[str]) -> Tuple[Any, Any]:
    """``communicate()`` in ``CANCEL_POLL_S`` slices until exit, cancel or deadline."""
    from memdiver.engine.progress import Cancelled

    deadline = time.monotonic() + timeout
    while True:
        try:
            slice_s = max(0.0, min(CANCEL_POLL_S, deadline - time.monotonic()))
            return proc.communicate(timeout=slice_s)
        except subprocess.TimeoutExpired:
            pass  # documented as safe to retry: no output is lost
        if cancel():
            _kill_group(proc)
            raise Cancelled()
        if time.monotonic() >= deadline:
            _kill_group(proc)
            raise subprocess.TimeoutExpired(argv, timeout)


def run_cancellable(
    argv: Sequence[str], cwd: Path, *, timeout: float,
    cancel: Optional[Callable[[], bool]] = None,
    stdout: Any, stderr: Any, env: Optional[dict] = None, text: bool = False,
) -> subprocess.CompletedProcess:
    """Run *argv* like ``subprocess.run(..., check=False)``, but stoppable.

    *stdout* / *stderr* are what ``Popen`` takes (``subprocess.PIPE`` or an open
    file). *cancel* defaults to never. Returns the ``CompletedProcess`` of a run
    that exited on its own.

    Raises:
        engine.progress.Cancelled: ``cancel()`` turned true (checked every
            :data:`CANCEL_POLL_S`); the process group is already dead.
        subprocess.TimeoutExpired: *timeout* seconds elapsed; group already dead.
    """
    proc, lifeline = _start_group(argv, cwd, timeout, stdout=stdout, stderr=stderr,
                                  env=env, text=text)
    try:
        out, err = _wait_or_stop(proc, timeout, cancel or _never, list(argv))
        return subprocess.CompletedProcess(list(argv), proc.returncode, out, err)
    finally:
        if proc.returncode is None:  # any exception mid-wait: never leave vol behind
            _kill_group(proc)
        os.close(lifeline)
        for pipe in (proc.stdout, proc.stderr):
            if pipe is not None:
                pipe.close()


def _start_group(argv: Sequence[str], cwd: Path, timeout: float, **popen: Any
                 ) -> Tuple["subprocess.Popen[Any]", int]:
    """Start *argv* under the lifeline watchdog in a new session; returns (leader, write end)."""
    read_end, write_end = os.pipe()  # both non-inheritable: only the watchdog gets read_end
    try:
        # Fixed argv, no shell; own session so one killpg reaches every descendant.
        proc = subprocess.Popen(  # nosec B603
            [sys.executable, "-I", "-S", "-c", _LIFELINE_SCRIPT, str(read_end),
             str(LIFELINE_POLL_S), str(float(timeout) + LIFELINE_GRACE_S), *argv],
            cwd=str(cwd), start_new_session=True, pass_fds=(read_end,), **popen)
    except BaseException:
        os.close(write_end)
        raise
    finally:
        os.close(read_end)
    return proc, write_end


def probe_version(launcher: Vol3Launcher) -> Optional[Tuple[int, int, int]]:
    """The framework version *launcher* actually resolves, or ``None``.

    Read by running :attr:`Vol3Launcher.python` with ``cwd`` set to the
    launcher's own directory, which for a checkout is the only invocation whose
    answer matches what ``vol.py`` itself will load. When no interpreter is
    knowable (or the probe fails) ``--version`` is tried and its output parsed;
    Volatility3 2.27.1 has no such flag, so ``None`` is then the honest answer
    rather than a guess.
    """
    if launcher.python is not None:
        result = _run(
            (launcher.python, "-c", _VERSION_SNIPPET), launcher.cwd, timeout=60,
        )
        parts = result.stdout.split()
        if result.returncode == 0 and len(parts) == 3:
            version = (int(parts[0]), int(parts[1]), int(parts[2]))
            logger.info("vol3 launcher %s resolves framework %s",
                        launcher.describe(), ".".join(map(str, version)))
            return version
        logger.warning("vol3 version probe failed (rc=%s): %s",
                       result.returncode, result.stderr.strip()[:200])
        # Fall through: an old release may still answer --version.
    result = _run((*launcher.argv, "--version"), launcher.cwd, timeout=60)
    found = _BANNER_VERSION.search(result.stdout + result.stderr)
    if found:
        version = (int(found.group(1)), int(found.group(2)), int(found.group(3)))
        logger.info("vol3 launcher %s resolves framework %s",
                    launcher.describe(), ".".join(map(str, version)))
        return version
    logger.warning("vol3 launcher %s reports no parseable version",
                   launcher.describe())
    return None


def plugin_module_name(plugin_path: Path) -> str:
    """The ``<module>.<Class>`` name ``vol`` addresses an emitted plugin by.

    ``-p/--plugin-dirs`` PREPENDS the directory to
    ``volatility3.plugins.__path__`` (``volatility3/cli/__init__.py``), so a
    file ``pad128.py`` holding ``class Pad128`` becomes ``pad128.Pad128``. The
    class name is read out of the source rather than guessed from the filename,
    because the emitter derives them independently.
    """
    source = plugin_path.read_text()
    match = re.search(r"^class\s+(\w+)\s*\(", source, re.M)
    if match is None:
        raise ValueError(f"no plugin class found in {plugin_path}")
    return f"{plugin_path.stem}.{match.group(1)}"


def _parse_json_rows(stdout: str) -> List[dict]:
    """Extract the JSON document ``-r json`` printed, ignoring the banner.

    ``vol`` writes "Volatility 3 Framework X.Y.Z" to stdout ahead of its
    results even under ``-q``, so a bare ``json.loads(stdout)`` fails on a
    perfectly good run. The document starts at the first line that begins with
    ``[`` or ``{``.
    """
    lines = stdout.splitlines()
    for index, line in enumerate(lines):
        if line[:1] in ("[", "{"):
            payload = json.loads("\n".join(lines[index:]))
            return list(payload) if isinstance(payload, list) else [payload]
    return []


def run_plugin(
    launcher: Vol3Launcher,
    plugin_path: Path,
    dump: Path,
    *,
    extra_args: Sequence[str] = (),
    plugin_args: Sequence[str] = (),
    timeout: int = DEFAULT_TIMEOUT_SECONDS,
    cancel: Optional[Callable[[], bool]] = None,
) -> List[dict]:
    """Run the emitted plugin at *plugin_path* over *dump*, returning its rows.

    Raises ``RuntimeError`` when the launcher exits non-zero, with the TAIL of
    its stderr attached (where vol's traceback is) -- a silently-empty list
    would be indistinguishable from a scan that legitimately found nothing.
    The run goes through :func:`run_vol` (memory-bounded output, no
    ``__pycache__`` in the plugin's directory); *cancel* can stop it. Rows
    beyond :data:`NAMED_STDOUT_CAP` of JSON raise ``RuntimeError`` (a refused
    run, never a silently truncated row list).

    **The two argument slots are not interchangeable, and putting a flag in the
    wrong one is a hard error rather than a subtlety.** ``vol``'s CLI is an
    argparse SUBCOMMAND parser: global options belong before the plugin target
    and the plugin's own options belong after it. Measured against the author's
    2.27.1 checkout::

        vol.py ... --virtual  Pad256.MemDiverScanPad256   -> exit 2,
                                          "unrecognized arguments: --virtual"
        vol.py ... Pad256.MemDiverScanPad256 --virtual     -> exit 0, [] rows
        vol.py ... Pad256.MemDiverScanPad256 --pid 1       -> exit 0, 1 row

    So *extra_args* (ahead of the target, as :class:`VolSpec`'s
    ``extra_globals``) is for GLOBAL ``vol`` options, and *plugin_args* -- appended after
    the target -- is the only slot a plugin flag such as ``--pid`` or
    ``--virtual`` can be passed in. No caller in the repo was using
    *extra_args* for a plugin flag, so nothing changes behaviour here; the new
    slot exists because there was previously no working one.
    """
    plugin_path = Path(plugin_path).resolve()
    spec = VolSpec(
        plugin=plugin_module_name(plugin_path), image=str(Path(dump).resolve()),
        plugin_dirs=[str(plugin_path.parent)], plugin_args=tuple(plugin_args),
        extra_globals=tuple(extra_args))
    return run_vol(launcher, spec, timeout=timeout, cancel=cancel).raise_for_status().rows


def launcher_report(
    *, vol_bin: Optional[str] = None, vol_python: Optional[str] = None,
) -> str:
    """One line naming the resolved launcher and its version, for a test header.

    Also the wording of the "neither mode is available" refusal every surface
    raises, which is why the not-found branch names the ``vol_bin`` PARAMETER
    beside the env var: on web and MCP the env var is not something the caller
    can reach.
    """
    launcher = resolve_launcher(vol_bin=vol_bin, vol_python=vol_python)
    if launcher is None:
        return (
            f"not found (set {VOL3_BIN_ENV} or pass vol_bin=, or put vol/vol.py "
            f"on PATH; a .py launcher also wants {VOL3_PYTHON_ENV} / vol_python=)"
        )
    version = probe_version(launcher)
    rendered = ".".join(map(str, version)) if version else "version unknown"
    return f"{launcher.describe()} -> {rendered}"


#: Memory bounds on one :func:`run_named_plugin` run: stdout (the JSON rows) is
#: refused beyond this size, and only the TAIL of stderr is kept.
NAMED_STDOUT_CAP = 64 * 1024 * 1024
NAMED_STDERR_TAIL = 64 * 1024

#: A vol plugin name: dotted identifiers (``msl.info``, ``linux.pslist.PsList``).
#: Anything else -- notably a leading ``-`` -- would be parsed as a vol option.
_PLUGIN_NAME = re.compile(r"^[A-Za-z_]\w*(\.[A-Za-z_]\w*)*$")


#: vol's GLOBAL long options (``volatility3/cli/__init__.py``), identical in
#: 2.27.0 and 2.28.2 (``tests/test_vol3_exec.py`` re-reads them from every
#: available launcher's ``-h`` and fails when one is missing here). vol parses
#: its globals with ``parse_known_args`` over the WHOLE argv, so a global
#: option after the plugin name still takes effect -- ``-p``/``--plugin-dirs``
#: would import code from anywhere, ``-l``/``--log`` write a file anywhere.
VOL_GLOBAL_LONG_OPTIONS = (
    "cache-path", "clear-cache", "config", "extend", "file", "filters", "help",
    "hide-columns", "log", "offline", "output-dir", "parallelism", "plugin-dirs",
    "quiet", "remote-isf-url", "renderer", "save-config", "single-location",
    "single-swap-locations", "stackers", "symbol-dirs", "verbosity", "write-config",
)
_NEGATIVE_NUMBER = re.compile(r"^-\d+(\.\d+)?$")


def refuse_global_options(plugin_args: Sequence[str]) -> None:
    """Raise ``ValueError`` for a plugin argument vol would read as a GLOBAL option.

    Refused: every single-dash option (``-p``, ``-p<dir>``, clusters such as
    ``-qp<dir>``; a negative number is allowed), and every ``--name[=value]``
    whose name equals or ABBREVIATES a global long option (argparse accepts
    unique prefixes: ``--plugin=`` is ``--plugin-dirs``), including a bare
    ``--``. Plugin options are long-form (``--pid``, ``--oracle-sample``), so
    they pass.
    """
    for arg in plugin_args:
        text = str(arg)
        if text.startswith("-") and not text.startswith("--"):
            if text != "-" and not _NEGATIVE_NUMBER.match(text):
                raise ValueError(f"plugin argument {text!r}: single-dash options are "
                                 "vol GLOBAL options and are not accepted after the plugin")
        elif text.startswith("--"):
            name = text[2:].split("=", 1)[0]
            if any(option.startswith(name) for option in VOL_GLOBAL_LONG_OPTIONS):
                raise ValueError(f"plugin argument {text!r} is (an abbreviation of) a vol "
                                 "GLOBAL option and is not accepted after the plugin")


def read_spooled(handle, cap: int, *, tail: bool) -> str:
    """At most *cap* bytes of a spooled output file: the tail, or the whole (else refuse)."""
    size = handle.seek(0, 2)
    if size > cap and not tail:
        raise RuntimeError(f"vol printed {size} bytes, over the {cap}-byte cap")
    handle.seek(max(0, size - cap))
    return handle.read().decode("utf-8", errors="replace")


def semicolon_paths(paths: Sequence[Any]) -> List[str]:
    """The given paths holding ``;``, which vol uses to split ``-p`` / ``-s`` directories.

    Empty / ``None`` entries are skipped. Each caller words its own refusal.
    """
    return [str(p) for p in paths if p and ";" in str(p)]


# ---------------------------------------------------------------------------
# One vol runner: a spec says WHAT to run, ``run_vol`` runs it
# ---------------------------------------------------------------------------

#: A directory or file path as a caller holds it: rendered with ``str()`` only.
PathText = Union[str, "os.PathLike[str]"]


@dataclass(frozen=True)
class VolSpec:
    """One ``vol`` invocation, pure data: the argv, the copy-paste line, the exec request.

    Paths are rendered with ``str()`` and NEVER resolved here: each caller
    passes exactly the strings it wants shown and run (a display keeps the
    path a user gave; a run resolves first, because vol runs in the
    launcher's directory). *plugin_args* follow the plugin name;
    *extra_globals* are trusted, caller-supplied GLOBAL options (unchecked).
    *renderer* ``None`` and *quiet* ``False`` drop ``-r`` / ``-q``, as a
    copy-paste line has them. *cache_path* is a run detail and never shown.
    """

    plugin: str
    image: PathText
    plugin_dirs: Sequence[PathText] = ()
    symbol_dirs: Sequence[PathText] = ()
    plugin_args: Sequence[str] = ()
    output_dir: Optional[PathText] = None
    cache_path: Optional[PathText] = None
    renderer: Optional[str] = "json"
    quiet: bool = True
    extra_globals: Sequence[str] = ()

    def argv(self, launcher: Vol3Launcher) -> List[str]:
        """``<launcher> [-q] [-r R] [--cache-path C] [-s S --offline] [-p P] [GLOBALS] [-o O] -f IMG PLUGIN ARGS``.

        Raises:
            ValueError: a malformed plugin name, a vol GLOBAL option among
                *plugin_args*, or a ``;`` in a ``-p`` / ``-s`` directory.
        """
        return [*launcher.argv, *self._options(with_cache=True)]

    def display_command(self) -> str:
        """The copy-pasteable ``vol …`` line (shell-quoted; no ``--cache-path``)."""
        import shlex

        return shlex.join(["vol", *self._options(with_cache=False)])

    def exec_request(self) -> dict:
        """The ``vol3 exec`` request that reruns this spec (plain strings and lists)."""
        return {"plugin": self.plugin, "image_path": str(self.image),
                "plugin_dirs": [str(d) for d in self.plugin_dirs],
                "symbol_dirs": [str(d) for d in self.symbol_dirs],
                "args": [str(a) for a in self.plugin_args]}

    def _options(self, *, with_cache: bool) -> List[str]:
        """Everything after the launcher, validated, in the one canonical order."""
        self._validate()
        options = (["-q"] if self.quiet else []) + (["-r", self.renderer] if self.renderer else [])
        if with_cache and self.cache_path is not None:
            options += ["--cache-path", str(self.cache_path)]
        if self.symbol_dirs:
            options += ["-s", ";".join(map(str, self.symbol_dirs)), "--offline"]
        if self.plugin_dirs:
            options += ["-p", ";".join(map(str, self.plugin_dirs))]
        options += [*self.extra_globals]
        if self.output_dir is not None:
            options += ["-o", str(self.output_dir)]
        return [*options, "-f", str(self.image), self.plugin, *map(str, self.plugin_args)]

    def _validate(self) -> None:
        """The refusals of :meth:`argv` (``ValueError``, worded as they always were)."""
        if not _PLUGIN_NAME.match(self.plugin):
            raise ValueError(f"not a vol plugin name: {self.plugin!r}")
        refuse_global_options(self.plugin_args)
        bad = semicolon_paths([*self.plugin_dirs, *self.symbol_dirs])
        if bad:
            raise ValueError(f"vol -p / -s directories may not contain ';': {bad}")


@dataclass(frozen=True)
class VolRun:
    """The outcome of :func:`run_vol`; a non-zero exit is NOT raised.

    ``rows`` are parsed only on exit 0. ``stderr_tail`` is the last
    ``stderr_tail`` bytes of vol's stderr (its warnings and errors).
    ``framework`` is the "Volatility 3 Framework X.Y.Z" banner, when printed.
    """

    argv: Tuple[str, ...]
    returncode: int
    rows: List[dict]
    stderr_tail: str
    framework: Optional[str]

    def raise_for_status(self) -> "VolRun":
        """This run, or ``RuntimeError`` naming the exit code and the stderr tail."""
        if self.returncode != 0:
            raise RuntimeError(f"vol exited {self.returncode}: {self.stderr_tail.strip()[-2000:]}")
        return self


#: The result type of :func:`run_named_plugin`, kept importable under its old name.
NamedPluginRun = VolRun


def run_vol(
    launcher: Vol3Launcher,
    spec: VolSpec,
    *,
    timeout: float,
    cancel: Optional[Callable[[], bool]] = None,
    stdout_cap: Optional[int] = None,
    stderr_tail: Optional[int] = None,
) -> VolRun:
    """Run *spec* under *launcher*: the one way this package starts a plugin.

    Always through :func:`run_cancellable` (own session, lifeline, whole group
    killed on cancel / timeout / any unwind), from ``launcher.cwd``, with
    ``PYTHONDONTWRITEBYTECODE=1`` so vol writes no ``__pycache__`` into the
    ``-p`` directories. Both streams are spooled to temporary files: stdout
    is refused beyond *stdout_cap* bytes, only the last *stderr_tail* bytes
    of stderr are kept (defaults: :data:`NAMED_STDOUT_CAP` /
    :data:`NAMED_STDERR_TAIL`, read at call time). Rows are parsed only on exit 0.

    Raises:
        ValueError: the spec is refused (see :meth:`VolSpec.argv`).
        subprocess.TimeoutExpired: the run exceeded *timeout* seconds.
        engine.progress.Cancelled: ``cancel()`` turned true.
        RuntimeError: stdout exceeded *stdout_cap*.
    """
    import tempfile

    argv = tuple(spec.argv(launcher))
    env = {**os.environ, "PYTHONDONTWRITEBYTECODE": "1"}
    logger.debug("vol3 subprocess: %s (cwd=%s)", " ".join(argv), launcher.cwd)
    with tempfile.TemporaryFile() as out, tempfile.TemporaryFile() as err:
        result = run_cancellable(argv, launcher.cwd, timeout=timeout, cancel=cancel,
                                 stdout=out, stderr=err, env=env)
        tail = read_spooled(err, NAMED_STDERR_TAIL if stderr_tail is None else stderr_tail,
                            tail=True)
        stdout = read_spooled(out, NAMED_STDOUT_CAP if stdout_cap is None else stdout_cap,
                              tail=False)
    # The banner goes to stdout on some releases and to stderr on others (2.27.0 -q).
    banner = _BANNER_VERSION.search(stdout) or _BANNER_VERSION.search(tail)
    logger.info("vol3 ran %s over %s via %s (framework %s, rc=%s)", spec.plugin,
                Path(spec.image).name, launcher.describe(),
                banner.group(0) if banner else "unknown", result.returncode)
    rows = _parse_json_rows(stdout) if result.returncode == 0 else []
    return VolRun(argv=argv, returncode=result.returncode, rows=rows, stderr_tail=tail,
                  framework=banner.group(0) if banner else None)


def named_plugin_spec(
    plugin: str, image: Path, *,
    plugin_dirs: Sequence[Path] = (), symbol_dirs: Sequence[Path] = (),
    plugin_args: Sequence[str] = (), output_dir: Optional[Path] = None,
) -> VolSpec:
    """The :class:`VolSpec` of a plugin run by NAME, every path made absolute.

    vol runs in the launcher's directory, so a relative path would point
    elsewhere; ``-q -r json`` because the rows are parsed.
    """
    return VolSpec(
        plugin=plugin, image=str(Path(image).resolve()),
        plugin_dirs=[str(Path(d).resolve()) for d in plugin_dirs],
        symbol_dirs=[str(Path(d).resolve()) for d in symbol_dirs],
        plugin_args=tuple(plugin_args),
        output_dir=None if output_dir is None else str(Path(output_dir).resolve()))


def named_plugin_argv(
    launcher: Vol3Launcher, plugin: str, image: Path, *,
    plugin_dirs: Sequence[Path] = (), symbol_dirs: Sequence[Path] = (),
    plugin_args: Sequence[str] = (), output_dir: Optional[Path] = None,
) -> Tuple[str, ...]:
    """``vol`` argv for running *plugin* by NAME: globals first, plugin flags after it.

    ``-p`` / ``-s`` take several directories joined by ``;`` (vol splits them
    on ``;`` on every OS), so a directory holding ``;`` is refused here. With
    *symbol_dirs* ``--offline`` stops vol fetching a remote ISF instead.
    """
    return tuple(named_plugin_spec(
        plugin, image, plugin_dirs=plugin_dirs, symbol_dirs=symbol_dirs,
        plugin_args=plugin_args, output_dir=output_dir).argv(launcher))


def run_named_plugin(
    launcher: Vol3Launcher,
    plugin: str,
    image: Path,
    *,
    plugin_dirs: Sequence[Path] = (),
    symbol_dirs: Sequence[Path] = (),
    plugin_args: Sequence[str] = (),
    output_dir: Optional[Path] = None,
    timeout: int = DEFAULT_TIMEOUT_SECONDS,
    cancel: Optional[Callable[[], bool]] = None,
) -> NamedPluginRun:
    """Run a plugin by its vol NAME (``msl.info``) over *image* -- the twin of :func:`run_plugin`.

    :func:`run_plugin` addresses one emitted FILE; this runs whatever the
    ``-p`` directories (*plugin_dirs*) and the framework provide, exactly as
    ``vol -p <dirs> -f <image> <plugin> <plugin_args>`` would, through
    :func:`run_vol` (memory bounds :data:`NAMED_STDOUT_CAP` /
    :data:`NAMED_STDERR_TAIL`, no ``__pycache__``, *cancel* stops it). vol's
    own ``-o`` defaults to the launcher's directory; pass *output_dir* for a
    plugin that writes files.

    Raises:
        ValueError: a malformed plugin name or a ``;`` in a directory.
        subprocess.TimeoutExpired: the run exceeded *timeout* seconds.
        engine.progress.Cancelled: ``cancel()`` turned true.
        RuntimeError: stdout exceeded :data:`NAMED_STDOUT_CAP`.
    """
    spec = named_plugin_spec(plugin, image, plugin_dirs=plugin_dirs, symbol_dirs=symbol_dirs,
                             plugin_args=plugin_args, output_dir=output_dir)
    return run_vol(launcher, spec, timeout=timeout, cancel=cancel)

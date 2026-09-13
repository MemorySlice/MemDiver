"""Run a MemDiver-emitted Volatility3 plugin through a REAL ``vol`` launcher.

The out-of-process twin of ``engine/vol3_verify.py``. That module proves the
emitted plugin works against the framework *this* interpreter imports; this one
proves it works the way a user actually runs it -- ``vol -p <dir> -f <dump>
<module>.<Class>`` -- against whichever Volatility3 checkout the user has, which
is frequently not the one MemDiver's own environment holds.

**No ``volatility3`` import lives here, by design.** Only ``subprocess``,
``json``, ``shutil.which`` and ``os``. That keeps this module free of any
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
# The safe no-shell form throughout (fixed argv, no user-supplied string is
# ever handed to a shell); see the [tool.bandit] notes in pyproject.toml.
import subprocess  # nosec B404
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import List, Optional, Sequence, Tuple

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


def _launcher_for_path(
    path: Path, source: str, *, python_override: Optional[str] = None,
) -> Optional[Vol3Launcher]:
    path = path.expanduser()
    if not path.is_file():
        logger.warning("vol3 launcher %s does not exist", path)
        return None
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
) -> subprocess.CompletedProcess:
    logger.debug("vol3 subprocess: %s (cwd=%s)", " ".join(argv), cwd)
    # Fixed argv, no shell.
    return subprocess.run(  # nosec B603
        list(argv), cwd=str(cwd), capture_output=True, text=True,
        timeout=timeout, check=False,
    )


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
) -> List[dict]:
    """Run the emitted plugin at *plugin_path* over *dump*, returning its rows.

    Raises ``RuntimeError`` when the launcher exits non-zero, with its stderr
    attached -- a silently-empty list would be indistinguishable from a scan
    that legitimately found nothing.

    **The two argument slots are not interchangeable, and putting a flag in the
    wrong one is a hard error rather than a subtlety.** ``vol``'s CLI is an
    argparse SUBCOMMAND parser: global options belong before the plugin target
    and the plugin's own options belong after it. Measured against the author's
    2.27.1 checkout::

        vol.py ... --virtual  Pad256.MemDiverScanPad256   -> exit 2,
                                          "unrecognized arguments: --virtual"
        vol.py ... Pad256.MemDiverScanPad256 --virtual     -> exit 0, [] rows
        vol.py ... Pad256.MemDiverScanPad256 --pid 1       -> exit 0, 1 row

    So *extra_args* (kept exactly where it has always been, ahead of the
    target) is for GLOBAL ``vol`` options, and *plugin_args* -- appended after
    the target -- is the only slot a plugin flag such as ``--pid`` or
    ``--virtual`` can be passed in. No caller in the repo was using
    *extra_args* for a plugin flag, so nothing changes behaviour here; the new
    slot exists because there was previously no working one.
    """
    plugin_path = Path(plugin_path).resolve()
    dump = Path(dump).resolve()
    target = plugin_module_name(plugin_path)
    argv = (
        *launcher.argv,
        "-q",
        "-p", str(plugin_path.parent),
        "-r", "json",
        "-f", str(dump),
        *extra_args,
        target,
        *plugin_args,
    )
    result = _run(argv, launcher.cwd, timeout=timeout)
    banner = _BANNER_VERSION.search(result.stdout)
    logger.info(
        "vol3 ran %s over %s via %s (framework %s, rc=%s)",
        target, dump.name, launcher.describe(),
        banner.group(0) if banner else "unknown", result.returncode,
    )
    if result.returncode != 0:
        raise RuntimeError(
            f"vol3 exited {result.returncode} running {target}: "
            f"{result.stderr.strip()[:2000]}"
        )
    return _parse_json_rows(result.stdout)


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

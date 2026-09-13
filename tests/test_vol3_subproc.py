"""Out-of-process proof: run the emitted plugin through a REAL ``vol`` launcher.

``tests/test_vol3_verify.py`` proves the emitted plugin works against the
Volatility3 that *this* interpreter imports. That is necessary and not
sufficient: users do not import MemDiver's environment, they run their own
``vol``, and on a forensics workstation that is routinely a source checkout with
its own venv and a different framework version. This file exercises that path.

Two classes of test live here, gated differently on purpose:

* **Pure resolution/parsing** tests -- launcher discovery, env-var precedence,
  JSON extraction past the framework banner -- need no Volatility3 at all and
  always run.
* **Real invocation** tests carry ``requires_vol3`` and auto-skip when no
  launcher resolves (``tests/conftest.py``). ``requires_vol3`` is a conditional
  gate, not ``slow``: putting a proof behind ``slow`` (which ``addopts``
  deselects) would mean it never runs on the one machine that has the launcher.
"""

from __future__ import annotations

import stat
from pathlib import Path

import pytest

from memdiver.engine.vol3_emit import emit_plugin_for_hit
from memdiver.engine.vol3_subproc import (
    VOL3_BIN_ENV,
    VOL3_BIN_PARAM,
    Vol3Launcher,
    VOL3_PYTHON_ENV,
    _parse_json_rows,
    find_vol3_launcher,
    launcher_report,
    plugin_module_name,
    probe_version,
    resolve_launcher,
    run_plugin,
)
from tests._emit_pins import synth_hit
from tests.fixtures.tls_ground_truth import tls_dumps_dir

_REAL_RUN = (
    "TLS12/100_iterations_Abort/openssl/openssl_run_12_1/"
    "20251025_104527_944938_pre_abort.dump"
)


@pytest.fixture
def clean_env(monkeypatch):
    """No inherited launcher configuration, so resolution order is testable."""
    monkeypatch.delenv(VOL3_BIN_ENV, raising=False)
    monkeypatch.delenv(VOL3_PYTHON_ENV, raising=False)
    return monkeypatch


# --------------------------------------------------------------------------- #
# The module must not import volatility3
# --------------------------------------------------------------------------- #

def test_module_does_not_import_volatility3():
    """No ``volatility3`` anywhere in this module's source.

    Deliberate: the module's job is to interrogate a FOREIGN Volatility3
    installation, and importing one into this process would answer a different
    question. It also keeps the module free of any obligation under
    ``tests/test_install_contract.py``'s probe scan.
    """
    import memdiver.engine.vol3_subproc as subproc

    source = Path(subproc.__file__).read_text()
    code_lines = [
        line for line in source.splitlines()
        if line.startswith("import ") or line.startswith("from ")
    ]
    assert not any("volatility3" in line for line in code_lines), code_lines


# --------------------------------------------------------------------------- #
# Launcher resolution
# --------------------------------------------------------------------------- #

def test_env_var_wins_over_path(clean_env, tmp_path, monkeypatch):
    """``MEMDIVER_VOL3_BIN`` beats ``which``.

    A forensics workstation commonly holds three Volatility3 trees that disagree
    on version, so the proof has to be pinnable to a chosen one rather than to
    whichever ``PATH`` happens to expose first.
    """
    pinned = tmp_path / "checkout" / "vol.py"
    pinned.parent.mkdir()
    pinned.write_text("# fake\n")
    clean_env.setenv(VOL3_BIN_ENV, str(pinned))
    monkeypatch.setattr(
        "memdiver.engine.vol3_subproc.shutil.which", lambda name: "/usr/bin/vol",
    )

    launcher = find_vol3_launcher()
    assert isinstance(launcher, Vol3Launcher)
    assert launcher.source == VOL3_BIN_ENV
    assert launcher.argv[-1] == str(pinned.resolve())
    assert launcher.cwd == pinned.parent.resolve(), (
        "cwd must be the launcher's OWN directory -- that shadowing is what "
        "makes a checkout's vol.py load the checkout's framework"
    )


def test_py_launcher_uses_the_configured_interpreter(clean_env, tmp_path):
    """A ``.py`` launcher is run with ``MEMDIVER_VOL3_PYTHON``, not ours.

    A checkout's ``vol.py`` belongs to that checkout's venv; running it under
    MemDiver's interpreter would test MemDiver's framework, which is the very
    confusion this env var exists to remove.
    """
    checkout = tmp_path / "checkout"
    checkout.mkdir()
    (checkout / "vol.py").write_text("# fake\n")
    (checkout / "python").write_text("#!/bin/sh\n")
    clean_env.setenv(VOL3_BIN_ENV, str(checkout / "vol.py"))
    clean_env.setenv(VOL3_PYTHON_ENV, str(checkout / "python"))

    launcher = find_vol3_launcher()
    assert launcher is not None
    assert launcher.python == str(checkout / "python")
    assert launcher.argv[0] == str(checkout / "python")


def test_console_script_launcher_has_no_interpreter(clean_env, tmp_path, monkeypatch):
    binary = tmp_path / "bin" / "vol"
    binary.parent.mkdir()
    binary.write_text("#!/bin/sh\n")
    binary.chmod(binary.stat().st_mode | stat.S_IEXEC)
    monkeypatch.setattr(
        "memdiver.engine.vol3_subproc.shutil.which",
        lambda name: str(binary) if name == "vol" else None,
    )
    launcher = find_vol3_launcher()
    assert launcher is not None
    assert launcher.python is None
    assert launcher.argv == (str(binary.resolve()),)
    assert launcher.source == 'which("vol")'


def test_missing_launcher_path_resolves_to_none(clean_env, tmp_path, monkeypatch):
    """A pinned path that does not exist is ``None``, not a crash.

    Honouring an explicit request INCLUDING its failure -- rather than silently
    falling back to ``PATH`` -- is what keeps the report header truthful.
    """
    clean_env.setenv(VOL3_BIN_ENV, str(tmp_path / "nope" / "vol.py"))
    monkeypatch.setattr(
        "memdiver.engine.vol3_subproc.shutil.which", lambda name: "/usr/bin/vol",
    )
    assert find_vol3_launcher() is None


def test_no_launcher_anywhere_resolves_to_none(clean_env, monkeypatch):
    monkeypatch.setattr(
        "memdiver.engine.vol3_subproc.shutil.which", lambda name: None,
    )
    assert find_vol3_launcher() is None
    assert "not found" in launcher_report()


# --------------------------------------------------------------------------- #
# Launcher selection by PARAMETER, not only by environment
# --------------------------------------------------------------------------- #
#
# ``MEMDIVER_VOL3_BIN`` / ``MEMDIVER_VOL3_PYTHON`` are unreachable from the web
# and MCP surfaces -- nobody sets an environment variable through an HTTP body
# or a tool call -- so env-only configuration could not satisfy the requirement
# that a user be able to point MemDiver at their own ``vol.py``.
# :func:`resolve_launcher` is the parameter form, and these tests pin that the
# parameters WIN over the environment rather than merely supplement it.

def test_vol_bin_parameter_beats_the_env_var(clean_env, tmp_path):
    env_pinned = tmp_path / "env" / "vol.py"
    env_pinned.parent.mkdir()
    env_pinned.write_text("# env\n")
    asked = tmp_path / "asked" / "vol.py"
    asked.parent.mkdir()
    asked.write_text("# asked\n")
    clean_env.setenv(VOL3_BIN_ENV, str(env_pinned))

    launcher = resolve_launcher(vol_bin=str(asked))
    assert launcher is not None
    assert launcher.argv[-1] == str(asked.resolve())
    # And the provenance says WHICH rule produced it: "the caller told us" and
    # "the environment told us" are different facts, and every verification
    # report carries the answer.
    assert launcher.source == VOL3_BIN_PARAM


def test_vol_python_parameter_beats_the_env_var(clean_env, tmp_path):
    checkout = tmp_path / "checkout"
    checkout.mkdir()
    (checkout / "vol.py").write_text("# fake\n")
    (checkout / "env_python").write_text("#!/bin/sh\n")
    (checkout / "asked_python").write_text("#!/bin/sh\n")
    clean_env.setenv(VOL3_PYTHON_ENV, str(checkout / "env_python"))

    launcher = resolve_launcher(
        vol_bin=str(checkout / "vol.py"),
        vol_python=str(checkout / "asked_python"),
    )
    assert launcher is not None
    assert launcher.python == str(checkout / "asked_python")
    assert launcher.argv[0] == str(checkout / "asked_python")


def test_vol_python_alone_still_pins_the_interpreter(clean_env, tmp_path, monkeypatch):
    """The launcher may come off ``PATH`` while the interpreter is named.

    A legitimate combination: ``vol`` is on ``PATH`` but the caller knows which
    venv owns its framework, which is the only thing that decides what loads.
    """
    found = tmp_path / "bin" / "vol.py"
    found.parent.mkdir()
    found.write_text("# fake\n")
    chosen = tmp_path / "bin" / "python"
    chosen.write_text("#!/bin/sh\n")
    monkeypatch.setattr(
        "memdiver.engine.vol3_subproc.shutil.which",
        lambda name: str(found) if name == "vol.py" else None,
    )

    launcher = resolve_launcher(vol_python=str(chosen))
    assert launcher is not None
    assert launcher.python == str(chosen)
    assert launcher.source == 'which("vol.py")'


def test_an_explicit_vol_bin_that_does_not_exist_does_NOT_fall_back(
    clean_env, tmp_path, monkeypatch,
):
    """Honouring a request INCLUDING its failure.

    Silently falling back to ``PATH`` would produce a report header naming a
    launcher the caller never asked for -- which is exactly the confusion this
    whole module's ``cwd``/version discipline exists to remove.
    """
    monkeypatch.setattr(
        "memdiver.engine.vol3_subproc.shutil.which", lambda name: "/usr/bin/vol",
    )
    assert resolve_launcher(vol_bin=str(tmp_path / "nope" / "vol.py")) is None


def test_resolve_launcher_with_no_arguments_is_find_vol3_launcher(clean_env, tmp_path):
    pinned = tmp_path / "checkout" / "vol.py"
    pinned.parent.mkdir()
    pinned.write_text("# fake\n")
    clean_env.setenv(VOL3_BIN_ENV, str(pinned))

    assert resolve_launcher() == find_vol3_launcher()


def test_launcher_report_not_found_names_the_PARAMETER_too(clean_env, monkeypatch):
    """The wording of the "no runtime" refusal every surface raises.

    Naming only the env var would tell a web or MCP caller to do something they
    cannot do.
    """
    monkeypatch.setattr(
        "memdiver.engine.vol3_subproc.shutil.which", lambda name: None,
    )
    report = launcher_report()
    assert "not found" in report
    assert VOL3_BIN_ENV in report
    assert "vol_bin=" in report
    assert "vol_python=" in report


# --------------------------------------------------------------------------- #
# Argument PLACEMENT: global before the target, plugin flags after it
# --------------------------------------------------------------------------- #

def test_plugin_args_are_appended_AFTER_the_target(tmp_path, monkeypatch):
    """``vol``'s CLI is an argparse SUBCOMMAND parser, and this is measured.

    Against the author's 2.27.1 checkout::

        vol.py ... --virtual Pad256.MemDiverScanPad256  -> exit 2,
                                        "unrecognized arguments: --virtual"
        vol.py ... Pad256.MemDiverScanPad256 --virtual   -> exit 0, [] rows
        vol.py ... Pad256.MemDiverScanPad256 --pid 1     -> exit 0, 1 row

    So a plugin flag placed in ``extra_args`` (which sits BEFORE the target, and
    is correct for global ``vol`` options) is a hard error, not a subtlety.
    ``plugin_args`` is the slot that works; no caller in the repo was using
    ``extra_args`` for a plugin flag, so nothing changed behaviour.
    """
    ref, hit, _ = synth_hit()
    plugin = emit_plugin_for_hit(hit, ref, "ArgOrder", tmp_path / "argorder.py")
    dump = tmp_path / "argorder.dump"
    dump.write_bytes(ref)
    seen = {}

    class _Result:
        returncode = 0
        stdout = "Volatility 3 Framework 2.27.1\n\n[]\n"
        stderr = ""

    def _fake_run(argv, cwd, timeout):
        seen["argv"] = list(argv)
        return _Result()

    monkeypatch.setattr("memdiver.engine.vol3_subproc._run", _fake_run)
    launcher = Vol3Launcher(
        argv=("/bin/true",), cwd=tmp_path, python=None, source="test")

    run_plugin(
        launcher, plugin, dump,
        extra_args=("--offline",), plugin_args=("--pid", "1"),
    )

    argv = seen["argv"]
    target = "argorder.ArgOrder"
    assert argv[-2:] == ["--pid", "1"], argv
    assert argv[argv.index(target) - 1] == "--offline", argv
    assert argv.index("--offline") < argv.index(target) < argv.index("--pid")


def test_plugin_args_default_to_nothing(tmp_path, monkeypatch):
    """The historical argv, byte for byte, when no plugin flag is passed."""
    ref, hit, _ = synth_hit()
    plugin = emit_plugin_for_hit(hit, ref, "ArgNone", tmp_path / "argnone.py")
    dump = tmp_path / "argnone.dump"
    dump.write_bytes(ref)
    seen = {}

    class _Result:
        returncode = 0
        stdout = "[]"
        stderr = ""

    monkeypatch.setattr(
        "memdiver.engine.vol3_subproc._run",
        lambda argv, cwd, timeout: (seen.update(argv=list(argv)), _Result())[1],
    )
    launcher = Vol3Launcher(
        argv=("/bin/true",), cwd=tmp_path, python=None, source="test")

    run_plugin(launcher, plugin, dump)

    assert seen["argv"][-1] == "argnone.ArgNone"


# --------------------------------------------------------------------------- #
# Output parsing
# --------------------------------------------------------------------------- #

def test_json_rows_are_parsed_past_the_framework_banner():
    """``vol`` prints its banner to stdout even under ``-q``.

    Measured: ``vol.py -q -r json ...`` emits "Volatility 3 Framework 2.27.1"
    and a blank line before the JSON document, so a bare ``json.loads(stdout)``
    fails on a perfectly good run.
    """
    stdout = 'Volatility 3 Framework 2.27.1\n\n[\n{"KeyOffset": 370672}\n]\n'
    assert _parse_json_rows(stdout) == [{"KeyOffset": 370672}]


def test_json_rows_handles_an_empty_result_set():
    assert _parse_json_rows("Volatility 3 Framework 2.27.1\n\n[]\n") == []


def test_json_rows_wraps_a_bare_object():
    assert _parse_json_rows('{"a": 1}') == [{"a": 1}]


def test_json_rows_on_output_with_no_document():
    assert _parse_json_rows("usage: vol.py [-h]\n") == []


def test_plugin_module_name_reads_the_class_from_the_source(tmp_path):
    """``-p`` PREPENDS to ``volatility3.plugins.__path__``, so the target is
    ``<module stem>.<ClassName>``. The class name is read out of the source
    rather than guessed from the filename because the emitter derives the two
    independently."""
    ref, hit, _ = synth_hit()
    path = emit_plugin_for_hit(hit, ref, "MySubprocPlugin", tmp_path / "myplug.py")
    assert plugin_module_name(path) == "myplug.MySubprocPlugin"


def test_plugin_module_name_rejects_a_source_with_no_class(tmp_path):
    path = tmp_path / "empty.py"
    path.write_text("X = 1\n")
    with pytest.raises(ValueError, match="no plugin class"):
        plugin_module_name(path)


# --------------------------------------------------------------------------- #
# Real invocation
# --------------------------------------------------------------------------- #

@pytest.mark.requires_vol3
def test_launcher_resolves_a_version():
    """The resolved launcher reports a framework version in the supported range.

    This is the hazard guard. On the author's machine the same venv answers
    2.27.1 when ``vol.py`` runs as a script from its own directory and 2.28.2
    when the interpreter merely imports ``volatility3`` from elsewhere, because
    an editable install's finder points at a sibling checkout. ``probe_version``
    therefore probes WITH ``cwd`` set to the launcher's directory, which is the
    only invocation whose answer matches what ``vol.py`` will actually load.
    """
    launcher = find_vol3_launcher()
    assert launcher is not None
    version = probe_version(launcher)
    assert version is not None, launcher.describe()
    assert version[0] == 2, (
        f"emitted plugins declare framework major 2; launcher reports {version}"
    )
    assert version[1] >= 27, f"the `vol` extra floors at 2.27; got {version}"


@pytest.mark.requires_vol3
def test_run_plugin_over_a_synthetic_dump_returns_parsed_rows(tmp_path):
    """The full user-facing path runs and returns a parsed (possibly empty) list.

    What this asserts is narrow on purpose: that ``vol`` accepts the emitted
    plugin's ``-p``/target form, exits zero, and produces JSON this module can
    read. It does NOT assert a hit -- see
    ``test_run_plugin_over_the_real_dump_hits_the_elf_stacker_limitation``.
    """
    launcher = find_vol3_launcher()
    assert launcher is not None
    ref, hit, _ = synth_hit()
    plugin = emit_plugin_for_hit(hit, ref, "SubprocSynth", tmp_path / "subsynth.py")
    dump = tmp_path / "synth.dump"
    dump.write_bytes(ref)

    rows = run_plugin(launcher, plugin, dump)
    assert isinstance(rows, list)
    for row in rows:
        assert "KeyOffset" in row, row


@pytest.mark.requires_vol3
@pytest.mark.requires_dataset
def test_run_plugin_over_the_real_dump_finds_the_key_through_real_vol(tmp_path):
    """The ELF-stacker limitation, FIXED in B5.2 and proved through the real CLI.

    This test used to assert ``rows == []`` and told a future fixer to update it
    deliberately. B5.2 is that fix, so here is the deliberate update.

    **What was wrong.** ``vol`` runs its ``LayerStacker`` automagic first, and
    MemDiver's flat dumps begin with ``7f 45 4c 46`` and carry
    ``e_type = ET_DYN``, so the stacker builds ``['Elf64Layer', 'FileLayer']``
    and bound the plugin's ``primary`` requirement to the ``Elf64Layer`` -- whose
    sections have no size ("Scan Failure: Sections have no size, nothing to
    scan"). The scan saw zero bytes, so the pad-128 plugin that finds this key in
    0.02 s in-process returned ``[]`` through ``vol``.

    **What changed.** The emitted plugin now walks ``layer.dependencies`` down to
    the lowest layer -- the ``FileLayer`` -- unless ``--virtual`` says otherwise.
    Its offsets are FILE offsets, which is the space MemDiver's own output is in,
    so the row that comes back is directly comparable to the in-process one.

    **Measured through the real launcher** (framework 2.27.0): one row,
    ``KeyOffset 370672``, ``PatternOffset 370544``, ``KeyLength 48``, key hex
    byte-identical to ``data[370672:370720]``. Note the single row is also the
    selectivity claim from ``tests/test_vol3_verify.py`` reproduced
    out-of-process: at pad 128 this pattern's anchor carries 18 distinct byte
    values and matches once in 11 MB.
    """
    dump = tls_dumps_dir() / _REAL_RUN
    if not dump.is_file():
        pytest.skip(f"measured ground-truth dump not present: {dump}")
    launcher = find_vol3_launcher()
    assert launcher is not None

    data = dump.read_bytes()
    assert data[:4] == b"\x7fELF", (
        "premise: the stacker fires because this is an ELF -- without that this "
        "test no longer exercises the layer walk at all"
    )

    key_offset, key_length, pad = 370_672, 48, 128
    hit = {
        "offset": key_offset,
        "length": key_length,
        "neighborhood_start": key_offset - pad,
        "neighborhood_variance": (
            [100.0] * pad + [15000.0] * key_length + [50.0] * pad
        ),
    }
    plugin = emit_plugin_for_hit(hit, data, "SubprocReal", tmp_path / "subreal.py")

    rows = run_plugin(launcher, plugin, dump)
    assert len(rows) == 1, (
        "expected exactly one row through the real vol CLI after the B5.2 layer "
        f"walk; got {len(rows)}: {rows[:3]}"
    )
    row = rows[0]
    assert int(row["KeyOffset"]) == key_offset, row
    assert int(row["PatternOffset"]) == key_offset - pad, row
    assert int(row["KeyLength"]) == key_length, row
    assert row["KeyHex"] == data[key_offset:key_offset + key_length].hex(), row

"""``engine.vol3_subproc.VolSpec``: one canonical vol argv, its copy-paste line and its exec request.

Pure units (no process is started). The golden file
``tests/fixtures/vol3_spec/exec_request_golden.json`` pins, for real specs,
``display_command`` -> ``exec_request``; the frontend's
``execRequestFromVolCommand`` must parse every ``display_command`` back into
the same request (``tests/frontend/components/vol3/vol-spec-golden.test.ts``),
so the backend spec and the UI parser cannot drift apart. Regenerate with
``MEMDIVER_REGEN_GOLDEN=1`` after an intended change.
"""

from __future__ import annotations

import itertools
import json
import os
import shlex
from pathlib import Path

import pytest

from memdiver.engine import vol3_subproc
from memdiver.engine.vol3_subproc import NamedPluginRun, Vol3Launcher, VolRun, VolSpec

GOLDEN = Path(__file__).resolve().parent / "fixtures" / "vol3_spec" / "exec_request_golden.json"
LAUNCHER = Vol3Launcher(argv=("/py", "/vol.py"), cwd=Path("/"), python=None, source="t")

#: (field, value) of every optional VolSpec field, in the canonical argv order.
FIELDS = {
    "quiet": (True, ["-q"]),
    "renderer": ("json", ["-r", "json"]),
    "cache_path": ("/c", ["--cache-path", "/c"]),
    "symbol_dirs": (("/s1", "/s 2"), ["-s", "/s1;/s 2", "--offline"]),
    "plugin_dirs": (("/p1", "/p2"), ["-p", "/p1;/p2"]),
    "extra_globals": (("-c", "/cfg"), ["-c", "/cfg"]),
    "output_dir": ("/o", ["-o", "/o"]),
}
OFF = {"quiet": False, "renderer": None, "cache_path": None, "symbol_dirs": (),
       "plugin_dirs": (), "extra_globals": (), "output_dir": None}


@pytest.mark.parametrize("on", list(itertools.product([False, True], repeat=len(FIELDS))))
@pytest.mark.parametrize("args", [(), ("--pid", "7")])
def test_argv_is_canonical_for_every_field_combination(on, args):
    kwargs, expected = dict(OFF), []
    for enabled, (name, (value, rendered)) in zip(on, FIELDS.items()):
        if enabled:
            kwargs[name] = value
            expected += rendered
    spec = VolSpec(plugin="m.C", image="/i", plugin_args=args, **kwargs)
    assert spec.argv(LAUNCHER) == ["/py", "/vol.py", *expected, "-f", "/i", "m.C", *args]
    shown = [w for w in expected if w not in ("--cache-path", "/c")]
    assert shlex.split(spec.display_command()) == ["vol", *shown, "-f", "/i", "m.C", *args]


def test_defaults_are_a_quiet_json_run():
    assert VolSpec(plugin="m.C", image="/i").argv(LAUNCHER)[2:] == [
        "-q", "-r", "json", "-f", "/i", "m.C"]


def test_paths_are_never_resolved():
    spec = VolSpec(plugin="m.C", image="rel/img", plugin_dirs=("rel/p", Path("/var/x")),
                   symbol_dirs=("../s",))
    argv = spec.argv(LAUNCHER)
    assert argv[argv.index("-p") + 1] == "rel/p;/var/x"
    assert argv[argv.index("-s") + 1] == "../s" and argv[argv.index("-f") + 1] == "rel/img"


def test_display_command_never_shows_the_cache_path():
    spec = VolSpec(plugin="m.C", image="/i", cache_path="/secret/cache", renderer=None,
                   quiet=False)
    assert "--cache-path" not in spec.display_command()
    assert "/secret/cache" not in spec.display_command()
    assert "--cache-path" in spec.argv(LAUNCHER)


@pytest.mark.parametrize("name", ["", "-c", "--help", "a..b", "a b", "1x", "x;y"])
def test_a_plugin_name_vol_would_parse_as_an_option_is_refused(name):
    spec = VolSpec(plugin=name, image="/i")
    with pytest.raises(ValueError, match="not a vol plugin name"):
        spec.argv(LAUNCHER)
    with pytest.raises(ValueError):
        spec.display_command()


@pytest.mark.parametrize("arg", ["-p", "-qp/x", "--plugin-dirs=/x", "--plug", "--", "--log"])
def test_a_global_option_among_the_plugin_args_is_refused(arg):
    with pytest.raises(ValueError, match="GLOBAL"):
        VolSpec(plugin="m.C", image="/i", plugin_args=(arg,)).argv(LAUNCHER)


def test_plugin_flags_and_negative_numbers_pass():
    spec = VolSpec(plugin="m.C", image="/i", plugin_args=("--pid", "-1", "--oracle-sample", "/v"))
    assert spec.argv(LAUNCHER)[-4:] == ["--pid", "-1", "--oracle-sample", "/v"]


@pytest.mark.parametrize("field", ["plugin_dirs", "symbol_dirs"])
def test_a_semicolon_in_a_directory_is_refused(field):
    spec = VolSpec(plugin="m.C", image="/i", **{field: ("/ok", "/a;b")})
    with pytest.raises(ValueError, match="may not contain ';'"):
        spec.argv(LAUNCHER)


def test_extra_globals_are_trusted_and_not_checked():
    spec = VolSpec(plugin="m.C", image="/i", extra_globals=("--offline", "-c", "/cfg"))
    argv = spec.argv(LAUNCHER)
    assert argv[argv.index("--offline"):argv.index("-f")] == ["--offline", "-c", "/cfg"]


def test_exec_request_is_plain_strings_and_lists():
    spec = VolSpec(plugin="m.C", image=Path("/i"), plugin_dirs=(Path("/p"),),
                   plugin_args=("--pid", 7), output_dir="/o", cache_path="/c")  # type: ignore[arg-type]
    assert spec.exec_request() == {"plugin": "m.C", "image_path": "/i", "plugin_dirs": ["/p"],
                                   "symbol_dirs": [], "args": ["--pid", "7"]}


def test_named_plugin_run_is_the_vol_run_type():
    assert NamedPluginRun is VolRun
    run = NamedPluginRun(("vol",), 0, [{"a": 1}], "", None)  # positional, as before
    assert run.raise_for_status() is run


def test_named_plugin_spec_resolves_every_path(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    spec = vol3_subproc.named_plugin_spec("msl.info", Path("i"), plugin_dirs=[Path("p")],
                                          symbol_dirs=[Path("s")], output_dir=Path("o"))
    root = tmp_path.resolve()
    assert (spec.image, list(spec.plugin_dirs), list(spec.symbol_dirs), spec.output_dir) == (
        str(root / "i"), [str(root / "p")], [str(root / "s")], str(root / "o"))
    assert (spec.renderer, spec.quiet) == ("json", True)


# --------------------------------------------------------------------------- golden cross-check

SPACED = "/Users/a b/My \"Dumps\"/it's here"


def _golden_specs():
    """Real specs as each surface builds them (synth .msl / full image, exec)."""
    pkg = "/opt/memdiver/vol3plugins"
    plugins = f"{SPACED}/case/vol3/plugins"
    return {
        "synth_msl_dump0": VolSpec(plugin="memdiver_gocryptfs.MemDiverSynthGocryptfs",
                                   image=f"{SPACED}/run_0001/memslicer.msl",
                                   plugin_dirs=(pkg, plugins), renderer=None, quiet=False),
        "synth_msl_oracle_sample": VolSpec(
            plugin="memdiver_gocryptfs.MemDiverSynthGocryptfs",
            image=f"{SPACED}/run_0002/memslicer.msl", plugin_dirs=(pkg, plugins),
            plugin_args=("--oracle-sample", f"{SPACED}/run_0002/cipher dir"),
            renderer=None, quiet=False),
        "synth_full_image_pid_symbols": VolSpec(
            plugin="memdiver_gocryptfs.MemDiverSynthGocryptfs", image=f"{SPACED}/img 4level.lime",
            plugin_dirs=(pkg, plugins), symbol_dirs=(f"{SPACED}/sym a", "/sym/b"),
            plugin_args=("--pid", "9878", "--oracle-sample", f"{SPACED}/vault"),
            cache_path="/tmp/memdiver_vol3_cache_x", renderer=None, quiet=False),
        "exec_quiet_json_out_dir": VolSpec(
            plugin="linux.pslist", image=f"{SPACED}/img.lime", plugin_dirs=(pkg,),
            symbol_dirs=(f"{SPACED}/sym",), output_dir=f"{SPACED}/out"),
        "exec_bare": VolSpec(plugin="msl.info", image="/d.msl"),
        "exec_args_with_equals_and_negative": VolSpec(
            plugin="windows.pslist.PsList", image="/i.raw", plugin_dirs=("/p_q",),
            plugin_args=("--pid=4", "-1", "")),
    }


def _golden_cases():
    return {name: {"display_command": spec.display_command(), "exec_request": spec.exec_request()}
            for name, spec in _golden_specs().items()}


def test_golden_exec_requests_match_the_specs():
    cases = _golden_cases()
    if os.environ.get("MEMDIVER_REGEN_GOLDEN") == "1":
        GOLDEN.parent.mkdir(parents=True, exist_ok=True)
        GOLDEN.write_text(json.dumps(cases, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    assert json.loads(GOLDEN.read_text(encoding="utf-8")) == cases


@pytest.mark.parametrize("name", sorted(_golden_cases()))
def test_golden_display_command_splits_back_into_the_exec_request(name):
    """The same parse the UI does, in Python: ``shlex.split`` + vol's value options."""
    case = _golden_cases()[name]
    words = shlex.split(case["display_command"])
    image = words[words.index("-f") + 1]
    plugin_at = words.index("-f") + 2
    request = case["exec_request"]
    assert (image, words[plugin_at], words[plugin_at + 1:]) == (
        request["image_path"], request["plugin"], request["args"])

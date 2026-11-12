"""``vol3.exec``: ``engine.vol3_subproc.run_named_plugin`` + ``app.tools_vol3_dev.vol3_exec_result``.

Most tests drive a FAKE ``vol.py`` launcher (``vol_bin=`` + ``vol_python=``) that
echoes its argv / environment as JSON rows, so argv order, bounds, refusals and
the ``ok: false`` path run without Volatility 3. Two tests run the real stock
``vol`` (on ``PATH``): ``msl.info`` over a synthetic ``.msl`` and over the
gocryptfs corpus ``run_0001`` (skipped without it).
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

from memdiver.app.tools_pipeline import vol3_plugin_dir
from memdiver.app.tools_vol3_dev import vol3_exec_result
from memdiver.core.service_errors import CapabilityError, ErrorCategory
from memdiver.engine import vol3_subproc
from memdiver.engine.vol3_subproc import Vol3Launcher, named_plugin_argv, run_named_plugin

FAKE_VOL = '''\
import json, os, sys
args = sys.argv[1:]
mode = os.environ.get("FAKE_VOL_MODE", "ok")
sys.stderr.write("Volatility 3 Framework 9.8.7\\n")
if mode == "fail":
    sys.stderr.write("plugin exploded\\n")
    sys.exit(2)
if mode == "big":
    sys.stdout.write("x" * 4096)
    sys.exit(0)
if mode == "sleep":
    import time; time.sleep(30)
if "-o" in args:
    out = args[args.index("-o") + 1]
    open(os.path.join(out, "dumped.bin"), "wb").write(b"z")
rows = [{"argv": args, "nobytecode": os.environ.get("PYTHONDONTWRITEBYTECODE")}]
rows += [{"i": i} for i in range(int(os.environ.get("FAKE_VOL_ROWS", "0")))]
print(json.dumps(rows))
'''


@pytest.fixture
def fake_vol(tmp_path):
    path = tmp_path / "bin" / "vol.py"
    path.parent.mkdir()
    path.write_text(FAKE_VOL, encoding="utf-8")
    return {"vol_bin": str(path), "vol_python": sys.executable}


@pytest.fixture
def image(tmp_path):
    path = tmp_path / "img.msl"
    path.write_bytes(b"MSL\0" + b"\0" * 60)
    return path


def _launcher(fake):
    return vol3_subproc.resolve_launcher(**fake)


# -- engine -------------------------------------------------------------------------

def test_argv_puts_globals_before_the_plugin_and_its_args_after(tmp_path, image):
    launcher = Vol3Launcher(argv=("vol",), cwd=tmp_path, python=None, source="t")
    a, b, s = tmp_path / "a", tmp_path / "b", tmp_path / "s"
    argv = named_plugin_argv(launcher, "msl.info", image, plugin_dirs=[a, b],
                             symbol_dirs=[s], plugin_args=["--pid", "7"],
                             output_dir=tmp_path / "o")
    assert argv == ("vol", "-q", "-r", "json", "-s", str(s.resolve()), "--offline",
                    "-p", f"{a.resolve()};{b.resolve()}", "-o", str((tmp_path / "o").resolve()),
                    "-f", str(image.resolve()), "msl.info", "--pid", "7")


@pytest.mark.parametrize("name", ["", "-c", "--help", "a..b", "a b", "1x", "x;y"])
def test_argv_refuses_a_name_vol_would_parse_as_an_option(tmp_path, image, name):
    launcher = Vol3Launcher(argv=("vol",), cwd=tmp_path, python=None, source="t")
    with pytest.raises(ValueError):
        named_plugin_argv(launcher, name, image)


def test_argv_refuses_a_semicolon_directory(tmp_path, image):
    launcher = Vol3Launcher(argv=("vol",), cwd=tmp_path, python=None, source="t")
    with pytest.raises(ValueError, match="';'"):
        named_plugin_argv(launcher, "msl.info", image, plugin_dirs=[tmp_path / "a;b"])
    with pytest.raises(ValueError, match="';'"):
        named_plugin_argv(launcher, "msl.info", image, symbol_dirs=[tmp_path / "s;t"])


def test_run_named_plugin_parses_rows_and_disables_bytecode(fake_vol, image):
    run = run_named_plugin(_launcher(fake_vol), "msl.info", image, plugin_args=["--x"])
    assert run.returncode == 0 and run.framework == "Volatility 3 Framework 9.8.7"
    assert run.rows[0]["argv"][-2:] == ["msl.info", "--x"]
    assert run.rows[0]["nobytecode"] == "1"
    assert "Framework 9.8.7" in run.stderr_tail


def test_run_named_plugin_reports_a_failure_without_raising(fake_vol, image, monkeypatch):
    monkeypatch.setenv("FAKE_VOL_MODE", "fail")
    run = run_named_plugin(_launcher(fake_vol), "msl.info", image)
    assert run.returncode == 2 and run.rows == [] and "plugin exploded" in run.stderr_tail


def test_run_named_plugin_bounds_stdout(fake_vol, image, monkeypatch):
    monkeypatch.setenv("FAKE_VOL_MODE", "big")
    monkeypatch.setattr(vol3_subproc, "NAMED_STDOUT_CAP", 1024)
    with pytest.raises(RuntimeError, match="1024-byte cap"):
        run_named_plugin(_launcher(fake_vol), "msl.info", image)


def test_run_named_plugin_times_out(fake_vol, image, monkeypatch):
    monkeypatch.setenv("FAKE_VOL_MODE", "sleep")
    with pytest.raises(subprocess.TimeoutExpired):
        run_named_plugin(_launcher(fake_vol), "msl.info", image, timeout=1)


# -- run_vol (the one runner under run_named_plugin / run_plugin / synthesis) ---------

def _spec(image, **kwargs):
    return vol3_subproc.VolSpec(plugin="msl.info", image=str(image), **kwargs)


def test_run_vol_runs_the_spec_argv_without_bytecode(fake_vol, image):
    launcher = _launcher(fake_vol)
    spec = _spec(image, plugin_args=("--x",))
    run = vol3_subproc.run_vol(launcher, spec, timeout=60)
    assert run.argv == tuple(spec.argv(launcher)) and run.returncode == 0
    assert run.rows[0]["argv"] == spec.argv(launcher)[len(launcher.argv):]
    assert run.rows[0]["nobytecode"] == "1"
    assert run.framework == "Volatility 3 Framework 9.8.7"  # read from the stderr tail
    assert run.raise_for_status() is run


def test_run_vol_reports_a_failure_and_raise_for_status_raises(fake_vol, image, monkeypatch):
    monkeypatch.setenv("FAKE_VOL_MODE", "fail")
    run = vol3_subproc.run_vol(_launcher(fake_vol), _spec(image), timeout=60)
    assert run.returncode == 2 and run.rows == [] and "plugin exploded" in run.stderr_tail
    with pytest.raises(RuntimeError) as info:
        run.raise_for_status()
    assert str(info.value) == f"vol exited 2: {run.stderr_tail.strip()}"


def test_raise_for_status_keeps_the_last_2000_characters():
    run = vol3_subproc.VolRun(("vol",), 1, [], "head " + "x" * 3000 + " tail\n", None)
    with pytest.raises(RuntimeError) as info:
        run.raise_for_status()
    message = str(info.value)
    assert message.startswith("vol exited 1: ") and message.endswith(" tail")
    assert len(message) == len("vol exited 1: ") + 2000 and "head" not in message


def test_run_vol_bounds_stdout_and_keeps_only_the_stderr_tail(fake_vol, image, monkeypatch):
    launcher = _launcher(fake_vol)
    monkeypatch.setenv("FAKE_VOL_MODE", "big")
    with pytest.raises(RuntimeError, match="1024-byte cap"):
        vol3_subproc.run_vol(launcher, _spec(image), timeout=60, stdout_cap=1024)
    monkeypatch.setenv("FAKE_VOL_MODE", "fail")
    run = vol3_subproc.run_vol(launcher, _spec(image), timeout=60, stderr_tail=16)
    assert run.stderr_tail == "plugin exploded\n"  # 16 bytes: the banner line is cut


def test_run_vol_times_out(fake_vol, image, monkeypatch):
    monkeypatch.setenv("FAKE_VOL_MODE", "sleep")
    with pytest.raises(subprocess.TimeoutExpired):
        vol3_subproc.run_vol(_launcher(fake_vol), _spec(image), timeout=1)


def test_run_vol_refuses_a_bad_spec_before_spawning(fake_vol, image, monkeypatch):
    monkeypatch.setattr(vol3_subproc, "run_cancellable", None)  # must not be reached
    with pytest.raises(ValueError, match="GLOBAL"):
        vol3_subproc.run_vol(_launcher(fake_vol), _spec(image, plugin_args=("-p",)), timeout=5)


def test_run_plugin_raises_with_the_stderr_tail(fake_vol, image, tmp_path, monkeypatch):
    """``run_plugin``'s error is ``raise_for_status``'s: the tail, where vol's traceback is."""
    plugin = tmp_path / "pp.py"
    plugin.write_text("class Pp(object):\n    pass\n")
    monkeypatch.setenv("FAKE_VOL_MODE", "fail")
    with pytest.raises(RuntimeError, match=r"(?s)^vol exited 2: .*plugin exploded$"):
        vol3_subproc.run_plugin(_launcher(fake_vol), plugin, image)
    monkeypatch.setenv("FAKE_VOL_MODE", "ok")
    (row,) = vol3_subproc.run_plugin(_launcher(fake_vol), plugin, image, extra_args=["-c", "x"])
    assert row["argv"][-5:] == ["-c", "x", "-f", str(image.resolve()), "pp.Pp"]
    assert row["nobytecode"] == "1"


# -- producer -----------------------------------------------------------------------

def test_exec_result_payload_and_memdiver_plugins_first(fake_vol, image, tmp_path):
    extra = tmp_path / "extra"
    extra.mkdir()
    payload = vol3_exec_result("msl.info", str(image), plugin_dirs=[str(extra)],
                               args=["--pid", 3], **fake_vol).payload
    package = vol3_plugin_dir()["path"]
    assert payload["ok"] is True and payload["returncode"] == 0
    assert payload["plugin_dirs"] == [package, str(extra.resolve())]
    argv = payload["rows"][0]["argv"]
    assert argv[argv.index("-p") + 1] == f"{package};{extra.resolve()}"
    assert payload["args"] == ["--pid", "3"] and argv[-3:] == ["msl.info", "--pid", "3"]
    assert payload["framework"] == "Volatility 3 Framework 9.8.7"
    assert payload["out_dir"] is None and payload["output_files"] == ["dumped.bin"]
    assert payload["vol_command"].startswith("vol -q -r json -p ")
    assert " -o " not in payload["vol_command"]  # the discarded scratch dir is not named


def test_exec_result_without_memdiver_plugins_and_with_out_dir(fake_vol, image, tmp_path):
    out = tmp_path / "out"
    payload = vol3_exec_result("msl.info", str(image), include_memdiver_plugins=False,
                               out_dir=str(out), **fake_vol).payload
    assert payload["plugin_dirs"] == [] and "-p" not in payload["rows"][0]["argv"]
    assert payload["out_dir"] == str(out.resolve()) and (out / "dumped.bin").is_file()
    assert f"-o {out.resolve()}" in payload["vol_command"]


def test_exec_result_caps_rows(fake_vol, image, monkeypatch):
    monkeypatch.setenv("FAKE_VOL_ROWS", "10")
    payload = vol3_exec_result("msl.info", str(image), max_rows=4, **fake_vol).payload
    assert payload["row_count"] == 11 and len(payload["rows"]) == 4 and payload["truncated"]


def test_exec_result_failing_plugin_is_ok_false(fake_vol, image, monkeypatch):
    monkeypatch.setenv("FAKE_VOL_MODE", "fail")
    payload = vol3_exec_result("msl.info", str(image), **fake_vol).payload
    assert payload["ok"] is False and payload["returncode"] == 2
    assert "plugin exploded" in payload["stderr_tail"] and payload["rows"] == []


def test_exec_result_timeout_is_a_504(fake_vol, image, monkeypatch):
    monkeypatch.setenv("FAKE_VOL_MODE", "sleep")
    with pytest.raises(CapabilityError) as exc:
        vol3_exec_result("msl.info", str(image), timeout_s=1, **fake_vol)
    assert exc.value.code == "vol3.exec.timeout" and exc.value.status == 504


def _code(**kwargs):
    with pytest.raises(CapabilityError) as exc:
        vol3_exec_result(**kwargs)
    return exc.value


def test_exec_result_refuses_history_directories(fake_vol, image, tmp_path):
    case = tmp_path / "case"
    (case / "vol3" / "history").mkdir(parents=True)
    (case / "vol3" / "plugins").mkdir()
    for bad in (case, case / "vol3", case / "vol3" / "history"):
        err = _code(plugin="msl.info", image_path=str(image), plugin_dirs=[str(bad)],
                    **fake_vol)
        assert err.code == "vol3.exec.history_dir", bad
    nested = case / "vol3" / "history" / "deeper"
    nested.mkdir()
    assert _code(plugin="msl.info", image_path=str(image), plugin_dirs=[str(nested)],
                 **fake_vol).code == "vol3.exec.history_dir"
    ok = vol3_exec_result("msl.info", str(image), plugin_dirs=[str(case / "vol3" / "plugins")],
                          **fake_vol).payload
    assert ok["ok"] is True


def test_exec_result_refuses_semicolons_in_plugin_and_symbol_dirs(fake_vol, image, tmp_path):
    bad = tmp_path / "a;b"
    bad.mkdir()
    for key in ("plugin_dirs", "symbol_dirs"):
        err = _code(plugin="msl.info", image_path=str(image), **{key: [str(bad)]}, **fake_vol)
        assert err.code == "vol3.exec.semicolon_in_path", key


def test_exec_result_input_errors(fake_vol, image, tmp_path):
    assert _code(plugin="", image_path=str(image)).code == "vol3.exec.plugin_required"
    assert _code(plugin="msl.info", image_path=str(tmp_path / "nope")).category \
        == ErrorCategory.NOT_FOUND
    assert _code(plugin="msl.info", image_path=str(image),
                 plugin_dirs=[str(tmp_path / "missing")]).category == ErrorCategory.NOT_FOUND
    assert _code(plugin="msl.info", image_path=str(image), args="--pid 1",
                 **fake_vol).code == "vol3.exec.bad_args"
    assert _code(plugin="-c", image_path=str(image), **fake_vol).code == "vol3.exec.failed"
    err = _code(plugin="msl.info", image_path=str(image), vol_bin=str(tmp_path / "no_vol"))
    assert err.category == ErrorCategory.UNSUPPORTED and err.code == "vol3.exec.no_launcher"


# -- real stock vol -----------------------------------------------------------------

needs_vol = pytest.mark.skipif(shutil.which("vol") is None, reason="stock `vol` not on PATH")


def _info(payload):
    return {row["Variable"]: row["Value"] for row in payload["rows"]}


@needs_vol
def test_real_vol_runs_msl_info_on_a_synthetic_slice(tmp_path):
    pytest.importorskip("volatility3")
    from tests.test_vol3plugins_msl_layer import _write_slice
    path = tmp_path / "plain.msl"
    _write_slice(path)
    payload = vol3_exec_result("msl.info", str(path)).payload
    assert payload["ok"] is True, payload["stderr_tail"]
    info = _info(payload)
    assert info["OS"] == "LINUX" and info["File"] == str(path.resolve())
    assert payload["framework"] and payload["framework"].startswith("Volatility 3 Framework")


GOCRYPTFS_RUN_0001 = Path(os.environ.get("MEMDIVER_GOCRYPTFS_CORPUS", "") or "/nonexistent") / "run_0001"


@needs_vol
@pytest.mark.skipif(not (GOCRYPTFS_RUN_0001 / "memslicer.msl").is_file(),
                    reason="gocryptfs corpus run_0001 absent")
def test_real_vol_runs_msl_info_on_gocryptfs_run_0001():
    import json
    meta = json.loads((GOCRYPTFS_RUN_0001 / "meta.json").read_text())
    payload = vol3_exec_result("msl.info", str(GOCRYPTFS_RUN_0001 / "memslicer.msl")).payload
    assert payload["ok"] is True, payload["stderr_tail"]
    info = _info(payload)
    assert info["OS"] == "LINUX" and str(meta["pid"]) in json.dumps(payload["rows"])


# -- review fixes: vol GLOBAL options smuggled through plugin args ------------------

SMUGGLED = [
    ["-p", "/x"], ["-p/x"], ["-qp/x"], ["-l", "/x.log"], ["-s", "/x"], ["-u", "http://x"],
    ["--plugin-dirs", "/x"], ["--plugin-dirs=/x"], ["--plugin=/x"], ["--plug", "/x"],
    ["--log=/x"], ["--lo", "/x"], ["--cache-path", "/x"], ["--clear-cache"],
    ["--parallelism", "off"], ["--symbol-dirs=/x"], ["--remote-isf-url", "http://x"],
    ["--offline"], ["--output-dir", "/x"], ["--config", "/x"], ["--"], ["--pid", "1", "-p", "/x"],
]


@pytest.mark.parametrize("args", SMUGGLED, ids=lambda a: " ".join(a))
def test_global_vol_options_after_the_plugin_are_refused(args, fake_vol, image, tmp_path):
    launcher = Vol3Launcher(argv=("vol",), cwd=tmp_path, python=None, source="t")
    with pytest.raises(ValueError, match="GLOBAL"):
        named_plugin_argv(launcher, "msl.info", image, plugin_args=args)
    assert _code(plugin="msl.info", image_path=str(image), args=args,
                 **fake_vol).code == "vol3.exec.global_option"


@pytest.mark.parametrize("args", [["--pid", "1"], ["--oracle-sample", "/v"], ["--pid", "-1"],
                                  ["--dump"], ["--export", "dmsetup"], ["-"], ["--btf-method=auto"]])
def test_plugin_long_options_still_pass(args, fake_vol, image):
    payload = vol3_exec_result("msl.info", str(image), args=args, **fake_vol).payload
    assert payload["ok"] and payload["rows"][0]["argv"][-len(args):] == args


def _launchers_for_help():
    found = [shutil.which("vol")]
    alt = os.environ.get("MEMDIVER_VOL3_ALT_VOL_PY", "")
    if alt and Path(alt).is_file():
        found.append(alt)
    return [f for f in found if f]


@pytest.mark.parametrize("launcher", _launchers_for_help())
def test_pinned_global_options_cover_the_launchers_help(launcher):
    """Every global long option a real vol (2.27.0 on PATH, 2.28.2 when present) prints is pinned."""
    import re
    argv = [sys.executable, launcher] if launcher.endswith(".py") else [launcher]
    cwd = str(Path(launcher).parent)
    help_text = subprocess.run([*argv, "-h"], capture_output=True, text=True, cwd=cwd,
                               timeout=120).stdout
    usage = help_text.split("Plugins", 1)[0]
    printed = set(re.findall(r"--([a-z][a-z-]+)", usage))
    assert printed and "plugin-dirs" in printed
    assert printed <= set(vol3_subproc.VOL_GLOBAL_LONG_OPTIONS), printed - set(
        vol3_subproc.VOL_GLOBAL_LONG_OPTIONS)


# -- review fixes: history walk -----------------------------------------------------

def test_history_refusal_is_casefolded_and_follows_symlinks(fake_vol, image, tmp_path):
    case = tmp_path / "case"
    (case / "vol3" / "history").mkdir(parents=True)
    (case / "vol3" / "plugins").mkdir()
    upper = tmp_path / "Other" / "VOL3" / "HISTORY"
    upper.mkdir(parents=True)
    link_to_history = tmp_path / "h"
    link_to_history.symlink_to(case / "vol3" / "history")
    (case / "vol3" / "plugins" / "link").symlink_to(case / "vol3")
    for bad in (upper, tmp_path / "Other", link_to_history, case / "vol3" / "plugins"):
        assert _code(plugin="msl.info", image_path=str(image), plugin_dirs=[str(bad)],
                     **fake_vol).code == "vol3.exec.history_dir", bad


def test_history_walk_survives_a_symlink_loop(fake_vol, image, tmp_path):
    plugins = tmp_path / "plugins"
    (plugins / "sub").mkdir(parents=True)
    (plugins / "sub" / "loop").symlink_to(plugins)
    payload = vol3_exec_result("msl.info", str(image), plugin_dirs=[str(plugins)],
                               **fake_vol).payload
    assert payload["ok"] is True


def test_history_walk_is_bounded(fake_vol, image, tmp_path, monkeypatch):
    from memdiver.app import tools_vol3_dev
    plugins = tmp_path / "plugins"
    for i in range(5):
        (plugins / f"d{i}").mkdir(parents=True)
    monkeypatch.setattr(tools_vol3_dev, "HISTORY_WALK_MAX_DIRS", 3)
    assert _code(plugin="msl.info", image_path=str(image), plugin_dirs=[str(plugins)],
                 **fake_vol).code == "vol3.exec.plugin_dir_too_large"
    monkeypatch.setattr(tools_vol3_dev, "HISTORY_WALK_MAX_DIRS", 100)
    monkeypatch.setattr(tools_vol3_dev, "HISTORY_WALK_MAX_DEPTH", 0)
    assert _code(plugin="msl.info", image_path=str(image), plugin_dirs=[str(plugins)],
                 **fake_vol).code == "vol3.exec.plugin_dir_too_large"


def test_exec_output_files_lists_only_what_this_run_wrote(fake_vol, image, tmp_path):
    """A reused out_dir keeps files from before the run: they are not this run's output,
    while a pre-existing file the plugin rewrites IS (new mtime)."""
    out = tmp_path / "reused"
    out.mkdir()
    (out / "stale_from_last_week.txt").write_text("old")
    (out / "dumped.bin").write_bytes(b"old")
    os.utime(out / "dumped.bin", (1_000_000, 1_000_000))
    payload = vol3_exec_result("msl.info", str(image), out_dir=str(out), **fake_vol).payload
    assert payload["output_files"] == ["dumped.bin"]
    assert (out / "stale_from_last_week.txt").is_file()  # still there, just not reported

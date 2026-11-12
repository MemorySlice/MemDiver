"""``synthesize_vol3_plugin(full_image=..., pid=...)`` on an image of ANOTHER session.

A plugin synthesized from the gocryptfs ``.msl`` corpus is run under stock
``vol`` over a full kernel image narrowed with ``--pid``. The image's gocryptfs
daemon has its own key and vault, so the producer takes the image's own oracle
sample (``full_image_sample``), the ISF directory (``symbol_dirs`` ->
``-s ... --offline``) and reports whether ``--pid`` was honoured.

Unit tests cover the helpers; a synthetic test runs stock ``vol`` on a third
``.msl`` session; the corpus test (``MEMDIVER_SECRETS_CORPUS`` = absolute path
of the acquired-secrets capture dir, plus the gocryptfs ``.msl`` corpus) does
the real thing: the vault is recovered from the image's PAGE CACHE with
``linux.pagecache.Files`` / ``InodePages --dump``, checked against the
sidecar key, then the synthesized plugin must prove the sidecar key inside
the daemon's address space. Set ``MEMDIVER_VOL3_ALT_VOL_PY`` to a second
``vol.py`` (e.g. vol 2.28.2) to re-run the returned ``vol_command`` under it.
"""

from __future__ import annotations

import hashlib
import json
import os
import shlex
import shutil
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

from memdiver.app import tools_pipeline as tp
from memdiver.app import vol3_synth
from memdiver.core.service_errors import CapabilityError, FileNotFoundServiceError
from memdiver.engine import vol3_subproc
from memdiver.msl.enums import ArchType, OSType
from memdiver.msl.writer import MslWriter
from memdiver.oracles.formats import gocryptfs_gcm
from memdiver.services import synthesize_vol3_plugin, vol3_plugin_dir
from tests import _vol3_recipe_fixtures as fx
from tests._oracle_gocryptfs_fixtures import GOCRYPTFS_CORPUS, HAVE_CORPUS

REPO = Path(__file__).resolve().parents[1]
KIND = fx.KIND
THIRD_MASTER = hashlib.sha256(b"a third gocryptfs session").digest()
REGION_VA = 0x7F0000000000


def _row(offset, key_hex, proven):
    return {"KeyOffset": offset, "PatternOffset": offset - 64, "KeyHex": key_hex,
            "Proven": proven}


# --------------------------------------------------------------------------- helpers (unit)

def _symbol_globals(symbol_dirs):
    """The ``-s ... --offline`` a full-image display spec renders for *symbol_dirs*."""
    spec = tp._synth_display_spec("/pkg", Path("/pl"), "m.C", Path("/i"), (),
                                  tp._synth_paths(symbol_dirs))
    argv = shlex.split(spec.display_command())
    return argv[1:argv.index("-p")]


def test_symbol_globals_join_dirs_with_semicolon_and_go_offline(tmp_path):
    assert _symbol_globals(()) == []
    root = tmp_path.resolve()
    got = _symbol_globals([str(tmp_path / "a"), tmp_path / "b"])
    assert got == ["-s", f"{root / 'a'};{root / 'b'}", "--offline"]


@pytest.mark.parametrize("single", ["str", "path"])
def test_symbol_globals_accept_one_path_not_split_into_characters(tmp_path, single):
    value = str(tmp_path / "sym") if single == "str" else tmp_path / "sym"
    assert _symbol_globals(value) == ["-s", str((tmp_path / "sym").resolve()), "--offline"]


def test_relative_symbol_dir_is_made_absolute(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    assert _symbol_globals("sym")[1] == str((tmp_path / "sym").resolve())


def test_semicolon_in_a_vol_path_is_refused():
    tp._synth_refuse_semicolon(["/a/b", None, ""], "x")
    with pytest.raises(CapabilityError) as info:
        tp._synth_refuse_semicolon(["/a;b"], "symbol_dirs")
    assert info.value.code == "synth.vol3_plugin.semicolon_in_path"


def test_bounded_read_keeps_the_tail_or_refuses(tmp_path):
    import tempfile

    with tempfile.TemporaryFile() as handle:
        handle.write(b"x" * 10 + b"TAIL")
        assert vol3_subproc.read_spooled(handle, 4, tail=True) == "TAIL"
        assert vol3_subproc.read_spooled(handle, 100, tail=False) == "x" * 10 + "TAIL"
        with pytest.raises(RuntimeError, match="cap"):
            vol3_subproc.read_spooled(handle, 4, tail=False)


def test_pid_honoured_falls_back_to_the_plugin_warnings():
    warning = "WARNING ... --pid [9878] could NOT be honoured (no kernel module, ...)"
    mismatch = "WARNING ... --pid [7]: this .msl slice holds pid 42; scanning it anyway"
    assert tp._synth_pid_honoured(None, warning) is None
    assert tp._synth_pid_honoured(9878, warning) is False
    assert tp._synth_pid_honoured(7, mismatch) is False
    assert tp._synth_pid_scope(7, [], mismatch) == "msl_mismatch"
    assert tp._synth_pid_honoured(9878, "Volatility 3 Framework 2.27.0\n") is None


@pytest.mark.parametrize("scopes, pid, expected", [
    (["process:9878", "process:9878"], 9878, "process"),
    (["process:9878", "physical"], 9878, "physical"),
    (["process:1"], 9878, "physical"),
    (["msl:42"], 42, "msl"),
    (["msl:42"], 7, "msl_mismatch"),
])
def test_pid_scope_reads_the_scope_column_first(scopes, pid, expected):
    rows = [{"Scope": s} for s in scopes]
    # the column wins over a contradicting stderr line
    assert tp._synth_pid_scope(pid, rows, "could NOT be honoured") == expected
    assert tp._synth_pid_honoured(pid, "", rows) is (expected in ("process", "msl"))


def test_merged_pid_scope_lets_any_failure_win():
    assert tp._synth_merge_pid_scopes([]) is None
    assert tp._synth_merge_pid_scopes([None, "process"]) == "process"
    assert tp._synth_merge_pid_scopes(["process", "physical"]) == "physical"
    assert tp._synth_merge_pid_scopes(["msl", "msl_mismatch"]) == "msl_mismatch"


def _display(plugin_dir):
    """A full-image verdict's ``command``: dump + extra args -> its display ``VolSpec``."""
    return lambda dump, extra: tp._synth_display_spec("/p", plugin_dir, "m.C", dump, extra)


def test_crashed_vol_leaves_pid_honoured_unknown(tmp_path, monkeypatch):
    def crash(*_args, **_kwargs):
        raise RuntimeError("vol exited 1: crash")
    monkeypatch.setattr(vol3_synth, "_synth_image_run", crash)
    verdict = tp._synth_verify_full_image(
        plugin_dir=tmp_path, target="m.C", image=tmp_path / "i", pid=7, keys=[b"\1" * 32],
        samples=[None], kind=KIND, pkg_dir="/p",
        launcher=SimpleNamespace(argv=("vol",), cwd=tmp_path), command=_display(tmp_path))
    assert verdict["status"] == "error" and verdict["pid_honoured"] is None
    assert tp._synth_pid_diagnostics([verdict]) == []


def test_image_args_without_full_image_warn():
    (diag,) = tp._synth_image_args_diagnostics(None, "/vault", "aa" * 32)
    assert diag["code"] == tp.SYNTH_IMAGE_ARGS_IGNORED_CODE
    assert "full_image_sample and full_image_key_hex" in diag["message"]
    assert "aa" * 32 not in diag["message"]
    assert tp._synth_image_args_diagnostics("/img", "/vault", "") == []
    assert tp._synth_image_args_diagnostics(None, None, "") == []


def test_image_rows_proven_without_key_trusts_the_oracle_only():
    rows = [_row(0x100, "aa" * 32, f"oracle:{KIND}"), _row(0x200, "bb" * 32, "rejected"),
            _row(0x300, "cc" * 32, "oracle:other-kind")]
    assert [h["key_offset"] for h in tp._synth_rows_proven(rows, KIND, None)] == [0x100]
    assert tp._synth_rows_proven(rows, KIND, bytes.fromhex("aa" * 32))[0]["key_offset"] == 0x100
    assert tp._synth_rows_proven(rows, KIND, bytes.fromhex("dd" * 32)) == []


def test_image_attempts_try_the_image_sample_first():
    keys, samples = [b"\x01" * 32, b"\x02" * 32], ["/s1", "/s2"]
    got = tp._synth_image_attempts(keys, samples, "/img_vault", None)
    assert got[0] == (None, None, ["--oracle-sample", str(Path("/img_vault").resolve())])
    dumps = [(0, keys[0], []), (1, keys[1], ["--oracle-sample", str(Path("/s2").resolve())])]
    assert got[1:] == dumps
    assert tp._synth_image_attempts(keys, samples, None, None) == dumps


def test_image_attempts_skip_a_repeated_key_and_sample():
    keys = [b"\x01" * 32, b"\x01" * 32, b"\x02" * 32, b"\x02" * 32]
    got = tp._synth_image_attempts(keys, [None, None, "/s", "/s"], None, None)
    assert [index for index, _, _ in got] == [0, 2]


def test_image_attempts_skip_a_sample_equal_to_the_inlined_one():
    # A broadcast sample is dump 0's (inlined) sample: passing it again is no new attempt.
    key = b"\x01" * 32
    got = tp._synth_image_attempts([key, key, key], ["/s", "/s", "/s"], None, None)
    assert got == [(0, key, [])]


def test_attempts_with_the_same_argv_share_one_vol_run(tmp_path, monkeypatch):
    calls = []

    def fake_run(_launcher, display, **kwargs):
        calls.append(display.argv(SimpleNamespace(argv=("vol",))))
        return [_row(0x200, "02" * 32, f"oracle:{KIND}")], ""
    monkeypatch.setattr(vol3_synth, "_synth_image_run", fake_run)
    verdict = tp._synth_verify_full_image(
        plugin_dir=tmp_path, target="m.C", image=tmp_path / "i", pid=None,
        keys=[b"\x01" * 32, b"\x02" * 32], samples=[None, None], kind=KIND, pkg_dir="/p",
        launcher=SimpleNamespace(argv=("vol",), cwd=tmp_path), command=_display(tmp_path))
    assert len(calls) == 1  # dump 1's key is checked against dump 0's rows, not re-scanned
    assert verdict["status"] == "proven" and verdict["matched_dump_index"] == 1


def test_expected_image_key_filters_every_attempt():
    keys, samples = [b"\x01" * 32, b"\x02" * 32], ["/s1", "/s2"]
    for image_sample in ("/img_vault", None):
        got = tp._synth_image_attempts(keys, samples, image_sample, b"\x03" * 32)
        assert {key for _, key, _ in got} == {b"\x03" * 32}


def test_relative_sample_paths_are_made_absolute(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    got = tp._synth_image_attempts([b"\x01" * 32, b"\x02" * 32], ["s1", "s2"], "img", None)
    assert [args[1] for _, _, args in got if args] == [
        str((tmp_path / name).resolve()) for name in ("img", "s2")]


def test_image_evidence_checks_the_path_and_never_echoes_the_key(tmp_path):
    assert tp._synth_image_evidence(None, "") == (None, None)
    path, key = tp._synth_image_evidence(str(tmp_path), "aa" * 32)
    assert path == str(tmp_path) and key == bytes.fromhex("aa" * 32)
    with pytest.raises(FileNotFoundServiceError):
        tp._synth_image_evidence(str(tmp_path / "missing"), "")
    bad = "zz" + "ab" * 31
    with pytest.raises(CapabilityError) as info:
        tp._synth_image_evidence(None, bad)
    assert bad not in str(info.value) and info.value.code == "synth.vol3_plugin.invalid_key"


def test_pid_diagnostics_warn_only_for_unhonoured_pid():
    verdicts = [{"name": "a.lime", "dump_path": "/a.lime", "pid_honoured": False},
                {"name": "b.lime", "dump_path": "/b.lime", "pid_honoured": True},
                {"name": "c.msl", "dump_path": "/c.msl"}]
    (diag,) = tp._synth_pid_diagnostics(verdicts)
    assert diag["code"] == tp.SYNTH_PID_UNHONOURED_CODE and "a.lime" in diag["message"]


def test_vol_command_and_argv_put_symbol_globals_before_plugin_dirs(monkeypatch):
    globals_ = ["-s", "/sym", "--offline"]
    display = tp._synth_display_spec("/pkg", Path("/pl"), "m.C", Path("/i.lime"),
                                     ["--pid", "7"], ["/sym"])
    command = shlex.split(display.display_command())
    assert command[:4] == ["vol", *globals_] and command[4] == "-p"
    assert command[-3:] == ["m.C", "--pid", "7"]
    assert tp._synth_display_spec("/pkg", Path("/pl"), "m.C", Path("/i")).display_command() == \
        "vol -p '/pkg;/pl' -f /i m.C"
    seen = {}

    def fake_run_vol(launcher, spec, **kwargs):
        seen.update(argv=spec.argv(launcher), **kwargs)
        return vol3_subproc.VolRun(tuple(seen["argv"]), 0, [], "", None)
    monkeypatch.setattr(vol3_subproc, "run_vol", fake_run_vol)
    tp._synth_image_run(SimpleNamespace(argv=("vol",)), display,
                        plugin_dirs=("/pkg", Path("/real/pl")), cache="/c")
    argv = seen["argv"]
    assert argv == ["vol", "-q", "-r", "json", "--cache-path", "/c", *globals_,
                    "-p", "/pkg;/real/pl", "-f", "/i.lime", "m.C", "--pid", "7"]
    assert (seen["stdout_cap"], seen["stderr_tail"]) == (tp.SYNTH_VOL_STDOUT_CAP,
                                                         tp.SYNTH_VOL_STDERR_TAIL)


def test_image_run_raises_with_the_stderr_tail_as_before(monkeypatch):
    """The verdict's ``error`` text is unchanged: ``vol exited <rc>: <last 2000 chars>``."""
    tail = "x" * 3000 + "Traceback: boom\n"
    monkeypatch.setattr(vol3_subproc, "run_vol",
                        lambda *a, **k: vol3_subproc.VolRun(("vol",), 2, [], tail, None))
    display = tp._synth_display_spec("/pkg", Path("/pl"), "m.C", Path("/i"))
    with pytest.raises(RuntimeError) as info:
        tp._synth_image_run(SimpleNamespace(argv=("vol",)), display, plugin_dirs=("/p",),
                            cache="/c")
    assert str(info.value) == f"vol exited 2: {tail.strip()[-2000:]}"


def test_every_verdict_carries_the_exec_request_of_its_vol_command(tmp_path, monkeypatch):
    monkeypatch.setattr(vol3_synth, "_synth_image_run",
                        lambda *a, **k: ([_row(0x200, "01" * 32, f"oracle:{KIND}")], ""))
    verdict = tp._synth_verify_full_image(
        plugin_dir=tmp_path, target="m.C", image=tmp_path / "i", pid=7, keys=[b"\1" * 32],
        samples=[None], kind=KIND, pkg_dir="/p",
        launcher=SimpleNamespace(argv=("vol",), cwd=tmp_path), command=_display(tmp_path))
    image = str((tmp_path / "i").resolve())
    assert verdict["exec"] == {"plugin": "m.C", "image_path": image,
                               "plugin_dirs": ["/p", str(tmp_path)], "symbol_dirs": [],
                               "args": ["--pid", "7"]}
    assert verdict["vol_command"] == shlex.join(
        ["vol", "-p", f"/p;{tmp_path}", "-f", image, "m.C", "--pid", "7"])


# --------------------------------------------------------------------------- synthetic, stock vol

def _write_msl(path: Path, master: bytes) -> Path:
    writer = MslWriter(path, pid=4242, os_type=OSType.LINUX, arch_type=ArchType.X86_64)
    writer.add_memory_region(REGION_VA, fx.process_buffer(master))
    writer.add_end_of_capture()
    writer.write()
    return path


@pytest.fixture
def sessions(tmp_path):
    """Two learning sessions + a third 'image' session with its own key and vault."""
    out = []
    for label, master in (("a", fx.MASTER), ("b", fx.OTHER_MASTER), ("image", THIRD_MASTER)):
        run = tmp_path / f"run_{label}"
        run.mkdir()
        out.append({"msl": str(_write_msl(run / "memslicer.msl", master)),
                    "vault": str(fx.write_vault(run / "cipher", master=master)),
                    "key": master.hex()})
    (tmp_path / "case").mkdir()
    return out


def _synth_on_image(sessions, tmp_path, **kwargs):
    learn, image = sessions[:2], sessions[2]
    return synthesize_vol3_plugin(
        dump_paths=[r["msl"] for r in learn], name="memdiver_gocryptfs_img",
        key_hex=[r["key"] for r in learn], oracle_kind=KIND,
        oracle_sample_path=[r["vault"] for r in learn], case_dir=str(tmp_path / "case"),
        verify_on=(), full_image=image["msl"], full_image_sample=image["vault"], **kwargs)


@pytest.mark.skipif(shutil.which("vol") is None, reason="stock `vol` not on PATH")
def test_image_of_another_session_is_proven_by_its_own_sample(sessions, tmp_path):
    pytest.importorskip("cryptography")
    image = sessions[2]
    result = _synth_on_image(sessions, tmp_path, full_image_key_hex=image["key"])
    (verdict,) = result["verdicts"]
    assert verdict["status"] == "proven", verdict
    assert verdict["matched_dump_index"] is None and verdict["image_sample"] is True
    assert verdict["proven_by_image_sample"] is True
    assert verdict["pid_honoured"] is None
    assert {h["key_offset"] for h in verdict["proven_hits"]} == {
        REGION_VA + site for site in fx.KEY_SITES}
    assert f"--oracle-sample {image['vault']}" in verdict["vol_command"]
    assert image["key"] not in json.dumps(result, default=str)


@pytest.mark.skipif(shutil.which("vol") is None, reason="stock `vol` not on PATH")
def test_wrong_expected_image_key_is_not_proven(sessions, tmp_path):
    """The image IS learning session a, but the expected key is another: the corpus
    fallback (which would prove a's own key) must not turn that into proven."""
    pytest.importorskip("cryptography")
    sessions[2]["msl"] = sessions[0]["msl"]
    result = _synth_on_image(sessions, tmp_path, full_image_key_hex=THIRD_MASTER.hex())
    (verdict,) = result["verdicts"]
    assert verdict["status"] == "not_proven" and result["proven"] is False
    assert verdict["proven_by_image_sample"] is False


@pytest.mark.skipif(shutil.which("vol") is None, reason="stock `vol` not on PATH")
def test_expected_image_key_without_sample_filters_the_corpus_attempts(sessions, tmp_path):
    pytest.importorskip("cryptography")
    learn = sessions[:2]
    common = dict(dump_paths=[r["msl"] for r in learn], name="memdiver_gocryptfs_img",
                  key_hex=[r["key"] for r in learn], oracle_kind=KIND,
                  oracle_sample_path=[r["vault"] for r in learn],
                  case_dir=str(tmp_path / "case"), verify_on=(), full_image=learn[0]["msl"])
    wrong = synthesize_vol3_plugin(**common, full_image_key_hex=THIRD_MASTER.hex())
    assert wrong["verdicts"][0]["status"] == "not_proven"
    right = synthesize_vol3_plugin(**common, full_image_key_hex=learn[0]["key"])
    assert right["verdicts"][0]["status"] == "proven"
    assert right["verdicts"][0]["proven_by_image_sample"] is False
    assert right["verdicts"][0]["matched_dump_index"] == 0


@pytest.mark.skipif(shutil.which("vol") is None, reason="stock `vol` not on PATH")
def test_msl_image_of_another_pid_is_a_pid_mismatch(sessions, tmp_path):
    pytest.importorskip("cryptography")
    result = _synth_on_image(sessions, tmp_path, pid=999999)
    (verdict,) = result["verdicts"]
    assert verdict["status"] == "proven"  # the slice is still scanned and its key proven
    assert verdict["pid_honoured"] is False and verdict["pid_scope"] == "msl_mismatch"
    assert tp.SYNTH_PID_MISMATCH_CODE in {d["code"] for d in result["diagnostics"]}
    same = _synth_on_image(sessions, tmp_path, pid=4242)  # _write_msl records pid 4242
    assert same["verdicts"][0]["pid_honoured"] is True
    assert same["verdicts"][0]["pid_scope"] == "msl"


def test_image_args_without_full_image_are_reported(sessions, tmp_path):
    pytest.importorskip("cryptography")
    pytest.importorskip("volatility3")
    learn = sessions[:2]
    result = synthesize_vol3_plugin(
        dump_paths=[r["msl"] for r in learn], name="memdiver_gocryptfs_img",
        key_hex=[r["key"] for r in learn], oracle_kind=KIND,
        oracle_sample_path=[r["vault"] for r in learn], case_dir=str(tmp_path / "case"),
        full_image_sample=sessions[2]["vault"])
    assert tp.SYNTH_IMAGE_ARGS_IGNORED_CODE in {d["code"] for d in result["diagnostics"]}


def test_semicolon_in_case_dir_is_refused(sessions, tmp_path):
    case = tmp_path / "a;b"
    case.mkdir()
    learn = sessions[:2]
    with pytest.raises(CapabilityError) as info:
        synthesize_vol3_plugin(
            dump_paths=[r["msl"] for r in learn], name="memdiver_gocryptfs_img",
            key_hex=[r["key"] for r in learn], oracle_kind=KIND,
            oracle_sample_path=[r["vault"] for r in learn], case_dir=str(case), verify_on=())
    assert info.value.code == "synth.vol3_plugin.semicolon_in_path"


@pytest.mark.skipif(shutil.which("vol") is None, reason="stock `vol` not on PATH")
def test_unhonoured_pid_is_reported_not_hidden(sessions, tmp_path):
    """A raw image without a kernel: the plugin scans the physical layer and warns.

    The key is still proven (physical offsets), but the ``--pid`` narrowing
    did not happen -> ``pid_honoured`` False + a warning diagnostic. (A
    ``.msl`` is not this case: a slice IS the process, so it is scanned as is.)
    """
    pytest.importorskip("cryptography")
    raw = tmp_path / "image.raw"
    raw.write_bytes(fx.process_buffer(THIRD_MASTER))
    sessions[2]["msl"] = str(raw)
    result = _synth_on_image(sessions, tmp_path, pid=1)
    (verdict,) = result["verdicts"]
    assert verdict["status"] == "proven", verdict
    assert {h["key_offset"] for h in verdict["proven_hits"]} == set(fx.KEY_SITES)
    assert verdict["pid_honoured"] is False and verdict["pid_scope"] == "physical"
    assert tp.SYNTH_PID_UNHONOURED_CODE in {d["code"] for d in result["diagnostics"]}


# --------------------------------------------------------------------------- real captures (gated)

SECRETS_CORPUS = Path(os.environ.get("MEMDIVER_SECRETS_CORPUS", "") or "/nonexistent")
CIPHER_DIR = "/var/lib/memdiver-gt/gocryptfs_cipher/"
CAPTURES = {  # stem -> gocryptfs daemon pid (sidecar daemon_pids)
    "ubuntu-24.04-secrets-x86-4level_6.8.0-136-generic": 9878,
    "ubuntu-24.04-secrets-x86-la57_6.8.0-136-generic": 9884,
}
ALT_VOL_PY = os.environ.get("MEMDIVER_VOL3_ALT_VOL_PY", "")


def _stock_vol():
    return shutil.which("vol") or str(Path(sys.executable).with_name("vol"))


def _vol(work: Path, stem: str, *args: str, out: Path = None) -> subprocess.CompletedProcess:
    """Stock vol on a capture, with our -p (the LA57 stacker) and a private cache."""
    argv = [_stock_vol(), "-q", "--offline", "--cache-path", str(work / "cache"),
            "-s", str(work / "sym"), "-p", vol3_plugin_dir()["path"],
            "-f", str(SECRETS_CORPUS / f"{stem}.lime"), *(["-o", str(out)] if out else []), *args]
    result = subprocess.run(argv, capture_output=True, text=True, cwd=str(work), timeout=1800)
    assert result.returncode == 0, result.stderr[-2000:]
    return result


def _symbols(work: Path, stem: str) -> Path:
    linux = work / "sym" / "linux"
    linux.mkdir(parents=True)
    (linux / f"{stem}.json").symlink_to(SECRETS_CORPUS / f"{stem}.isf.json")
    (work / "cache").mkdir()
    return work / "sym"


def _vault_files(listing: list) -> dict:
    """``{basename: inode address}``: gocryptfs.conf + the smallest resident content file."""
    files = [r for r in listing if r["FilePath"].startswith(CIPHER_DIR) and r["FileType"] == "REG"
             and r["CachedPages"] >= r["InodePages"] > 0]
    by_name = {Path(r["FilePath"]).name: r for r in files}
    content = sorted((r for name, r in by_name.items()
                      if name not in gocryptfs_gcm.VAULT_METADATA_FILES),
                     key=lambda r: r["InodeSize"])
    assert "gocryptfs.conf" in by_name and content, sorted(by_name)
    return {name: by_name[name]["InodeAddr"]
            for name in ("gocryptfs.conf", Path(content[0]["FilePath"]).name)}


def _recover_vault(work: Path, stem: str) -> Path:
    """The vault recovered from the image's page cache (memory only)."""
    listing = json.loads(_vol(work, stem, "-r", "json", "linux.pagecache.Files").stdout)
    vault, dumps = work / "vault", work / "inode_dumps"
    vault.mkdir()
    dumps.mkdir()
    for name, inode in _vault_files(listing).items():
        _vol(work, stem, "linux.pagecache.InodePages", "--inode", str(inode), "--dump", out=dumps)
        (dumped,) = dumps.glob(f"inode_{inode:#x}.dmp")
        dumped.rename(vault / name)
    return vault


def _corpus_runs():
    runs = [GOCRYPTFS_CORPUS / "run_0001", GOCRYPTFS_CORPUS / "run_0002"]
    if not all((r / "memslicer.msl").is_file() for r in runs):
        pytest.skip("run_0001/run_0002 have no memslicer.msl")
    return runs


def _run_alt(command: str, work: Path) -> list:
    argv = shlex.split(command)
    argv = [sys.executable, ALT_VOL_PY, "-q", "-r", "json", "--cache-path", str(work / "cache"),
            *argv[1:]]
    result = subprocess.run(argv, capture_output=True, text=True, cwd="/", timeout=1800)
    assert result.returncode == 0, result.stderr[-2000:]
    return json.loads(result.stdout[result.stdout.index("["):])


@pytest.mark.skipif(not HAVE_CORPUS, reason="gocryptfs .msl corpus not present")
@pytest.mark.parametrize("stem", sorted(CAPTURES))
def test_real_image_pid_proof_from_the_page_cache_vault(tmp_path, stem):
    pytest.importorskip("cryptography")
    sidecar = SECRETS_CORPUS / f"{stem}.secrets.json"
    if not ((SECRETS_CORPUS / f"{stem}.lime").is_file() and sidecar.is_file()
            and Path(_stock_vol()).is_file()):
        pytest.skip("MEMDIVER_SECRETS_CORPUS capture or stock `vol` not present")
    truth = json.loads(sidecar.read_text())["gocryptfs"][0]["master_key_hex"]
    symbols = _symbols(tmp_path, stem)
    vault = _recover_vault(tmp_path, stem)
    oracle = gocryptfs_gcm.build_oracle({}, gocryptfs_gcm.sample_from_vault(str(vault)))
    assert oracle.verify(bytes.fromhex(truth))["status"] == "proven"
    assert oracle.verify(bytes(32))["status"] == "rejected"

    runs = _corpus_runs()
    (tmp_path / "case").mkdir()
    result = synthesize_vol3_plugin(
        dump_paths=[str(r / "memslicer.msl") for r in runs], name="memdiver_gocryptfs",
        key_hex=[json.loads((r / "meta.json").read_text())["master_key_hex"] for r in runs],
        oracle_kind=KIND, oracle_sample_path=[str(r / "cipher") for r in runs],
        case_dir=str(tmp_path / "case"), verify_on=(), vol_bin=_stock_vol(),
        full_image=str(SECRETS_CORPUS / f"{stem}.lime"), pid=CAPTURES[stem],
        full_image_sample=str(vault), full_image_key_hex=truth, symbol_dirs=[str(symbols)])
    (verdict,) = result["verdicts"]
    assert verdict["status"] == "proven", verdict
    assert verdict["pid_honoured"] is True and verdict["matched_dump_index"] is None
    assert verdict["pid_scope"] == "process" and verdict["proven_by_image_sample"] is True
    assert all(h["key_offset"] < 1 << 47 for h in verdict["proven_hits"])  # user VA, not physical
    assert truth not in json.dumps(result, default=str)
    if ALT_VOL_PY and Path(ALT_VOL_PY).is_file():
        rows = _run_alt(verdict["vol_command"], tmp_path)
        proven = {r["KeyHex"] for r in rows if r["Proven"] == f"oracle:{KIND}"}
        assert proven == {truth}


# --------------------------------------------------------------------------- Scope column (template v2)

def test_v2_template_reports_scope_last_and_vol3_verify_reads_it():
    pytest.importorskip("cryptography")
    pytest.importorskip("volatility3")
    from memdiver.architect import vol3_recipe as vr
    from memdiver.engine.vol3_verify import run_over_buffer, run_rows_over_buffer

    source = vr.render(fx.synthetic_recipe())
    assert '("Detail", str),' in source and source.index('("Detail", str),') < source.index(
        '("Scope", str),')
    data = fx.process_buffer()
    rows = run_rows_over_buffer(source, data)
    assert rows and {r["Scope"] for r in rows} == {"physical"}  # a flat buffer: no pid, no slice
    report = run_over_buffer(source, data)
    assert report.hits and {h.scope for h in report.hits} == {"physical"}
    assert report.proven_count >= 1


# --------------------------------------------------------------------------- review fixes (2026-11-11)

def test_a_relative_dash_sample_of_a_later_dump_is_passed_absolute(tmp_path, monkeypatch):
    """A later dump's own sample named ``-k.bin`` (relative) must not read as a vol option.

    It used to raise from the verdict's display spec (``refuse_global_options``)
    AFTER the plugin was emitted; it is now passed absolute, like the full-image
    attempts pass theirs.
    """
    from memdiver.app import tools_pipeline as tp

    monkeypatch.chdir(tmp_path)
    (tmp_path / "-k.bin").write_bytes(b"sample")
    seen = []
    monkeypatch.setattr(vol3_synth, "_synth_run_in_process",
                        lambda source, path, **kw: seen.append(kw["extra_config"]) or (_ for _ in ()).throw(RuntimeError("boom")))

    def command(dump, extra):
        return tp._synth_display_spec("/pkg", tmp_path / "plugins", "m.C", dump, extra)

    verdicts = tp._synth_verify_msl(
        "src", paths=[tmp_path / "a.msl", tmp_path / "b.msl"], keys=[b"k" * 32] * 2,
        samples=["first", "-k.bin"], kind="gocryptfs-gcm", formats=["msl", "msl"],
        key_file=None, kem_key_file=None, command=command)
    absolute = str((tmp_path / "-k.bin").resolve())
    assert seen[1] == {"oracle_sample": absolute}
    assert verdicts[1]["exec"]["args"] == ["--oracle-sample", absolute]
    assert verdicts[1]["vol_command"].endswith(f"m.C --oracle-sample {absolute}")


def test_a_keyed_open_that_fails_closes_the_half_open_reader(tmp_path, monkeypatch):
    """``_open_keyed``: a header the reader refuses after mapping the file leaks no handle."""
    from memdiver.app import key_material
    from memdiver.msl.reader import MslReader

    bad = tmp_path / "bad.msl"
    bad.write_bytes(b"MEMSLICE" + b"\x02" + b"\x00" * 200)  # MSL magic, invalid endianness
    closed = []
    real_close = MslReader.close
    monkeypatch.setattr(MslReader, "close", lambda self: closed.append(self) or real_close(self))
    from memdiver.msl.reader import MslParseError

    with pytest.raises(MslParseError, match="Endianness"):
        key_material._open_keyed(bad, {"key": b"k" * 32, "passphrase": None,
                                       "kem_private_key": None})
    assert closed and closed[-1]._file is None and closed[-1]._mmap is None

"""Regression tests for the second P4 review: export/overwrite safety, read-path case
creation, ISF job cancel, bare case names, disasm arch/gaps, va_bits mismatch, tryloop
timeout blame, and profiles vol3 cannot load (4xx at open time and on every read)."""
from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from memdiver.analysis.case import cases_root
from memdiver.app import tools_image as ti
from memdiver.app import tools_isf as T
from memdiver.core.service_errors import CapabilityError, ErrorCategory

CAP = "c" * 64


@pytest.fixture(autouse=True)
def home(tmp_path, monkeypatch):
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "xdg"))
    monkeypatch.delenv("MEMDIVER_ALLOWED_ROOTS", raising=False)
    return tmp_path / "xdg" / "memdiver"


@pytest.fixture
def client(tmp_path, monkeypatch):
    from fastapi.testclient import TestClient

    from memdiver.api.config import get_settings
    from memdiver.api.main import create_app
    monkeypatch.setenv("MEMDIVER_UPLOAD_DIR", str(tmp_path / "uploads"))
    get_settings.cache_clear()
    yield TestClient(create_app(), base_url="http://127.0.0.1", raise_server_exceptions=False)
    get_settings.cache_clear()


def _draft(client, case="c1"):
    r = client.post("/api/isf/drafts", json={"case_dir": case, "capture_id": CAP,
                                             "name": "d", "arch": "x86_64"})
    assert r.status_code == 200, r.text


# -- HIGH 1: export never overwrites ------------------------------------------------

def test_export_refuses_record_overwrite_bad_suffix_and_existing(client):
    _draft(client)
    case = cases_root() / "c1"
    record = next(p for p in (case / "annotations").rglob("*") if p.is_file())
    before = record.read_bytes()
    for target, code in [(record, "isf_export_target"), (case / "tables", "isf_export_target"),
                         (case / "annotations" / "x.isf.json", "isf_export_target")]:
        r = client.post("/api/isf/drafts/d/export", json={
            "case_dir": "c1", "capture_id": CAP, "out_path": str(target)})
        assert 400 <= r.status_code < 500, r.text
        assert code in r.text
    assert record.read_bytes() == before
    fresh = case / "out.isf.json"
    ok = client.post("/api/isf/drafts/d/export", json={
        "case_dir": "c1", "capture_id": CAP, "out_path": str(fresh)})
    assert ok.status_code == 200 and fresh.is_file()
    again = client.post("/api/isf/drafts/d/export", json={
        "case_dir": "c1", "capture_id": CAP, "out_path": str(fresh)})
    assert 400 <= again.status_code < 500 and "isf_export_exists" in again.text


def test_open_view_and_extract_out_path_never_overwrite(tmp_path):
    existing = tmp_path / "keep.mdview"
    existing.write_text("precious")
    with pytest.raises(CapabilityError) as err:
        ti._view_target(tmp_path / "i.raw", ti.ViewKind.KERNEL, None, None, str(existing))
    assert err.value.code == "view_out_exists" and existing.read_text() == "precious"
    with pytest.raises(CapabilityError) as err:
        ti._view_target(tmp_path / "i.raw", ti.ViewKind.KERNEL, None, None,
                        str(tmp_path / "x.jsonl"))
    assert err.value.code == "view_out_target"


# -- HIGH 2: reads never create a case; bare names work everywhere ------------------

def test_reads_do_not_create_cases_and_bare_names_work(client, tmp_path):
    evil = tmp_path / "evil_case"
    r = client.get("/api/isf/drafts", params={"case_dir": str(evil), "capture_id": CAP})
    assert r.status_code == 403 and not evil.exists()
    r = client.get("/api/isf/drafts", params={"case_dir": "ghost", "capture_id": CAP})
    assert r.status_code == 404 and "case.not_found" in r.text
    assert not (cases_root() / "ghost").exists()
    with pytest.raises(CapabilityError) as err:
        T.isf_draft_list_result("ghost", CAP)
    assert err.value.category is ErrorCategory.NOT_FOUND
    _draft(client)
    assert client.get("/api/isf/drafts", params={"case_dir": "c1", "capture_id": CAP}
                      ).json()["count"] == 1
    for path, body in [("/api/isf/drafts/d/validate", {}), ("/api/isf/drafts/d/diff",
                                                            {"against_version": "x"})]:
        r = client.post(path, json={"case_dir": "ghost", "capture_id": CAP, **body})
        assert r.status_code in (404, 422, 503), r.text
        assert not (cases_root() / "ghost").exists()


def test_path_policy_admits_bare_case_and_sha_but_checks_paths(tmp_path, monkeypatch):
    from memdiver.api import path_policy as pp
    monkeypatch.setenv("MEMDIVER_ALLOWED_ROOTS", str(tmp_path / "ok"))
    from memdiver.api.config import get_settings
    get_settings.cache_clear()
    try:
        assert list(pp._iter_path_values({"case_dir": "bare", "capture_id": CAP}, False)) == []
        got = list(pp._iter_path_values({"capture_id": "/etc/passwd", "case_dir": "../x"}, False))
        assert got == ["/etc/passwd", "../x"]
    finally:
        get_settings.cache_clear()


# -- HIGH 3: cancel -------------------------------------------------------------------

class _FakeSession:
    capture, arch_name, arch_source = CAP, "x86_64", "explicit"

    def __init__(self, image, arch, params):
        self.params, self.timings, self.warnings = params, {}, []

    def close(self):
        pass


def test_cancelled_probe_feeds_nothing(tmp_path, monkeypatch):
    pytest.importorskip("pakunoda")
    image = tmp_path / "i.raw"
    image.write_bytes(b"\0" * 64)
    monkeypatch.setattr(T, "file_sha256", lambda p: CAP)
    T.isf_draft_create_result("c1", CAP, "d", "x86_64")
    fed = []
    monkeypatch.setattr(T, "_Session", _FakeSession)
    monkeypatch.setitem(T._BUILDERS, "vmcoreinfo", lambda s, limit: {"rows": []})
    monkeypatch.setattr(T, "_feed_draft", lambda *a, **k: fed.append(1))
    with pytest.raises(CapabilityError) as err:
        T.isf_probe_result(str(image), "vmcoreinfo", arch="x86_64", case_dir="c1",
                           draft="d", cancel=lambda: True)
    assert err.value.code == "cancelled" and not fed
    flips = iter([False, True])
    with pytest.raises(CapabilityError):  # cancelled after the builder, before the feed
        T.isf_probe_result(str(image), "vmcoreinfo", arch="x86_64", case_dir="c1",
                           draft="d", cancel=lambda: next(flips, True))
    assert not fed


def test_cancelled_try_records_nothing(tmp_path, monkeypatch):
    from memdiver.analysis.record_store import AnalysisRecord
    image = tmp_path / "i.raw"
    image.write_bytes(b"\0" * 64)
    monkeypatch.setattr(T, "file_sha256", lambda p: CAP)
    T.isf_draft_create_result("c1", CAP, "d", "x86_64")
    state = {"ran": False}

    def fake_try(*a, **k):
        state["ran"] = True
        return {"verdict": "pass", "stage": "done", "implicated": []}
    monkeypatch.setattr("memdiver.isf.tryloop.try_isf", fake_try)
    # With ``cancel`` the try runs in a spawned child (``run_killable``), which cannot see
    # this in-process fake; stand in for the child so the parent-side checks are exercised.
    monkeypatch.setattr("memdiver.engine.killable.run_killable",
                        lambda target, kwargs, **_: fake_try(**kwargs))
    with pytest.raises(CapabilityError) as err:   # cancelled only once the run finished
        T.isf_try_result(str(image), case_dir="c1", draft="d",
                         cancel=lambda: state["ran"])
    assert err.value.code == "cancelled"
    assert AnalysisRecord(cases_root() / "c1").entries(CAP, ) is not None
    kinds = [e.kind for e in AnalysisRecord(cases_root() / "c1").entries(CAP)]
    assert "isf_try" not in kinds
    with pytest.raises(CapabilityError):          # cancelled before the run
        state["ran"] = False
        T.isf_try_result(str(image), case_dir="c1", draft="d", cancel=lambda: True)
    assert not state["ran"]


def test_isf_jobs_receive_the_cancel_control():
    from memdiver.app.pipeline.image_task_runner import _job_controls
    ctx = SimpleNamespace(is_cancelled=lambda: False, emit=lambda *a, **k: None)
    for job in ("isf_probe", "isf_try"):
        assert _job_controls(job, ctx)["cancel"] is ctx.is_cancelled
    assert _job_controls("open_view", ctx) == {}


def test_try_records_the_state_it_exported(tmp_path, monkeypatch):
    image = tmp_path / "i.raw"
    image.write_bytes(b"\0" * 64)
    monkeypatch.setattr(T, "file_sha256", lambda p: CAP)
    T.isf_draft_create_result("c1", CAP, "d", "x86_64")
    seen = {}

    def fake_try(img, target, **k):
        seen["target"] = Path(target)
        return {"verdict": "unverified", "stage": "done", "implicated": []}
    monkeypatch.setattr("memdiver.isf.tryloop.try_isf", fake_try)
    out = T.isf_try_result(str(image), case_dir="c1", draft="d").payload
    assert out["state_id"] in seen["target"].name


# -- MEDIUM 4: bare case names for draft views -----------------------------------------

def test_bare_case_name_resolves_for_draft_view(tmp_path, monkeypatch):
    image = tmp_path / "i.raw"
    image.write_bytes(b"\0" * 4096)
    T.isf_draft_create_result("revcase", T.file_sha256(image), "d1", "x86_64")
    monkeypatch.setattr(ti, "_check_profile_loads", lambda d, t: None)
    out = ti.image_open_view_result(str(image), "kernel", case_dir="revcase", draft="d1")
    assert out.payload["view_path"]


# -- MEDIUM 5/6: disasm -----------------------------------------------------------------

def test_gap_rows_carry_exact_hex_start():
    from memdiver.app.tools_disasm import _gap_row, _gaps_of
    big = 0xFFFFFFFF81000001
    assert _gaps_of(big, 4, [])[0]["start_hex"] == hex(big)
    assert _gap_row({"start": big, "length": 1, "reason": "x"})["start_hex"] == hex(big)


def test_profiled_view_arch_is_never_guessed():
    from memdiver.app.tools_disasm import resolve_arch
    source = SimpleNamespace(descriptor=SimpleNamespace(paging=None, profile="isf"))
    with pytest.raises(CapabilityError) as err:
        resolve_arch(source, "auto", None)
    assert err.value.code == "disasm.arch_undetected"
    assert err.value.category is ErrorCategory.INVALID_INPUT


# -- MEDIUM 8: va_bits ---------------------------------------------------------------

def test_requested_va_bits_mismatch_is_refused(tmp_path, monkeypatch):
    seen = {}

    def fake_probe(image, probe, arch="auto", params=None, **k):
        seen["params"] = params
        return SimpleNamespace(payload={"arch": "x86_64", "rows": [
            {"verified": True, "pgd_phys": 4096, "va_bits": 48, "page_size": 4096}]})
    monkeypatch.setattr(T, "isf_probe_result", fake_probe)
    with pytest.raises(CapabilityError) as err:
        ti._discovered_paging(tmp_path / "i.raw", {"arch": "x86_64", "va_bits": 57})
    assert err.value.code == "paging_va_bits_mismatch"
    assert seen["params"] == {"va_bits": 57}
    spec = ti._discovered_paging(tmp_path / "i.raw", {"arch": "x86_64", "va_bits": 48})
    assert spec.va_bits == 48


# -- LOW: truncated run is never a field blame ---------------------------------------

def test_timeout_truncated_run_blames_no_field(tmp_path, monkeypatch):
    from memdiver.isf import tryloop
    cmp = SimpleNamespace(returned=1, recall=0.1, matched=1, expected=10, precision=1.0,
                          mismatches=[], duplicates=[], to_dict=lambda: {})
    monkeypatch.setattr("memdiver.core.image.context.ImageContext.build",
                        lambda *a, **k: SimpleNamespace(
                            kernel_paging=SimpleNamespace(to_dict=lambda: {}, va_bits=48)))
    run = SimpleNamespace(row_count=1, truncated=True, stop_reason="timeout", diagnostics=[],
                          columns=[], rows=[])
    monkeypatch.setattr("memdiver.engine.vol3_runner.run_plugin", lambda *a, **k: run)
    monkeypatch.setattr("memdiver.engine.vol3_runner.resolve_plugin", lambda p: p)
    monkeypatch.setattr(tryloop, "parse_ground_truth",
                        lambda p: SimpleNamespace(source="ps", path=str(p), tasks=[],
                                                  skipped_rows=0))
    monkeypatch.setattr(tryloop, "compare_pslist", lambda *a, **k: cmp)
    truth = tmp_path / "ps.txt"
    truth.write_text("x")
    out = tryloop.try_isf(tmp_path / "i", tmp_path / "x.isf.json", ground_truth=truth)
    assert out["verdict"] == "error" and out["stage"] == "run" and out["implicated"] == []


# -- profiles vol3 cannot load: 4xx, never 500, never cached --------------------------

@pytest.fixture
def bad_profile(tmp_path):
    pytest.importorskip("volatility3")
    image = tmp_path / "img" / "box.raw"
    image.parent.mkdir()
    image.write_bytes(b"\x00" * 8192)
    isf = tmp_path / "img" / "bad.isf.json"
    isf.write_text("{}", encoding="utf-8")
    return image, isf


def test_unloadable_profile_refuses_open_view(bad_profile):
    image, isf = bad_profile
    target = cases_root() / "v.mdview"
    with pytest.raises(CapabilityError) as err:
        ti.image_open_view_result(str(image), "kernel", isf=str(isf), out_path=str(target))
    assert err.value.code == "profile_build_failed"
    assert err.value.category is ErrorCategory.PRECONDITION
    assert "cannot load yet" in err.value.message and "implicated" in err.value.details
    assert not target.exists()


def test_open_view_job_reports_the_unloadable_profile(bad_profile):
    """REST open-view is a job: its terminal error carries the same message."""
    from memdiver.app.pipeline.image_task_runner import run_image_job
    image, isf = bad_profile
    events = []
    ctx = SimpleNamespace(emit=lambda kind, **kw: events.append((kind, kw)),
                          is_cancelled=lambda: False)
    with pytest.raises(ValueError, match="cannot load yet"):
        run_image_job({"job": "open_view", "args": {
            "image_path": str(image), "view": "kernel", "isf": str(isf),
            "out_path": str(cases_root() / "v2.mdview")}, "task_root": str(image.parent)}, ctx)
    assert any(kind == "error" for kind, _ in events)


def test_every_read_on_an_unloadable_view_is_4xx_and_not_cached(client, bad_profile):
    from memdiver.core.image import context as ctxmod
    from memdiver.core.image.context import file_sha256
    from memdiver.core.image.view_descriptor import ProfileRef, ViewDescriptor, ViewKind
    image, isf = bad_profile
    view = image.with_suffix(".mdview")
    ViewDescriptor(str(image), file_sha256(image), ViewKind.KERNEL,
                   profile=ProfileRef(str(isf), file_sha256(isf), "draft")).write(view)
    before = len(ctxmod._CACHE)
    r = client.get("/api/image/processes", params={"view_path": str(view)})
    assert 400 <= r.status_code < 500 and "profile_build_failed" in r.text, r.text
    r = client.get("/api/inspect/hex-raw", params={"path": str(view), "offset": 0, "length": 16})
    assert r.status_code != 500, r.text
    assert len(ctxmod._CACHE) == before


def test_build_failure_names_implicated_types(tmp_path):
    from memdiver.core.image.context import _profile_build_failed
    isf = tmp_path / "x.isf.json"
    isf.write_text(json.dumps({"user_types": {}}))
    err = _profile_build_failed(
        ValueError("Symbol type not in kernel_isf_probe SymbolTable: file"), isf)
    assert err.code == "profile_build_failed" and err.category is ErrorCategory.PRECONDITION
    assert {"item": "type:file"}.items() <= err.details["implicated"][0].items()

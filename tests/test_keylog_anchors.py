"""Key-log driven anchoring: parser, per-dump resolution, producers, validate, policy."""

from __future__ import annotations

import argparse
import hashlib
import io
import json
import sys
from contextlib import ExitStack, redirect_stdout
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from memdiver.core.service_errors import CapabilityError  # noqa: E402
from memdiver.engine import keylog_anchors as ka  # noqa: E402
from memdiver.msl.enums import Protection, RegionType  # noqa: E402
from memdiver.msl.writer import MslWriter  # noqa: E402

PAGE = 0x1000
RW = Protection.READ | Protection.WRITE
ANCHOR_AT = 0x800
N = 4
CTS0, STS0, EXP = "CLIENT_TRAFFIC_SECRET_0", "SERVER_TRAFFIC_SECRET_0", "EXPORTER_SECRET"


def _rand(tag: str, i: int, n: int) -> bytes:
    return hashlib.sha256(f"{tag}{i}".encode()).digest()[:n]


def _session_bytes(i: int) -> dict:
    return {"cr": _rand("cr", i, 32), CTS0: _rand("cts", i, 32), STS0: _rand("sts", i, 32),
            EXP: _rand("exp", i, 32)}


def _lines(i: int) -> str:
    s = _session_bytes(i)
    cr = s["cr"].hex()
    return "".join(f"{lb} {cr} {s[lb].hex()}\n" for lb in (CTS0, STS0, EXP))


def _write_msl(path: Path, secrets: list, base_va: int = 0x20000000) -> str:
    """A page with each session's anchor secret, client_random and server secret."""
    page = bytearray(b"".join(hashlib.sha256(b"fill%d" % k).digest() for k in range(PAGE // 32)))
    page[0x600:0x7C0] = hashlib.sha256(path.name.encode()).digest() * 14   # volatile area
    for k, s in enumerate(secrets):
        at = ANCHOR_AT + k * 0x200
        page[at:at + 32] = s[CTS0]
        page[at - 0x80:at - 0x60] = s["cr"]
        page[at + 0x40:at + 0x60] = s[STS0]
    w = MslWriter(str(path), pid=7, imported=False)
    w.add_memory_region(base_va, bytes(page), protection=RW,
                        region_type=int(RegionType.ANONYMOUS))
    w.add_end_of_capture()
    w.write()
    return str(path)


@pytest.fixture(scope="module")
def corpus(tmp_path_factory):
    root = tmp_path_factory.mktemp("keylog")
    paths = [_write_msl(root / f"d{i}.msl", [_session_bytes(i)], 0x20000000 + i * 0x40000)
             for i in range(N)]
    per_dump = {}
    for i, p in enumerate(paths):
        kl = root / f"k{i}.txt"
        kl.write_text(_lines(i))
        per_dump[p] = str(kl)
    shared = root / "shared.txt"
    # a decoy session no dump contains is mixed in; the RSA/PMS lines must be ignored
    decoy = _lines(99)
    shared.write_text("# SSLKEYLOGFILE\n" + "".join(_lines(i) for i in range(N)) + decoy
                      + "RSA 0123456789abcdef 00112233\nPMS_CLIENT_RANDOM aa bb\n")
    return {"root": root, "paths": paths, "per_dump": per_dump, "shared": str(shared)}


def _session():
    from memdiver.app.composition import build_tool_session
    return build_tool_session()


# -- parser ------------------------------------------------------------------------

def test_parser_corpus_header_comments_and_ignored():
    text = ("line\n# comment\n" + _lines(0) + "RSA 0123456789abcdef 0011\n"
            "PMS_CLIENT_RANDOM aa bb\nEARLY_EXPORTER_SECRET " + "ab" * 32 + " " + "cd" * 32
            + "\nCLIENT_EARLY_TRAFFIC_SECRET " + "ab" * 32 + " " + "ef" * 32 + "\nbogus line\n")
    res = ka.parse_keylog_text(text)
    assert res.ignored == {"RSA": 1, "PMS_CLIENT_RANDOM": 1} and res.malformed == 1
    assert len(res.sessions) == 2           # the session of _lines(0) + the early-secret one
    early = res.sessions[1]
    assert set(early.secrets) == {"EARLY_EXPORTER_SECRET", "CLIENT_EARLY_TRAFFIC_SECRET"}
    assert set(res.sessions[0].secrets) == {CTS0, STS0, EXP}


def test_parser_reads_corpus_style_csv_rows_and_tls12(tmp_path):
    cr, ms = "11" * 32, "22" * 48
    path = tmp_path / "keylog.csv"
    path.write_text(f"id,line\n1,CLIENT_RANDOM {cr} {ms}\n")
    res = ka.parse_keylog_file(path)
    assert res.sessions[0].secrets == {"CLIENT_RANDOM": bytes.fromhex(ms)}
    assert ka.default_anchor_label({"d": res.sessions}) == "CLIENT_RANDOM"
    assert ka.field_name("CLIENT_RANDOM") == "master_secret"


# -- resolution ----------------------------------------------------------------------

def _resolve(paths, keylogs, **kw):
    from memdiver.app.tools_consensus import _anchor_view_for, _open_one

    with ExitStack() as stack:
        sources = {p: _open_one(stack, p, None) for p in paths}
        return ka.resolve_keylog_anchors(sources, keylogs, view=_anchor_view_for, **kw)


def test_resolution_shared_and_per_dump_pick_each_dumps_own_session(corpus):
    shared = ka.parse_keylog_file(corpus["shared"])
    assert shared.ignored == {"RSA": 1, "PMS_CLIENT_RANDOM": 1}
    out = _resolve(corpus["paths"], {p: shared.sessions for p in corpus["paths"]})
    for i, p in enumerate(corpus["paths"]):
        res, want = out[p], _session_bytes(i)
        assert res.anchored and res.candidates == N + 1
        assert res.needle == want[CTS0] and res.client_random == want["cr"]
        assert res.related["client_random"] == want["cr"]
        assert res.related["server_traffic_secret_0"] == want[STS0]
        assert res.labels["anchor"] == CTS0 and res.labels["exporter_secret"] == EXP
    per = {p: ka.parse_keylog_file(k).sessions for p, k in corpus["per_dump"].items()}
    assert {p: r.needle for p, r in _resolve(corpus["paths"], per).items()} == {
        p: r.needle for p, r in out.items()}


def test_resolution_absent_and_ambiguous_are_never_guessed(corpus, tmp_path):
    absent = _resolve(corpus["paths"][:1], {corpus["paths"][0]: ka.parse_keylog_text(
        _lines(50) + _lines(51)).sessions})[corpus["paths"][0]]
    assert not absent.anchored and absent.reason == (
        f"no {CTS0} secret from the key log occurs in this dump (2 candidates searched)")
    both = _write_msl(tmp_path / "two.msl", [_session_bytes(0), _session_bytes(1)])
    sessions = ka.parse_keylog_text(_lines(0) + _lines(1)).sessions
    amb = _resolve([both], {both: sessions})[both]
    assert not amb.anchored and amb.reason == "ambiguous: 2 key-log sessions occur in this dump"
    none = _resolve([both], {})[both]
    assert not none.anchored and "0 candidates" in none.reason


def test_related_labels_restrict_and_client_random_optional(corpus):
    p = corpus["paths"][0]
    sessions = ka.parse_keylog_file(corpus["per_dump"][p]).sessions
    res = _resolve([p], {p: sessions}, related_labels=[STS0], include_client_random=False)[p]
    assert set(res.related) == {"server_traffic_secret_0"}
    assert [m["field"] for m in ka.suggest_meanings([res])] == ["anchor", "server_traffic_secret_0"]


# -- producers -----------------------------------------------------------------------

def _consensus(corpus, **kw):
    from memdiver.app.tools_consensus import anchor_consensus_result

    return anchor_consensus_result(_session(), dump_paths=corpus["paths"], delta_start=-0x100,
                                   length=0x300, **kw)


def test_anchor_consensus_keylog_modes_agree(corpus):
    a = _consensus(corpus, keylog={"path": corpus["shared"]}).payload
    b = _consensus(corpus, keylog={"text": Path(corpus["shared"]).read_text()}).payload
    c = _consensus(corpus, keylog={"per_dump": corpus["per_dump"]}).payload
    assert len(a["instances"]) == N and a["unanchored"] == []
    assert a["regions"] == b["regions"] == c["regions"]
    assert a["suggested_meanings"] == c["suggested_meanings"]
    assert {r["dump_path"] for r in a["keylog_resolution"]} == set(corpus["paths"])
    assert a["keylog_anchor_label"] == CTS0
    assert a["keylog_summary"][0]["ignored"] == {"RSA": 1, "PMS_CLIENT_RANDOM": 1}


def test_exactly_one_anchor_mode_and_label_needs_keylog(corpus):
    with pytest.raises(CapabilityError, match="exactly one of"):
        _consensus(corpus, keylog={"path": corpus["shared"]}, needles={corpus["paths"][0]: "aa"})
    with pytest.raises(CapabilityError, match="need .keylog."):
        _consensus(corpus, needles={p: "aa" for p in corpus["paths"]}, anchor_label=CTS0)
    for bad in ({}, {"path": "x", "text": "y"}, {"nope": 1}):
        with pytest.raises(CapabilityError) as exc:
            _consensus(corpus, keylog=bad)
        assert exc.value.code == "keylog.spec"
    big = {"text": "# " + "x" * (4 * 1024 * 1024 + 1)}
    with pytest.raises(CapabilityError) as exc:
        _consensus(corpus, keylog=big)
    assert exc.value.code == "keylog.too_large"


def test_unanchored_dump_is_reported_not_dropped(corpus):
    kl = {"text": "".join(_lines(i) for i in range(N - 1))}   # last dump has no session
    payload = _consensus(corpus, keylog=kl).payload
    assert [u["dump_path"] for u in payload["unanchored"]] == [corpus["paths"][-1]]
    assert len(payload["instances"]) == N - 1


def _build(corpus, out, **kw):
    from memdiver.app.tools_semantic import artifact_model_build_result

    args = dict(dump_paths=corpus["paths"], keylog={"path": corpus["shared"]},
                delta_start=-0x100, length=0x300, heap=False, name="tls_obj",
                out_path=str(out), detail="full")
    args.update(kw)
    return artifact_model_build_result(_session(), **args)


def test_model_build_defaults_meanings_and_relationships_from_keylog(corpus, tmp_path):
    payload = _build(corpus, tmp_path / "m.json").payload
    assert payload["problems"] == []
    got = {a["field"]: (a["meaning"], a["label"]) for a in payload["model"]["assertions"]}
    assert got["anchor"] == ("tls.client_traffic_secret_0", CTS0)
    assert got["server_traffic_secret_0"] == ("tls.server_traffic_secret_0", STS0)
    assert "exporter_secret" not in got        # logged but never in the dumps: not asserted
    assert got["client_random"] == ("tls.client_random", "")
    rels = {(r["kind"], r["source"], r["target"]) for r in payload["model"]["relationships"]}
    assert ("owned_by", "anchor", "client_random") in rels
    assert ("owned_by", "server_traffic_secret_0", "client_random") in rels
    only = _build(corpus, tmp_path / "m2.json", related_labels=[STS0]).payload
    assert {a["field"] for a in only["model"]["assertions"]} == {
        "anchor", "server_traffic_secret_0", "client_random"}
    typed = _build(corpus, tmp_path / "m3.json",
                   meanings=[{"field": "anchor", "meaning": "x.key", "label": CTS0}]).payload
    assert [a["field"] for a in typed["model"]["assertions"]] == ["anchor"]


def test_propose_layout_keylog_echoes_resolution(corpus):
    from memdiver.app.tools_semantic import propose_layout_result

    payload = propose_layout_result(
        _session(), dump_paths=corpus["paths"], keylog={"path": corpus["shared"]},
        delta_start=-0x100, length=0x300, heap=False).payload
    assert payload["anchor_length"] == 32 and payload["suggested_meanings"]
    assert all(r["anchored"] for r in payload["keylog_resolution"])
    assert any(f["name"] == "client_random" for f in payload["fields"])


# -- validate with a shared keylog -----------------------------------------------------

def test_validate_shared_keylog_zero_sessions_is_indeterminate(corpus, tmp_path):
    pytest.importorskip("volatility3")
    from memdiver.app.tools_semantic import artifact_model_validate_result

    model = _build(corpus, tmp_path / "v.json", related_labels=[STS0]).payload["path"]
    held = [_write_msl(tmp_path / "h0.msl", [_session_bytes(70)]),
            _write_msl(tmp_path / "h1.msl", [_session_bytes(71)]),
            _write_msl(tmp_path / "h2.msl", [_session_bytes(72)])]   # no session in the log
    text = _lines(70) + _lines(71) + _lines(90)
    result = artifact_model_validate_result(
        _session(), model_path=model, held_out=[{"dump_path": p} for p in held],
        keylog={"text": text}).payload
    verdicts = [c["verdict"] for c in result["captures"]]
    assert verdicts == ["pass", "pass", "indeterminate"]
    assert result["verdict"] == "indeterminate"
    assert result["totals"]["expected"] == 4 and result["totals"]["fn"] == 0


def test_validate_rejects_per_dump_keylog(corpus, tmp_path):
    pytest.importorskip("volatility3")
    from memdiver.app.tools_semantic import artifact_model_validate_result

    model = _build(corpus, tmp_path / "vp.json").payload["path"]
    with pytest.raises(CapabilityError) as exc:
        artifact_model_validate_result(
            _session(), model_path=model, held_out=[{"dump_path": str(tmp_path / "x.msl")}],
            keylog={"per_dump": {}})
    assert exc.value.code == "keylog.spec"


# -- path policy -----------------------------------------------------------------------

def test_path_policy_covers_keylog_keys(corpus, tmp_path, monkeypatch):
    from memdiver.api import path_policy
    from memdiver.api.config import get_settings

    assert {"keylog_path", "per_dump", "path"} <= path_policy.READ_PATH_KEYS
    body = {"keylog": {"per_dump": {"/etc/dump.msl": "/etc/k.txt"}}, "keylog_path": "/etc/y"}
    assert sorted(path_policy._iter_path_values(body, False)) == [
        "/etc/dump.msl", "/etc/k.txt", "/etc/y"]
    monkeypatch.setenv("MEMDIVER_ALLOWED_ROOTS", str(corpus["root"]))
    get_settings.cache_clear()
    try:
        from fastapi.testclient import TestClient
        from memdiver.api.main import create_app

        client = TestClient(create_app())
        ok = {"dump_paths": corpus["paths"], "delta_start": -256, "length": 768}
        assert client.post("/api/analysis/consensus/anchor", json={
            **ok, "keylog": {"path": corpus["shared"]}}).status_code == 200
        for keylog in ({"path": "/etc/hosts"},
                       {"per_dump": {corpus["paths"][0]: "/etc/hosts"}},
                       {"per_dump": {"/etc/hosts": corpus["shared"]}}):
            assert client.post("/api/analysis/consensus/anchor",
                               json={**ok, "keylog": keylog}).status_code == 403
        held = {"model_path": corpus["shared"], "held_out": [{"dump_path": corpus["paths"][0],
                                                               "keylog_path": "/etc/hosts"}]}
        assert client.post("/api/semantic/model-validate", json=held).status_code == 403
    finally:
        monkeypatch.delenv("MEMDIVER_ALLOWED_ROOTS")
        get_settings.cache_clear()


# -- surfaces ---------------------------------------------------------------------------

def test_web_routes(corpus, tmp_path):
    from fastapi.testclient import TestClient
    from memdiver.api.main import create_app

    client = TestClient(create_app())
    body = {"dump_paths": corpus["paths"], "delta_start": -256, "length": 768,
            "keylog": {"path": corpus["shared"]}}
    resp = client.post("/api/analysis/consensus/anchor", json=body)
    assert resp.status_code == 200, resp.text
    assert resp.json()["suggested_meanings"]
    resp = client.post("/api/semantic/propose-layout", json={**body, "heap": False,
                                                              "anchor_label": CTS0})
    assert resp.status_code == 200, resp.text
    assert resp.json()["keylog_anchor_label"] == CTS0


def test_mcp_tools(corpus, tmp_path):
    pytest.importorskip("mcp")
    from memdiver.mcp_server.server import create_server

    tools = {t.name: t for t in create_server()._tool_manager.list_tools()}
    out = json.loads(tools["anchor_consensus"].fn(
        dump_paths=corpus["paths"], delta_start=-256, length=768,
        keylog={"per_dump": corpus["per_dump"]}, related_labels=[STS0]))
    assert len(out["instances"]) == N and out["keylog_resolution"]
    built = json.loads(tools["artifact_model_build"].fn(
        name="tls_obj", out_path=str(tmp_path / "mcp.json"), dump_paths=corpus["paths"],
        keylog={"path": corpus["shared"]}, delta_start=-256, length=768, heap=False,
        detail="full"))
    assert built["problems"] == [] and built["model"]["assertions"]


def test_cli_flags(corpus, tmp_path):
    from memdiver.cli.consensus import _cmd_consensus_anchor
    from memdiver.cli.main import build_parser
    from memdiver.cli.semantic import _cmd_model_build, _cmd_propose_layout

    parse = build_parser().parse_args
    out = tmp_path / "ca.json"
    args = parse(["consensus-anchor", *corpus["paths"], "--keylog", corpus["shared"],
                  "--anchor-label", CTS0, "--delta-start", "-256", "-o", str(out)])
    with redirect_stdout(io.StringIO()):
        assert _cmd_consensus_anchor(args) == 0
    assert len(json.loads(out.read_text())["instances"]) == N
    per = tmp_path / "per.json"
    per.write_text(json.dumps(corpus["per_dump"]))
    out2 = tmp_path / "pl.json"
    args = parse(["propose-layout", *corpus["paths"], "--keylog-per-dump", str(per),
                  "--related-labels", STS0, "--delta-start", "-256", "--length", "768",
                  "--no-heap", "-o", str(out2)])
    with redirect_stdout(io.StringIO()):
        assert _cmd_propose_layout(args) == 0
    assert json.loads(out2.read_text())["suggested_meanings"]
    model = tmp_path / "cli.json"
    args = parse(["model-build", *corpus["paths"], "--keylog", corpus["shared"], "--name", "o",
                  "--delta-start", "-256", "--length", "768", "--no-heap",
                  "--out-path", str(model)])
    with redirect_stdout(io.StringIO()):
        assert _cmd_model_build(args) == 0
    assert model.is_file()
    args = parse(["model-build", *corpus["paths"], "--keylog", "x", "--keylog-per-dump", "{}",
                  "--name", "o", "--out-path", str(tmp_path / "no.json")])
    with redirect_stdout(io.StringIO()):
        assert _cmd_model_build(args) == 1       # both modes: refused, not a traceback


# -- review fixes: length validation, input hardening, limits, held-out ----------------

def test_truncated_and_short_entries_are_malformed_with_line_numbers():
    good = _lines(0)
    cr = "ab" * 32
    text = (good + f"{CTS0} {cr} eb17\n" + f"CLIENT_RANDOM {cr} {'11' * 32}\n"
            + f"{STS0} {'ab' * 31} {'cd' * 32}\n" + f"{STS0} {cr} zz{'cd' * 31}\n")
    res = ka.parse_keylog_text(text)
    assert res.malformed == 4 and len(res.sessions) == 1
    lines = {d["line"] for d in res.malformed_details}
    assert lines == {4, 5, 6, 7} and all(d["reason"] for d in res.malformed_details)
    assert res.to_dict()["malformed_details"]


def test_tls13_48_byte_secrets_ok_and_mixed_lengths_flagged():
    cr = "cd" * 32
    res = ka.parse_keylog_text(f"{CTS0} {cr} {'11' * 48}\n{STS0} {cr} {'22' * 32}\n")
    assert res.malformed == 0 and res.length_mismatches == [cr]


def test_truncated_line_never_anchors_a_dump(corpus, tmp_path):
    """Run 3's line removed, run 4's cut to 2 bytes: dump 3 must not anchor to run 4."""
    text = _lines(0) + _lines(1) + f"{CTS0} {_session_bytes(3)['cr'].hex()} eb17\n"
    parsed = ka.parse_keylog_text(text)
    assert parsed.malformed == 1
    with ExitStack() as stack:
        from memdiver.app.tools_consensus import _open_one
        src = {p: _open_one(stack, p, None) for p in corpus["paths"]}
        out = ka.resolve_keylog_anchors(
            src, {p: parsed.sessions for p in src}, anchor_label=CTS0,
            view=lambda s: "va")
    assert out[corpus["paths"][0]].anchored and out[corpus["paths"][1]].anchored
    assert out[corpus["paths"][0]].client_random_present is True
    assert not out[corpus["paths"][3]].anchored


def test_short_needle_is_never_searched():
    sess = ka.KeylogSession(b"\x01" * 32, {CTS0: b"\xeb\x17"})
    res = ka.resolve_keylog_anchors({"d": object()}, {"d": [sess]}, anchor_label=CTS0)
    assert not res["d"].anchored and res["d"].candidates == 0


def test_bad_inputs_are_invalid_input_not_500(tmp_path):
    from memdiver.app.keylog_input import load_keylogs
    binary = tmp_path / "b.bin"
    binary.write_bytes(b"\xff\xfe\x00\x80" * 8)
    for spec in ({"per_dump": "x"}, {"text": 5}, {"path": str(binary)}):
        with pytest.raises(CapabilityError) as e:
            load_keylogs(spec, ["d"])
        assert e.value.category.name == "INVALID_INPUT"
    with pytest.raises(CapabilityError, match="not UTF-8"):
        load_keylogs({"path": str(binary)}, ["d"])


def test_limits_inline_4mib_but_file_up_to_64mib(tmp_path):
    from memdiver.app.keylog_input import load_keylogs
    big = "# pad\n" * (ka.MAX_KEYLOG_BYTES // 6 + 10) + _lines(0)
    assert len(big) > ka.MAX_KEYLOG_BYTES
    f = tmp_path / "big.log"
    f.write_text(big)
    keylogs, _ = load_keylogs({"path": str(f)}, ["d"])
    assert len(keylogs["d"]) == 1
    with pytest.raises(CapabilityError, match="inline"):
        load_keylogs({"text": big}, ["d"])


def test_held_out_expected_uses_secret_presence_and_shared_parser(corpus, tmp_path):
    from memdiver.app.tools_semantic import _parse_keylog_expected, _shared_expected
    from memdiver.app.tools_consensus import _open_one
    # BOM + corpus header + CSV id form + truncated line (dropped)
    text = "﻿id,line\n1," + _lines(2).splitlines()[0] + f"\n2,{CTS0} {'ab' * 32} eb17\n"
    got = _parse_keylog_expected(text, [CTS0])
    assert got == {(CTS0, _session_bytes(2)["cr"].hex(), _session_bytes(2)[CTS0].hex())}
    # session 1 has its client_random in dump 0 but no secrets there -> not_in_memory
    absent_secret = ka.KeylogSession(_session_bytes(0)["cr"], {CTS0: _rand("nope", 0, 32)})
    own = ka.parse_keylog_text(_lines(0)).sessions[0]
    note: list = []
    with ExitStack() as stack:
        opened = _open_one(stack, corpus["paths"][0], None)
        exp = _shared_expected([own, absent_secret], opened, [CTS0], note)
    assert exp == {(CTS0, own.client_random.hex(), own.secrets[CTS0].hex())}
    note2: list = []
    with ExitStack() as stack:
        opened = _open_one(stack, corpus["paths"][0], None)
        assert _shared_expected([absent_secret], opened, [CTS0], note2) == set()
    assert note2 == [absent_secret.client_random.hex()]


def test_validate_shared_keylog_reports_malformed_lines(corpus, tmp_path):
    """A dropped held-out key-log line must be visible in the validate payload, never silent."""
    pytest.importorskip("volatility3")
    from memdiver.app.tools_semantic import artifact_model_validate_result

    model = _build(corpus, tmp_path / "vm.json", related_labels=[STS0]).payload["path"]
    held = [_write_msl(tmp_path / "m0.msl", [_session_bytes(70)])]
    text = _lines(70) + f"CLIENT_TRAFFIC_SECRET_0 {'ab' * 32} eb17\n"
    result = artifact_model_validate_result(
        _session(), model_path=model, held_out=[{"dump_path": p} for p in held],
        keylog={"text": text}).payload
    summary = result["keylog_summary"]
    assert summary and sum(int(s.get("malformed", 0)) for s in summary) >= 1
    assert result["captures"][0]["verdict"] == "pass"

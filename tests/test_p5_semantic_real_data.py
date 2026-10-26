"""P5 gate on real TLS 1.3 dumps: learn on 8 runs, validate a Volatility3 plugin on the rest.

Driven through the PUBLIC producers (app.tools_semantic / app.tools_consensus, the
functions the CLI, web and MCP surfaces call). Gated on MEMDIVER_TLS_CORPUS, the
``experiment2_tls_local/data`` dir (``TLS13/<lib>/<lib>_run_13_<n>/``). Run with ``-s``
to see timings.
"""

from __future__ import annotations

import glob
import os
import re
import time
from pathlib import Path

import pytest

from memdiver.app.composition import build_tool_session
from memdiver.app import tools_semantic as S
from memdiver.app.tools_consensus import anchor_consensus_result
from memdiver.core.service_errors import CapabilityError, ErrorCategory

CORPUS = os.environ.get("MEMDIVER_TLS_CORPUS")
pytestmark = pytest.mark.skipif(
    not CORPUS or not (Path(CORPUS) / "TLS13").is_dir(),
    reason="MEMDIVER_TLS_CORPUS must point at experiment2_tls_local/data (holding TLS13/)")

N_LEARN, MIN_HELD = 8, 30
DELTA_START, LENGTH = -0x800, 0x1600
CTS, STS = "CLIENT_TRAFFIC_SECRET_0", "SERVER_TRAFFIC_SECRET_0"
# library -> expected verified deltas (client_random, STS0) and object bounds
EXPECT = {
    "openssl": {"client_random": -0x5BC, "server_traffic_secret_0": 0x40,
                "total_size": 0x1510, "base_delta": -0x6FC},
    "boringssl": {"client_random": -0xF0, "server_traffic_secret_0": 0x31},
}
RELATIONSHIPS = [{"kind": "owned_by", "source": "anchor", "target": "client_random"},
                 {"kind": "owned_by", "source": "server_traffic_secret_0", "target": "client_random"}]
MEANINGS = [
    {"field": "anchor", "meaning": "tls13.client_traffic_secret_0", "label": CTS,
     "support": [{"kind": "ground_truth", "ref": "keylog.csv"}]},
    {"field": "server_traffic_secret_0", "meaning": "tls13.server_traffic_secret_0", "label": STS,
     "support": [{"kind": "ground_truth", "ref": "keylog.csv"}]},
    {"field": "client_random", "meaning": "tls.client_random"}]


def _run_key(p: Path):
    return [int(x) if x.isdigit() else x for x in re.split(r"(\d+)", p.name)]


def _msl(run: Path) -> str:
    return sorted(glob.glob(str(run / "dumps/msl/*.msl")))[0]


def _keylog(run: Path) -> dict:
    out = {}
    for line in (run / "keylog.csv").read_text().splitlines():
        parts = line.split()
        if len(parts) == 3 and parts[0].isupper():
            out[parts[0]] = (parts[1], parts[2])
    return out


def _usable(lib: str):
    root = Path(CORPUS) / "TLS13" / lib
    runs = sorted((p for p in root.iterdir() if p.is_dir()), key=_run_key)
    return [r for r in runs if (r / "keylog.csv").exists() and glob.glob(str(r / "dumps/msl/*.msl"))]


def _inputs(lib: str):
    runs = _usable(lib)
    learn, held = runs[:N_LEARN], runs[N_LEARN:]
    kl = {r: _keylog(r) for r in learn}
    paths = [_msl(r) for r in learn]
    return {
        "learn": learn, "held": held, "paths": paths,
        "needles": {_msl(r): kl[r][CTS][1] for r in learn},
        "related": {"client_random": {_msl(r): kl[r][CTS][0] for r in learn},
                    "server_traffic_secret_0": {_msl(r): kl[r][STS][1] for r in learn}},
    }


@pytest.fixture(scope="module")
def session():
    return build_tool_session()


@pytest.fixture(scope="module", params=sorted(EXPECT))
def learned(request, session, tmp_path_factory):
    lib = request.param
    inp = _inputs(lib)
    assert len(inp["held"]) >= MIN_HELD, f"only {len(inp['held'])} held-out {lib} runs"
    common = dict(dump_paths=inp["paths"], needles=inp["needles"],
                  delta_start=DELTA_START, length=LENGTH)
    t0 = time.monotonic()
    anchor = anchor_consensus_result(session, **common)
    t_anchor = time.monotonic() - t0
    t0 = time.monotonic()
    proposal = S.propose_layout_result(session, related=inp["related"], heap=True, **common)
    t_propose = time.monotonic() - t0
    out = tmp_path_factory.mktemp(f"p5_{lib}")
    model_path = out / f"{lib}_model.json"
    t0 = time.monotonic()
    built = S.artifact_model_build_result(
        session, related=inp["related"], heap=True, name=f"{lib}_tls13_session",
        meanings=MEANINGS, relationships=RELATIONSHIPS,
        applicability={"library": lib, "states": ["post_handshake"]},
        out_path=str(model_path), **common)
    t_build = time.monotonic() - t0
    exported = S.artifact_model_export_result(
        session, model_path=str(model_path), out_path=str(out / f"{lib}_plugin.py"))
    return dict(lib=lib, inp=inp, anchor=anchor.payload, anchor_result=anchor,
                proposal=proposal.payload, built=built.payload, exported=exported.payload,
                model_path=model_path,
                timings=dict(anchor=t_anchor, propose=t_propose, build=t_build))


def test_anchor_consensus_all_anchored(learned):
    a = learned["anchor"]
    assert len(a["instances"]) == N_LEARN and not a["unanchored"], a["unanchored"]
    assert all(n == 1 for n in a["alternatives"].values()), a["alternatives"]
    assert learned["anchor_result"].status.resolution.name == "OK"
    anchor_len = len(next(iter(learned["inp"]["needles"].values()))) // 2
    anchor_regions = [r for r in a["regions"]
                      if r["delta_start"] < anchor_len and r["delta_end"] > 0]
    # The key bytes differ per run: never invariant. Random bytes legitimately split into
    # key_candidate / pointer-looking / variable runs, so only "not invariant" is a fact.
    anchor_classes = {r["class"] for r in anchor_regions}
    assert "key_candidate" in anchor_classes and "invariant" not in anchor_classes, anchor_regions
    assert a["class_counts"].get("invariant", 0) > 0, a["class_counts"]


def test_layout_proposal_bounds_and_verified_deltas(learned):
    p, exp = learned["proposal"], EXPECT[learned["lib"]]
    assert len(p["instances"]) == N_LEARN and not p["unanchored"]
    assert p["base_delta"] is not None and p["total_size"], "object bounds not proposed"
    verified = {f["name"]: f["delta"] for f in p["fields"] if f["kind"] == "verified_field"}
    for name in ("client_random", "server_traffic_secret_0"):
        assert verified.get(name) == exp[name], (learned["lib"], name, verified)
    for key in ("total_size", "base_delta"):
        if key in exp:
            assert p[key] == exp[key], (key, hex(p[key]))


def test_validate_held_out_pass(learned, session):
    inp = learned["inp"]
    held = [{"dump_path": _msl(r), "keylog_path": str(r / "keylog.csv")} for r in inp["held"]]
    t0 = time.monotonic()
    res = S.artifact_model_validate_result(
        session, model_path=str(learned["model_path"]), held_out=held)
    t_val = time.monotonic() - t0
    tot, n = res.payload["totals"], len(held)
    t = learned["timings"]
    msg = (f"{learned['lib']}: held={n} totals={tot} verdict={res.payload['verdict']} "
           f"anchor={t['anchor']:.1f}s propose={t['propose']:.1f}s build={t['build']:.1f}s "
           f"validate={t_val:.1f}s (plugin run {res.payload['seconds']}s)")
    print(msg)
    assert res.payload["verdict"] == "pass", msg
    assert tot["expected"] == tot["tp"] == 2 * n, msg
    assert tot["fp"] == 0 and tot["fn"] == 0, msg
    assert tot["relationships_correct"] == tot["expected"], msg


def test_validating_a_learning_run_is_refused(learned, session):
    run = learned["inp"]["learn"][0]
    with pytest.raises(CapabilityError) as exc:
        S.artifact_model_validate_result(
            session, model_path=str(learned["model_path"]),
            held_out=[{"dump_path": _msl(run), "keylog_path": str(run / "keylog.csv")}])
    assert exc.value.code == "semantic.held_out_leak"


def test_gnutls_invents_no_relationship(session, tmp_path):
    """gnutls does not keep client_random at a constant delta: the build is refused."""
    inp = _inputs("gnutls")
    with pytest.raises(CapabilityError) as exc:
        S.artifact_model_build_result(
            session, dump_paths=inp["paths"], needles=inp["needles"], related=inp["related"],
            delta_start=DELTA_START, length=LENGTH, heap=True, name="gnutls_tls13_session",
            meanings=MEANINGS, relationships=RELATIONSHIPS,
            out_path=str(tmp_path / "gnutls_model.json"))
    assert exc.value.category == ErrorCategory.INVALID_INPUT, exc.value
    assert not (tmp_path / "gnutls_model.json").exists()


PRIMARY_RECORD_HEADER = bytes.fromhex("00000000050017030300fc")


def test_boringssl_alternative_window_survives_patched_primary(learned, session, tmp_path):
    """Patch the primary prefilter's fixed TLS record-length byte (fc -> fd) in held-out
    dumps: the primary window can no longer match, yet every secret is still found
    through an alternative in-object window."""
    if learned["lib"] != "boringssl":
        pytest.skip("boringssl-only mutation test")
    held = learned["inp"]["held"][:3]
    original, patched = [], []
    for run in held:
        data = bytearray(Path(_msl(run)).read_bytes())
        pos = bytes(data).find(PRIMARY_RECORD_HEADER)
        assert pos >= 0, f"{run.name}: primary prefilter not present in the original dump"
        data[pos + len(PRIMARY_RECORD_HEADER) - 1] = 0xFD
        out = tmp_path / f"{run.name}.msl"
        out.write_bytes(bytes(data))
        original.append({"dump_path": _msl(run), "keylog_path": str(run / "keylog.csv")})
        patched.append({"dump_path": str(out), "keylog_path": str(run / "keylog.csv")})
    model = str(learned["model_path"])
    base = S.artifact_model_validate_result(session, model_path=model, held_out=original).payload
    res = S.artifact_model_validate_result(session, model_path=model, held_out=patched).payload
    n = len(held)
    print("original", base["totals"], base["window_redundancy"])
    print("patched ", res["totals"], res["window_redundancy"], res["warnings"])
    for pl in (base, res):
        assert pl["verdict"] == "pass", pl["totals"]
        assert pl["totals"]["tp"] == 2 * n and pl["totals"]["fn"] == 0 and pl["totals"]["fp"] == 0
    for pl in (base, res):  # owner correct for every TP, alternative-only included
        assert pl["totals"]["relationships_correct"] == pl["totals"]["relationships_checked"] == 2 * n, pl["totals"]
    assert base["window_redundancy"]["tp_by_window"].get("0", 0) == 2 * n
    patched_by_window = res["window_redundancy"]["tp_by_window"]
    assert patched_by_window.get("0", 0) == 0, patched_by_window  # primary did NOT hit
    assert sum(patched_by_window.values()) >= 2 * n
    assert all(tp["windows"] and 0 not in tp["windows"]
               for cap in res["captures"] for tp in cap["tp_windows"])

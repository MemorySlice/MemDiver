"""Workload-shift gate: a boringssl model learned on the OLD cohort still finds the keys
in a NEW (early-data) cohort whose primary prefilter bytes changed.

Learn on 8 runs of ``MEMDIVER_TLS_CORPUS`` (``experiment2_tls_local/data``); validate on
``MEMDIVER_TLS_EARLYDATA_CORPUS`` (``.../data_earlydata``). The primary window (0) must not
hit on the new cohort; every TP must come via an alternative window. Control: held-out OLD
runs hit window 0. Pass ABSOLUTE paths for both env vars. Helpers come from
tests/test_p5_semantic_real_data.py.
"""

from __future__ import annotations

import glob
import os
from pathlib import Path

import pytest

from memdiver.app import tools_semantic as S
from memdiver.app.composition import build_tool_session
from tests import test_p5_semantic_real_data as P5

OLD = os.environ.get("MEMDIVER_TLS_CORPUS")
NEW = os.environ.get("MEMDIVER_TLS_EARLYDATA_CORPUS")
_OLD_DIR = Path(OLD) / "TLS13" / "boringssl" if OLD else None
_NEW_DIR = Path(NEW) / "TLS13" / "boringssl" if NEW else None
pytestmark = pytest.mark.skipif(
    not (_OLD_DIR and _OLD_DIR.is_dir() and _NEW_DIR and _NEW_DIR.is_dir()),
    reason="MEMDIVER_TLS_CORPUS (.../data) and MEMDIVER_TLS_EARLYDATA_CORPUS "
           "(.../data_earlydata) must both be set to existing ABSOLUTE paths")

N_LEARN, N_VALIDATE = 8, 6


def _usable(root: Path):
    runs = sorted((p for p in root.iterdir() if p.is_dir()), key=P5._run_key)
    return [r for r in runs if (r / "keylog.csv").exists()
            and glob.glob(str(r / "dumps/msl/*.msl"))]


def _held(runs):
    return [{"dump_path": P5._msl(r), "keylog_path": str(r / "keylog.csv")} for r in runs]


@pytest.fixture(scope="module")
def session():
    return build_tool_session()


@pytest.fixture(scope="module")
def model(session, tmp_path_factory):
    learn = _usable(_OLD_DIR)[:N_LEARN]
    assert len(learn) == N_LEARN
    kl = {r: P5._keylog(r) for r in learn}
    paths = [P5._msl(r) for r in learn]
    built = S.artifact_model_build_result(
        session, dump_paths=paths, delta_start=P5.DELTA_START, length=P5.LENGTH,
        needles={P5._msl(r): kl[r][P5.CTS][1] for r in learn},
        related={"client_random": {P5._msl(r): kl[r][P5.CTS][0] for r in learn},
                 "server_traffic_secret_0": {P5._msl(r): kl[r][P5.STS][1] for r in learn}},
        heap=True, name="boringssl_tls13_session", meanings=P5.MEANINGS,
        relationships=P5.RELATIONSHIPS,
        applicability={"library": "boringssl", "states": ["post_handshake"]},
        out_path=str(tmp_path_factory.mktemp("shift") / "model.json"), detail="full")
    return built.payload


def _validate(session, model, runs):
    return S.artifact_model_validate_result(
        session, model_path=model["path"], held_out=_held(runs)).payload


def test_model_has_alternative_and_low_information_warning(model):
    assert model["model"]["locator"]["alternatives"], "no alternative window learned"
    assert any(w.startswith("prefilter.low_information") for w in model["model"]["warnings"])


def test_new_cohort_found_only_via_alternative_window(session, model):
    runs = _usable(_NEW_DIR)[:N_VALIDATE]
    assert len(runs) == N_VALIDATE
    p = _validate(session, model, runs)
    t = p["totals"]
    assert p["verdict"] == "pass", t
    assert t["fp"] == 0 and t["fn"] == 0 and t["tp"] == t["expected"] > 0, t
    assert t["relationships_correct"] == t["relationships_checked"] == t["expected"], t
    by_window = p["window_redundancy"]["tp_by_window"]
    assert by_window.get("0", 0) == 0, by_window
    assert sum(by_window.values()) >= t["tp"], by_window
    assert all(tp["windows"] and 0 not in tp["windows"]
               for cap in p["captures"] for tp in cap["tp_windows"])


def test_old_heldout_control_hits_primary_window(session, model):
    runs = _usable(_OLD_DIR)[N_LEARN:N_LEARN + N_VALIDATE]
    assert len(runs) == N_VALIDATE
    p = _validate(session, model, runs)
    t = p["totals"]
    assert p["verdict"] == "pass", t
    assert t["fp"] == 0 and t["fn"] == 0, t
    assert p["window_redundancy"]["tp_by_window"].get("0", 0) == t["tp"] > 0

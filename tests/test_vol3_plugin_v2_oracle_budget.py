"""Oracle budget, verify order, prefilter, ``unique`` and ctx of the recipe-v2 template.

A stub oracle bundle replaces the inlined gocryptfs oracle (``render(bundle=...)``),
so these tests control cost, verdicts and timing exactly and can see every
``verify`` call and the ctx it got. The real gocryptfs oracle is covered by
``tests/test_vol3_plugin_v2_template.py``.
"""

from __future__ import annotations

import itertools
import sys

import pytest

from memdiver.architect import vol3_recipe as vr
from tests import _vol3_recipe_fixtures as fx

pytest.importorskip("volatility3")

STUB_BUNDLE = r'''
# <test stub oracle bundle>
import time as _stub_time

MEMDIVER_INLINED_SOURCES = ''
CALLS = []


class _StubOracle(object):
    def __init__(self, params):
        self.proven_key = bytes.fromhex(params["proven_hex"])
        self.sleep_s = float(params.get("sleep_s", 0))
        self.candidate_lengths = (32,)
        if params.get("cost_us") is not None:
            self.cost_us = params["cost_us"]
        if params.get("unique"):
            self.unique = True
        if params.get("backend"):
            self.backend = params["backend"]
        if params.get("prefilter"):
            self.prefilter = self._prefilter

    def _prefilter(self, key):
        return None if key == self.proven_key else "not the stub key"

    def verify(self, key, ctx):
        CALLS.append((bytes(key), ctx))
        if self.sleep_s:
            _stub_time.sleep(self.sleep_s)
        if key == self.proven_key:
            return {"status": "proven", "detail": "stub proof"}
        return {"status": "rejected", "detail": "stub mismatch"}


class _StubFormat(object):
    KIND = "stub"
    COST_US = 7

    @staticmethod
    def build_oracle(params, sample):
        return _StubOracle(params)


def load_inlined(kind, sources):
    return _StubFormat
'''

_NAMES = itertools.count()
#: The Proven label names the RECIPE's oracle kind (the stub stands in for it).
PROVEN = "oracle:" + fx.KIND


def _source(*, ctx=None, entropy_mode="fallback", **params):
    recipe = fx.synthetic_recipe()
    data = recipe.to_dict()
    data["oracle"]["params"] = dict({"proven_hex": fx.MASTER.hex()}, **params)
    if ctx:
        data["oracle"]["ctx"] = ctx
    data["locators"][1]["params"]["mode"] = entropy_mode
    return vr.render(vr.PluginRecipe.from_dict(data), bundle=STUB_BUNDLE)


def _run(source, **config):
    from memdiver.engine.vol3_verify import run_rows_over_buffer

    name = "memdiver_budget_test_%d" % next(_NAMES)
    rows = run_rows_over_buffer(source, fx.process_buffer(), module_name=name,
                                extra_config=dict(config, show_unverified=True))
    return rows, sys.modules[name]


def _plugin(source):
    """``(plugin instance without a vol context, module)`` for direct ``_judge`` calls."""
    from memdiver.engine.vol3_verify import load_plugin_class

    name = "memdiver_budget_unit_%d" % next(_NAMES)
    cls = load_plugin_class(source, name)
    module = sys.modules[name]
    return cls.__new__(cls), module


def _oracle(module, **params):
    return module._StubOracle(dict({"proven_hex": fx.MASTER.hex()}, **params))


def _candidate(module, key, locator, offset):
    candidate = module.Candidate(key)
    candidate.add_site(offset, offset, 0.0, locator)
    return candidate


def _keys(n, seed=b"k"):
    return [fx.filler(64, seed + bytes([i]))[32:] for i in range(n)]


# -- parse_oracle_budget ------------------------------------------------------------------

def test_parse_oracle_budget():
    _plugin_obj, module = _plugin(_source())
    parse = module.parse_oracle_budget
    assert parse(None) == module.DEFAULT_ORACLE_BUDGET_S == 120.0
    assert parse("") == 120.0
    assert parse("2.5") == 2.5
    assert parse("0") is None and parse("-1") is None and parse("inf") is None
    for bad in ("abc", "nan"):
        with pytest.raises(ValueError):
            parse(bad)


def test_unparseable_budget_warns_and_uses_the_default(caplog):
    caplog.set_level("WARNING")
    rows, _module = _run(_source(), oracle_budget="soon")
    assert any(r["Proven"] == PROVEN for r in rows)
    assert "using the default 120 s" in caplog.text


# -- budget ------------------------------------------------------------------------------

def test_budget_expiry_leaves_candidates_unverified_never_rejected(caplog):
    caplog.set_level("INFO")
    rows, module = _run(_source(sleep_s=0.02), exhaustive=True, oracle_budget="0.05")
    proven = [r for r in rows if r["Proven"] == PROVEN]
    assert {r["KeyOffset"] for r in proven} == set(fx.KEY_SITES), "anchor key verified first"
    budget = [r for r in rows if "budget:" in r["Detail"]]
    assert budget, "the entropy pass must run out of budget"
    assert all(r["Proven"] == "unverified" for r in budget)
    assert all("raise --oracle-budget" in r["Detail"] for r in budget)
    rejected = [r for r in rows if r["Proven"] == "rejected" and "prefilter" not in r["Detail"]]
    assert len(rejected) == len(module.CALLS) - 1, "only verified candidates are rejected"
    assert len(module.CALLS) <= 5
    assert "oracle budget exhausted" in caplog.text
    assert "candidate(s) to verify, est" in caplog.text


def test_budget_detail_carries_the_estimate():
    plugin, module = _plugin(_source())
    plugin._budget_left = 0.0
    oracle = _oracle(module, cost_us=1000)
    candidates = {k: _candidate(module, k, "entropy", i) for i, k in enumerate(_keys(4))}
    plugin._judge(candidates, oracle, "stub", None)
    assert not module.CALLS
    assert {c.proven for c in candidates.values()} == {"unverified"}
    assert {c.detail for c in candidates.values()} == {
        "budget: 4 not verified (est 0.00 s; raise --oracle-budget)"}
    assert plugin._budget_skipped == 4


def test_cost_us_defaults_to_the_module_constant_and_is_scaled_for_pure_python():
    plugin, module = _plugin(_source())
    plugin._module_cost_us = 7
    assert plugin._cost_us(_oracle(module)) == 7
    assert plugin._cost_us(_oracle(module, cost_us=500000)) == 500000
    assert plugin._cost_us(_oracle(module, backend="pure-python")) == 140
    del plugin._module_cost_us
    assert plugin._cost_us(_oracle(module)) is None
    assert plugin._estimate_s(_oracle(module, cost_us=500000), 3) == 1.5


def test_unlimited_budget_verifies_everything():
    rows, module = _run(_source(), exhaustive=True, oracle_budget="0")
    assert not any("budget:" in r["Detail"] for r in rows)
    assert len(module.CALLS) > 10


# -- order ---------------------------------------------------------------------------------

def test_verify_order_is_anchor_first_then_entropy_descending():
    plugin, module = _plugin(_source())
    low, high = fx.filler(64, b"lo")[32:], fx.MASTER
    weak = bytes(range(16)) * 2                       # 4.0 bits/byte, passes the filter
    candidates = {
        weak: _candidate(module, weak, "entropy", 0x10),
        low: _candidate(module, low, "entropy", 0x20),
        high: _candidate(module, high, "anchor", 0x9000),
    }
    candidates[low].add_site(0x30, 0x30, 0.5, "anchor")
    ordered = sorted(candidates.values(), key=plugin._verify_order_key())
    assert ordered[0].locators == ["anchor"]          # anchor-only first (locator order)
    assert ordered[1].key == low                      # found by anchor too
    assert ordered[2].key == weak
    entropy_only = [_candidate(module, k, "entropy", i) for i, k in enumerate(_keys(6))]
    ordered = sorted(entropy_only, key=plugin._verify_order_key())
    assert [c.entropy for c in ordered] == sorted((c.entropy for c in ordered), reverse=True)


def test_anchor_candidate_is_verified_first_in_one_pass():
    plugin, module = _plugin(_source())
    plugin._budget_left = None
    candidates = {k: _candidate(module, k, "entropy", i) for i, k in enumerate(_keys(5))}
    candidates[fx.MASTER] = _candidate(module, fx.MASTER, "anchor", 0x4000)
    plugin._judge(candidates, _oracle(module), "stub", None)
    assert module.CALLS[0][0] == fx.MASTER
    assert len(module.CALLS) == 6


# -- unique ---------------------------------------------------------------------------------

def test_unique_oracle_stops_after_the_proof_in_one_pass():
    plugin, module = _plugin(_source())
    candidates = {fx.MASTER: _candidate(module, fx.MASTER, "anchor", 0x4000)}
    candidates.update({k: _candidate(module, k, "entropy", i) for i, k in enumerate(_keys(5))})
    plugin._judge(candidates, _oracle(module, unique=True), "stub", None)
    assert len(module.CALLS) == 1
    rest = [c for c in candidates.values() if c.key != fx.MASTER]
    assert {(c.proven, c.detail) for c in rest} == {("unverified", "skipped: key already proven")}


def test_unique_oracle_skips_the_entropy_pass_after_an_anchor_proof():
    rows, module = _run(_source(unique=True), exhaustive=True)
    assert len(module.CALLS) == 1
    skipped = [r for r in rows if r["Detail"].endswith("skipped: key already proven")]
    assert skipped and all(r["Proven"] == "unverified" for r in skipped)
    assert not any(r["Proven"] == "rejected" and "prefilter" not in r["Detail"] for r in rows)


def test_non_unique_oracle_keeps_verifying():
    plugin, module = _plugin(_source())
    candidates = {fx.MASTER: _candidate(module, fx.MASTER, "anchor", 0x4000)}
    candidates.update({k: _candidate(module, k, "entropy", i) for i, k in enumerate(_keys(5))})
    plugin._judge(candidates, _oracle(module), "stub", None)
    assert len(module.CALLS) == 6


# -- prefilter -------------------------------------------------------------------------------

def test_prefilter_rejects_with_its_reason_before_any_verify():
    rows, module = _run(_source(prefilter=True), exhaustive=True)
    assert [k for k, _ctx in module.CALLS] == [fx.MASTER]
    pre = [r for r in rows if r["Detail"].endswith("prefilter: not the stub key")]
    assert pre and all(r["Proven"] == "rejected" for r in pre)


def test_a_raising_prefilter_rejects_nothing():
    plugin, module = _plugin(_source())
    oracle = _oracle(module)

    def broken(_key):
        raise RuntimeError("bug")
    oracle.prefilter = broken
    candidates = {k: _candidate(module, k, "entropy", i) for i, k in enumerate(_keys(3))}
    plugin._judge(candidates, oracle, "stub", None)
    assert len(module.CALLS) == 3
    assert not any(c.detail.startswith("prefilter") for c in candidates.values())


# -- ctx -------------------------------------------------------------------------------------

def test_ctx_reaches_the_oracle():
    rows, module = _run(_source(ctx={"hint": "static"}))
    assert any(r["Proven"] == PROVEN for r in rows)
    key, ctx = module.CALLS[0]
    assert key == fx.MASTER
    assert ctx["hint"] == "static"
    assert ctx["found"] == (fx.MASTER,)
    assert isinstance(ctx["layer"], str) and ctx["layer"]
    assert ctx["offset"] in fx.KEY_SITES
    assert ctx["locators"] == ("anchor",)
    assert ctx["read"](ctx["offset"], 32) == fx.MASTER
    assert ctx["read"](10 ** 9, 4) == bytes(4), "reads pad outside the layer"


def test_found_lists_every_filtered_candidate_of_the_pass():
    plugin, module = _plugin(_source())
    keys = _keys(3)
    candidates = {k: _candidate(module, k, "entropy", i) for i, k in enumerate(keys)}
    zero = bytes(32)
    candidates[zero] = _candidate(module, zero, "entropy", 99)
    plugin._judge(candidates, _oracle(module), "stub", None)
    found = module.CALLS[0][1]["found"]
    assert set(found) == set(keys) and zero not in found
    assert module.CALLS[0][1]["read"] is None and module.CALLS[0][1]["layer"] is None

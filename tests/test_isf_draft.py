"""ISF drafts: operation log, replay, blobs, diff, export (plan T4.1)."""

import json
import os
import time
from pathlib import Path

import hashlib

import pytest

from memdiver.analysis.record import ISF_DRAFT
from memdiver.analysis.record_store import AnalysisRecord
from memdiver.core.service_errors import CapabilityError, ErrorCategory
from memdiver.isf.draft import IsfDraft, IsfDraftStore, Provenance

CAP = "a" * 64
INT = {"kind": "base", "name": "int"}
PROV = Provenance("manual", "manual", ("hex selection 0x10",))
PROBE = Provenance("kallsyms", "probe", author="tool:probe")


@pytest.fixture
def store(tmp_path):
    s = IsfDraftStore(tmp_path)
    s.create(CAP, "d", arch="x86_64", banner="Linux version 5.10")
    return s


def mat(s, **kw):
    return s.materialize(CAP, "d", **kw)


def donor_isf():
    return {
        "metadata": {"format": "6.2.0"},
        "base_types": {"int": {"size": 4, "signed": True, "kind": "int", "endian": "little"}},
        "user_types": {
            "task": {"kind": "struct", "size": 64, "fields": {
                "pid": {"offset": 8, "type": INT}, "comm": {"offset": 16, "type": INT}}},
            "mm": {"kind": "struct", "size": 8, "fields": {}}},
        "enums": {"e": {"size": 4, "base": "int", "constants": {"A": 1}}},
        "symbols": {"init_task": {"address": 2 ** 63 + 5}, "init_mm": {"address": 0x1000}},
    }


# -- lifecycle ------------------------------------------------------------------

def test_create_list_duplicate_and_unknown(store):
    listed = store.list_drafts(CAP)
    assert [d["name"] for d in listed] == ["d"] and listed[0]["arch"] == "x86_64"
    assert listed[0]["applied"] == 1 and listed[0]["counts"]["symbols"] == 0
    with pytest.raises(CapabilityError) as dup:
        store.create(CAP, "d", arch="x86_64")
    assert dup.value.category is ErrorCategory.INVALID_INPUT
    with pytest.raises(CapabilityError) as unk:
        store.set_struct(CAP, "nope", "s", 1, PROV)
    assert unk.value.category is ErrorCategory.NOT_FOUND
    with pytest.raises(CapabilityError):
        store.create(CAP, "Bad Name", arch="x86_64")
    assert mat(store).metadata["banner"] == "Linux version 5.10"


def test_each_single_key_op(store):
    sym = store.set_symbol(CAP, "d", "init_task", 0xFFFF800000001000, PROBE,
                           type_descriptor={"kind": "struct", "name": "task"})
    store.set_struct(CAP, "d", "task", 64, PROV, kind="union")
    store.set_field(CAP, "d", "task", "pid", 8, INT, PROV)
    store.set_base_type(CAP, "d", "int", size=4, signed=True, kind="int", endian="little",
                        provenance=PROV)
    store.set_enum(CAP, "d", "e", size=4, base="int", constants={"A": 1}, provenance=PROV)
    d = mat(store)
    assert d.symbols["init_task"] == {"address": 0xFFFF800000001000,
                                      "type": {"kind": "struct", "name": "task"}}
    assert d.user_types["task"] == {"kind": "union", "size": 64,
                                    "fields": {"pid": {"offset": 8, "type": INT}}}
    assert d.base_types["int"]["size"] == 4 and d.enums["e"]["constants"] == {"A": 1}
    assert d.provenance_of(("symbol", "init_task")).provenance == PROBE
    assert sym.kind == ISF_DRAFT and sym.author == "tool:probe"
    assert sym.locations[0].value == 0xFFFF800000001000 and sym.locations[0].capture_id == CAP
    assert [s.ref for s in sym.support] == []
    assert d.applied == 6 and d.version != sym.id


def test_set_field_creates_struct_flagged_unsized(store):
    store.set_field(CAP, "d", "s", "f", 4, INT, PROV)
    d = mat(store)
    assert d.user_types["s"]["size"] == 0
    assert "size_unknown" in d.provenance_of(("type", "s")).provenance.evidence
    store.set_struct(CAP, "d", "s", 16, PROV)
    d = mat(store)
    assert d.user_types["s"]["size"] == 16 and "f" in d.user_types["s"]["fields"]


def test_validation(store):
    for bad in (lambda: store.set_symbol(CAP, "d", "x", -1, PROV),
                lambda: store.set_symbol(CAP, "d", "x", 2 ** 64, PROV),
                lambda: store.set_struct(CAP, "d", "s", -1, PROV),
                lambda: store.set_field(CAP, "d", "s", "f", -4, INT, PROV),
                lambda: store.set_field(CAP, "d", "s", "f", 0, {"name": "int"}, PROV),
                lambda: store.set_struct(CAP, "d", "s", 1, Provenance("m", "bogus")),
                lambda: store.set_struct(CAP, "d", "s", 1, PROV, kind="class"),
                lambda: store.remove(CAP, "d", ("nonsense", "x"), PROV)):
        with pytest.raises(CapabilityError) as err:
            bad()
        assert err.value.category is ErrorCategory.INVALID_INPUT
    assert mat(store).applied == 1


def test_last_writer_wins_and_supersedes_chain(store):
    first = store.set_symbol(CAP, "d", "s", 0x10, PROV)
    second = store.set_symbol(CAP, "d", "s", 0x20, PROV)
    third = store.set_symbol(CAP, "d", "s", 0x30, PROV)
    assert first.supersedes is None
    assert second.supersedes == first.id and third.supersedes == second.id
    assert mat(store).symbols["s"]["address"] == 0x30
    assert [e.id for e in AnalysisRecord(store.case_dir).history(CAP, first.id)] == \
        [first.id, second.id, third.id]


def test_single_key_edit_keeps_rest_of_import(store):
    store.import_isf(CAP, "d", donor_isf(), Provenance("isf_import", "imported"))
    store.set_field(CAP, "d", "task", "pid", 12, INT, PROV)
    d = mat(store)
    assert d.user_types["task"]["fields"]["pid"]["offset"] == 12
    assert "comm" in d.user_types["task"]["fields"] and d.symbols["init_mm"]


def test_retraction_restores_previous_value(store):
    store.set_symbol(CAP, "d", "s", 0x10, PROV)
    second = store.set_symbol(CAP, "d", "s", 0x20, PROV)
    store.retract(CAP, "d", second.id, reason="wrong")
    assert mat(store).symbols["s"]["address"] == 0x10
    # a new write after the retraction does not chain onto the withdrawn entry
    third = store.set_symbol(CAP, "d", "s", 0x30, PROV)
    assert third.supersedes != second.id
    with pytest.raises(CapabilityError):
        store.retract(CAP, "d", second.id)
    create_id = store.versions(CAP, "d")[0]["entry_id"]
    with pytest.raises(CapabilityError):
        store.retract(CAP, "d", create_id)
    flags = {v["entry_id"]: v["retracted"] for v in store.versions(CAP, "d")}
    assert flags[second.id] is True and flags[third.id] is False


def test_remove_tombstones(store):
    store.import_isf(CAP, "d", donor_isf(), Provenance("isf_import", "imported"))
    store.remove(CAP, "d", ("symbol", "init_mm"), PROV)
    store.remove(CAP, "d", ("field", "task", "comm"), PROV)
    store.remove(CAP, "d", ("user_types", "mm"), PROV)
    d = mat(store)
    assert "init_mm" not in d.symbols and "comm" not in d.user_types["task"]["fields"]
    assert "mm" not in d.user_types and ("type", "mm") not in d.origins


# -- imports --------------------------------------------------------------------

def test_import_full_only_and_missing(store):
    isf = donor_isf()
    entry = store.import_isf(CAP, "d", isf, Provenance("isf_import", "imported"))
    d = mat(store)
    assert d.user_types == isf["user_types"] and d.symbols == isf["symbols"]
    assert d.enums == isf["enums"] and d.base_types == isf["base_types"]
    assert d.provenance_of(("field", "task", "pid")).entry_id == entry.id
    assert entry.payload["counts"] == {"base_types": 1, "user_types": 2, "enums": 1, "symbols": 2}

    store.create(CAP, "sub", arch="x86_64")
    store.import_isf(CAP, "sub", isf, PROV, only={"user_types": ["task"], "symbols": ["init_task"]})
    sub = store.materialize(CAP, "sub")
    assert list(sub.user_types) == ["task"] and list(sub.symbols) == ["init_task"]
    assert not sub.enums and not sub.base_types

    with pytest.raises(CapabilityError) as err:
        store.import_isf(CAP, "sub", isf, PROV, only={"symbols": ["init_task", "ghost"]})
    assert "ghost" in str(err.value)
    assert store.materialize(CAP, "sub").applied == 2
    with pytest.raises(CapabilityError):
        store.import_isf(CAP, "sub", {}, PROV)


def test_blob_dedupe_and_tamper(store):
    a = store.import_isf(CAP, "d", donor_isf(), PROV)
    b = store.import_isf(CAP, "d", donor_isf(), PROV)
    assert a.payload["blob_sha256"] == b.payload["blob_sha256"]
    blobs = list((store.case_dir / "isf_drafts" / "blobs").glob("*.json"))
    assert len(blobs) == 1 and not list(blobs[0].parent.glob("*.tmp"))
    blobs[0].write_bytes(b'{"symbols":{}}')
    with pytest.raises(CapabilityError) as err:
        mat(store)
    assert err.value.code == "isf_blob_tampered"
    blobs[0].unlink()
    with pytest.raises(CapabilityError) as missing:
        mat(store)
    assert missing.value.category is ErrorCategory.NOT_FOUND


def test_import_symbols(store):
    entry = store.import_symbols(CAP, "d", {"a": 1, "b": 2 ** 63}, PROBE)
    d = mat(store)
    assert d.symbols == {"a": {"address": 1}, "b": {"address": 2 ** 63}}
    assert entry.payload["op"] == "import" and entry.author == "tool:probe"
    with pytest.raises(CapabilityError):
        store.import_symbols(CAP, "d", {"a": -1}, PROBE)
    with pytest.raises(CapabilityError):
        store.import_symbols(CAP, "d", {}, PROBE)


def test_import_pakunoda_result_accepts_dict_and_store(store):
    class Result:
        type_store = None
        isf_json = donor_isf()

    store.import_pakunoda_result(CAP, "d", Result(), PROV)
    assert "task" in mat(store).user_types
    with pytest.raises(CapabilityError):
        store.import_pakunoda_result(CAP, "d", object(), PROV)


def test_import_layout_claims(store):
    lc = pytest.importorskip("pakunoda.core.layout_claims")
    tier = lc.LayoutTier
    claims = [
        lc.LayoutClaim("task", "mm", 0x40, 8, tier.EXACT, "anchor", ("init_task+0x40 == &init_mm",), 2),
        lc.LayoutClaim("task", "pid", 0x8, 4, tier.CODE, "code"),
        lc.LayoutClaim("task", None, None, 128, tier.EXACT, "anchor"),
        lc.LayoutClaim("other", None, None, 256, tier.BOUND, "population"),
    ]
    entries = store.import_layout_claims(
        CAP, "d", claims, type_hints={("task", "pid"): INT})
    assert len(entries) == 4
    d = mat(store)
    assert d.user_types["task"]["size"] == 128
    assert d.user_types["task"]["fields"]["pid"]["type"] == INT
    mm = d.user_types["task"]["fields"]["mm"]
    assert mm == {"offset": 0x40, "type": {"kind": "base", "name": "void"}}
    mm_prov = d.provenance_of(("field", "task", "mm")).provenance
    assert mm_prov.source == "anchor" and mm_prov.tier == "exact" and mm_prov.witnesses == 2
    assert "type_unknown" in mm_prov.evidence and "init_task+0x40 == &init_mm" in mm_prov.evidence
    assert d.provenance_of(("field", "task", "pid")).provenance.author == "tool:pakunoda"
    assert d.size_bounds == {"other": 256} and "other" not in d.user_types
    assert "other" not in d.to_isf_dict()["user_types"]


# -- versions / materialize(upto) -----------------------------------------------

def test_versions_and_upto(store):
    one = store.set_symbol(CAP, "d", "s", 0x10, PROV)
    two = store.set_symbol(CAP, "d", "s", 0x20, PROV)
    imp = store.import_symbols(CAP, "d", {"t": 5}, PROBE)
    vs = store.versions(CAP, "d")
    assert [v["op"] for v in vs] == ["create", "set_symbol", "set_symbol", "import"]
    assert vs[1]["key"] == ["symbol", "s"] and vs[3]["blob"] == imp.payload["blob_sha256"]
    assert mat(store, upto=one.id).symbols == {"s": {"address": 0x10}}
    older = mat(store, upto=two.id)
    assert older.symbols == {"s": {"address": 0x20}} and older.version == two.id
    store.retract(CAP, "d", two.id)
    assert mat(store, upto=two.id).symbols["s"]["address"] == 0x20  # as it was then
    assert mat(store).symbols["s"]["address"] == 0x10
    with pytest.raises(CapabilityError):
        mat(store, upto="deadbeef")


# -- round trip / diff / export --------------------------------------------------

def test_isf_roundtrip_and_equal_diff(store):
    isf = donor_isf()
    store.import_isf(CAP, "d", isf, PROV)
    out = mat(store).to_isf_dict()
    meta = out["metadata"]
    assert meta["format"] == "6.2.0" and meta["producer"]["name"] == "memdiver"
    drafted = meta["producer"]["memdiver_draft"]
    assert drafted["name"] == "d" and drafted["applied"] == 2
    for section in ("base_types", "user_types", "enums", "symbols"):
        assert out[section] == isf[section]
    ref = IsfDraft.from_isf_dict(out)
    assert mat(store).diff(ref).equal


def test_diff_added_removed_changed_and_only():
    a = IsfDraft.from_isf_dict(donor_isf())
    isf = donor_isf()
    isf["symbols"]["init_task"]["address"] = 1
    isf["symbols"]["new_sym"] = {"address": 9}
    del isf["symbols"]["init_mm"]
    isf["user_types"]["task"]["size"] = 72
    isf["user_types"]["task"]["fields"]["pid"]["offset"] = 9
    del isf["user_types"]["task"]["fields"]["comm"]
    isf["user_types"]["task"]["fields"]["new"] = {"offset": 0, "type": INT}
    isf["enums"]["e"]["constants"]["B"] = 2
    isf["user_types"]["extra"] = {"kind": "struct", "size": 1, "fields": {}}
    b = IsfDraft.from_isf_dict(isf)
    diff = a.diff(b)
    got = {(i.key, i.change) for i in diff.items}
    assert got == {
        (("symbol", "init_task"), "changed"), (("symbol", "new_sym"), "added"),
        (("symbol", "init_mm"), "removed"), (("type", "task"), "changed"),
        (("field", "task", "pid"), "changed"), (("field", "task", "comm"), "removed"),
        (("field", "task", "new"), "added"), (("enum", "e"), "changed"),
        (("type", "extra"), "added")}
    assert diff.counts() == {"added": 3, "removed": 2, "changed": 4}
    assert diff.compared["symbols"] == 3
    limited = diff.to_dict(limit=2)
    assert limited["truncated"] is True and limited["total"] == 9 and len(limited["items"]) == 2
    assert diff.to_dict()["truncated"] is False
    only = a.diff(b, only={"symbols": ["init_task"], "user_types": ["mm"]},
                  sections=("symbols", "user_types"))
    assert [i.key for i in only.items] == [("symbol", "init_task")]
    assert a.diff(b, sections=("base_types",)).equal


def test_symbol_type_compared_only_when_both_typed():
    a = IsfDraft.from_isf_dict({"symbols": {"s": {"address": 1}}})
    b = IsfDraft.from_isf_dict({"symbols": {"s": {"address": 1, "type": INT}}})
    assert a.diff(b).equal
    c = IsfDraft.from_isf_dict({"symbols": {"s": {"address": 1, "type": {"kind": "base", "name": "x"}}}})
    assert not b.diff(c).equal


def test_diff_carries_origins(store):
    store.set_symbol(CAP, "d", "s", 0x10, PROBE)
    ref = IsfDraft.from_isf_dict({"symbols": {"s": {"address": 0x99}}})
    item = mat(store).diff(ref).items[0]
    assert item.origin_before.provenance == PROBE and item.origin_after is None
    assert item.to_dict()["origin_before"]["provenance"]["source"] == "kallsyms"


def test_export_isf_paths(store, tmp_path):
    store.import_isf(CAP, "d", donor_isf(), PROV)
    path = store.export_isf(CAP, "d")
    version = mat(store).version
    assert path.parent == store.case_dir / "isf_drafts" / CAP / "d"
    assert path.name.startswith(f"{version}-{mat(store).state_id}-")
    assert hashlib.sha256(path.read_bytes()).hexdigest()[:8] == path.name.split("-")[-1][:8]
    assert json.loads(path.read_text())["symbols"]["init_mm"] == {"address": 0x1000}
    custom = store.export_isf(CAP, "d", out_path=tmp_path / "out" / "x.isf.json")
    assert custom.is_file() and not list(custom.parent.glob("*.tmp"))


# -- real corpus ------------------------------------------------------------------

ARISTA = (Path(__file__).resolve().parents[1] / ".." / ".." / ".." / "pakunoda" / "experiments"
          / "dumps" / "acquired" / "arista-eos-4.36.1F_5.10.165.Ar-48367454.4361F.isf.json")


@pytest.mark.skipif(not os.environ.get("MEMDIVER_IMAGE_CORPUS") or not ARISTA.is_file(),
                    reason="needs MEMDIVER_IMAGE_CORPUS and the shipped arista ISF")
def test_arista_import_export_roundtrip(tmp_path):
    shipped = json.loads(ARISTA.read_text())
    s = IsfDraftStore(tmp_path)
    s.create(CAP, "arista", arch="x86_64")
    start = time.perf_counter()
    s.import_isf(CAP, "arista", shipped, Provenance("isf_import", "imported"))
    out = s.export_isf(CAP, "arista")
    draft = s.materialize(CAP, "arista")
    diff = draft.diff(IsfDraft.from_isf_dict(shipped))
    elapsed = time.perf_counter() - start
    print(f"arista import+export+materialize+diff: {elapsed:.1f}s")
    assert diff.equal and out.is_file()
    assert elapsed < 120


def test_state_id_distinguishes_retracted_state_and_export_filenames(store):
    store.set_symbol(CAP, "d", "s", 0x10, PROV)
    second = store.set_symbol(CAP, "d", "s", 0x20, PROV)
    full = mat(store)
    store.retract(CAP, "d", second.id, reason="wrong")
    after = mat(store)
    upto = mat(store, upto=second.id)
    # the retraction entry is itself applied-or-not; compare against the pre-retraction state
    assert upto.version == second.id and upto.symbols["s"]["address"] == 0x20
    assert after.symbols["s"]["address"] == 0x10
    assert after.state_id != upto.state_id != ""
    assert full.state_id == upto.state_id and len(upto.state_id) == 16
    assert after.to_isf_dict()["metadata"]["producer"]["memdiver_draft"]["state_id"] == after.state_id
    assert store.list_drafts(CAP)[0]["state_id"] == after.state_id
    p1, p2 = store.export_isf(CAP, "d"), store.export_isf(CAP, "d", upto=second.id)
    assert p1 != p2 and p1.exists() and p2.exists()
    assert p1.name.startswith(f"{after.version}-{after.state_id}-")
    good = p1.read_bytes()
    assert store.export_isf(CAP, "d") == p1  # identical bytes are reused
    p1.write_text("tampered")  # a name is a content address: export restores its bytes
    assert store.export_isf(CAP, "d") == p1 and p1.read_bytes() == good


def test_same_version_different_content_after_retraction(store):
    a = store.set_symbol(CAP, "d", "s", 0x10, PROV)
    b = store.set_symbol(CAP, "d", "s", 0x20, PROV)
    store.retract(CAP, "d", a.id)  # retract an EARLIER entry: last applied stays b
    now, then = mat(store), mat(store, upto=b.id)
    assert now.version == then.version == b.id
    assert now.state_id != then.state_id


def test_diff_added_removed_struct_before_after_are_none():
    a = IsfDraft.from_isf_dict({"user_types": {}})
    st = {"kind": "struct", "size": 4, "fields": {}}
    b = IsfDraft.from_isf_dict({"user_types": {"t": st}})
    added = a.diff(b).items
    assert [(i.change, i.before, i.after) for i in added] == [("added", None, st)]
    removed = b.diff(a).items
    assert [(i.change, i.before, i.after) for i in removed] == [("removed", st, None)]


def test_exported_metadata_is_valid_under_vol3_schema(tmp_path):
    """Regression (P4 gate): extra top-level metadata keys made vol3 refuse every draft."""
    schemas = pytest.importorskip("volatility3.schemas")
    store = IsfDraftStore(tmp_path)
    store.create(CAP, "d", arch="x86_64", banner="Linux version 5.10")
    isf = store.materialize(CAP, "d").to_isf_dict()
    assert set(isf["metadata"]) <= {"format", "producer", "linux", "windows", "mac"}
    assert schemas.validate(isf, False)


def test_untyped_layout_claims_are_kept_but_not_exported(tmp_path):
    """Regression (P4 gate): exported void members broke vol3's task_struct.is_valid."""
    lc = pytest.importorskip("pakunoda.core.layout_claims")
    store = IsfDraftStore(tmp_path)
    store.create(CAP, "d", arch="x86_64")
    claim = lc.LayoutClaim("task_struct", "signal", 1712, 8, lc.LayoutTier.EXACT, "anchor")
    store.import_layout_claims(CAP, "d", [claim])
    store.set_field(CAP, "d", "task_struct", "pid", 1128, {"kind": "base", "name": "int"}, PROV)
    draft = store.materialize(CAP, "d")
    assert draft.untyped_fields() == [("task_struct", "signal")]
    assert "signal" in draft.user_types["task_struct"]["fields"]  # kept in the draft
    isf = draft.to_isf_dict()
    assert set(isf["user_types"]["task_struct"]["fields"]) == {"pid"}
    assert isf["metadata"]["producer"]["memdiver_draft"]["untyped_fields_omitted"] == 1
    store.set_field(CAP, "d", "task_struct", "signal", 1712,
                    {"kind": "pointer", "subtype": {"kind": "struct", "name": "signal_struct"}}, PROV)
    assert "signal" in store.materialize(CAP, "d").to_isf_dict()["user_types"]["task_struct"]["fields"]


def test_export_filename_is_version_state_sha8(store, tmp_path):
    import re
    store.set_symbol(CAP, "d", "s", 0x10, PROV)
    path = store.export_isf(CAP, "d")
    draft = mat(store)
    assert re.fullmatch(rf"{re.escape(draft.version)}-{draft.state_id}-[0-9a-f]{{8}}\.isf\.json",
                        path.name)


def test_untyped_field_still_appears_in_diff(tmp_path):
    """untyped_fields only gates EXPORT; per docstring diff compares offset+type descriptors,
    so a void placeholder differs from a typed field and equals another placeholder."""
    lc = pytest.importorskip("pakunoda.core.layout_claims")
    claim = lc.LayoutClaim("task_struct", "signal", 1712, 8, lc.LayoutTier.EXACT, "anchor")
    drafts = []
    for sub in ("a", "b", "c"):
        st = IsfDraftStore(tmp_path / sub)
        st.create(CAP, "d", arch="x86_64")
        st.import_layout_claims(CAP, "d", [claim])
        drafts.append((st, st.materialize(CAP, "d")))
    (_, untyped_a), (_, untyped_b), (st_c, _) = drafts
    st_c.set_field(CAP, "d", "task_struct", "signal", 1712,
                   {"kind": "pointer", "subtype": {"kind": "struct", "name": "signal_struct"}},
                   PROV)
    typed = st_c.materialize(CAP, "d")
    assert untyped_a.untyped_fields() == [("task_struct", "signal")] and not typed.untyped_fields()
    assert untyped_a.diff(untyped_b).equal
    changed = untyped_a.diff(typed).items
    assert [(i.key, i.change) for i in changed] == [(("field", "task_struct", "signal"), "changed")]

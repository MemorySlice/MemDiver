"""Batched record appends (``AnalysisRecord.append_many``) and the ISF draft blob cache.

Both are efficiency refactors: the record on disk, the validation errors and the
materialized drafts must be exactly what the one-at-a-time code produced.
"""

import json
from types import SimpleNamespace

import pytest

from memdiver.analysis.record import AnalysisEntry
from memdiver.analysis.record_store import AnalysisRecord
from memdiver.core.service_errors import CapabilityError
from memdiver.isf import draft as draft_mod
from memdiver.isf.draft import IsfDraftStore, Provenance

CAP = "a" * 64
CAP2 = "b" * 64
INT = {"kind": "base", "name": "int"}
PROV = Provenance("manual", "manual", ("hex selection 0x10",))


def _entry(label, *, ident, supersedes=None, capture_id=CAP):
    return AnalysisEntry(capture_id=capture_id, kind="annotation", author="human",
                         label=label, id=ident, supersedes=supersedes,
                         created="2026-01-01T00:00:00Z")


def _file_bytes(record, capture_id=CAP):
    path = record.path_for(capture_id)
    return path.read_bytes() if path.is_file() else b""


def _sequential(record, entries):
    """The pre-refactor bulk path: one ``append`` per entry, stop at the first error."""
    for entry in entries:
        record.append(entry)


def _outcome(fn):
    try:
        fn()
    except CapabilityError as exc:
        return (exc.code, str(exc), exc.category)
    return None


# -- append_many --------------------------------------------------------------

def test_append_many_writes_the_same_file_as_sequential_appends(tmp_path):
    seed = [_entry("root", ident="e0")]
    batch = [_entry("a", ident="e1"), _entry("b", ident="e2", supersedes="e1"),
             _entry("c", ident="e3", supersedes="e0"), _entry("other", ident="e4", capture_id=CAP2)]
    seq, bulk = AnalysisRecord(tmp_path / "seq"), AnalysisRecord(tmp_path / "bulk")
    for record in (seq, bulk):
        record.append(seed[0])
    _sequential(seq, batch)
    returned = bulk.append_many(batch)
    assert returned == batch
    assert _file_bytes(bulk) == _file_bytes(seq) and _file_bytes(bulk)
    assert _file_bytes(bulk, CAP2) == _file_bytes(seq, CAP2) and _file_bytes(bulk, CAP2)
    assert [e.id for e in bulk.latest(CAP)] == [e.id for e in seq.latest(CAP)]


def test_append_many_empty_batch_writes_nothing(tmp_path):
    record = AnalysisRecord(tmp_path)
    assert record.append_many([]) == []
    assert not (tmp_path / "annotations").exists()


@pytest.mark.parametrize("batch", [
    pytest.param(lambda: [_entry("x", ident="new1"), _entry("dup", ident="e0")],
                 id="duplicate-of-existing"),
    pytest.param(lambda: [_entry("x", ident="new1"), _entry("again", ident="new1")],
                 id="duplicate-within-batch"),
    pytest.param(lambda: [_entry("x", ident="new1"), _entry("y", ident="new2", supersedes="ghost")],
                 id="unknown-supersedes"),
    pytest.param(lambda: [_entry("y", ident="new2", supersedes="new3"), _entry("z", ident="new3")],
                 id="forward-reference-within-batch"),
    pytest.param(lambda: [_entry("x", ident="new1", capture_id=CAP2),
                          _entry("dup", ident="e0")],
                 id="second-capture-then-duplicate"),
])
def test_append_many_raises_what_sequential_raises_but_writes_nothing(tmp_path, batch):
    seq, bulk = AnalysisRecord(tmp_path / "seq"), AnalysisRecord(tmp_path / "bulk")
    for record in (seq, bulk):
        record.append(_entry("root", ident="e0"))
    before = _file_bytes(bulk)
    seq_error = _outcome(lambda: _sequential(seq, batch()))
    bulk_error = _outcome(lambda: bulk.append_many(batch()))
    assert seq_error is not None and bulk_error == seq_error
    assert _file_bytes(bulk) == before                     # all-or-nothing
    assert _file_bytes(bulk, CAP2) == b""


def test_append_many_reports_a_corrupt_record_like_append(tmp_path):
    record = AnalysisRecord(tmp_path)
    record.append(_entry("root", ident="e0"))
    with open(record.path_for(CAP), "a", encoding="utf-8") as handle:
        handle.write("{not json\n")
    single = _outcome(lambda: record.append(_entry("x", ident="n1")))
    many = _outcome(lambda: record.append_many([_entry("x", ident="n1")]))
    assert single is not None and single[0] == "analysis_record_corrupt" and many == single


def test_append_many_reads_the_record_once(tmp_path, monkeypatch):
    from memdiver.analysis import record_store
    record = AnalysisRecord(tmp_path)
    record.append(_entry("root", ident="e0"))
    calls = []
    real = record_store._read_file
    monkeypatch.setattr(record_store, "_read_file", lambda p: calls.append(p) or real(p))
    record.append_many([_entry(f"r{i}", ident=f"n{i}") for i in range(50)])
    assert len(calls) == 1
    assert len(record.entries(CAP)) == 51


# -- import_layout_claims batch ------------------------------------------------

def _claim(struct, member, offset, width, tier, source="anchor", evidence=(), witnesses=1):
    return SimpleNamespace(struct=struct, member=member, offset=offset, width=width,
                           tier=SimpleNamespace(value=tier), source=source,
                           evidence=evidence, witnesses=witnesses)


CLAIMS = [
    _claim("task", "mm", 0x40, 8, "exact", evidence=("init_task+0x40 == &init_mm",), witnesses=2),
    _claim("task", "pid", 0x8, 4, "code", source="code"),
    _claim("task", None, None, 128, "exact"),
    _claim("other", None, None, 256, "bound", source="population"),
    _claim("task", "pid", 0xc, 4, "code", source="code"),       # same key again: supersedes
    _claim("other", None, None, 200, "bound", source="population"),
]


def _per_claim(store, claims, hints):
    """The pre-refactor path: one set_field / set_struct / size_bound per claim."""
    known = store.materialize(CAP, "d").user_types
    out = []
    for claim in claims:
        prov = Provenance(claim.source, claim.tier.value, tuple(claim.evidence),
                          "tool:pakunoda", claim.witnesses)
        if claim.member is not None:
            hint = hints.get((claim.struct, claim.member))
            if hint is None:
                prov = draft_mod._with_evidence(prov, "type_unknown")
            out.append(store.set_field(CAP, "d", claim.struct, claim.member, claim.offset,
                                       hint if hint is not None else {"kind": "base", "name": "void"},
                                       prov))
        elif claim.tier.value == "bound":
            out.append(store._append(CAP, "d", "size_bound", prov,
                                     {"struct": claim.struct, "bound": claim.width},
                                     label=f"sizeof({claim.struct}) <= {claim.width}",
                                     entries=store._all(CAP)))
        else:
            kind = known.get(claim.struct, {}).get("kind", "struct")
            out.append(store.set_struct(CAP, "d", claim.struct, claim.width, prov, kind=kind))
    return out


def _shape(store, entries):
    """Entries with ids replaced by their batch position (ids are random uuids)."""
    pos = {e.id: i for i, e in enumerate(store._all(CAP))}
    return [(e.payload, e.label, e.author, pos.get(e.supersedes)) for e in entries]


def _fresh(tmp_path, sub):
    store = IsfDraftStore(tmp_path / sub)
    store.create(CAP, "d", arch="x86_64")
    store.set_field(CAP, "d", "task", "pid", 0x4, INT, PROV)       # pre-existing writer
    return store


def test_layout_claims_batch_matches_one_call_per_claim(tmp_path):
    hints = {("task", "pid"): INT}
    one, batch = _fresh(tmp_path, "one"), _fresh(tmp_path, "batch")
    single = _per_claim(one, CLAIMS, hints)
    bulk = batch.import_layout_claims(CAP, "d", CLAIMS, type_hints=hints)
    assert len(bulk) == len(CLAIMS)
    assert _shape(batch, bulk) == _shape(one, single)
    a, b = one.materialize(CAP, "d"), batch.materialize(CAP, "d")
    assert (a.user_types, a.size_bounds, a.applied) == (b.user_types, b.size_bounds, b.applied)
    pid_writer = b.provenance_of(("field", "task", "pid")).entry_id
    assert pid_writer == bulk[4].id and bulk[4].supersedes == bulk[1].id
    assert bulk[1].supersedes == batch._all(CAP)[1].id               # the pre-existing set_field


def test_layout_claims_batch_is_all_or_nothing(tmp_path):
    store = _fresh(tmp_path, "s")
    before = store._record.path_for(CAP).read_bytes()
    bad = CLAIMS[:2] + [_claim("task", "comm", -1, 4, "code")]
    with pytest.raises(CapabilityError) as err:
        store.import_layout_claims(CAP, "d", bad)
    assert err.value.code == "invalid_isf_draft"
    assert store._record.path_for(CAP).read_bytes() == before


# -- blob cache ------------------------------------------------------------------

@pytest.fixture
def blob_reads(monkeypatch):
    draft_mod._blob_cache.clear()
    calls = []
    real = draft_mod._read_verified_blob
    monkeypatch.setattr(draft_mod, "_read_verified_blob",
                        lambda path, sha: calls.append(sha) or real(path, sha))
    yield calls
    draft_mod._blob_cache.clear()


def _donor():
    return {"base_types": {"int": {"size": 4, "signed": True, "kind": "int", "endian": "little"}},
            "user_types": {"task": {"kind": "struct", "size": 64, "fields": {
                "pid": {"offset": 8, "type": INT}, "comm": {"offset": 16, "type": INT}}},
                "bare": {"kind": "union", "size": 8}},
            "enums": {"e": {"size": 4, "base": "int", "constants": {"A": 1}}},
            "symbols": {"init_task": {"address": 0xffffffff82000000}}}


@pytest.fixture
def imported(tmp_path):
    store = IsfDraftStore(tmp_path)
    store.create(CAP, "d", arch="x86_64")
    entry = store.import_isf(CAP, "d", _donor(), PROV)
    return store, store.blob_path(entry.payload["blob_sha256"])


def test_repeated_materialize_reads_the_blob_once(imported, blob_reads):
    store, _ = imported
    first = store.materialize(CAP, "d")
    for _ in range(3):
        assert store.materialize(CAP, "d").to_isf_dict() == first.to_isf_dict()
    store.list_drafts(CAP)
    assert len(blob_reads) == 1


def test_rewritten_or_removed_blob_is_still_detected_after_caching(imported, blob_reads):
    store, blob = imported
    store.materialize(CAP, "d")
    blob.write_bytes(b'{"symbols":{}}')
    with pytest.raises(CapabilityError) as err:
        store.materialize(CAP, "d")
    assert err.value.code == "isf_blob_tampered"
    blob.unlink()
    with pytest.raises(CapabilityError) as missing:
        store.materialize(CAP, "d")
    assert missing.value.code == "isf_blob_missing"


def test_replay_and_caller_mutation_do_not_corrupt_the_cached_blob(imported, blob_reads):
    store, blob = imported
    pristine = json.loads(blob.read_bytes())
    store.set_struct(CAP, "d", "task", 96, PROV)                     # replay mutates struct
    store.set_field(CAP, "d", "task", "mm", 0x40, INT, PROV)         # ...and its fields dict
    store.set_field(CAP, "d", "bare", "x", 0, INT, PROV)             # struct without fields
    store.remove(CAP, "d", ("field", "task", "comm"), PROV)
    expected = store.materialize(CAP, "d").to_isf_dict()
    draft = store.materialize(CAP, "d")
    draft.user_types["task"]["size"] = 1                             # a careless caller
    draft.user_types["task"]["fields"].clear()
    draft.user_types.pop("bare")
    draft.symbols.clear()
    assert store.materialize(CAP, "d").to_isf_dict() == expected
    cached = next(iter(draft_mod._blob_cache.values()))
    assert cached == pristine
    assert len(blob_reads) == 1
    upto = store.materialize(CAP, "d", upto=store.versions(CAP, "d")[1]["entry_id"])
    assert upto.user_types == pristine["user_types"]


def test_blob_cache_is_bounded(tmp_path, blob_reads):
    store = IsfDraftStore(tmp_path)
    store.create(CAP, "d", arch="x86_64")
    for i in range(draft_mod._BLOB_CACHE_MAX + 3):
        store.import_symbols(CAP, "d", {f"s{i}": i + 1}, PROV)
    store.materialize(CAP, "d")
    assert len(draft_mod._blob_cache) == draft_mod._BLOB_CACHE_MAX


def test_blob_cache_is_bounded_by_bytes(tmp_path, blob_reads, monkeypatch):
    store = IsfDraftStore(tmp_path)
    store.create(CAP, "d", arch="x86_64")
    entries = [store.import_symbols(CAP, "d", {f"s{i}": i + 1}, PROV) for i in range(3)]
    sizes = sorted(store.blob_path(e.payload["blob_sha256"]).stat().st_size for e in entries)
    budget = sizes[-1] + sizes[-2]                 # room for two blobs, not three
    monkeypatch.setattr(draft_mod, "_BLOB_CACHE_MAX_BYTES", budget)
    store.materialize(CAP, "d")
    assert len(draft_mod._blob_cache) == 2
    assert sum(key[1] for key in draft_mod._blob_cache) <= budget
    # Replay reads the blobs in import order, so LRU evicts the first import's blob.
    cached_shas = [key[-1] for key in draft_mod._blob_cache]
    assert cached_shas == [e.payload["blob_sha256"] for e in entries[1:]]


def test_blob_larger_than_the_byte_budget_is_not_cached(imported, blob_reads, monkeypatch):
    store, blob = imported
    monkeypatch.setattr(draft_mod, "_BLOB_CACHE_MAX_BYTES", blob.stat().st_size - 1)
    first = store.materialize(CAP, "d").to_isf_dict()
    assert store.materialize(CAP, "d").to_isf_dict() == first
    assert not draft_mod._blob_cache
    assert len(blob_reads) == 2

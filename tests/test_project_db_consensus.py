"""Tests for the v4 DIFFERENTIAL ledger in :mod:`engine.project_db`.

``consensus_runs`` / ``candidate_regions`` are the first persistence the
multi-dump variance workflow — the tool's core feature — has ever had. Until v4
a comparison produced loose ``.npy`` / ``.json`` files plus a 30-minute
in-process dict (``api/services/consensus_session.py``) that died with the
server, so a ranked candidate list could not be re-read, re-filtered or cited.

Its own file rather than more of ``tests/test_project_db.py`` for the reason
``tests/test_project_db_ground_truth.py`` is: this is one ledger with one
identity scheme and one conflict policy, and the questions worth asking of it
(is the id injective? does a re-run correct or duplicate? does a half-written
candidate list survive?) are the same handful asked of every column.

The three failure modes each have a test here, because each is SILENT:

1. **A non-injective id.** The identity parts are DUMP PATHS, which routinely
   contain whatever separator a naive join would pick. Two different dump sets
   hashing to one id means the second comparison overwrites the first and the
   caller still gets a plausible id back. See
   :func:`test_a_pipe_join_would_collide_and_this_one_does_not`.
2. **A re-run that duplicates instead of correcting.** Item A3 lands its
   ranking by re-writing an already-persisted batch with scores filled in; if
   that appends, every candidate list doubles while still looking sorted. See
   :func:`test_rewriting_the_same_batch_corrects_rather_than_duplicating`.
3. **A silent zero.** Every reader returns ``[]`` and every writer ``0`` on an
   unavailable database, so a caller cannot distinguish "nothing to write" from
   "nothing was written". See
   :func:`test_readers_and_writers_degrade_without_duckdb`.
"""

from unittest.mock import patch

import pytest

from memdiver.core.service_errors import CapabilityError, ErrorCategory
from memdiver.core.variance import ByteClass
from memdiver.engine.project_db import (
    ALIGNMENT_FILE_OFFSET,
    ALIGNMENT_MODULE_OFFSET,
    ALIGNMENT_VIRTUAL_ADDRESS,
    BYTE_CLASSES,
    HAS_DUCKDB,
)

if HAS_DUCKDB:
    import duckdb

    from memdiver.engine.project_db import ProjectDB

needs_duckdb = pytest.mark.skipif(not HAS_DUCKDB, reason="duckdb not installed")

#: The real shape of one comparison from the plan's evidence run: eight dumps
#: of ``openssl_run_12_1``, all 11,223,040 bytes, 99.945 % INVARIANT.
DUMPS = ["/corpus/openssl_run_12_1/pre_master.dump",
         "/corpus/openssl_run_12_1/post_master.dump"]
CLASS_COUNTS = {"invariant": 11216911, "structural": 1652,
                "pointer": 2566, "key_candidate": 1911}


def _consensus(db, **over):
    """Write one comparison with the evidence run's real numbers."""
    kwargs = dict(
        project_id=over.pop("project_id", "proj-1"),
        dump_paths=over.pop("dump_paths", DUMPS),
        alignment_method=over.pop("alignment_method", ALIGNMENT_FILE_OFFSET),
        bytes_compared=11223040,
        class_counts=CLASS_COUNTS,
    )
    kwargs.update(over)
    return db.add_consensus_run(**kwargs)


def _candidates():
    """Three candidates, including the real TLS 1.2 secret at 370,672.

    Its bytes classify as 22 KEY_CANDIDATE + 18 POINTER + 8 STRUCTURAL — the
    top class dominates, which is the whole claim the workflow rests on.
    """
    return [
        {"offset": 370672, "length": 48, "byte_class": "key_candidate",
         "mean_variance": 4210.5, "mean_entropy": 7.9, "rank": 1,
         "score": 9.5, "score_class_weight": 3.0},
        {"offset": 1024, "length": 16, "byte_class": "pointer",
         "mean_variance": 900.0, "mean_entropy": 3.1, "rank": 2,
         "score": 4.0},
        # No rank and no score: what a producer writes before item A3 exists.
        {"offset": 2048, "length": 8, "byte_class": "structural",
         "mean_variance": 12.0, "mean_entropy": 1.2},
    ]


def _count(db, table):
    return db._conn.execute(
        'SELECT COUNT(*) FROM "' + table + '"').fetchone()[0]


# -- round trip -----------------------------------------------------------

@needs_duckdb
def test_consensus_run_round_trip(tmp_path):
    """Every input of a comparison comes back off disk unchanged."""
    with ProjectDB(tmp_path / "t.duckdb") as db:
        cid = _consensus(db, alignment_method=ALIGNMENT_VIRTUAL_ADDRESS,
                         bytes_discarded=4096, sizes_differed=True,
                         alignment_warnings=["dump sizes differ by 4096 bytes"],
                         run_id="run-7")
        assert cid != ""
        rows = db.consensus_runs(project_id="proj-1")
        assert len(rows) == 1
        row = rows[0]
        assert row["consensus_id"] == cid
        assert row["run_id"] == "run-7"
        assert row["n_dumps"] == 2
        assert row["bytes_compared"] == 11223040
        # Alignment provenance (item A1 fills these richly; the columns are
        # here now so it does not need a second schema bump).
        assert row["alignment_method"] == ALIGNMENT_VIRTUAL_ADDRESS
        assert row["bytes_discarded"] == 4096
        assert row["sizes_differed"] is True
        assert "sizes differ" in row["alignment_warnings"]
        # The boundaries that produced the histogram, on the same row as the
        # histogram: without them the four counts are uninterpretable.
        assert row["invariant_max"] == 0.0
        assert row["structural_max"] == 200.0
        assert row["pointer_max"] == 3000.0
        assert row["invariant_bytes"] == 11216911
        assert row["key_candidate_bytes"] == 1911
        # Paths survive as JSON, in build order.
        assert row["dump_paths"].index("pre_master") < \
            row["dump_paths"].index("post_master")


@needs_duckdb
def test_candidate_regions_round_trip(tmp_path):
    with ProjectDB(tmp_path / "t.duckdb") as db:
        cid = _consensus(db)
        assert db.add_candidate_regions_batch(cid, _candidates()) == 3
        rows = db.candidate_regions(cid)
        assert [r["offset"] for r in rows] == [370672, 1024, 2048]
        best = rows[0]
        assert best["byte_class"] == "key_candidate"
        assert best["length"] == 48
        assert best["mean_variance"] == pytest.approx(4210.5)
        assert best["mean_entropy"] == pytest.approx(7.9)
        assert best["rank"] == 1
        assert best["score"] == pytest.approx(9.5)
        assert best["score_class_weight"] == pytest.approx(3.0)
        # Item A3 owns the remaining components; they default rather than NULL.
        assert best["score_entropy_component"] == 0.0


@needs_duckdb
def test_unranked_candidates_sort_last_not_first(tmp_path):
    """``rank = 0`` means UNRANKED, and rank 1 is the BEST candidate.

    A plain ascending sort would therefore put every un-scored row above the
    best scored one — the exact inversion of what the reader is for.
    """
    with ProjectDB(tmp_path / "t.duckdb") as db:
        cid = _consensus(db)
        db.add_candidate_regions_batch(cid, _candidates())
        ranks = [r["rank"] for r in db.candidate_regions(cid)]
        assert ranks == [1, 2, 0]


# -- identity -------------------------------------------------------------

@needs_duckdb
def test_the_same_comparison_yields_the_same_id(tmp_path):
    with ProjectDB(tmp_path / "t.duckdb") as db:
        assert _consensus(db) == _consensus(db)
        assert _count(db, "consensus_runs") == 1


@needs_duckdb
@pytest.mark.parametrize("change", [
    {"project_id": "proj-2"},
    {"dump_paths": DUMPS + ["/corpus/openssl_run_12_1/third.dump"]},
    {"dump_paths": list(reversed(DUMPS))},
    {"alignment_method": ALIGNMENT_MODULE_OFFSET},
    {"invariant_max": 1.0},
    {"structural_max": 200.5},
    {"pointer_max": 4000.0},
])
def test_every_identity_input_changes_the_id(tmp_path, change):
    """Each identity component is genuinely part of the key.

    Order is in the key because the FIRST source supplies
    ``ConsensusVector.reference_bytes`` — reordering the same files is a
    different comparison. The boundaries are in it because they decide the
    histogram outright, and the alignment method because a flat-offset result
    and a module-aligned one are not comparable.
    """
    with ProjectDB(tmp_path / "t.duckdb") as db:
        assert _consensus(db) != _consensus(db, **change)
        assert _count(db, "consensus_runs") == 2


@needs_duckdb
def test_a_pipe_join_would_collide_and_this_one_does_not(tmp_path):
    """The injectivity case a ``"|"`` join loses.

    ``["/a", "/b|/c"]`` and ``["/a|/b", "/c"]`` are two genuinely different
    two-dump comparisons that a separator join maps to the same string, hence
    the same id — so the second silently overwrites the first while returning a
    plausible-looking id. ``_row_identity`` length-prefixes each part
    (``len:value``) and a length prefix cannot contain the ``:`` that ends it,
    so the encoding decodes unambiguously whatever a path contains.
    """
    with ProjectDB(tmp_path / "t.duckdb") as db:
        left = _consensus(db, dump_paths=["/a", "/b|/c"])
        right = _consensus(db, dump_paths=["/a|/b", "/c"])
        assert "|".join(["/a", "/b|/c"]) == "|".join(["/a|/b", "/c"])
        assert left != right
        assert _count(db, "consensus_runs") == 2


@needs_duckdb
def test_candidate_ids_are_deterministic_and_scoped_to_their_run(tmp_path):
    """Same (run, offset, length) -> same id; a different run -> a different one.

    The scoping half matters most: without ``consensus_id`` in the key, two
    comparisons' candidates share a namespace and the second overwrites the
    first at every shared offset.
    """
    with ProjectDB(tmp_path / "t.duckdb") as db:
        a = ProjectDB._candidate_identity("run-a", 370672, 48)
        assert a == ProjectDB._candidate_identity("run-a", 370672, 48)
        assert a != ProjectDB._candidate_identity("run-b", 370672, 48)
        assert a != ProjectDB._candidate_identity("run-a", 370673, 48)
        assert a != ProjectDB._candidate_identity("run-a", 370672, 49)


# -- re-runs correct, they do not duplicate -------------------------------

@needs_duckdb
def test_rewriting_the_same_batch_corrects_rather_than_duplicating(tmp_path):
    """Item A3 lands by re-writing a persisted batch with scores filled in.

    If that appended, every candidate list would double while still looking
    sorted. The invariant checked here is the one that cannot be faked:
    ``COUNT(*) == COUNT(DISTINCT consensus_id, offset, length)``.
    """
    with ProjectDB(tmp_path / "t.duckdb") as db:
        cid = _consensus(db)
        db.add_candidate_regions_batch(cid, _candidates())
        ranked = _candidates()
        ranked[2].update({"rank": 3, "score": 1.25,
                          "score_entropy_component": 0.4})
        assert db.add_candidate_regions_batch(cid, ranked) == 3

        total, distinct = db._conn.execute(
            'SELECT COUNT(*), COUNT(DISTINCT ("consensus_id", "offset",'
            ' "length")) FROM "candidate_regions"').fetchone()
        assert total == 3
        assert total == distinct

        # The correction landed, rather than losing to the stored row.
        last = db.candidate_regions(cid)[-1]
        assert last["offset"] == 2048
        assert last["rank"] == 3
        assert last["score"] == pytest.approx(1.25)
        assert last["score_entropy_component"] == pytest.approx(0.4)


@needs_duckdb
def test_re_declaring_a_comparison_corrects_its_histogram(tmp_path):
    """A second pass over the same inputs updates the counts in place.

    ``created_at`` is NOT restamped: it records when the comparison was first
    recorded, and a re-run is not a new comparison.
    """
    with ProjectDB(tmp_path / "t.duckdb") as db:
        cid = _consensus(db)
        first_seen = db.consensus_runs(consensus_id=cid)[0]["created_at"]
        again = _consensus(db, class_counts={"invariant": 1, "structural": 2,
                                             "pointer": 3, "key_candidate": 4},
                           run_id="run-9")
        assert again == cid
        row = db.consensus_runs(consensus_id=cid)[0]
        assert _count(db, "consensus_runs") == 1
        assert row["key_candidate_bytes"] == 4
        assert row["run_id"] == "run-9"
        assert row["created_at"] == first_seen


# -- closed vocabularies --------------------------------------------------

@needs_duckdb
def test_byte_classes_come_from_the_enum(tmp_path):
    """``BYTE_CLASSES`` is derived from :class:`core.variance.ByteClass`.

    A hand-written tuple would be a second source of truth, and the day a fifth
    class is added the DB would reject it while the classifier emitted it.
    """
    assert BYTE_CLASSES == tuple(c.name.lower() for c in ByteClass)
    assert "key_candidate" in BYTE_CLASSES


@needs_duckdb
def test_unknown_byte_class_is_rejected(tmp_path):
    with ProjectDB(tmp_path / "t.duckdb") as db:
        cid = _consensus(db)
        with pytest.raises(CapabilityError) as exc:
            db.add_candidate_regions_batch(
                cid, [{"offset": 0, "length": 4, "byte_class": "KEY_CANDIDATE"}])
        assert exc.value.category is ErrorCategory.INVALID_INPUT
        assert _count(db, "candidate_regions") == 0


@needs_duckdb
def test_a_candidate_without_a_class_is_rejected(tmp_path):
    """An unclassified candidate is a row no class filter can ever return."""
    with ProjectDB(tmp_path / "t.duckdb") as db:
        cid = _consensus(db)
        with pytest.raises(CapabilityError) as exc:
            db.add_candidate_regions_batch(cid, [{"offset": 0, "length": 4}])
        assert exc.value.category is ErrorCategory.INVALID_INPUT


@needs_duckdb
def test_unknown_alignment_method_is_rejected(tmp_path):
    with ProjectDB(tmp_path / "t.duckdb") as db:
        with pytest.raises(CapabilityError) as exc:
            _consensus(db, alignment_method="flat")
        assert exc.value.category is ErrorCategory.INVALID_INPUT
        assert _count(db, "consensus_runs") == 0


@needs_duckdb
def test_unknown_class_count_key_is_rejected(tmp_path):
    """A silently-dropped class turns a histogram into a smaller histogram
    that still looks complete."""
    with ProjectDB(tmp_path / "t.duckdb") as db:
        with pytest.raises(CapabilityError) as exc:
            _consensus(db, class_counts={"invariant": 1, "unknown_class": 2})
        assert exc.value.category is ErrorCategory.INVALID_INPUT


@needs_duckdb
def test_the_readers_reject_an_unknown_vocabulary_value_too(tmp_path):
    """A typo'd filter would otherwise return ``[]`` — which reads exactly like
    "this project has no VA-aligned comparisons", the answer a caller acts on."""
    with ProjectDB(tmp_path / "t.duckdb") as db:
        _consensus(db)
        with pytest.raises(CapabilityError):
            db.consensus_runs(alignment_method="virtual-address")
        with pytest.raises(CapabilityError):
            db.candidate_regions("x", byte_class="keycandidate")


# -- the empty-identity collapses -----------------------------------------

@needs_duckdb
def test_a_comparison_without_dump_paths_is_rejected(tmp_path):
    """The same collapse ``survival.dump_path`` guards against.

    With no paths, every comparison in a project sharing an alignment method
    and a boundary set resolves to ONE ``consensus_id``, each run's histogram
    overwriting the last, with every call still returning a plausible id.
    """
    with ProjectDB(tmp_path / "t.duckdb") as db:
        with pytest.raises(CapabilityError) as exc:
            db.add_consensus_run(project_id="proj-1", dump_paths=[])
        assert exc.value.category is ErrorCategory.INVALID_INPUT
        assert _count(db, "consensus_runs") == 0


@needs_duckdb
def test_candidates_without_a_consensus_id_are_rejected(tmp_path):
    """An empty scope merges every comparison's candidates into one namespace."""
    with ProjectDB(tmp_path / "t.duckdb") as db:
        with pytest.raises(CapabilityError) as exc:
            db.add_candidate_regions_batch("", _candidates())
        assert exc.value.category is ErrorCategory.INVALID_INPUT
        assert _count(db, "candidate_regions") == 0


# -- filters and aggregation ----------------------------------------------

@needs_duckdb
def test_candidate_filters(tmp_path):
    with ProjectDB(tmp_path / "t.duckdb") as db:
        cid = _consensus(db)
        db.add_candidate_regions_batch(cid, _candidates())

        assert [r["offset"] for r in
                db.candidate_regions(cid, byte_class="key_candidate")] == [370672]
        # rank 1 is BEST, so the useful bound is an upper one.
        assert [r["rank"] for r in db.candidate_regions(cid, max_rank=1)] == [1]
        assert [r["offset"] for r in
                db.candidate_regions(cid, min_score=5.0)] == [370672]
        assert [r["offset"] for r in
                db.candidate_regions(cid, min_length=16)] == [370672, 1024]
        assert [r["offset"] for r in
                db.candidate_regions(cid, max_length=16)] == [1024, 2048]
        assert len(db.candidate_regions(cid, limit=2)) == 2


@needs_duckdb
def test_candidates_are_scoped_to_their_comparison(tmp_path):
    with ProjectDB(tmp_path / "t.duckdb") as db:
        first = _consensus(db)
        second = _consensus(db, alignment_method=ALIGNMENT_MODULE_OFFSET)
        db.add_candidate_regions_batch(first, _candidates())
        db.add_candidate_regions_batch(second, _candidates()[:1])
        assert len(db.candidate_regions(first)) == 3
        assert len(db.candidate_regions(second)) == 1
        assert _count(db, "candidate_regions") == 4


@needs_duckdb
def test_consensus_run_filters(tmp_path):
    with ProjectDB(tmp_path / "t.duckdb") as db:
        flat = _consensus(db)
        va = _consensus(db, alignment_method=ALIGNMENT_VIRTUAL_ADDRESS,
                        run_id="run-7")
        _consensus(db, project_id="other")
        assert {r["consensus_id"] for r in db.consensus_runs(project_id="proj-1")} \
            == {flat, va}
        assert [r["consensus_id"] for r in db.consensus_runs(run_id="run-7")] == [va]
        assert [r["consensus_id"] for r in db.consensus_runs(
            alignment_method=ALIGNMENT_VIRTUAL_ADDRESS)] == [va]
        assert len(db.consensus_runs(limit=1)) == 1


@needs_duckdb
def test_candidate_class_counts_aggregate_in_duckdb(tmp_path):
    """The reduction is the product; it must not be spent pulling rows out."""
    with ProjectDB(tmp_path / "t.duckdb") as db:
        cid = _consensus(db)
        db.add_candidate_regions_batch(cid, _candidates())
        assert db.candidate_class_counts(cid) == {
            "key_candidate": 1, "pointer": 1, "structural": 1}
        assert db.candidate_class_counts("nope") == {}


# -- transactions ---------------------------------------------------------
#
# THE FAILURE HAS TO LAND MID-BATCH, as it does for `survival`: a proxy that
# raises on the first row leaves nothing to roll back and would keep this test
# green with the whole wrapper deleted.

def _candidate_that_fails_to_convert():
    """Passes the writer's validation, then overflows BIGINT inside DuckDB."""
    return {"offset": 2 ** 70, "length": 4, "byte_class": "pointer"}


@needs_duckdb
def test_candidate_batch_rolls_back_a_mid_batch_failure(tmp_path):
    """Half a ranked candidate list reads downstream as a whole one."""
    with ProjectDB(tmp_path / "t.duckdb") as db:
        cid = _consensus(db)
        db.add_candidate_regions_batch(cid, _candidates()[:1])
        assert _count(db, "candidate_regions") == 1

        with pytest.raises(duckdb.Error):
            db.add_candidate_regions_batch(cid, [
                # Good on its own, and WOULD commit unwrapped.
                {"offset": 4096, "length": 32, "byte_class": "key_candidate"},
                _candidate_that_fails_to_convert(),
            ])
        # ZERO of the two landed — not one of them.
        assert _count(db, "candidate_regions") == 1


@needs_duckdb
def test_the_mid_batch_reproducer_is_not_vacuous(tmp_path):
    """Prove the reproducer really does commit a partial batch unwrapped.

    Without this, the rollback test above would stay green if DuckDB ever
    became atomic per-``executemany`` and the wrapper were deleted.
    """
    conn = duckdb.connect(str(tmp_path / "raw.duckdb"))
    try:
        conn.execute('CREATE TABLE c("id" VARCHAR PRIMARY KEY, "off" BIGINT)')
        with pytest.raises(duckdb.Error):
            conn.executemany('INSERT INTO c("id", "off") VALUES ($1, $2)',
                             [["a", 1], ["b", 2 ** 70]])
        assert conn.execute("SELECT COUNT(*) FROM c").fetchone()[0] == 1
    finally:
        conn.close()


# -- the degrade-gracefully contract --------------------------------------

def test_readers_and_writers_degrade_without_duckdb(tmp_path):
    """Documented silent-zero hazard: ``0`` / ``""`` / ``[]`` mean BOTH
    "nothing to write" and "nothing was written".

    The writers are held to the same discipline as ``add_survival_batch`` — and
    the sentinel chains safely: an unavailable ``add_consensus_run`` returns
    ``""``, which the candidate writer then REJECTS rather than filing rows
    under an empty scope.
    """
    with patch("memdiver.engine.project_db.HAS_DUCKDB", False):
        from memdiver.engine.project_db import ProjectDB as PDB
        db = PDB(tmp_path / "noop.duckdb")
        db.open()
        assert db._available is False
        assert db.add_consensus_run(project_id="p", dump_paths=DUMPS) == ""
        assert db.add_candidate_regions_batch("c", _candidates()) == 0
        assert db.consensus_runs() == []
        assert db.candidate_regions("c") == []
        assert db.candidate_class_counts("c") == {}
        db.close()


@needs_duckdb
def test_an_empty_batch_writes_nothing_and_says_so(tmp_path):
    """The return value cannot claim success when nothing was written."""
    with ProjectDB(tmp_path / "t.duckdb") as db:
        cid = _consensus(db)
        assert db.add_candidate_regions_batch(cid, []) == 0
        assert _count(db, "candidate_regions") == 0
        assert db.add_candidate_regions_batch(cid, _candidates()) == 3
        assert _count(db, "candidate_regions") == 3

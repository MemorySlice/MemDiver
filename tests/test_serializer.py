"""Tests for engine.serializer module."""
import json
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from memdiver.core.discovery import DatasetInfo
from memdiver.engine.results import AnalysisResult, LibraryReport, SecretHit, StaticRegion
from memdiver.engine.serializer import (
    _convert_value,
    deserialize_hit,
    deserialize_report,
    deserialize_result,
    serialize_dataset_info,
    serialize_hit,
    serialize_report,
    serialize_result,
    serialize_static_region,
    summarize_result,
)


def test_convert_path():
    assert _convert_value(Path("/tmp/test")) == "/tmp/test"


def test_convert_bytes():
    assert _convert_value(b"\xde\xad") == "dead"


def test_convert_set():
    assert _convert_value({"b", "a"}) == ["a", "b"]


def test_serialize_hit():
    hit = SecretHit(
        secret_type="CLIENT_RANDOM",
        offset=100,
        length=32,
        dump_path=Path("/tmp/test.dump"),
        library="openssl",
        phase="pre_abort",
        run_id=1,
    )
    d = serialize_hit(hit)
    assert d["dump_path"] == "/tmp/test.dump"
    assert d["secret_type"] == "CLIENT_RANDOM"
    assert isinstance(d, dict)


def test_serialize_static_region():
    region = StaticRegion(start=0, end=16, mean_variance=0.01, classification="invariant")
    d = serialize_static_region(region)
    assert d["length"] == 16
    assert d["start"] == 0


def test_serialize_report():
    report = LibraryReport(
        library="openssl",
        protocol_version="13",
        phase="pre_abort",
        num_runs=3,
    )
    d = serialize_report(report)
    assert d["library"] == "openssl"
    assert d["hits"] == []


def test_serialize_result():
    result = AnalysisResult()
    result.libraries.append(
        LibraryReport(library="test", protocol_version="13", phase="pre_abort", num_runs=1)
    )
    d = serialize_result(result)
    assert d["total_hits"] == 0
    assert len(d["libraries"]) == 1


def test_serialize_dataset_info():
    info = DatasetInfo(
        protocol_versions={"12", "13"},
        root=Path("/tmp/data"),
        total_runs=5,
    )
    d = serialize_dataset_info(info)
    assert d["root"] == "/tmp/data"
    assert d["protocol_versions"] == ["12", "13"]
    assert d["total_runs"] == 5


def _representative_result() -> AnalysisResult:
    """An AnalysisResult with two libraries and a mix of hits/metadata."""
    result = AnalysisResult(metadata={"source": "unit-test"})
    result.libraries.append(
        LibraryReport(
            library="openssl",
            protocol_version="13",
            phase="pre_abort",
            num_runs=3,
            hits=[
                SecretHit(
                    secret_type="CLIENT_RANDOM",
                    offset=100,
                    length=32,
                    dump_path=Path("/tmp/a.dump"),
                    library="openssl",
                    phase="pre_abort",
                    run_id=1,
                ),
                SecretHit(
                    secret_type="SERVER_RANDOM",
                    offset=200,
                    length=32,
                    dump_path=Path("/tmp/a.dump"),
                    library="openssl",
                    phase="pre_abort",
                    run_id=2,
                ),
            ],
        )
    )
    result.libraries.append(
        LibraryReport(
            library="gnutls",
            protocol_version="12",
            phase="post_handshake",
            num_runs=1,
        )
    )
    return result


def test_summarize_result_equivalence_lock():
    """summarize_result must be byte-identical to the runner's legacy
    _result_summary for the serialized-dict inputs the runner passes."""
    from memdiver.app.pipeline.analysis_task_runner import _result_summary

    result = _representative_result()
    serialized = serialize_result(result)

    canonical = summarize_result(serialized)
    legacy = _result_summary(serialized)
    assert canonical == legacy
    # Delegation means the wrapper now IS summarize_result; also confirm the
    # dataclass path matches the serialized-dict path.
    assert summarize_result(result) == canonical

    # Lock the exact shape and values.
    assert canonical == {
        "library_count": 2,
        "total_hits": 2,
        "libraries": [
            {"library": "openssl", "phase": "pre_abort", "num_runs": 3, "hit_count": 2},
            {"library": "gnutls", "phase": "post_handshake", "num_runs": 1, "hit_count": 0},
        ],
    }


def test_summarize_result_json_safe():
    """The summary must survive json.dumps for the ProcessPool boundary."""
    summary = summarize_result(_representative_result())
    text = json.dumps(summary)
    assert json.loads(text) == summary


def test_json_roundtrip():
    result = AnalysisResult()
    result.libraries.append(
        LibraryReport(
            library="test",
            protocol_version="13",
            phase="pre_abort",
            num_runs=1,
            hits=[
                SecretHit(
                    secret_type="KEY",
                    offset=0,
                    length=32,
                    dump_path=Path("/tmp/x.dump"),
                    library="test",
                    phase="pre_abort",
                    run_id=1,
                    metadata={"raw": b"\xaa\xbb"},
                )
            ],
        )
    )
    d = serialize_result(result)
    text = json.dumps(d)
    parsed = json.loads(text)
    assert parsed["total_hits"] == 1
    assert parsed["libraries"][0]["hits"][0]["metadata"]["raw"] == "aabb"


# ---------------------------------------------------------------------------
# The persistence boundary: the serialized shape must carry the axes
# ---------------------------------------------------------------------------
#
# There are TWO writers into the project database, and this comment used to
# name the wrong one as "the ONLY production path". Correctly:
#
#   * `engine.pipeline.AnalysisPipeline._persist_report` is the writer that
#     actually runs. It reads the axes and `value_hex` straight off the
#     `LibraryReport` / `SecretHit` objects — the serializer is not involved.
#   * `engine/batch.py` -> `serialize_result` -> `ProjectDB.persist_report` is
#     SUPPORTED BUT DORMANT: `persist_report` has no production caller at all,
#     because `BatchRunner` reaches it only when constructed with a
#     `project_db`, and neither production construction
#     (`app/pipeline/batch_task_runner.py`, `cli/dataset.py`) passes one.
#
# The serialized path still has to carry everything, or the day it is wired up
# every key the serializer fails to emit becomes a column that writer fills
# with its default, silently. These tests pin BOTH directions, because a key
# added to `serialize_*` and not to `deserialize_*` is lost on every round trip
# with nothing to notice it.

#: The historical key order of a serialized hit / report. Appending is allowed;
#: reordering, renaming or dropping is not (`frontend/src/api/types.ts` and
#: `engine.project_db._finding_row_from_hit` both read this shape).
_HISTORICAL_HIT_KEYS = [
    "secret_type", "offset", "length", "dump_path", "library", "phase",
    "run_id", "confidence", "verified", "metadata",
]
_HISTORICAL_REPORT_KEYS = [
    "library", "protocol_version", "phase", "num_runs", "hits",
    "static_regions", "metadata",
]


def _wide_hit():
    return SecretHit(
        secret_type="CLIENT_HANDSHAKE_TRAFFIC_SECRET",
        offset=585148,
        length=32,
        dump_path=Path("/corpus/openssl_run_13_4/pre_abort.dump"),
        library="openssl",
        phase="pre_abort",
        run_id=4,
        confidence=0.5,
        verified=True,
        metadata={"cipher": "AES_256_GCM", "confirmed_by": "pcap"},
        value_hex="ab" * 32,
        canonical_phase="handshake_end",
    )


def _wide_report(hits=None):
    return LibraryReport(
        library="openssl",
        protocol_version="13",
        phase="pre_abort",
        num_runs=1,
        hits=hits if hits is not None else [],
        canonical_phase="handshake_end",
        library_version="3.0.2",
        version_axis="protocol_version",
        scenario="100_iterations_Abort_KeyUpdate",
        protocol="TLS",
    )


def test_serialize_hit_keeps_the_historical_keys_first():
    """Append-only: the existing keys keep their names AND their order.

    A FORWARD GUARD, and nothing more. It passes with the whole widening
    reverted — the historical keys are first whether or not anything was
    appended after them — so it proves nothing about the added fields. What it
    catches is a LATER edit that reorders, renames or drops one of the keys
    `frontend/src/api/types.ts` and `engine.project_db._finding_row_from_hit`
    read positionally-by-name. The tests that prove the widening are
    `test_serialize_hit_emits_value_hex_and_canonical_phase` and friends.
    """
    assert list(serialize_hit(_wide_hit()))[:len(_HISTORICAL_HIT_KEYS)] == \
        _HISTORICAL_HIT_KEYS


def test_serialize_report_keeps_the_historical_keys_first():
    """The report-shaped twin of the guard above — and equally forward-only.

    It too passes with the five axis keys removed again; see
    `test_serialize_report_emits_every_corpus_axis` for the one that does not.
    """
    assert list(serialize_report(_wide_report()))[:len(_HISTORICAL_REPORT_KEYS)] == \
        _HISTORICAL_REPORT_KEYS


def test_serialize_hit_emits_value_hex_and_canonical_phase():
    d = serialize_hit(_wide_hit())
    assert d["value_hex"] == "ab" * 32
    assert d["canonical_phase"] == "handshake_end"


def test_serialize_hit_promotes_the_verification_labels():
    """``cipher`` / ``confirmed_by`` are mirrored to the TOP LEVEL.

    ``engine.project_db._finding_row_from_hit`` reads them there; the verifier
    produces them inside ``metadata``. The mirror is what makes the two agree —
    and it is a MIRROR: ``metadata`` keeps its copy.
    """
    d = serialize_hit(_wide_hit())
    assert d["cipher"] == "AES_256_GCM"
    assert d["confirmed_by"] == "pcap"
    assert d["metadata"]["cipher"] == "AES_256_GCM"
    assert d["metadata"]["confirmed_by"] == "pcap"


def test_serialize_hit_labels_are_none_when_unverified():
    """A plain hit emits the keys with ``None``, not an invented label."""
    d = serialize_hit(
        SecretHit(secret_type="K", offset=0, length=32,
                  dump_path=Path("/tmp/x.dump"), library="l", phase="p",
                  run_id=0)
    )
    assert d["cipher"] is None
    assert d["confirmed_by"] is None
    assert d["value_hex"] is None
    assert d["canonical_phase"] == ""


def test_serialize_report_emits_every_corpus_axis():
    d = serialize_report(_wide_report())
    assert d["canonical_phase"] == "handshake_end"
    assert d["library_version"] == "3.0.2"
    assert d["scenario"] == "100_iterations_Abort_KeyUpdate"
    assert d["protocol"] == "TLS"
    assert d["version_axis"] == "protocol_version"


def test_round_trip_preserves_every_new_field():
    """Through real JSON, so a non-serializable addition fails here too."""
    result = AnalysisResult()
    result.libraries.append(_wide_report([_wide_hit()]))

    parsed = json.loads(json.dumps(serialize_result(result)))
    back = deserialize_result(parsed)

    lib = back.libraries[0]
    assert lib.canonical_phase == "handshake_end"
    assert lib.library_version == "3.0.2"
    assert lib.version_axis == "protocol_version"
    assert lib.scenario == "100_iterations_Abort_KeyUpdate"
    assert lib.protocol == "TLS"

    hit = lib.hits[0]
    assert hit.value_hex == "ab" * 32
    assert hit.canonical_phase == "handshake_end"
    assert hit.run_id == 4
    assert hit.verified is True
    # cipher / confirmed_by have no SecretHit field: they round-trip as the
    # metadata entries they are mirrors of.
    assert hit.metadata["cipher"] == "AES_256_GCM"
    assert hit.metadata["confirmed_by"] == "pcap"


def test_deserialize_falls_back_to_the_column_defaults():
    """A narrow (pre-axis) dict still deserializes to the report it used to."""
    lib = deserialize_report({"library": "openssl", "protocol_version": "13"})
    assert lib.canonical_phase == ""
    assert lib.library_version == "unknown"
    assert lib.version_axis == "protocol_version"
    assert lib.scenario == ""
    assert lib.protocol == ""

    hit = deserialize_hit({"secret_type": "K"})
    assert hit.value_hex is None
    assert hit.canonical_phase == ""


# ---------------------------------------------------------------------------
# Source parity with frontend/src/api/types.ts
# ---------------------------------------------------------------------------
#
# The docstrings above say the frontend "consumes this exact shape" and the
# comment block above says the same -- and until this section, nothing checked
# it. It had already drifted: the serializer emitted seven keys the TypeScript
# could not see (`verified`, `metadata`, `value_hex`, `canonical_phase`,
# `cipher`, `confirmed_by` on a hit; the five corpus axes on a report), so a
# component reading `hit.confirmed_by` off an `AnalysisResult` was a type error
# rather than the provenance badge it should have been.
#
# There is no build step generating the TS from Python, so the only thing that
# can hold the two together is a test that reads the file. This one does, and
# needs no vitest run: it parses the ONE named interface body it is asked for
# and compares its field names to the keys the serializer actually produces on
# a fully-populated fixture. Both directions are asserted -- a Python key with
# no TS field is invisible to the UI; a TS field with no Python key is a
# promise the backend does not keep.

#: frontend/src/api/types.ts, relative to this test file (repo_root/tests).
_TYPES_TS = Path(__file__).resolve().parents[1] / "frontend" / "src" / "api" / "types.ts"


def _interface_body(source: str, name: str) -> str:
    """Return the text between the braces of ``interface <name> { ... }``.

    Deliberately narrow: it locates that one declaration and brace-matches to
    its close, so a neighbouring interface -- or a later one whose name merely
    begins with the same word -- can neither satisfy the check nor pollute it.
    """
    match = re.search(rf"\binterface\s+{name}\s*(?:extends[^{{]*)?{{", source)
    assert match, f"could not locate `interface {name}` in {_TYPES_TS}"
    start = match.end()
    depth = 1
    for index in range(start, len(source)):
        char = source[index]
        if char == "{":
            depth += 1
        elif char == "}":
            depth -= 1
            if depth == 0:
                return source[start:index]
    raise AssertionError(f"unterminated `interface {name}` body in {_TYPES_TS}")


def _ts_field_names(body: str) -> set:
    """The declared field names of an interface body (``name?: type;``).

    Comment lines cannot match: they open with ``//`` or ``*``, neither of
    which is a word character.
    """
    return set(re.findall(r"^\s*(\w+)\??\s*:", body, re.MULTILINE))


def _assert_ts_parity(interface: str, serialized: dict) -> None:
    """Assert one TS interface and one serialized dict carry the same keys."""
    ts_fields = _ts_field_names(_interface_body(_TYPES_TS.read_text(), interface))
    py_keys = set(serialized)
    assert py_keys == ts_fields, (
        f"frontend/src/api/types.ts `{interface}` drifted from the serializer. "
        f"emitted but not typed: {sorted(py_keys - ts_fields)}; "
        f"typed but not emitted: {sorted(ts_fields - py_keys)}"
    )


def test_types_ts_secret_hit_matches_serialize_hit():
    """Every key `serialize_hit` emits is visible to the frontend, and no more."""
    _assert_ts_parity("SecretHit", serialize_hit(_wide_hit()))


def test_types_ts_library_report_matches_serialize_report():
    """The report twin -- this is where the five corpus axes were missing."""
    _assert_ts_parity("LibraryReport", serialize_report(_wide_report([_wide_hit()])))


def test_types_ts_static_region_matches_serialize_static_region():
    """`length` is a real emitted key, not a frontend-side derivation."""
    _assert_ts_parity(
        "StaticRegion", serialize_static_region(StaticRegion(start=16, end=48))
    )


def test_the_types_ts_parity_check_is_not_vacuous():
    """The parity check FAILS on a truncated interface -- proven here, in-band.

    A source-parity test that keeps passing against a stale file is worse than
    no test at all, and every failure mode is silent: a bad regex matches
    nothing, a greedy one swallows the neighbouring interfaces and every name
    "appears". So the extractor is pinned against a hand-written stub whose
    answer is known, and the comparison is shown to reject it.
    """
    truncated = (
        "export interface SecretHit {\n"
        "  secret_type: string;\n"
        "  // offset: number;   <- commented out, so it must NOT count\n"
        "  length: number;\n"
        "}\n"
        "\n"
        "export interface SecretHitButNotReally {\n"
        "  canonical_phase: string;\n"
        "}\n"
    )
    fields = _ts_field_names(_interface_body(truncated, "SecretHit"))

    # Stops at the first interface's closing brace: the decoy's field is absent,
    # and so is the commented-out one.
    assert fields == {"secret_type", "length"}
    assert set(serialize_hit(_wide_hit())) - fields, (
        "the truncated interface must be missing keys the serializer emits, "
        "or this proof of non-vacuity proves nothing"
    )

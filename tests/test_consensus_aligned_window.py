"""Aligned-window producer + route: the N-dump differential read.

Invariant W1 is what every test here is ultimately pinning. For every dump
``d`` and every ``i`` in ``[0, length)``, ``dumps[d].bytes[i]`` is the byte
``d`` holds at the address the consensus put in correspondence with the
anchor's byte at ``offset + i``. Where no correspondence exists: ``i`` falls in
a ``gaps`` run, ``classes[i] == -1``, ``bytes[i] == 0x00``, and ``i`` is
outside every ``bytes_valid`` run.

The flagship (T1) is deliberately NON-VACUOUS: it asserts run 2's bytes are
the SECRET of run 2 and not the page filler (``0xFE``) and not zeros. A
producer that read the peer at the anchor's own offset would return the filler
and a producer that read an unmapped VA would return zeros, so both broken
implementations fail loudly rather than "look plausible".
"""

from __future__ import annotations

import base64
import os
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from fastapi.testclient import TestClient  # noqa: E402

from memdiver.api.main import create_app  # noqa: E402
from memdiver.api.services.consensus_session import ConsensusSessionManager  # noqa: E402
from memdiver.app.composition import build_tool_session  # noqa: E402
from memdiver.app.tools_consensus import (  # noqa: E402
    MAX_WINDOW_TOTAL_BYTES,
    aligned_window_from_vector,
    aligned_window_result,
)
from memdiver.core.service_errors import CapabilityError  # noqa: E402
from memdiver.engine.consensus_service import build_consensus  # noqa: E402
from tests.fixtures.generate_msl_aslr_fixtures import (  # noqa: E402
    EXTRA_BASE_RUN1,
    HEAP_BASE_RUN1,
    SECRET_OFFSET_IN_PAGE,
    SECRET_VALUES_BY_RUN,
    generate_aslr_msl_pair,
)

#: The secret's absolute VA in run 1, and run 1's VA-view span start. The extra
#: region sorts FIRST, so the span starts at IT, not at the heap — which is the
#: whole reason a single scalar "VA delta per dump" cannot describe this pair.
SECRET_VA_RUN1 = HEAP_BASE_RUN1 + SECRET_OFFSET_IN_PAGE
VA_SPAN_START_RUN1 = EXTRA_BASE_RUN1
#: Slab coordinates measured off the built layout: row 0 is the extra region
#: (run-to-run delta 0x1000), row 1 is the heap page (delta 0x10000000).
SLAB_HEAP_PAGE = 4096
SLAB_SECRET = SLAB_HEAP_PAGE + SECRET_OFFSET_IN_PAGE
SLAB_TOTAL = 8192
HEAP_DELTA = 0x10000000
EXTRA_DELTA = 0x1000


@pytest.fixture
def aslr_pair(tmp_path):
    """Two ASLR-shifted ``.msl`` runs with TWO differently-shifted regions."""
    run1, run2 = generate_aslr_msl_pair(extra_region=True)
    p1 = tmp_path / "run_1.msl"
    p2 = tmp_path / "run_2.msl"
    p1.write_bytes(run1)
    p2.write_bytes(run2)
    return str(p1), str(p2)


@pytest.fixture
def aslr_consensus(aslr_pair):
    return build_consensus(list(aslr_pair)), aslr_pair


@pytest.fixture
def flat_pair(tmp_path):
    """Two plain ``.dump`` files — a flat (``file_offset``) build."""
    p1 = tmp_path / "a.dump"
    p2 = tmp_path / "b.dump"
    p1.write_bytes(bytes(range(256)) * 4)
    p2.write_bytes(bytes(range(256)) * 4)
    return str(p1), str(p2)


@pytest.fixture
def client():
    return TestClient(create_app())


@pytest.fixture(autouse=True)
def _fresh_manager(monkeypatch):
    """Per-test consensus manager so ids never leak between tests."""
    import memdiver.api.services.consensus_session as mod

    manager = ConsensusSessionManager()
    monkeypatch.setattr(mod, "_default_manager", manager)
    yield manager


def _bytes_of(block) -> bytes:
    assert block["bytes"] is not None
    return base64.b64decode(block["bytes"])


# ---------------------------------------------------------------------------
# T1 — the flagship. Real ASLR, real secrets, non-vacuous.
# ---------------------------------------------------------------------------


def test_t1_window_reads_each_run_secret_at_its_own_address(aslr_consensus):
    """Anchor on run 1's secret VA; run 2 must yield RUN 2's secret.

    Every assertion below is a different broken implementation:
    ``!= 0xFE * 32`` fails a producer that applied the anchor's offset to the
    peer (it would land in run 2's page filler); ``!= 0x00 * 32`` fails one
    that read an unmapped VA; the ``0x10000000`` delta fails one that assumed
    the pair's ONE shift is the extra region's ``0x1000``.
    """
    consensus, (p1, _p2) = aslr_consensus
    offset = SECRET_VA_RUN1 - VA_SPAN_START_RUN1

    window = aligned_window_from_vector(
        consensus, anchor_path=p1, anchor_view="va", offset=offset, length=32,
    )

    assert window["classified"] is True
    assert window["alignment"]["method"] == "module_offset"
    assert window["length"] == 32
    assert window["truncated"] is False
    assert window["gaps"] == []
    assert len(window["classes"]) == 32

    assert _bytes_of(window["dumps"][0]) == SECRET_VALUES_BY_RUN[1]
    assert _bytes_of(window["dumps"][1]) == SECRET_VALUES_BY_RUN[2]
    assert _bytes_of(window["dumps"][1]) != b"\xFE" * 32  # not the page filler
    assert _bytes_of(window["dumps"][1]) != b"\x00" * 32  # not an unmapped read

    seg = window["segments"][0]
    assert seg["slab_offset"] == SLAB_SECRET
    assert seg["dumps"][1]["va"] - seg["dumps"][0]["va"] == HEAP_DELTA
    assert seg["dumps"][1]["offset"] != seg["dumps"][0]["offset"]
    assert window["anchor"]["slab_offset"] == SLAB_SECRET


def test_t1_multi_page_window_carries_two_different_deltas(aslr_consensus):
    """A window spanning BOTH aligned pages: two segments, two deltas.

    This is the case a single per-dump peer offset gets wrong in a way that
    reads as plausible bytes — the two regions moved by ``0x1000`` and
    ``0x10000000`` between runs, so the correct answer cannot be one scalar.
    """
    consensus, _paths = aslr_consensus
    window = aligned_window_from_vector(
        consensus, slab_offset=SLAB_HEAP_PAGE - 16, length=96,
    )

    segments = window["segments"]
    assert len(segments) == 2, segments
    deltas = [s["dumps"][1]["va"] - s["dumps"][0]["va"] for s in segments]
    assert deltas == [EXTRA_DELTA, HEAP_DELTA]
    assert deltas[0] != deltas[1]

    # W1: the bytes follow the per-segment coordinates, not one of them.
    run1 = _bytes_of(window["dumps"][0])
    run2 = _bytes_of(window["dumps"][1])
    assert run1[:16] == b"\x00" * 16          # run 1's extra-region filler
    assert run2[:16] == b"\xFE" * 16          # run 2's extra-region filler
    assert run1[16:16 + 4] == b"\x00" * 4     # heap page 0, run 1 filler
    assert run2[16:16 + 4] == b"\xFE" * 4
    assert window["dumps"][0]["bytes_valid"] == [[0, 16], [16, 80]]


def test_w1_gap_bytes_are_zero_unclassified_and_outside_bytes_valid(aslr_consensus):
    """The other half of W1: where there is no correspondence, say so 3 ways."""
    consensus, _paths = aslr_consensus
    window = aligned_window_from_vector(
        consensus, slab_offset=SLAB_TOTAL - 92, length=200,
    )

    assert window["gaps"] == [[92, 108]]
    assert set(window["classes"][92:]) == {-1}
    assert all(c >= 0 for c in window["classes"][:92])
    for block in window["dumps"]:
        assert _bytes_of(block)[92:] == b"\x00" * 108
        assert block["bytes_valid"] == [[0, 92]]


def test_segments_and_gaps_partition_the_window(aslr_consensus):
    """Every byte of the window is in exactly one segment or one gap."""
    consensus, _paths = aslr_consensus
    window = aligned_window_from_vector(
        consensus, slab_offset=SLAB_TOTAL - 64, length=256,
    )
    spans = sorted(
        [(s["window_offset"], s["length"]) for s in window["segments"]]
        + [tuple(g) for g in window["gaps"]]
    )
    cursor = 0
    for start, run in spans:
        assert start == cursor
        cursor += run
    assert cursor == window["length"] == len(window["classes"])


# ---------------------------------------------------------------------------
# T5 — the flat (file_offset) build
# ---------------------------------------------------------------------------


def test_t5_flat_build_serves_raw_view_and_reports_file_offset(flat_pair):
    consensus = build_consensus(list(flat_pair))
    assert consensus.msl_layout is None

    window = aligned_window_from_vector(
        consensus, anchor_path=flat_pair[0], anchor_view="raw",
        offset=16, length=32,
    )
    assert window["alignment"]["method"] == "file_offset"
    assert window["classified"] is True
    assert _bytes_of(window["dumps"][0]) == bytes(range(16, 48))
    assert _bytes_of(window["dumps"][1]) == bytes(range(16, 48))
    # Real classifications, not the -1 of an unclassified window.
    assert set(window["classes"]) != {-1}


def test_t5_flat_build_refuses_a_va_anchor(flat_pair):
    consensus = build_consensus(list(flat_pair))
    with pytest.raises(CapabilityError) as excinfo:
        aligned_window_from_vector(
            consensus, anchor_path=flat_pair[0], anchor_view="va", length=32,
        )
    assert excinfo.value.status == 400


def test_t5_flat_build_va_anchor_is_400_over_http(client, flat_pair):
    built = client.post(
        "/api/analysis/consensus", json={"dump_paths": list(flat_pair)},
    ).json()
    response = client.post("/api/analysis/consensus/aligned-window", json={
        "consensus_id": built["consensus_id"],
        "anchor_path": flat_pair[0], "view": "va", "length": 32,
    })
    assert response.status_code == 400, response.text


# ---------------------------------------------------------------------------
# T6 — the no-consensus fallback, LABELLED
# ---------------------------------------------------------------------------


def test_t6_unclassified_equal_sizes_has_no_warnings_and_no_zero_classes(flat_pair):
    result = aligned_window_result(
        build_tool_session(), dump_paths=list(flat_pair),
        anchor_path=flat_pair[0], anchor_view="raw", offset=0, length=64,
        classify=False,
    )
    window = result.payload
    assert window["classified"] is False
    assert window["alignment"]["method"] == "file_offset"
    assert window["alignment"]["warnings"] == []
    assert window["alignment"]["n_sources"] == 2
    assert set(window["classes"]) == {-1}
    assert 0 not in window["classes"]   # INVARIANT is a claim nobody measured
    assert _bytes_of(window["dumps"][0]) == bytes(range(64))


def test_t6_unclassified_differing_sizes_warns_and_still_never_claims_zero(tmp_path):
    short = tmp_path / "short.dump"
    long_ = tmp_path / "long.dump"
    short.write_bytes(b"\x01" * 64)
    long_.write_bytes(b"\x02" * 256)

    result = aligned_window_result(
        build_tool_session(), dump_paths=[str(short), str(long_)],
        anchor_path=str(short), anchor_view="raw", offset=0, length=128,
        classify=False,
    )
    window = result.payload
    warnings = window["alignment"]["warnings"]
    assert warnings and "without ASLR correction" in warnings[0]
    assert window["alignment"]["sizes_differed"] is True
    assert set(window["classes"]) == {-1}
    assert 0 not in window["classes"]
    # Compared only up to the shortest dump; the rest is an honest gap.
    assert window["gaps"] == [[64, 64]]
    assert _bytes_of(window["dumps"][1])[:64] == b"\x02" * 64
    assert _bytes_of(window["dumps"][1])[64:] == b"\x00" * 64


# ---------------------------------------------------------------------------
# T7 — source lifetime: the build's sources are DEAD, the window re-opens
# ---------------------------------------------------------------------------


def test_t7_window_after_post_consensus_does_not_hit_a_closed_source(
    client, aslr_pair,
):
    """Regression shape of tests/test_api_consensus.py:140.

    ``build_consensus`` closes every source before it returns and the session
    keeps only the matrix, so a window served off a stored build MUST re-open
    the dumps. Reading the stored sources would raise
    ``RuntimeError('MslDumpSource not opened')``.
    """
    built = client.post(
        "/api/analysis/consensus", json={"dump_paths": list(aslr_pair)},
    )
    assert built.status_code == 200, built.text
    consensus_id = built.json()["consensus_id"]

    response = client.post("/api/analysis/consensus/aligned-window", json={
        "consensus_id": consensus_id,
        "anchor": "slab", "slab_offset": SLAB_SECRET, "length": 32,
    })
    assert response.status_code == 200, response.text
    window = response.json()
    assert window["consensus_id"] == consensus_id
    assert base64.b64decode(window["dumps"][0]["bytes"]) == SECRET_VALUES_BY_RUN[1]
    assert base64.b64decode(window["dumps"][1]["bytes"]) == SECRET_VALUES_BY_RUN[2]


def test_t7_each_selected_dump_is_opened_exactly_once(aslr_consensus, monkeypatch):
    """One open per selected dump — including the anchor, which reads off the
    same open source rather than re-opening its own."""
    import memdiver.app.key_material as key_material_module

    opens = []
    original = key_material_module.open_dump_source

    def _counting_open(path, km):
        opens.append(str(path))
        return original(path, km)

    monkeypatch.setattr(key_material_module, "open_dump_source", _counting_open)

    consensus, (p1, p2) = aslr_consensus
    aligned_window_from_vector(
        consensus, anchor_path=p1, anchor_view="va",
        offset=SECRET_VA_RUN1 - VA_SPAN_START_RUN1, length=32,
    )
    assert sorted(opens) == sorted([p1, p2])


# ---------------------------------------------------------------------------
# T8 — a locked peer costs that peer's bytes and NOTHING else
# ---------------------------------------------------------------------------


def _write_encrypted_msl(path: Path, key: bytes, data: bytes) -> None:
    """A NATIVE (``imported=False``) encrypted ``.msl``.

    Native on purpose: an imported container takes the flat-offset fallback,
    and the locked-peer behaviour this test pins has to be proven on an ALIGNED
    build — that is the path where a missing key could otherwise take the whole
    window down.
    """
    from memdiver.msl.writer import MslEncryptionConfig, MslWriter

    writer = MslWriter(
        str(path), pid=7, imported=False,
        encryption=MslEncryptionConfig(raw_key=key),
    )
    writer.add_process_identity(exe_path="/proc")
    writer.add_memory_region(0x1000, data)
    writer.add_end_of_capture()
    writer.write()


@pytest.fixture
def encrypted_pair(tmp_path):
    from memdiver.msl import crypto
    from memdiver.msl.enums import EncAlgo

    if not crypto.cipher_is_available(EncAlgo.AES_256_GCM):
        pytest.skip("AES-256-GCM backend not installed")
    key = os.urandom(32)
    first = tmp_path / "enc_a.msl"
    second = tmp_path / "enc_b.msl"
    _write_encrypted_msl(first, key, b"\xA1" * 4096)
    _write_encrypted_msl(second, key, b"\xB2" * 4096)
    return str(first), str(second), {"key": key}


def test_t8_locked_peer_is_reported_and_the_other_dump_still_returns_bytes(
    encrypted_pair,
):
    """One peer nobody has the key for must not cost every other peer's bytes.

    ``raise_if_locked`` is deliberately NOT used: it would turn one missing key
    into a dead window. The locked dump reports ``bytes: None`` plus a hint and
    the plaintext-to-us peer is served normally.
    """
    first, second, key_material = encrypted_pair
    consensus = build_consensus([first, second], key_material=key_material)
    assert consensus.msl_layout is not None

    window = aligned_window_from_vector(
        consensus, slab_offset=0, length=64,
        key_material_by_path={first: key_material},   # second: no key
    )

    unlocked, locked = window["dumps"]
    assert unlocked["key_status"]["decrypted"] is True
    assert _bytes_of(unlocked) == b"\xA1" * 64

    assert locked["bytes"] is None
    assert locked["bytes_valid"] == []
    assert locked["key_status"]["decrypted"] is False
    assert locked["key_status"]["hint"]

    # The window itself is intact: classes and segments are unaffected.
    assert len(window["classes"]) == 64
    assert window["segments"]


# ---------------------------------------------------------------------------
# T9 — caps CLAMP length; they never drop a dump
# ---------------------------------------------------------------------------


def test_t9_window_cap_clamps_length_and_keeps_every_dump(aslr_consensus):
    consensus, _paths = aslr_consensus
    window = aligned_window_from_vector(consensus, slab_offset=0, length=99999)
    assert window["requested_length"] == 99999
    assert window["length"] == 16384
    assert window["truncated"] is True
    assert len(window["dumps"]) == 2


def test_t9_total_bytes_cap_clamps_length_and_keeps_every_dump(monkeypatch, aslr_consensus):
    """The N-wide cap bites by CLAMPING, never by dropping a dump.

    A silently missing dump reads as "this dump has nothing there", which is a
    different and wrong answer, so the cap is forced down to a value only the
    length can satisfy.
    """
    import memdiver.app.tools_consensus as module

    monkeypatch.setattr(module, "MAX_WINDOW_TOTAL_BYTES", 128)
    consensus, _paths = aslr_consensus
    window = aligned_window_from_vector(consensus, slab_offset=0, length=512)

    assert window["requested_length"] == 512
    assert window["length"] == 64          # 128 total / 2 dumps
    assert window["truncated"] is True
    assert len(window["dumps"]) == 2
    assert len(window["classes"]) == 64
    assert MAX_WINDOW_TOTAL_BYTES == 262144   # the real ceiling is untouched


def test_t9_subset_cap_rejects_rather_than_silently_trimming(aslr_consensus):
    consensus, (p1, _p2) = aslr_consensus
    with pytest.raises(CapabilityError) as excinfo:
        aligned_window_from_vector(
            consensus, slab_offset=0, length=16, dumps=[0, 1] * 20,
        )
    assert "at most 32 dumps" in str(excinfo.value)


# ---------------------------------------------------------------------------
# T10 — end-to-end: the returned offsets are a REAL viewer target
# ---------------------------------------------------------------------------


def test_t10_segment_offsets_reread_through_hex_raw_are_byte_identical(
    client, aslr_pair,
):
    """Re-read each dump at the offset the window reported, through the
    ordinary ``/api/inspect/hex-raw`` route, and get the same bytes back.

    This is the end-to-end proof that the coordinates handed to an operator
    ("go look here") name the very bytes the window painted.
    """
    built = client.post(
        "/api/analysis/consensus", json={"dump_paths": list(aslr_pair)},
    ).json()
    window = client.post("/api/analysis/consensus/aligned-window", json={
        "consensus_id": built["consensus_id"],
        "anchor": "slab", "slab_offset": SLAB_SECRET, "length": 32,
    }).json()

    segment = window["segments"][0]
    assert segment["length"] == 32
    for block, provenance in zip(window["dumps"], segment["dumps"]):
        reread = client.get("/api/inspect/hex-raw", params={
            "dump_path": block["dump_path"],
            "offset": provenance["offset"],
            "length": segment["length"],
            "view": block["view"],
        })
        assert reread.status_code == 200, reread.text
        assert base64.b64decode(reread.json()["bytes"]) == (
            base64.b64decode(block["bytes"])[:segment["length"]]
        )


# ---------------------------------------------------------------------------
# The `.msl` raw-view refusal (the block-header trap)
# ---------------------------------------------------------------------------


def test_raw_view_is_refused_for_an_msl_anchor(aslr_consensus):
    """``va_to_file_offset`` answers with a BLOCK HEADER's offset, so a raw
    peer read lands on real bytes at the wrong address — the exact failure
    this endpoint exists to prevent."""
    consensus, (p1, _p2) = aslr_consensus
    with pytest.raises(CapabilityError) as excinfo:
        aligned_window_from_vector(
            consensus, anchor_path=p1, anchor_view="raw", offset=0, length=32,
        )
    assert "block header" in str(excinfo.value)


def test_no_msl_peer_is_ever_read_in_raw_view(aslr_consensus):
    consensus, _paths = aslr_consensus
    window = aligned_window_from_vector(consensus, slab_offset=0, length=32)
    assert [block["view"] for block in window["dumps"]] == ["va", "va"]


# ---------------------------------------------------------------------------
# HTTP surface: the request/anchor/lifecycle errors
# ---------------------------------------------------------------------------


def test_http_requires_exactly_one_of_consensus_id_or_dump_paths(client, aslr_pair):
    neither = client.post("/api/analysis/consensus/aligned-window", json={})
    assert neither.status_code == 400

    both = client.post("/api/analysis/consensus/aligned-window", json={
        "consensus_id": "x", "dump_paths": list(aslr_pair),
    })
    assert both.status_code == 400


def test_http_unknown_consensus_id_is_404(client):
    response = client.post("/api/analysis/consensus/aligned-window", json={
        "consensus_id": "nope", "anchor": "slab", "slab_offset": 0, "length": 16,
    })
    assert response.status_code == 404


def test_http_anchor_outside_the_build_is_404(client, aslr_pair, tmp_path):
    built = client.post(
        "/api/analysis/consensus", json={"dump_paths": list(aslr_pair)},
    ).json()
    stranger = tmp_path / "stranger.msl"
    stranger.write_bytes(b"not in the build")
    response = client.post("/api/analysis/consensus/aligned-window", json={
        "consensus_id": built["consensus_id"],
        "anchor_path": str(stranger), "length": 16,
    })
    assert response.status_code == 404, response.text


def test_http_unfinalized_incremental_vector_is_409(client, _fresh_manager):
    """An incremental session that was never finalized has a live Welford state
    and NO classifications; serving it would claim ``classified: true`` over a
    window whose every class is -1."""
    session = _fresh_manager.begin(256)
    _fresh_manager.add_dump(session.session_id, b"\x01" * 256)
    _fresh_manager.add_dump(session.session_id, b"\x02" * 256)

    response = client.post("/api/analysis/consensus/aligned-window", json={
        "consensus_id": session.session_id,
        "anchor": "slab", "slab_offset": 0, "length": 16,
    })
    assert response.status_code == 409, response.text


def test_http_dump_paths_branch_builds_and_serves(client, aslr_pair):
    response = client.post("/api/analysis/consensus/aligned-window", json={
        "dump_paths": list(aslr_pair),
        "anchor": "slab", "slab_offset": SLAB_SECRET, "length": 32,
    })
    assert response.status_code == 200, response.text
    window = response.json()
    assert window["consensus_id"] is None
    assert window["classified"] is True
    assert base64.b64decode(window["dumps"][1]["bytes"]) == SECRET_VALUES_BY_RUN[2]


def test_http_dump_anchor_without_anchor_path_is_400_not_a_slab_window(
    client, aslr_pair,
):
    """The regression that 28 producer-level tests could not see.

    Every other test here either calls the producer with Python kwargs or
    spells the model's own field name, so none of them crossed the HTTP
    boundary with the name the frontend actually sends. When the request field
    was ``dump_path``, an ``anchor_path`` from the client was silently dropped
    by pydantic and the route fell through to a SLAB anchor at offset 0 — a
    200 carrying real bytes from a completely different address. Asking for a
    dump anchor and being handed a slab one is worse than an error, so the
    absent field must be a 400 and must NOT be a window.
    """
    built = client.post(
        "/api/analysis/consensus", json={"dump_paths": list(aslr_pair)},
    ).json()
    response = client.post("/api/analysis/consensus/aligned-window", json={
        "consensus_id": built["consensus_id"],
        "anchor": "dump", "view": "va",
        "offset": SECRET_VA_RUN1 - VA_SPAN_START_RUN1, "length": 32,
    })

    assert response.status_code == 400, response.text
    assert "anchor_path" in response.json()["detail"]
    # Not a 200 slab window wearing an anchor it was never asked for.
    assert "anchor" not in response.json()
    assert "dumps" not in response.json()


def test_http_slab_anchor_without_slab_offset_is_400_not_offset_zero(
    client, aslr_pair,
):
    """The same refusal on the other anchor: 0 has to be said, not assumed."""
    built = client.post(
        "/api/analysis/consensus", json={"dump_paths": list(aslr_pair)},
    ).json()
    response = client.post("/api/analysis/consensus/aligned-window", json={
        "consensus_id": built["consensus_id"], "anchor": "slab", "length": 32,
    })

    assert response.status_code == 400, response.text
    assert "slab_offset" in response.json()["detail"]
    assert "dumps" not in response.json()


def test_http_dump_anchored_window_holds_w1_end_to_end(client, aslr_pair):
    """W1 through the ROUTE, with the wire name the frontend sends.

    Anchor on run 1's secret VA over HTTP; run 2 must come back with RUN 2's
    secret. Non-vacuous the same way T1 is: ``!= 0xFE * 32`` fails a peer read
    at the anchor's own offset (run 2's page filler), ``!= 0x00 * 32`` fails an
    unmapped read, and the two blocks differing fails any implementation that
    quietly served one dump's bytes twice — including the slab-at-0 fallback
    this endpoint used to degrade into.
    """
    built = client.post(
        "/api/analysis/consensus", json={"dump_paths": list(aslr_pair)},
    ).json()
    response = client.post("/api/analysis/consensus/aligned-window", json={
        "consensus_id": built["consensus_id"],
        "anchor": "dump", "anchor_path": aslr_pair[0], "view": "va",
        "offset": SECRET_VA_RUN1 - VA_SPAN_START_RUN1, "length": 32,
    })

    assert response.status_code == 200, response.text
    window = response.json()
    assert window["anchor"]["kind"] == "dump"
    assert window["anchor"]["dump_path"] == aslr_pair[0]
    assert window["anchor"]["slab_offset"] == SLAB_SECRET

    run1 = base64.b64decode(window["dumps"][0]["bytes"])
    run2 = base64.b64decode(window["dumps"][1]["bytes"])
    assert run1 == SECRET_VALUES_BY_RUN[1]
    assert run2 == SECRET_VALUES_BY_RUN[2]
    assert run2 != run1                 # the peer is not the anchor re-served
    assert run2 != b"\xFE" * 32         # not run 2's page filler
    assert run2 != b"\x00" * 32         # not an unmapped read


def test_http_length_over_the_cap_is_clamped_not_rejected(client, aslr_pair):
    built = client.post(
        "/api/analysis/consensus", json={"dump_paths": list(aslr_pair)},
    ).json()
    response = client.post("/api/analysis/consensus/aligned-window", json={
        "consensus_id": built["consensus_id"],
        "anchor": "slab", "slab_offset": 0, "length": 999999,
    })
    assert response.status_code == 200, response.text
    window = response.json()
    assert window["requested_length"] == 999999
    assert window["length"] <= 16384
    assert window["truncated"] is True
    assert len(window["dumps"]) == 2


# ---------------------------------------------------------------------------
# The other surfaces
# ---------------------------------------------------------------------------


def test_cli_consensus_window_emits_the_same_window(aslr_pair, tmp_path, capsys):
    import json

    from memdiver.cli.main import build_parser

    out = tmp_path / "window.json"
    parser = build_parser()
    args = parser.parse_args([
        "consensus-window", *aslr_pair,
        "--slab-offset", str(SLAB_SECRET), "--length", "32", "-o", str(out),
    ])
    from memdiver.cli.consensus import _cmd_consensus_window

    assert _cmd_consensus_window(args) == 0
    window = json.loads(out.read_text())
    assert base64.b64decode(window["dumps"][0]["bytes"]) == SECRET_VALUES_BY_RUN[1]
    assert base64.b64decode(window["dumps"][1]["bytes"]) == SECRET_VALUES_BY_RUN[2]


def test_cli_dispatch_table_registers_consensus_window():
    """The parser knows the subcommand AND main() dispatches it."""
    import inspect as _inspect

    from memdiver.cli.main import _build_parser, main as cli_entry_point

    assert '"consensus-window": _cmd_consensus_window' in _inspect.getsource(
        cli_entry_point
    )
    args = _build_parser().parse_args(["consensus-window", "a.msl", "b.msl"])
    assert args.command == "consensus-window"


def test_mcp_aligned_window_tool_returns_the_same_window(aslr_pair):
    pytest.importorskip("mcp")
    import json

    from memdiver.mcp_server.server import create_server

    server = create_server()
    tool = {t.name: t for t in server._tool_manager.list_tools()}["aligned_window"]
    raw = tool.fn(
        dump_paths=list(aslr_pair), slab_offset=SLAB_SECRET, length=32,
    )
    window = raw if isinstance(raw, dict) else json.loads(raw)
    assert base64.b64decode(window["dumps"][1]["bytes"]) == SECRET_VALUES_BY_RUN[2]


def test_library_surface_exposes_the_producer():
    import memdiver

    assert "aligned_window_result" in memdiver.services.__all__
    assert callable(memdiver.services.aligned_window_result)

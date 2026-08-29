"""The key-location spine (B1/B3) — ``analysis.locate_key`` + ``export.key_pattern``.

Two capabilities, four surfaces each. The question they answer is the one the
rest of the pipeline cannot: *I ALREADY HOLD this secret — which of my dumps
still contain it, and where?* Everything else in ``tools_pipeline`` either
searches for unknown keys (``analyze_candidates``) or needs an oracle to confirm
one (``brute_force``).

What these tests pin, in order:

* both capabilities are wired on all four surfaces and are NOT documented gaps;
* the THREE-VALUED verdict: ``found`` / ``absent`` / ``not_searched``, and in
  particular that an all-unreadable dump set NEVER reads as ``absent``;
* the three input forms produce IDENTICAL answers, and supplying zero or two of
  them is refused rather than resolved by precedence;
* the HTTP contract — 200 for a legitimate absence, 400/404 for real errors —
  reaches the transport through the app's single global ``CapabilityError``
  handler, with no ``try/except`` in either route;
* and for B3, the load-bearing property of the export: the static mask is
  measured over EVERY searched dump, so the dumps that do NOT hold the key are
  what wildcard it. Masking over only the dumps that hold it produces a
  100 %-static rule with the secret embedded verbatim — which the
  ``key_fully_static`` diagnostic is there to catch.

The synthetic fixtures are deliberate miniatures of the real corpus: the
2-of-4 ``planted_dumps`` mirrors the measured 2-of-8 survival of the reference
OpenSSL TLS 1.2 run, which the ``requires_dataset`` test at the bottom then
proves for real.
"""

from __future__ import annotations

import inspect
import sys
from pathlib import Path

import numpy as np
import pytest
from fastapi.testclient import TestClient

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from memdiver.api.config import get_settings  # noqa: E402
from memdiver.api.main import create_app  # noqa: E402
from memdiver.app.export_service import (  # noqa: E402
    InsufficientStaticError,
    KeyNotFoundError,
)
from memdiver.app.tools_pipeline import (  # noqa: E402
    KEY_PATTERN_DEGENERATE_ANCHORS_CODE,
    KEY_PATTERN_NO_ANCHORS_CODE,
    KEY_PATTERN_STATIC_KEY_CODE,
    KEY_PATTERN_SUBSET_CODE,
    LOCATE_KEY_ABSENT_CODE,
    LOCATE_KEY_MULTI_HIT_CODE,
    LOCATE_KEY_NOT_SEARCHED_CODE,
    LOCATE_KEY_OFFSET_DRIFT_CODE,
    LOCATE_KEY_PARTIAL_CODE,
    export_key_pattern,
    locate_key,
)
from memdiver.core.service_errors import CapabilityError, ErrorCategory  # noqa: E402

#: The synthetic secret every fixture plants. 48 bytes, matching the real TLS 1.2
#: master-secret length so the window arithmetic below is the real arithmetic.
SECRET = bytes(range(0x40, 0x40 + 48))
SECRET_HEX = SECRET.hex()
CLIENT_RANDOM = "11" * 32
KEYLOG_LINE = f"CLIENT_RANDOM {CLIENT_RANDOM} {SECRET_HEX}"
SECRET_DICT = {
    "secret_type": "CLIENT_RANDOM",
    "client_random": CLIENT_RANDOM,
    "secret": SECRET_HEX,
}

#: Shared low-entropy background. Values 0..3 give ~2 bits/byte, deliberately
#: ABOVE the ``degenerate_anchors`` floor: the synthetic fixtures must not trip
#: that diagnostic, because the real-corpus test below is what proves it fires.
_BACKGROUND_ALPHABET = 4
_SIZE = 8192


def _background(seed: int) -> np.ndarray:
    rng = np.random.default_rng(seed)
    return rng.integers(0, _BACKGROUND_ALPHABET, _SIZE, dtype=np.uint8)


def _write(path: Path, body: np.ndarray) -> str:
    path.write_bytes(body.tobytes())
    return str(path)


@pytest.fixture
def planted_dumps(tmp_path):
    """Four 8 KB dumps; the secret sits at 2048 in dumps 0-1 ONLY.

    A miniature of the measured real corpus, where the master secret survives in
    2 of 8 lifecycle phases. The two dumps that do NOT hold it are not padding:
    they are what turns the key span into wildcards in ``export_key_pattern``.
    """
    background = _background(11)
    paths = []
    for i in range(4):
        body = background.copy()
        if i < 2:
            body[2048:2096] = np.frombuffer(SECRET, dtype=np.uint8)
        paths.append(_write(tmp_path / f"phase_{i}.dump", body))
    return paths


@pytest.fixture
def all_present_dumps(tmp_path):
    """Four dumps that ALL hold the secret at 2048 — the degenerate mask set.

    Every byte of every window is identical, so the mask is 100 % static and the
    exported rule embeds the secret verbatim. This is the input shape an analyst
    reaches for by instinct ("give it the dumps with the key in them") and the
    one ``key_fully_static`` exists to warn about.
    """
    background = _background(23)
    paths = []
    for i in range(4):
        body = background.copy()
        body[2048:2096] = np.frombuffer(SECRET, dtype=np.uint8)
        paths.append(_write(tmp_path / f"same_{i}.dump", body))
    return paths


@pytest.fixture
def drifting_dumps(tmp_path):
    """Four dumps holding the secret at 2048 / 2100 / 3000 / 4096, plus one wiped.

    Each key is surrounded by the SAME 64-byte anchors on both sides, so the
    per-dump windows are byte-identical even though no single offset is shared —
    which is exactly the case that makes ``region.offset`` meaningless and the
    absent dump un-maskable (it has no offset of its own to borrow).
    """
    background = _background(37)
    rng = np.random.default_rng(41)
    left = rng.integers(0, 256, 64, dtype=np.uint8)
    right = rng.integers(0, 256, 64, dtype=np.uint8)
    window = np.concatenate(
        [left, np.frombuffer(SECRET, dtype=np.uint8), right])
    paths = []
    for i, offset in enumerate((2048, 2100, 3000, 4096)):
        body = background.copy()
        body[offset - 64:offset - 64 + len(window)] = window
        paths.append(_write(tmp_path / f"drift_{i}.dump", body))
    # One dump the key was wiped from. Under drift it CANNOT join the mask set,
    # which is what makes ``mask_subset`` fire.
    paths.append(_write(tmp_path / "drift_wiped.dump", background.copy()))
    return paths


@pytest.fixture
def boundary_dumps(tmp_path):
    """The secret at offset 10 — too close to the start for the full context."""
    background = _background(53)
    paths = []
    for i in range(4):
        body = background.copy()
        if i < 2:
            body[10:58] = np.frombuffer(SECRET, dtype=np.uint8)
        paths.append(_write(tmp_path / f"edge_{i}.dump", body))
    return paths


@pytest.fixture
def absent_dumps(tmp_path):
    """Four dumps none of which contains the secret."""
    background = _background(67)
    return [
        _write(tmp_path / f"clean_{i}.dump", background.copy()) for i in range(4)
    ]


@pytest.fixture
def client(tmp_path, monkeypatch):
    """A TestClient over the real app, with the task substrate in tmp_path."""
    monkeypatch.setenv("MEMDIVER_ORACLE_DIR", str(tmp_path / "oracles"))
    monkeypatch.setenv("MEMDIVER_TASK_ROOT", str(tmp_path / "tasks"))
    monkeypatch.setenv("MEMDIVER_PIPELINE_MAX_WORKERS", "1")
    get_settings.cache_clear()
    with TestClient(create_app()) as c:
        yield c
    get_settings.cache_clear()


def _codes(payload) -> list:
    return [d["code"] for d in payload["diagnostics"]]


def _flattened_hex(text: str) -> str:
    """Every hex nibble in *text*, separators and case removed.

    The exporters render bytes differently — the YARA rule uses UPPERCASE
    space-separated pairs, the Volatility3 template a ``\\x``-escaped literal —
    so a naive substring check for a lowercase secret passes for the wrong
    reason. This is the check that actually answers "does the emitted rule
    contain the secret?".
    """
    import re

    return re.sub(r"[^0-9a-f]", "", text.lower())


# ---------------------------------------------------------------------------
# (a) four-surface parity
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "name,producer",
    [
        ("analysis.locate_key", "memdiver.app.tools_pipeline.locate_key"),
        ("export.key_pattern",
         "memdiver.app.tools_pipeline.export_key_pattern"),
    ],
)
def test_capability_is_wired_on_all_four_surfaces(name, producer):
    """Both capabilities claim every in-scope surface and are not documented
    gaps — the ratchet in ``test_architecture_invariants`` then holds that claim
    honest for every future change."""
    from memdiver.app.capabilities import (
        CAPABILITIES,
        IN_SCOPE_SURFACES,
        KNOWN_PARITY_GAPS,
    )

    cap = next(c for c in CAPABILITIES if c.name == name)
    assert cap.producer == producer
    assert IN_SCOPE_SURFACES - cap.surfaces == set()
    assert not any(gap_name == name for gap_name, _ in KNOWN_PARITY_GAPS)


def test_mcp_tools_return_results_inline(planted_dumps):
    """The MCP surface is why both payloads come back inline: an agent handed a
    server-side path has no way to read it."""
    import json

    pytest.importorskip("mcp")
    from memdiver.mcp_server.server import create_server

    tools = {t.name: t for t in create_server()._tool_manager.list_tools()}
    assert "locate_key" in tools
    assert "export_key_pattern" in tools

    located = json.loads(
        tools["locate_key"].fn(dump_paths=planted_dumps, key_hex=SECRET_HEX))
    assert located["verdict"] == "found"
    assert len(located["dumps"]) == 4
    assert not any(key.endswith("_path") for key in located)

    exported = json.loads(tools["export_key_pattern"].fn(
        dump_paths=planted_dumps, key_hex=SECRET_HEX))
    assert exported["pattern"]["length"] == 176
    assert not any(key.endswith("_path") for key in exported)
    # The MCP default diverges from the producer's on purpose.
    assert exported["format"] == "yara"


def test_cli_parsers_expose_both_commands():
    from memdiver.cli import build_parser

    parser = build_parser()
    args = parser.parse_args(["locate-key", "a.dump", "--key-hex", "aabb"])
    assert args.command == "locate-key"
    assert (args.key_hex, args.keylog_line) == ("aabb", None)

    args = parser.parse_args(
        ["export-key-pattern", "a.dump", "b.dump", "--keylog-line", KEYLOG_LINE])
    assert args.command == "export-key-pattern"
    # yara on the CLI, volatility3 in the producer — a documented divergence.
    assert args.format == "yara"
    assert args.context == 64
    assert args.include_window_hex is False


def test_cli_refuses_both_input_forms_at_the_parser():
    """``--key-hex`` and ``--keylog-line`` are mutually exclusive AND required,
    so the CLI never even reaches the producer's check."""
    from memdiver.cli import build_parser

    parser = build_parser()
    with pytest.raises(SystemExit):
        parser.parse_args(
            ["locate-key", "a.dump", "--key-hex", "aa", "--keylog-line", "x"])
    with pytest.raises(SystemExit):
        parser.parse_args(["locate-key", "a.dump"])


# ---------------------------------------------------------------------------
# (b) the verdict model — the whole point of the capability
# ---------------------------------------------------------------------------


def test_found_reports_the_partial_survival_it_measured(planted_dumps):
    payload = locate_key(dump_paths=planted_dumps, key_hex=SECRET_HEX)

    assert payload["verdict"] == "found"
    assert (payload["dumps_total"], payload["dumps_searched"]) == (4, 4)
    assert (payload["dumps_present"], payload["dumps_absent"]) == (2, 2)
    assert payload["unanimous"] is False
    assert payload["offsets_agree"] is True
    assert payload["common_offset"] == 2048
    assert payload["first_offset"] == 2048
    assert payload["needle_length"] == 48
    # The needle bytes are NEVER echoed — only their digest.
    assert SECRET_HEX not in str(payload)
    assert len(payload["needle_sha256"]) == 64
    # Rows come back in the SUPPLIED order, so they can be zipped.
    assert [d["dump_path"] for d in payload["dumps"]] == planted_dumps
    assert [d["present"] for d in payload["dumps"]] == [True, True, False, False]
    assert LOCATE_KEY_PARTIAL_CODE in _codes(payload)


def test_absent_is_a_finding_over_a_known_denominator(absent_dumps):
    payload = locate_key(dump_paths=absent_dumps, key_hex=SECRET_HEX)

    assert payload["verdict"] == "absent"
    assert payload["dumps_searched"] == 4
    assert payload["dumps_present"] == 0
    assert payload["unanimous"] is True
    assert payload["first_offset"] is None
    assert payload["common_offset"] is None
    assert LOCATE_KEY_ABSENT_CODE in _codes(payload)
    message = next(d["message"] for d in payload["diagnostics"]
                   if d["code"] == LOCATE_KEY_ABSENT_CODE)
    # The message must name the denominator, or "absent" reads as "we looked
    # everywhere" when it means "we looked at four files".
    assert "4" in message


def test_a_single_dump_is_a_complete_answer(planted_dumps):
    """Unlike every sibling producer, N == 1 is allowed: "is this key in this
    dump, and where" is a whole question about one dump."""
    payload = locate_key(dump_paths=planted_dumps[:1], key_hex=SECRET_HEX)
    assert payload["verdict"] == "found"
    assert payload["dumps_total"] == 1
    assert payload["unanimous"] is True


def test_empty_dump_paths_is_a_precondition():
    with pytest.raises(CapabilityError) as excinfo:
        locate_key(dump_paths=[], key_hex=SECRET_HEX)
    assert excinfo.value.category is ErrorCategory.PRECONDITION


def test_missing_dump_is_not_found(planted_dumps, tmp_path):
    with pytest.raises(CapabilityError) as excinfo:
        locate_key(
            dump_paths=planted_dumps + [str(tmp_path / "nope.dump")],
            key_hex=SECRET_HEX,
        )
    assert excinfo.value.category is ErrorCategory.NOT_FOUND


def test_one_unreadable_dump_claims_nothing_about_that_dump(
    planted_dumps, monkeypatch
):
    """An unreadable dump gets ``present: null`` and ``status: "unreadable"`` —
    never ``present: false``, which would be an absence claim over bytes that
    were never read."""
    from memdiver.engine import key_location as key_location_module

    real_open = key_location_module.open_dump
    doomed = planted_dumps[3]

    def _flaky(path, **kwargs):
        if str(path) == doomed:
            raise OSError("simulated read failure")
        return real_open(path, **kwargs)

    monkeypatch.setattr(key_location_module, "open_dump", _flaky)
    payload = locate_key(dump_paths=planted_dumps, key_hex=SECRET_HEX)

    assert payload["verdict"] == "found"
    assert (payload["dumps_total"], payload["dumps_searched"]) == (4, 3)
    assert payload["dumps_unreadable"] == 1
    row = payload["dumps"][3]
    assert row["status"] == "unreadable"
    assert row["present"] is None
    assert "simulated read failure" in row["detail"]
    # Fires EVEN on a `found` verdict: the denominator is short.
    assert LOCATE_KEY_NOT_SEARCHED_CODE in _codes(payload)


def test_all_unreadable_is_not_searched_and_never_absent(
    planted_dumps, monkeypatch
):
    """THE assertion this whole three-valued model exists for."""
    from memdiver.engine import key_location as key_location_module

    monkeypatch.setattr(
        key_location_module, "open_dump",
        lambda path, **kwargs: (_ for _ in ()).throw(OSError("all gone")))
    payload = locate_key(dump_paths=planted_dumps, key_hex=SECRET_HEX)

    assert payload["verdict"] == "not_searched"
    assert payload["verdict"] != "absent"
    assert payload["dumps_searched"] == 0
    assert payload["dumps_absent"] == 0
    assert payload["unanimous"] is False
    assert all(d["present"] is None for d in payload["dumps"])
    assert LOCATE_KEY_NOT_SEARCHED_CODE in _codes(payload)
    assert LOCATE_KEY_ABSENT_CODE not in _codes(payload)


def test_a_view_shorter_than_the_needle_claims_nothing(planted_dumps, tmp_path):
    """A truncated / half-decrypted view is ``too_small``, not ``absent``:
    absence IS logically provable there, but such a view is almost always
    broken, and a red cell drawn from it is the misattribution to avoid."""
    stub = tmp_path / "tiny.dump"
    stub.write_bytes(b"\x00\x01\x02\x03")
    payload = locate_key(
        dump_paths=[planted_dumps[0], str(stub)], key_hex=SECRET_HEX)

    assert payload["verdict"] == "found"
    assert payload["dumps_too_small"] == 1
    row = payload["dumps"][1]
    assert row["status"] == "too_small"
    assert row["present"] is None
    assert "48" in row["detail"]
    assert LOCATE_KEY_NOT_SEARCHED_CODE in _codes(payload)


def test_offset_drift_is_reported(drifting_dumps):
    payload = locate_key(dump_paths=drifting_dumps, key_hex=SECRET_HEX)

    assert payload["verdict"] == "found"
    assert payload["dumps_present"] == 4
    assert payload["offsets_agree"] is False
    assert payload["common_offset"] is None
    assert payload["first_offset"] == 2048
    assert LOCATE_KEY_OFFSET_DRIFT_CODE in _codes(payload)


def test_multiple_occurrences_are_real_copies(tmp_path):
    """A TLS library keeps copies of one secret in its key-schedule and
    record-layer structs, so >1 hit is signal, not a search artefact."""
    background = _background(71)
    paths = []
    for i in range(2):
        body = background.copy()
        body[1024:1072] = np.frombuffer(SECRET, dtype=np.uint8)
        body[4096:4144] = np.frombuffer(SECRET, dtype=np.uint8)
        paths.append(_write(tmp_path / f"copies_{i}.dump", body))

    payload = locate_key(dump_paths=paths, key_hex=SECRET_HEX)
    assert [d["hit_count"] for d in payload["dumps"]] == [2, 2]
    assert payload["dumps"][0]["offsets"] == [1024, 4096]
    assert payload["dumps"][0]["first_offset"] == 1024
    assert LOCATE_KEY_MULTI_HIT_CODE in _codes(payload)


def test_truncated_offsets_keep_the_true_hit_count(tmp_path):
    background = _background(73)
    paths = []
    for i in range(2):
        body = background.copy()
        for slot in range(4):
            start = 1024 + slot * 512
            body[start:start + 48] = np.frombuffer(SECRET, dtype=np.uint8)
        paths.append(_write(tmp_path / f"many_{i}.dump", body))

    payload = locate_key(dump_paths=paths, key_hex=SECRET_HEX, max_offsets=2)
    row = payload["dumps"][0]
    assert row["hit_count"] == 4
    assert len(row["offsets"]) == 2
    assert row["offsets_truncated"] is True
    codes = _codes(payload)
    assert "analysis.locate_key.offsets_truncated" in codes


# ---------------------------------------------------------------------------
# (c) the three input forms
# ---------------------------------------------------------------------------


def test_the_three_forms_produce_identical_census(planted_dumps):
    by_hex = locate_key(dump_paths=planted_dumps, key_hex=SECRET_HEX)
    by_line = locate_key(dump_paths=planted_dumps, keylog_line=KEYLOG_LINE)
    by_dict = locate_key(dump_paths=planted_dumps, secret=dict(SECRET_DICT))

    assert by_hex["dumps"] == by_line["dumps"] == by_dict["dumps"]
    assert by_hex["needle_sha256"] == by_line["needle_sha256"] == by_dict[
        "needle_sha256"]
    # What DOES differ is the provenance, which is the point of carrying it.
    assert (by_hex["input_form"], by_hex["secret_type"], by_hex["client_random"]) == (
        "key_hex", "", "")
    assert (by_line["input_form"], by_line["secret_type"]) == (
        "keylog_line", "CLIENT_RANDOM")
    assert by_line["client_random"] == CLIENT_RANDOM
    assert by_dict["input_form"] == "secret"
    assert by_dict["client_random"] == CLIENT_RANDOM


@pytest.mark.parametrize("spelling", [
    SECRET_HEX,
    "0x" + SECRET_HEX,
    " ".join(SECRET_HEX[i:i + 2] for i in range(0, len(SECRET_HEX), 2)),
    "0X" + SECRET_HEX.upper(),
])
def test_hex_normalisation_matches_the_byte_search_box(planted_dumps, spelling):
    """Copied verbatim from ``search_bytes_result`` so hex that works in the
    hex viewer's search box works here — an analyst pastes the same string."""
    payload = locate_key(dump_paths=planted_dumps, key_hex=spelling)
    assert payload["verdict"] == "found"
    assert payload["common_offset"] == 2048


def test_zero_input_forms_is_refused(planted_dumps):
    with pytest.raises(CapabilityError) as excinfo:
        locate_key(dump_paths=planted_dumps)
    assert excinfo.value.category is ErrorCategory.INVALID_INPUT
    assert "none" in excinfo.value.message


def test_two_input_forms_is_refused_naming_what_was_supplied(planted_dumps):
    """No precedence and no autodetect: two forms naming DIFFERENT bytes would
    otherwise yield a confident census of the wrong secret."""
    with pytest.raises(CapabilityError) as excinfo:
        locate_key(
            dump_paths=planted_dumps,
            key_hex=SECRET_HEX,
            keylog_line=KEYLOG_LINE,
        )
    assert excinfo.value.category is ErrorCategory.INVALID_INPUT
    assert "key_hex" in excinfo.value.message
    assert "keylog_line" in excinfo.value.message


def test_malformed_hex_is_rejected(planted_dumps):
    with pytest.raises(CapabilityError) as excinfo:
        locate_key(dump_paths=planted_dumps, key_hex="zzzz")
    assert excinfo.value.category is ErrorCategory.INVALID_INPUT
    assert "Invalid hex key" in excinfo.value.message


@pytest.mark.parametrize("line,fragment", [
    ("CLIENT_RANDOM " + CLIENT_RANDOM, "field(s), expected 3"),
    (f"NOT_A_LABEL {CLIENT_RANDOM} {SECRET_HEX}", "non-canonical label"),
    (f"CLIENT_RANDOM {CLIENT_RANDOM} zzzz", "malformed hex"),
])
def test_three_distinct_keylog_line_failures(planted_dumps, line, fragment):
    """One "could not parse that line" message would send the analyst hunting
    through three unrelated fixes; ``is_well_formed_keylog_line`` splits them."""
    with pytest.raises(CapabilityError) as excinfo:
        locate_key(dump_paths=planted_dumps, keylog_line=line)
    assert excinfo.value.category is ErrorCategory.INVALID_INPUT
    assert fragment in excinfo.value.message


@pytest.mark.parametrize("item,fragment", [
    ({"client_random": CLIENT_RANDOM, "secret": SECRET_HEX},
     "missing required key"),
    ({"secret_type": "NOPE", "client_random": CLIENT_RANDOM,
      "secret": SECRET_HEX}, "has non-canonical secret_type"),
    ({"secret_type": "CLIENT_RANDOM", "client_random": CLIENT_RANDOM,
      "secret": "zz"}, "has malformed hex"),
])
def test_secret_dict_shares_keylog_results_error_strings(
    planted_dumps, item, fragment
):
    """The validation block was EXTRACTED from ``keylog_result``, not copied, so
    the two producers cannot drift on what a canonical label is."""
    from memdiver.app.tools_pipeline import keylog_result

    with pytest.raises(CapabilityError) as via_locate:
        locate_key(dump_paths=planted_dumps, secret=item)
    with pytest.raises(CapabilityError) as via_keylog:
        keylog_result(secrets=[item])

    assert fragment in via_locate.value.message
    assert fragment in via_keylog.value.message
    # Identical apart from the item label ("secret" vs "secrets[0]").
    assert via_locate.value.message.split(fragment, 1)[1] == (
        via_keylog.value.message.split(fragment, 1)[1])


def test_an_empty_secret_is_refused(planted_dumps):
    with pytest.raises(CapabilityError) as excinfo:
        locate_key(
            dump_paths=planted_dumps,
            secret={"secret_type": "CLIENT_RANDOM",
                    "client_random": CLIENT_RANDOM, "secret": ""},
        )
    assert excinfo.value.category is ErrorCategory.INVALID_INPUT
    assert "Empty secret" in excinfo.value.message


# ---------------------------------------------------------------------------
# (d) the HTTP surface
# ---------------------------------------------------------------------------


def test_route_returns_the_census_inline(client, planted_dumps):
    resp = client.post("/api/analysis/locate-key", json={
        "dump_paths": planted_dumps,
        "secret_hex": SECRET_HEX,
    })
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["verdict"] == "found"
    assert (body["dumps_present"], body["dumps_absent"]) == (2, 2)
    assert len(body["dumps"]) == 4


def test_route_reports_a_legitimate_absence_as_200(client, absent_dumps):
    """A key that is provably not there is a FINDING, not an HTTP error."""
    resp = client.post("/api/analysis/locate-key", json={
        "dump_paths": absent_dumps, "secret_hex": SECRET_HEX,
    })
    assert resp.status_code == 200, resp.text
    assert resp.json()["verdict"] == "absent"


def test_route_maps_two_input_forms_to_400(client, planted_dumps):
    resp = client.post("/api/analysis/locate-key", json={
        "dump_paths": planted_dumps,
        "secret_hex": SECRET_HEX,
        "keylog_line": KEYLOG_LINE,
    })
    assert resp.status_code == 400, resp.text


def test_route_maps_a_missing_dump_to_404(client, planted_dumps, tmp_path):
    resp = client.post("/api/analysis/locate-key", json={
        "dump_paths": planted_dumps + [str(tmp_path / "gone.dump")],
        "secret_hex": SECRET_HEX,
    })
    assert resp.status_code == 404, resp.text


def test_key_pattern_route_returns_the_windows(client, planted_dumps):
    resp = client.post("/api/analysis/key-pattern", json={
        "dump_paths": planted_dumps, "secret_hex": SECRET_HEX,
    })
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["format"] == "yara"
    assert body["pattern"]["length"] == 176
    # include_window_hex defaults to TRUE on this route alone.
    assert all("hex" in w for w in body["windows"])
    assert len(body["windows"][0]["hex"]) == 176 * 2


def test_key_pattern_route_maps_an_absent_key_to_404(client, absent_dumps):
    resp = client.post("/api/analysis/key-pattern", json={
        "dump_paths": absent_dumps, "secret_hex": SECRET_HEX,
    })
    assert resp.status_code == 404, resp.text


@pytest.mark.parametrize("route_name", ["analysis_locate_key",
                                        "analysis_key_pattern"])
def test_routes_delegate_error_translation_to_the_global_handler(route_name):
    """No ``try/except`` in either route: the app's single ``CapabilityError``
    handler owns translation, which is what keeps the error contract identical
    to every other producer-backed route. And never ``key_file=`` — the web
    surface decodes key material itself and passes ``key_material=``."""
    from memdiver.api.routers import analysis

    source = inspect.getsource(getattr(analysis, route_name))
    assert "try:" not in source
    # (No "except" assertion: both docstrings legitimately mention the
    # no-try/except contract in prose.)
    # `key_file=` would make the app layer read a path off the server's disk on
    # behalf of an HTTP caller; the web surface decodes the material itself.
    assert "key_file=" not in source
    assert "decode_key_material(" in source
    assert "key_material=km" in source


# ---------------------------------------------------------------------------
# (e) B3 — the export, and why the mask uses ALL the dumps
# ---------------------------------------------------------------------------


def test_export_wildcards_exactly_the_key_span(planted_dumps):
    payload = export_key_pattern(dump_paths=planted_dumps, key_hex=SECRET_HEX)

    assert payload["pattern"]["length"] == 176
    region = payload["region"]
    assert region["key_offset_in_pattern"] == 64
    assert (region["context_requested"], region["context_before"],
            region["context_after"]) == (64, 64, 64)
    assert (region["offset"], region["length"]) == (1984, 176)
    assert (region["key_start"], region["key_end"]) == (2048, 2096)

    tokens = payload["pattern"]["wildcard_pattern"].split()
    assert tokens[64:112] == ["??"] * 48
    assert [i for i, t in enumerate(tokens) if t == "??"] == list(
        range(64, 112))
    assert (payload["key_static_count"], payload["key_wildcard_count"]) == (0, 48)
    assert payload["offsets_agree"] is True
    assert KEY_PATTERN_STATIC_KEY_CODE not in _codes(payload)


def test_the_mask_is_measured_over_every_searched_dump(planted_dumps):
    """The two dumps that do NOT hold the key are IN the mask set — they are the
    wildcard mechanism, not padding."""
    payload = export_key_pattern(dump_paths=planted_dumps, key_hex=SECRET_HEX)

    assert payload["mask_regions"] == 4
    assert payload["mask_dumps_present"] == 2
    assert payload["mask_dumps_absent"] == 2
    assert payload["excluded_dumps"] == []
    assert [w["present"] for w in payload["windows"]] == [
        True, True, False, False]
    # The reference is a dump that HOLDS the key, or hex_pattern would not
    # contain it at all.
    assert payload["windows"][0]["reference"] is True
    assert sum(1 for w in payload["windows"] if w["reference"]) == 1
    assert SECRET_HEX in payload["pattern"]["hex_pattern"].replace(" ", "")
    assert KEY_PATTERN_SUBSET_CODE not in _codes(payload)


def test_masking_only_the_dumps_that_hold_the_key_embeds_the_secret(
    all_present_dumps
):
    """THE counter-arm. Give it only dumps where the key is present and the rule
    is 100 % static: it contains the secret verbatim and matches nothing else.
    ``min_static_ratio`` cannot catch this — it is a LOWER bound — and all three
    exporters render only ``wildcard_pattern``, so there is no ``??`` anywhere."""
    payload = export_key_pattern(
        dump_paths=all_present_dumps, key_hex=SECRET_HEX, fmt="yara")

    assert payload["pattern"]["static_ratio"] == 1.0
    assert payload["key_wildcard_count"] == 0
    assert payload["key_static_count"] == 48
    assert "??" not in payload["pattern"]["wildcard_pattern"]
    assert "??" not in payload["content"]
    assert SECRET_HEX in _flattened_hex(payload["content"])
    assert KEY_PATTERN_STATIC_KEY_CODE in _codes(payload)
    warning = next(d for d in payload["diagnostics"]
                   if d["code"] == KEY_PATTERN_STATIC_KEY_CODE)
    assert warning["severity"] == "warning"
    # The message must tell the analyst the FIX, not just the fact.
    assert "ABSENT" in warning["message"]


def test_drift_excludes_the_absent_dumps_and_says_so(drifting_dumps):
    """Under drift an absent dump has no offset of its own to borrow, so it
    cannot join the mask. The export still succeeds — the analyst gets a rule
    plus the two diagnostics that qualify it."""
    payload = export_key_pattern(dump_paths=drifting_dumps, key_hex=SECRET_HEX)

    assert payload["offsets_agree"] is False
    assert payload["mask_regions"] == 4
    assert payload["mask_dumps_present"] == 4
    assert payload["mask_dumps_absent"] == 0
    assert len(payload["excluded_dumps"]) == 1
    assert payload["location"]["dumps_total"] == 5
    codes = _codes(payload)
    assert KEY_PATTERN_SUBSET_CODE in codes
    assert LOCATE_KEY_OFFSET_DRIFT_CODE in codes
    # Every window is anchored on its OWN occurrence, so the key sits at the
    # same index in all of them even though no offset is shared.
    assert {w["key_start"] for w in payload["windows"]} == {
        2048, 2100, 3000, 4096}
    assert {w["window_start"] for w in payload["windows"]} == {
        1984, 2036, 2936, 4032}


def test_padding_is_common_to_every_dump_in_the_mask_set(boundary_dumps):
    """A dump 10 bytes from the start cannot give 64 bytes of left context, and
    per-dump clamping would put the key at a DIFFERENT index in its window,
    destroying the positional comparison. The padding is common instead."""
    payload = export_key_pattern(dump_paths=boundary_dumps, key_hex=SECRET_HEX)

    region = payload["region"]
    assert region["context_requested"] == 64
    assert region["context_before"] == 10
    assert region["context_after"] == 64
    assert region["key_offset_in_pattern"] == 10
    assert payload["pattern"]["length"] == 10 + 48 + 64
    assert all(w["window_start"] == 0 for w in payload["windows"])
    tokens = payload["pattern"]["wildcard_pattern"].split()
    assert tokens[10:58] == ["??"] * 48


def test_zero_context_leaves_no_anchor_at_all(all_present_dumps):
    payload = export_key_pattern(
        dump_paths=all_present_dumps, key_hex=SECRET_HEX, context=0)

    region = payload["region"]
    assert (region["context_before"], region["context_after"]) == (0, 0)
    assert payload["pattern"]["length"] == 48
    codes = _codes(payload)
    assert KEY_PATTERN_NO_ANCHORS_CODE in codes
    assert KEY_PATTERN_STATIC_KEY_CODE in codes


def test_negative_context_is_invalid_input(planted_dumps):
    with pytest.raises(CapabilityError) as excinfo:
        export_key_pattern(
            dump_paths=planted_dumps, key_hex=SECRET_HEX, context=-1)
    assert excinfo.value.category is ErrorCategory.INVALID_INPUT


def test_unknown_format_is_unsupported(planted_dumps):
    with pytest.raises(CapabilityError) as excinfo:
        export_key_pattern(
            dump_paths=planted_dumps, key_hex=SECRET_HEX, fmt="snort")
    assert excinfo.value.category is ErrorCategory.UNSUPPORTED


def test_absent_key_is_key_not_found_never_insufficient_static(absent_dumps):
    """``InsufficientStaticError`` would blame the DATA for a missing key."""
    with pytest.raises(KeyNotFoundError) as excinfo:
        export_key_pattern(dump_paths=absent_dumps, key_hex=SECRET_HEX)
    assert not isinstance(excinfo.value, InsufficientStaticError)
    assert excinfo.value.status == 404
    assert excinfo.value.category is ErrorCategory.NOT_FOUND
    assert excinfo.value.verdict == "absent"


def test_nothing_searched_is_a_precondition_not_a_missing_key(
    planted_dumps, monkeypatch
):
    """Nothing was read, so a static-ratio (or key-absent) complaint would blame
    the data for what is an access problem."""
    from memdiver.engine import key_location as key_location_module

    monkeypatch.setattr(
        key_location_module, "open_dump",
        lambda path, **kwargs: (_ for _ in ()).throw(OSError("no access")))
    with pytest.raises(CapabilityError) as excinfo:
        export_key_pattern(dump_paths=planted_dumps, key_hex=SECRET_HEX)
    assert excinfo.value.category is ErrorCategory.PRECONDITION
    assert not isinstance(excinfo.value, KeyNotFoundError)
    assert excinfo.value.details["verdict"] == "not_searched"


def test_fewer_than_two_dumps_is_refused_before_any_pattern(planted_dumps):
    with pytest.raises(CapabilityError) as excinfo:
        export_key_pattern(dump_paths=planted_dumps[:1], key_hex=SECRET_HEX)
    assert excinfo.value.category is ErrorCategory.PRECONDITION
    assert "2 dumps" in excinfo.value.message


def test_one_searched_dump_never_yields_a_perfect_pattern(
    planted_dumps, monkeypatch
):
    """``StaticChecker.check_regions([one])`` never enters its comparison loop
    and returns all-True — a silent ``static_ratio == 1.0``. Two paths in, one
    readable, must still refuse rather than emit that."""
    from memdiver.engine import key_location as key_location_module

    real_open = key_location_module.open_dump
    readable = planted_dumps[0]

    def _only_one(path, **kwargs):
        if str(path) != readable:
            raise OSError("simulated")
        return real_open(path, **kwargs)

    monkeypatch.setattr(key_location_module, "open_dump", _only_one)
    with pytest.raises(CapabilityError) as excinfo:
        export_key_pattern(
            dump_paths=planted_dumps[:2], key_hex=SECRET_HEX)
    assert excinfo.value.category is ErrorCategory.PRECONDITION
    # No pattern was produced at all, so no static_ratio could have leaked.
    assert not hasattr(excinfo.value, "pattern")


def test_include_window_hex_is_off_by_default_in_the_producer(planted_dumps):
    payload = export_key_pattern(dump_paths=planted_dumps, key_hex=SECRET_HEX)
    assert all("hex" not in w for w in payload["windows"])

    with_hex = export_key_pattern(
        dump_paths=planted_dumps, key_hex=SECRET_HEX, include_window_hex=True)
    assert all(len(w["hex"]) == 176 * 2 for w in with_hex["windows"])


def test_the_nested_location_block_is_the_locate_key_payload(planted_dumps):
    """Same shape, so a surface that renders the census does not need a second
    code path for the export response."""
    located = locate_key(dump_paths=planted_dumps, key_hex=SECRET_HEX)
    exported = export_key_pattern(dump_paths=planted_dumps, key_hex=SECRET_HEX)

    nested = exported["location"]
    assert set(nested) == set(located)
    assert nested["dumps"] == located["dumps"]
    assert nested["verdict"] == located["verdict"]
    # The top-level diagnostics carry the location ones plus the export ones.
    assert _codes(exported)[:len(nested["diagnostics"])] == [
        d["code"] for d in nested["diagnostics"]]


def test_output_dir_writes_the_rendered_pattern(planted_dumps, tmp_path):
    out = tmp_path / "rules"
    payload = export_key_pattern(
        dump_paths=planted_dumps, key_hex=SECRET_HEX,
        fmt="yara", name="my_rule", output_dir=str(out))
    written = out / "my_rule.yar"
    assert written.is_file()
    assert written.read_text() == payload["content"]
    assert payload["pattern_path"] == str(written)


def test_anchor_distinctiveness_measures_what_it_says():
    from memdiver.architect.pattern_generator import PatternGenerator

    zeros = PatternGenerator.anchor_distinctiveness(
        bytes(176), [True] * 64 + [False] * 48 + [True] * 64)
    assert zeros["distinct_bytes"] == 1
    assert zeros["shannon_bits"] == 0.0
    assert zeros["static_bytes"] == 128
    # Never spans two separate anchors, which are not adjacent in the match.
    assert zeros["longest_constant_run"] == 64

    varied = PatternGenerator.anchor_distinctiveness(
        bytes(range(16)), [True] * 16)
    assert varied["distinct_bytes"] == 16
    assert varied["shannon_bits"] == 4.0

    none = PatternGenerator.anchor_distinctiveness(bytes(8), [False] * 8)
    assert none == {"distinct_bytes": 0, "shannon_bits": 0.0,
                    "longest_constant_run": 0, "static_bytes": 0}


def test_degenerate_anchors_fires_on_a_zero_padded_key(tmp_path):
    """A window whose anchors are all zeros passes any static ratio and then
    matches almost anywhere. Nothing else in the pipeline notices."""
    paths = []
    for i in range(4):
        body = bytearray(_SIZE)
        if i < 2:
            body[2048:2096] = SECRET
        else:
            body[2048:2096] = bytes(range(0x80, 0x80 + 48))
        paths.append(_write(
            tmp_path / f"zeros_{i}.dump",
            np.frombuffer(bytes(body), dtype=np.uint8)))

    payload = export_key_pattern(dump_paths=paths, key_hex=SECRET_HEX)
    assert KEY_PATTERN_DEGENERATE_ANCHORS_CODE in _codes(payload)
    warning = next(d for d in payload["diagnostics"]
                   if d["code"] == KEY_PATTERN_DEGENERATE_ANCHORS_CODE)
    assert warning["severity"] == "warning"
    assert warning["details"]["distinct_bytes"] == 1
    # WARN, never refuse: the pattern is still returned.
    assert payload["pattern"]["length"] == 176


def test_degenerate_anchors_stays_quiet_on_varied_anchors(planted_dumps):
    payload = export_key_pattern(dump_paths=planted_dumps, key_hex=SECRET_HEX)
    assert KEY_PATTERN_DEGENERATE_ANCHORS_CODE not in _codes(payload)


# ---------------------------------------------------------------------------
# (f) the real corpus
# ---------------------------------------------------------------------------

_TLS12_RUN = "TLS12/100_iterations_Abort/openssl/openssl_run_12_1"
_TLS12_DUMP_SIZE = 11_223_040
#: The measured offset of the run's real 48-byte TLS 1.2 master secret.
_TLS12_KEY_OFFSET = 370_672


def _tls12_run_dir():
    from tests.fixtures.tls_ground_truth import tls_dumps_dir

    return Path(tls_dumps_dir()) / _TLS12_RUN


def _tls12_keylog_line(run_dir: Path) -> str:
    import csv

    with open(run_dir / "keylog.csv", newline="") as handle:
        return next(
            row["line"].strip()
            for row in csv.DictReader(handle)
            if row["line"].split()[:1] == ["CLIENT_RANDOM"]
        )


@pytest.mark.requires_dataset
def test_real_tls12_key_is_located_in_two_of_eight_dumps():
    """Eight phases of a real OpenSSL TLS 1.2 run, the run's OWN key log, and the
    honest verdict: present in 2, provably absent from 6.

    ``requires_dataset`` but deliberately NOT ``slow``: ``slow`` is deselected by
    the default addopts, so marking it would evict the one assertion that proves
    this chain works on real memory from ``make test``.
    """
    run_dir = _tls12_run_dir()
    dumps = sorted(run_dir.glob("*.dump"))
    if len(dumps) != 8:
        pytest.skip(f"TLS 1.2 reference run not present under {run_dir}")

    payload = locate_key(
        dump_paths=[str(p) for p in dumps],
        keylog_line=_tls12_keylog_line(run_dir),
    )

    assert payload["verdict"] == "found"
    assert payload["input_form"] == "keylog_line"
    assert payload["secret_type"] == "CLIENT_RANDOM"
    assert payload["needle_length"] == 48
    assert (payload["dumps_total"], payload["dumps_searched"]) == (8, 8)
    assert (payload["dumps_present"], payload["dumps_absent"]) == (2, 6)
    assert payload["dumps_unreadable"] == 0
    assert payload["unanimous"] is False
    assert payload["offsets_agree"] is True
    assert payload["common_offset"] == _TLS12_KEY_OFFSET

    present = [d for d in payload["dumps"] if d["present"] is True]
    assert len(present) == 2
    for row in present:
        assert row["name"].endswith("_abort.dump")
        assert row["hit_count"] == 1
        assert row["first_offset"] == _TLS12_KEY_OFFSET
        assert row["size_for_view"] == _TLS12_DUMP_SIZE

    absent = [d for d in payload["dumps"] if d["present"] is False]
    assert len(absent) == 6
    assert all(d["status"] == "searched" for d in absent)
    assert all(d["hit_count"] == 0 for d in absent)

    assert LOCATE_KEY_PARTIAL_CODE in _codes(payload)
    assert LOCATE_KEY_NOT_SEARCHED_CODE not in _codes(payload)


@pytest.mark.requires_dataset
def test_real_tls12_export_wildcards_the_key_using_all_eight_dumps():
    """The measured payoff: over all 8 dumps the rule wildcards exactly the 48
    key bytes (128/176 static) and does NOT contain the secret. Over only the 2
    dumps that hold it, the rule IS the secret."""
    run_dir = _tls12_run_dir()
    dumps = sorted(run_dir.glob("*.dump"))
    if len(dumps) != 8:
        pytest.skip(f"TLS 1.2 reference run not present under {run_dir}")
    line = _tls12_keylog_line(run_dir)
    secret_hex = line.split()[2]

    payload = export_key_pattern(
        dump_paths=[str(p) for p in dumps], keylog_line=line,
        context=64, fmt="yara")

    assert payload["mask_regions"] == 8
    assert (payload["mask_dumps_present"], payload["mask_dumps_absent"]) == (2, 6)
    assert payload["region"]["key_offset_in_pattern"] == 64
    assert (payload["region"]["offset"], payload["region"]["key_start"]) == (
        370_608, _TLS12_KEY_OFFSET)
    assert payload["pattern"]["length"] == 176
    assert (payload["pattern"]["static_count"],
            payload["pattern"]["volatile_count"]) == (128, 48)
    assert payload["pattern"]["static_ratio"] == 0.7273
    assert payload["key_wildcard_count"] == 48

    tokens = payload["pattern"]["wildcard_pattern"].split()
    assert tokens[64:112] == ["??"] * 48
    assert [i for i, t in enumerate(tokens) if t == "??"] == list(range(64, 112))
    # Every exporter renders wildcard_pattern only, so the secret never ships.
    assert secret_hex not in _flattened_hex(payload["content"])
    assert KEY_PATTERN_STATIC_KEY_CODE not in _codes(payload)

    # THE COUNTER-ARM: the 2 dumps that hold the key, alone.
    abort_dumps = [str(p) for p in dumps if p.name.endswith("_abort.dump")]
    assert len(abort_dumps) == 2
    counter = export_key_pattern(
        dump_paths=abort_dumps, keylog_line=line, context=64, fmt="yara")

    assert counter["pattern"]["static_ratio"] == 1.0
    assert counter["key_wildcard_count"] == 0
    assert "??" not in counter["content"]
    assert secret_hex in _flattened_hex(counter["content"])
    assert KEY_PATTERN_STATIC_KEY_CODE in _codes(counter)


@pytest.mark.requires_dataset
def test_real_tls12_key_sits_in_a_zero_run_so_the_anchors_are_degenerate():
    """The measured entropy of this key's surroundings: 1 distinct anchor byte at
    context=64, 17 (0.65 bits) at 128, and only at context=256 do the anchors
    carry more than 1 bit/byte and the diagnostic fall silent."""
    run_dir = _tls12_run_dir()
    dumps = sorted(run_dir.glob("*.dump"))
    if len(dumps) != 8:
        pytest.skip(f"TLS 1.2 reference run not present under {run_dir}")
    line = _tls12_keylog_line(run_dir)
    paths = [str(p) for p in dumps]

    near = export_key_pattern(
        dump_paths=paths, keylog_line=line, context=64, fmt="yara")
    assert KEY_PATTERN_DEGENERATE_ANCHORS_CODE in _codes(near)
    detail = next(d["details"] for d in near["diagnostics"]
                  if d["code"] == KEY_PATTERN_DEGENERATE_ANCHORS_CODE)
    assert detail["distinct_bytes"] == 1
    assert detail["shannon_bits"] == 0.0
    assert detail["static_bytes"] == 128

    wide = export_key_pattern(
        dump_paths=paths, keylog_line=line, context=256, fmt="yara")
    assert KEY_PATTERN_DEGENERATE_ANCHORS_CODE not in _codes(wide)

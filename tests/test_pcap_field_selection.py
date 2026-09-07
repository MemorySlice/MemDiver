"""C2 — protocol fields on the surfaces, and ``locate_key``'s symbolic form.

C1 built the extractor (``engine/resources/protocol_fields.py``); C2 makes it
*reachable* and makes "use this capture's ``client_random``" something a caller
can SAY rather than transcribe. Two producer changes, no new producer:

* ``inspect_pcap(include_fields=True)`` publishes the byte-addressed view;
* ``locate_key(pcap_field={...})`` resolves a field id into the needle.

What these tests pin, in order:

1. **The default is byte-identical.** ``include_fields`` unset must return
   exactly today's payload — the flag exists because switching it on costs a
   second read of the capture, so every existing caller (the arm step, the run's
   cap echo, the corpus sweep) has to be untouched. This is asserted as an
   equality on the whole dict, not as a key-set check, because a changed VALUE
   would be just as much a regression.
2. **The flag's shape**: ``fields`` + ``field_notes`` per session, a top-level
   ``field_index``, and the TLS 1.3 certificate note — the one absence that
   would otherwise read as a parse failure.
3. **The symbolic input form end to end**: a field id resolved off the wire
   finds the same bytes in the same dumps as the pasted hex would, and reports
   WHICH field of WHICH session it used.
4. **Every refusal.** A non-searchable field, an unknown id, an ambiguous
   capture, a missing key, an unknown key, and the exactly-one-of guard —
   including the half that matters for ``export_key_pattern``, which shares the
   resolver but must NOT accept ``pcap_field``.
5. **Cross-surface parity**, so a producer that grew two parameters cannot leave
   MCP / CLI / web behind.

The committed TLS 1.3 fixture is sufficient throughout: no corpus, and the
session-selection rules that need several sessions are proved against the pure
helper, which is why the selection rule lives in one.
"""

from __future__ import annotations

import json
from pathlib import Path

import numpy as np
import pytest

from memdiver.app.tools_pipeline import (
    LOCATE_KEY_INPUT_FORMS,
    PCAP_FIELD_KEYS,
    _resolve_key_needle,
    _select_pcap_field,
    _select_pcap_field_session,
    inspect_pcap,
    locate_key,
)
from memdiver.core.service_errors import CapabilityError, ErrorCategory

_FIXTURE_DIR = Path(__file__).resolve().parent / "e2e" / "fixtures" / "pcap"
_FIXTURE_PCAP = _FIXTURE_DIR / "session_tls13.pcap"
_FIXTURE_MANIFEST = _FIXTURE_DIR / "manifest.json"

#: Low-entropy background for the planted dumps, matching
#: ``test_api_locate_key``'s fixtures so the two read the same way.
_BACKGROUND_ALPHABET = 4
_SIZE = 8192
_PLANT_OFFSET = 2048


@pytest.fixture
def fixture_pcap() -> str:
    """The committed one-session TLS 1.3 capture, or a clean skip."""
    pytest.importorskip("dpkt")
    if not _FIXTURE_PCAP.is_file():  # pragma: no cover - committed fixture
        pytest.skip(f"fixture capture missing: {_FIXTURE_PCAP}")
    return str(_FIXTURE_PCAP)


@pytest.fixture
def fixture_client_random() -> bytes:
    """The capture's ``client_random``, read from its own manifest.

    Cross-checked rather than re-derived: the manifest is what
    ``tests/e2e/fixtures/pcap/generate.py`` recorded when it cut the fixture out
    of a real openssl run, so a mismatch means the extractor and the capture
    disagree — the failure this whole form would otherwise hide.
    """
    return bytes.fromhex(json.loads(_FIXTURE_MANIFEST.read_text())["client_random"])


@pytest.fixture
def planted_dumps(tmp_path, fixture_client_random):
    """Three 8 KB dumps; the capture's ``client_random`` sits at 2048 in two.

    Partial survival, like the real corpus: the third dump is what makes
    ``dumps_absent`` a real finding rather than a rounding error.
    """
    rng = np.random.default_rng(2026)
    background = rng.integers(0, _BACKGROUND_ALPHABET, _SIZE, dtype=np.uint8)
    needle = np.frombuffer(fixture_client_random, dtype=np.uint8)
    paths = []
    for index in range(3):
        body = background.copy()
        if index < 2:
            body[_PLANT_OFFSET:_PLANT_OFFSET + len(needle)] = needle
        path = tmp_path / f"phase_{index}.dump"
        path.write_bytes(body.tobytes())
        paths.append(str(path))
    return paths


# ---------------------------------------------------------------------------
# (1) the default is byte-identical — the whole reason the flag exists
# ---------------------------------------------------------------------------


def test_include_fields_off_is_byte_identical_to_today(fixture_pcap):
    """``include_fields`` unset returns EXACTLY the pre-C2 payload.

    Asserted as one equality over the whole dict — not a key-set comparison —
    because a changed value would regress the arm step just as badly as a
    changed shape. Two calls of the default are also compared to each other so
    the assertion cannot pass by accident on a producer that became
    non-deterministic.
    """
    baseline = inspect_pcap(pcap_path=fixture_pcap)
    again = inspect_pcap(pcap_path=fixture_pcap)
    assert baseline == again

    assert "field_index" not in baseline
    for session in baseline["sessions"]:
        assert "fields" not in session
        assert "field_notes" not in session

    # And the field-bearing response is a strict SUPERSET: every pre-existing
    # key keeps its value, so a caller upgrading to the flag re-reads nothing.
    enriched = inspect_pcap(pcap_path=fixture_pcap, include_fields=True)
    for key, value in baseline.items():
        if key == "sessions":
            continue  # compared per session below
        assert enriched[key] == value, f"{key} changed under include_fields"
    for before, after in zip(baseline["sessions"], enriched["sessions"]):
        assert {k: after[k] for k in before} == before


def test_default_response_has_the_same_keys_as_the_route_contract(fixture_pcap):
    """The frozen key set the web router and the frontend read.

    Spelled out literally so a key added WITHOUT the flag fails here rather
    than in a browser.
    """
    assert set(inspect_pcap(pcap_path=fixture_pcap)) == {
        "pcap_path",
        "session_count",
        "sessions",
        "skipped_sessions",
        "flow_count",
        "caps",
        "records_truncated",
        "challenges_available",
        "challenges_returned",
        "challenges_truncated",
    }


# ---------------------------------------------------------------------------
# (2) what the flag adds
# ---------------------------------------------------------------------------


def test_include_fields_publishes_fields_notes_and_an_index(fixture_pcap):
    result = inspect_pcap(pcap_path=fixture_pcap, include_fields=True)

    session = result["sessions"][0]
    assert session["fields"], "a parsed TLS 1.3 handshake yields fields"
    index = result["field_index"]

    # Every field id in the session is catalogued, and the catalogue points back
    # at the session that carries it.
    for field in session["fields"]:
        entry = index[field["field_id"]]
        assert 0 in entry["sessions"]
        assert entry["label"] == field["label"]
        assert entry["type"] == field["type"]
    assert set(index) == {f["field_id"] for f in session["fields"]}

    # The load-bearing note: RFC 8446 encrypts the Certificate message, so its
    # absence is by design and must be SAID rather than left as a silent gap.
    assert "tls13_certificates_encrypted" in {
        note["code"] for note in session["field_notes"]
    }


def test_the_index_is_a_catalogue_not_a_value_map(fixture_pcap):
    """No entry carries bytes: two sessions' ``client_random`` differ, so an
    id-keyed map of values could only ever be wrong for one of them."""
    index = inspect_pcap(pcap_path=fixture_pcap, include_fields=True)["field_index"]
    for entry in index.values():
        assert set(entry) == {"label", "type", "source", "searchable", "sessions"}


def test_extension_ids_are_hello_prefixed(fixture_pcap):
    """``client_ext.``/``server_ext.``, never a bare ``ext.``.

    Extension 0x000b appears in BOTH hellos of a real handshake, so an
    unprefixed id would collide — and since the index is id-keyed, a collision
    would silently resolve to whichever hello came last.
    """
    index = inspect_pcap(pcap_path=fixture_pcap, include_fields=True)["field_index"]
    extension_ids = [i for i in index if ".0x" in i]
    assert extension_ids, "the fixture's hellos carry extensions"
    assert all(i.startswith(("client_ext.", "server_ext.")) for i in extension_ids)


def test_searchable_is_derived_and_gates_the_short_fields(fixture_pcap):
    """``searchable`` is a property of dump search, not of TLS.

    The 32-byte randoms are needles; a 2-byte negotiation payload is not, and
    the flag says so without any per-extension allowlist.
    """
    fields = {
        f["field_id"]: f
        for f in inspect_pcap(
            pcap_path=fixture_pcap, include_fields=True
        )["sessions"][0]["fields"]
    }
    assert fields["client_random"]["searchable"] is True
    assert fields["client_random"]["length"] == 32
    # ``cipher_suites`` is a uint[]: no library stores the offered list in wire
    # form, so it is unsearchable regardless of length.
    assert fields["cipher_suites"]["searchable"] is False
    short = [f for f in fields.values() if f["type"] == "bytes" and f["length"] < 8]
    assert short, "the fixture has at least one short extension payload"
    assert not any(f["searchable"] for f in short)


# ---------------------------------------------------------------------------
# (3) the symbolic input form, end to end
# ---------------------------------------------------------------------------


def test_pcap_field_finds_the_same_bytes_as_the_pasted_hex(
    planted_dumps, fixture_pcap, fixture_client_random,
):
    """The point of the form: no transcription step, identical answer.

    Naming ``client_random`` must produce the census a caller would have got by
    copying 64 hex characters out of the capture — same verdict, same offsets,
    same needle digest — differing ONLY in the provenance it reports.
    """
    symbolic = locate_key(
        dump_paths=planted_dumps,
        pcap_field={"pcap_path": fixture_pcap, "field_id": "client_random"},
    )
    pasted = locate_key(
        dump_paths=planted_dumps, key_hex=fixture_client_random.hex(),
    )

    assert symbolic["verdict"] == "found"
    assert symbolic["needle_sha256"] == pasted["needle_sha256"]
    assert symbolic["dumps"] == pasted["dumps"]
    assert symbolic["common_offset"] == _PLANT_OFFSET
    assert (symbolic["dumps_present"], symbolic["dumps_absent"]) == (2, 1)

    # The provenance, which the pasted form cannot report at all.
    assert symbolic["input_form"] == "pcap_field"
    assert symbolic["secret_type"] == "client_random"  # the field id
    assert symbolic["client_random"] == fixture_client_random.hex()
    assert pasted["input_form"] == "key_hex"
    assert (pasted["secret_type"], pasted["client_random"]) == ("", "")


def test_pcap_field_accepts_an_explicit_session_selector(
    planted_dumps, fixture_pcap, fixture_client_random,
):
    """Naming the session the capture does hold is honoured, not merely
    tolerated — this is the spelling a multi-session capture requires."""
    payload = locate_key(
        dump_paths=planted_dumps,
        pcap_field={
            "pcap_path": fixture_pcap,
            "field_id": "client_random",
            "client_random": fixture_client_random.hex().upper(),  # case-insensitive
        },
    )
    assert payload["verdict"] == "found"
    assert payload["client_random"] == fixture_client_random.hex()


def test_a_key_share_is_a_needle_too(planted_dumps, fixture_pcap):
    """Not just the randoms: any searchable field id resolves.

    ``client_ext.0x0033`` is the TLS 1.3 key_share — a long, high-entropy blob
    the process must have held — and it comes out searchable by the derived rule
    rather than by being on a list.
    """
    payload = locate_key(
        dump_paths=planted_dumps,
        pcap_field={"pcap_path": fixture_pcap, "field_id": "client_ext.0x0033"},
    )
    # Absent from these synthetic dumps (only the client_random was planted),
    # which is a FINDING over a known denominator, not a failure of the form.
    assert payload["verdict"] == "absent"
    assert payload["secret_type"] == "client_ext.0x0033"
    assert payload["dumps_searched"] == 3


# ---------------------------------------------------------------------------
# (4) every refusal
# ---------------------------------------------------------------------------


def test_a_non_searchable_field_is_refused_as_a_needle(planted_dumps, fixture_pcap):
    """The rule C1 derives must be ENFORCED, not merely reported.

    A short or wire-artifact field matches everywhere, so accepting it would
    return "present in every dump" — the most confident wrong answer available.
    """
    with pytest.raises(CapabilityError) as excinfo:
        locate_key(
            dump_paths=planted_dumps,
            pcap_field={"pcap_path": fixture_pcap, "field_id": "cipher_suites"},
        )
    assert excinfo.value.category is ErrorCategory.INVALID_INPUT
    assert "not searchable" in excinfo.value.message
    # The message must offer a way forward, not just a refusal.
    assert "client_random" in excinfo.value.message


def test_an_unknown_field_id_lists_the_searchable_ones(planted_dumps, fixture_pcap):
    with pytest.raises(CapabilityError) as excinfo:
        locate_key(
            dump_paths=planted_dumps,
            pcap_field={"pcap_path": fixture_pcap, "field_id": "no_such_field"},
        )
    assert excinfo.value.category is ErrorCategory.INVALID_INPUT
    assert "no_such_field" in excinfo.value.message
    assert "client_random" in excinfo.value.message


@pytest.mark.parametrize(
    "pcap_field, fragment",
    [
        ({"field_id": "client_random"}, "pcap_path"),
        ({"pcap_path": "x.pcap"}, "field_id"),
        ({"pcap_path": "x.pcap", "field_id": "  "}, "field_id"),
        ({"pcap_path": "x.pcap", "field_id": "client_random", "typo": "1"}, "typo"),
    ],
)
def test_malformed_pcap_field_mappings_are_refused(
    planted_dumps, pcap_field, fragment,
):
    """A missing or unknown key is named, and refused BEFORE the capture is
    read — so a typo cannot be reported as a parse failure."""
    with pytest.raises(CapabilityError) as excinfo:
        locate_key(dump_paths=planted_dumps, pcap_field=pcap_field)
    assert excinfo.value.category is ErrorCategory.INVALID_INPUT
    assert fragment in excinfo.value.message


def test_an_unknown_client_random_names_what_the_capture_holds(
    planted_dumps, fixture_pcap,
):
    with pytest.raises(CapabilityError) as excinfo:
        locate_key(
            dump_paths=planted_dumps,
            pcap_field={
                "pcap_path": fixture_pcap,
                "field_id": "client_random",
                "client_random": "ff" * 32,
            },
        )
    assert excinfo.value.category is ErrorCategory.INVALID_INPUT
    assert "ff" * 32 in excinfo.value.message


def test_pcap_field_is_one_of_four_mutually_exclusive_forms(
    planted_dumps, fixture_pcap, fixture_client_random,
):
    """No precedence, exactly as for the other three: two forms naming
    different bytes would otherwise yield a confident census of the wrong one."""
    with pytest.raises(CapabilityError) as excinfo:
        locate_key(
            dump_paths=planted_dumps,
            key_hex=fixture_client_random.hex(),
            pcap_field={"pcap_path": fixture_pcap, "field_id": "client_random"},
        )
    assert excinfo.value.category is ErrorCategory.INVALID_INPUT
    assert "key_hex" in excinfo.value.message
    assert "pcap_field" in excinfo.value.message
    assert list(LOCATE_KEY_INPUT_FORMS) == [
        "key_hex", "keylog_line", "secret", "pcap_field",
    ]


def test_export_key_pattern_shares_the_resolver_but_not_this_form(fixture_pcap):
    """``export_key_pattern`` must REFUSE ``pcap_field`` by name, not ignore it.

    A signature anchored on a public handshake field proves nothing (the bytes
    are on the wire), so the form is not offered there — and silently dropping
    it would answer about whichever other form arrived with it, which is the
    exactly-one rule defeated from the other side.
    """
    with pytest.raises(CapabilityError) as excinfo:
        _resolve_key_needle(
            "", "", None,
            {"pcap_path": fixture_pcap, "field_id": "client_random"},
        )
    assert excinfo.value.category is ErrorCategory.INVALID_INPUT
    assert "pcap_field" in excinfo.value.message
    assert "not accepted" in excinfo.value.message


def test_the_three_form_error_message_is_unchanged_for_the_other_callers():
    """The shared resolver's default vocabulary stays three forms, so
    ``export_key_pattern``'s guidance does not start advertising a fourth form
    it would refuse."""
    with pytest.raises(CapabilityError) as excinfo:
        _resolve_key_needle("", "", None)
    assert "['key_hex', 'keylog_line', 'secret']" in excinfo.value.message
    assert "pcap_field" not in excinfo.value.message


# ---------------------------------------------------------------------------
# the pure selection rules — the multi-session cases no fixture provides
# ---------------------------------------------------------------------------


def _session(client_random: str, *fields: dict) -> dict:
    return {"client_random": client_random, "fields": list(fields)}


def _field(field_id: str, *, searchable: bool = True) -> dict:
    return {
        "field_id": field_id,
        "label": field_id,
        "type": "bytes",
        "length": 32 if searchable else 2,
        "searchable": searchable,
        "value_hex": ("aa" * 32) if searchable else "aabb",
    }


def test_a_single_session_capture_selects_itself():
    session = _session("11" * 32, _field("client_random"))
    assert _select_pcap_field_session([session], "") is session


def test_several_sessions_with_no_selector_is_refused_not_guessed():
    """The rule that matters most: defaulting to the first session would answer
    about a DIFFERENT handshake, and the answer would look entirely healthy."""
    sessions = [_session("11" * 32), _session("22" * 32)]
    with pytest.raises(CapabilityError) as excinfo:
        _select_pcap_field_session(sessions, "")
    assert excinfo.value.category is ErrorCategory.PRECONDITION
    assert "11" * 32 in excinfo.value.message
    assert "22" * 32 in excinfo.value.message


def test_a_selector_picks_one_of_several_sessions():
    first, second = _session("11" * 32), _session("22" * 32)
    assert _select_pcap_field_session([first, second], "22" * 32) is second
    # The same normalisation the hex key form applies, so a value pasted from a
    # hex viewer works here too.
    assert _select_pcap_field_session([first, second], "0x" + "22" * 32) is second


def test_a_capture_with_no_session_has_no_fields_to_name():
    with pytest.raises(CapabilityError) as excinfo:
        _select_pcap_field_session([], "")
    assert excinfo.value.category is ErrorCategory.INVALID_INPUT


def test_field_lookup_is_id_keyed_and_lists_only_usable_alternatives():
    fields = [_field("client_random"), _field("client_ext.0x000b", searchable=False)]
    assert _select_pcap_field(fields, "client_random")["field_id"] == "client_random"
    with pytest.raises(CapabilityError) as excinfo:
        _select_pcap_field(fields, "missing")
    # Only the searchable id is offered: the other one would be refused anyway.
    assert "client_random" in excinfo.value.message
    assert "0x000b" not in excinfo.value.message


def test_the_accepted_pcap_field_keys_are_the_documented_three():
    assert PCAP_FIELD_KEYS == ("pcap_path", "field_id", "client_random")


# ---------------------------------------------------------------------------
# (5) cross-surface parity
# ---------------------------------------------------------------------------


def test_mcp_tools_forward_both_new_parameters():
    """The signature-parity ratchet in ``test_architecture_invariants`` catches
    this generically; asserted here too so a C2 regression names C2."""
    import inspect as inspect_module

    pytest.importorskip("mcp")
    from memdiver.mcp_server.server import create_server

    tools = {t.name: t for t in create_server()._tool_manager.list_tools()}
    assert "include_fields" in inspect_module.signature(
        tools["inspect_pcap"].fn).parameters
    assert "pcap_field" in inspect_module.signature(
        tools["locate_key"].fn).parameters


def test_mcp_inspect_pcap_returns_the_fields_inline(fixture_pcap):
    """An agent handed a server-side path cannot read the file, so the fields
    have to come back in the response."""
    pytest.importorskip("mcp")
    from memdiver.mcp_server.server import create_server

    tools = {t.name: t for t in create_server()._tool_manager.list_tools()}
    payload = json.loads(
        tools["inspect_pcap"].fn(pcap_path=fixture_pcap, include_fields=True))
    assert payload["field_index"]
    assert payload["sessions"][0]["fields"]
    # And the default stays lean for the same agent.
    lean = json.loads(tools["inspect_pcap"].fn(pcap_path=fixture_pcap))
    assert "field_index" not in lean


def test_cli_exposes_both_spellings():
    from memdiver.cli import build_parser

    parser = build_parser()

    args = parser.parse_args(["inspect-pcap", "x.pcap"])
    assert args.fields is False
    args = parser.parse_args(["inspect-pcap", "x.pcap", "--fields"])
    assert args.fields is True

    args = parser.parse_args([
        "locate-key", "a.dump",
        "--pcap-field", "client_random",
        "--pcap", "x.pcap",
        "--pcap-session", "11" * 32,
    ])
    assert (args.pcap_field, args.pcap, args.pcap_session) == (
        "client_random", "x.pcap", "11" * 32)


def test_cli_refuses_a_hex_key_alongside_the_symbolic_form():
    """``--pcap-field`` joins the existing mutually-exclusive group, so the
    parser refuses a mixture before the producer is ever reached."""
    from memdiver.cli import build_parser

    parser = build_parser()
    with pytest.raises(SystemExit):
        parser.parse_args([
            "locate-key", "a.dump", "--key-hex", "aa",
            "--pcap-field", "client_random",
        ])


def test_cli_assembles_the_producer_dict_from_its_three_flags():
    import argparse

    from memdiver.cli.pipeline import _pcap_field_from_args

    assert _pcap_field_from_args(argparse.Namespace(pcap_field=None)) is None
    assert _pcap_field_from_args(argparse.Namespace(
        pcap_field="sni", pcap="x.pcap", pcap_session=None,
    )) == {"pcap_path": "x.pcap", "field_id": "sni"}
    assert _pcap_field_from_args(argparse.Namespace(
        pcap_field="sni", pcap="x.pcap", pcap_session="11" * 32,
    )) == {"pcap_path": "x.pcap", "field_id": "sni", "client_random": "11" * 32}


def test_cli_inspect_pcap_writes_the_fields(tmp_path, fixture_pcap):
    import argparse

    from memdiver.cli.pipeline import _cmd_inspect_pcap

    out = tmp_path / "fields.json"
    assert _cmd_inspect_pcap(argparse.Namespace(
        pcap=fixture_pcap, pcap_max_records=None, pcap_max_challenges=None,
        fields=True, output=str(out),
    )) == 0
    payload = json.loads(out.read_text())
    assert payload["field_index"]
    assert payload["sessions"][0]["fields"]


def test_web_route_defaults_to_no_fields_and_opts_in_on_request(fixture_pcap):
    """``ValidatePcapRequest.include_fields`` defaults False, so the arm request
    the UI has always sent keeps its exact response."""
    from fastapi.testclient import TestClient

    from memdiver.api.main import create_app
    from memdiver.api.routers.pcaps import ValidatePcapRequest

    assert ValidatePcapRequest(pcap_path="x.pcap").include_fields is False

    with TestClient(create_app()) as client:
        lean = client.post("/api/pcaps/validate", json={"pcap_path": fixture_pcap})
        assert lean.status_code == 200
        assert "field_index" not in lean.json()

        rich = client.post(
            "/api/pcaps/validate",
            json={"pcap_path": fixture_pcap, "include_fields": True},
        )
        assert rich.status_code == 200
        assert rich.json()["field_index"]
        assert rich.json()["sessions"][0]["fields"]


def test_library_surface_still_re_exports_the_two_producers():
    """``services.py`` re-exports the FUNCTION OBJECTS, so both new parameters
    are on the library surface with no edit there — this pins that."""
    import inspect as inspect_module

    from memdiver import services

    assert "include_fields" in inspect_module.signature(
        services.inspect_pcap).parameters
    assert "pcap_field" in inspect_module.signature(
        services.locate_key).parameters

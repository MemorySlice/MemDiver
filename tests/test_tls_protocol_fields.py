"""Proof for the C1 protocol field model (``engine/resources/protocol_fields.py``).

Three layers, deliberately separated because they can fail independently:

1. **Pure byte parsing**, driven from ``bytes`` literals. ``protocol_fields``
   imports no dpkt and no capture reader, so the hello/extension/SNI/certificate
   walks are testable with no file on disk — which is the whole reason they were
   hand-rolled rather than read off dpkt's parse.
2. **Wiring**, on the synthetic captures ``test_tls_pcap_resource`` already
   builds (reused rather than re-derived — a second copy of the frame loop is a
   second thing to drift). This layer proves ``describe_fields`` reaches the
   right fields, that provenance offsets really locate the bytes they claim, and
   — the load-bearing one — that ``describe_sessions``/``describe_capture`` are
   completely unaffected by the new model.
3. **Real captures**: the committed TLS 1.3 fixture (cross-checked against its
   own ``manifest.json``) and, behind ``requires_dataset``, the corpus for the
   two things no synthetic capture can honestly stand in for — a real
   certificate chain and a real SNI ClientHello.

A note on where the corpus SNI lives: the ``openssl`` runs send **no**
server_name extension at all (``openssl s_client`` omits it without
``-servername``), so the SNI proof uses a ``botanssl`` TLS 1.2 run, which does.
The openssl run is used for the certificate proof, where it has a real 1035-byte
DER chain. Both facts were measured, not assumed.
"""

import json
import warnings
from pathlib import Path

import pytest

dpkt = pytest.importorskip("dpkt")

from memdiver.engine.resources.protocol_fields import (  # noqa: E402
    MIN_SEARCHABLE_LEN,
    SOURCE_CERTIFICATE,
    SOURCE_CLIENT_HELLO,
    SOURCE_RECORD_LAYER,
    SOURCE_SERVER_HELLO,
    FieldProvenance,
    ProtocolField,
    is_searchable,
    parse_certificate_list,
    parse_extensions,
    parse_hello_layout,
    parse_server_name_list,
)
from memdiver.engine.resources.tls_pcap import (  # noqa: E402
    _CT_HANDSHAKE,
    _HS_CLIENT_HELLO,
    _HS_SERVER_HELLO,
    _RECORD_HEADER_LEN,
    TlsPcapResource,
    _find_hello,
    _find_hello_with_offset,
    _TlsSession,
    session_fields,
    session_notes,
)

# The synthetic wire builders, reused verbatim from the resource's own suite.
from tests.test_tls_pcap_resource import (  # noqa: E402
    CIPHER_CODE,
    CLIENT_PORT,
    CLIENT_RANDOM,
    SERVER_RANDOM,
    _handshake,
    _tls_record,
    _write_capture,
    _write_flows,
)
from tests._paths import dataset_root  # noqa: E402
from tests.fixtures.tls_ground_truth import tls_dumps_dir  # noqa: E402

#: The committed TLS 1.3 capture + its ground-truth manifest. Not gated on the
#: corpus: both files are in the repo, so this proof runs everywhere.
_FIXTURE_DIR = Path(__file__).resolve().parent / "e2e" / "fixtures" / "pcap"
_FIXTURE_PCAP = _FIXTURE_DIR / "session_tls13.pcap"
_FIXTURE_MANIFEST = _FIXTURE_DIR / "manifest.json"

#: A real TLS 1.2 handshake WITH a certificate chain (openssl sends no SNI).
_CORPUS_CERT_PCAP = (
    "TLS12/100_iterations_Abort/openssl/openssl_run_12_1/run_data/traffic.pcap"
)
#: A real TLS 1.2 handshake WITH a server_name extension (botan sends one).
_CORPUS_SNI_PCAP = (
    "TLS12/100_iterations_Abort/botanssl/botanssl_run_12_13/run_data/traffic.pcap"
)


# --------------------------------------------------------------------------- #
# Layer 1 — pure byte parsing, no capture
# --------------------------------------------------------------------------- #

def _extension(ext_type: int, data: bytes) -> bytes:
    """One hello extension: type(2) || length(2) || data."""
    return ext_type.to_bytes(2, "big") + len(data).to_bytes(2, "big") + data


def _sni_extension(hostname: bytes) -> bytes:
    """A server_name extension carrying one host_name entry (RFC 6066 §3)."""
    entry = b"\x00" + len(hostname).to_bytes(2, "big") + hostname
    return _extension(0x0000, len(entry).to_bytes(2, "big") + entry)


def _client_hello_body(
    *,
    random: bytes = CLIENT_RANDOM,
    session_id: bytes = b"",
    suites=(CIPHER_CODE,),
    extensions: bytes = b"",
) -> bytes:
    """A ClientHello body assembled by hand, so every offset is predictable."""
    suite_bytes = b"".join(code.to_bytes(2, "big") for code in suites)
    return (
        b"\x03\x03"
        + random
        + bytes([len(session_id)])
        + session_id
        + len(suite_bytes).to_bytes(2, "big")
        + suite_bytes
        + b"\x01\x00"                                  # compression: null
        + len(extensions).to_bytes(2, "big")
        + extensions
    )


def _server_hello_body(
    *,
    random: bytes = SERVER_RANDOM,
    session_id: bytes = b"",
    cipher: int = CIPHER_CODE,
    extensions: bytes = b"",
) -> bytes:
    """A ServerHello body assembled by hand (single suite, single compression)."""
    return (
        b"\x03\x03"
        + random
        + bytes([len(session_id)])
        + session_id
        + cipher.to_bytes(2, "big")
        + b"\x00"
        + len(extensions).to_bytes(2, "big")
        + extensions
    )


def test_is_searchable_needs_a_byte_type_and_a_useful_length():
    """Both clauses of the rule, and the fact that neither alone suffices."""
    assert is_searchable("bytes", b"\xaa" * MIN_SEARCHABLE_LEN) is True
    assert is_searchable("string", b"example.com") is True
    # Long enough, but not a byte run the process ever held.
    assert is_searchable("uint[]", b"\xaa" * 64) is False
    assert is_searchable("uint", b"\xc0\x2f") is False
    # A byte run, but too short to mean anything in a multi-megabyte dump.
    assert is_searchable("bytes", b"\xaa" * (MIN_SEARCHABLE_LEN - 1)) is False
    assert is_searchable("bytes", b"") is False


def test_parse_hello_layout_client_records_values_and_offsets():
    """A ClientHello walk yields dpkt's values AND the offsets dpkt discards."""
    exts = _extension(0x000B, b"\x01\x00") + _sni_extension(b"example.com")
    body = _client_hello_body(
        session_id=b"\x11" * 32, suites=(0xC02F, 0xC030), extensions=exts
    )

    layout = parse_hello_layout(body, is_client=True)

    assert layout.truncated is False
    assert layout.legacy_version == 0x0303
    assert layout.random == CLIENT_RANDOM
    assert layout.random_offset == 2
    assert layout.session_id == b"\x11" * 32
    assert layout.session_id_offset == 35          # 2 version + 32 random + 1 len
    assert layout.cipher_suites == (0xC02F, 0xC030)
    assert layout.cipher_suite is None             # a ClientHello negotiates nothing
    # Every offset must actually index its own bytes — the property that makes
    # provenance worth reporting at all.
    assert body[layout.random_offset : layout.random_offset + 32] == CLIENT_RANDOM
    assert (
        body[layout.session_id_offset : layout.session_id_offset + 32] == b"\x11" * 32
    )
    assert (
        body[layout.cipher_suites_offset : layout.cipher_suites_offset + 4]
        == layout.cipher_suites_raw
    )
    assert [ext_type for ext_type, _d, _o in layout.extensions] == [0x000B, 0x0000]
    for _ext_type, data, offset in layout.extensions:
        assert body[offset : offset + len(data)] == data


def test_parse_hello_layout_server_records_the_negotiated_suite_offset():
    """The ServerHello branch: one suite code and one compression byte."""
    body = _server_hello_body(session_id=b"\x22" * 32, extensions=_extension(0x0017, b""))

    layout = parse_hello_layout(body, is_client=False)

    assert layout.truncated is False
    assert layout.random == SERVER_RANDOM
    assert layout.session_id == b"\x22" * 32
    assert layout.cipher_suites == ()               # a ServerHello offers no list
    assert layout.cipher_suite == CIPHER_CODE
    assert (
        int.from_bytes(
            body[layout.cipher_suite_offset : layout.cipher_suite_offset + 2], "big"
        )
        == CIPHER_CODE
    )
    assert [ext_type for ext_type, _d, _o in layout.extensions] == [0x0017]


def test_parse_hello_layout_without_extensions_is_not_truncated():
    """The extensions block is optional — a hello may simply end after compression.

    The distinction matters: reporting ``truncated`` for a perfectly complete
    TLS 1.0-era hello would attach a "the capture is damaged" note to a session
    that is entirely intact.
    """
    body = _client_hello_body()[:-2]  # drop the 2-byte extensions_length

    layout = parse_hello_layout(body, is_client=True)

    assert layout.truncated is False
    assert layout.extensions == ()
    assert layout.cipher_suites == (CIPHER_CODE,)


@pytest.mark.parametrize("keep", [0, 1, 20, 34, 35, 40])
def test_parse_hello_layout_never_raises_on_a_short_body(keep):
    """A truncated hello degrades to the fields that arrived, flagged as such."""
    body = _client_hello_body(session_id=b"\x11" * 32)

    layout = parse_hello_layout(body[:keep], is_client=True)

    assert layout.truncated is True
    # Whatever it did report must still be self-consistent.
    assert len(layout.random) in (0, 32)
    assert layout.extensions == ()


def test_parse_extensions_offsets_are_in_the_callers_frame():
    """``base_offset`` is applied inside, so no call site repeats the arithmetic."""
    block = _extension(0x000A, b"\x00\x1d") + _extension(0x0017, b"")

    exts, truncated = parse_extensions(block, base_offset=100)

    assert truncated is False
    assert exts == ((0x000A, b"\x00\x1d", 104), (0x0017, b"", 110))


def test_parse_extensions_reports_a_block_that_ends_mid_extension():
    """A short block yields the complete extensions and says it was truncated."""
    block = _extension(0x000A, b"\x00\x1d") + b"\x00\x17\x00\x08\xaa\xbb"

    exts, truncated = parse_extensions(block)

    assert [ext_type for ext_type, _d, _o in exts] == [0x000A]
    assert truncated is True


def test_parse_extensions_keeps_duplicate_types():
    """Duplicates are preserved, because hiding them would misreport the wire."""
    block = _extension(0x0017, b"\x01") + _extension(0x0017, b"\x02")

    exts, truncated = parse_extensions(block)

    assert [(t, d) for t, d, _o in exts] == [(0x0017, b"\x01"), (0x0017, b"\x02")]
    assert truncated is False


def test_parse_server_name_list_finds_the_host_name_and_its_offset():
    payload = _sni_extension(b"example.com")[4:]  # strip the extension header

    parsed = parse_server_name_list(payload)

    assert parsed is not None
    hostname, offset = parsed
    assert hostname == b"example.com"
    assert payload[offset : offset + len(hostname)] == hostname


@pytest.mark.parametrize(
    "payload",
    [
        b"",                    # no list length at all
        b"\x00\x00",            # the EMPTY list a ServerHello echoes back
        b"\x00\x09\x00\x00",    # a length that overruns the payload
    ],
)
def test_parse_server_name_list_returns_none_rather_than_guessing(payload):
    """``None`` is a real answer here — most importantly for a ServerHello echo."""
    assert parse_server_name_list(payload) is None


def test_parse_certificate_list_splits_der_blobs_with_offsets():
    first, second = b"\x30\x82" + b"\xaa" * 30, b"\x30\x82" + b"\xbb" * 10
    body = b"".join(
        [
            (len(first) + len(second) + 6).to_bytes(3, "big"),
            len(first).to_bytes(3, "big"),
            first,
            len(second).to_bytes(3, "big"),
            second,
        ]
    )

    certs = parse_certificate_list(body)

    assert [der for der, _o in certs] == [first, second]
    for der, offset in certs:
        assert body[offset : offset + len(der)] == der


def test_parse_certificate_list_keeps_what_it_recovered_from_a_truncated_tail():
    """A chopped chain yields the complete certificates, not zero of them."""
    good = b"\x30\x82" + b"\xaa" * 30
    body = (
        (len(good) + 3 + 3 + 99).to_bytes(3, "big")
        + len(good).to_bytes(3, "big")
        + good
        + (999).to_bytes(3, "big")      # claims 999 bytes that are not there
    )

    assert [der for der, _o in parse_certificate_list(body)] == [good]


def test_protocol_field_and_provenance_serialise_to_stable_dicts():
    """The JSON shape every surface will render — its key set is the C2 contract."""
    field = ProtocolField(
        field_id="client_random",
        label="ClientHello.random",
        type="bytes",
        value_hex="aa" * 32,
        length=32,
        source=SOURCE_CLIENT_HELLO,
        provenance=FieldProvenance("client", 0, 11, 6),
        searchable=True,
    )

    as_dict = field.as_dict()

    assert set(as_dict) == {
        "field_id", "label", "type", "value_hex", "value",
        "length", "source", "provenance", "searchable",
    }
    assert as_dict["provenance"] == {
        "direction": "client", "record_index": 0,
        "stream_offset": 11, "record_offset": 6,
    }
    assert ProtocolField(field_id="x", label="x", type="uint").as_dict()["provenance"] is None


# --------------------------------------------------------------------------- #
# Layer 2 — wiring, on the synthetic captures
# --------------------------------------------------------------------------- #

def _session_flow_with_extensions(client_extensions: bytes, server_extensions: bytes):
    """A minimal complete TLS 1.2 flow whose hellos carry chosen extensions.

    The suite's own ``_session_flow`` builds extension-free hellos, so SNI and
    extension-collision cases need their own hello bodies. Everything else — the
    records, the CCS, the frame loop — is the shared builder's.
    """
    client_records = [
        _tls_record(22, _handshake(1, _client_hello_body(extensions=client_extensions))),
        _tls_record(20, b"\x01"),
    ]
    server_records = [
        _tls_record(22, _handshake(2, _server_hello_body(extensions=server_extensions))),
        _tls_record(20, b"\x01"),
    ]
    return (CLIENT_PORT, client_records, server_records)


def _field_map(fields):
    return {field["field_id"]: field for field in fields}


def test_describe_fields_reports_one_entry_per_session_with_the_agreed_shape(tmp_path):
    pcap = tmp_path / "session.pcap"
    _write_capture(str(pcap))

    described = TlsPcapResource(str(pcap)).describe_fields()

    assert len(described) == 1
    assert set(described[0]) == {"client_random", "session_index", "fields", "notes"}
    assert described[0]["client_random"] == CLIENT_RANDOM.hex()
    assert described[0]["session_index"] == 0
    # JSON-serialisable end to end: this is what four surfaces will return.
    json.dumps(described)


def test_describe_fields_extracts_the_expected_field_ids(tmp_path):
    pcap = tmp_path / "session.pcap"
    _write_capture(str(pcap))

    fields = _field_map(TlsPcapResource(str(pcap)).describe_fields()[0]["fields"])

    assert fields["client_random"]["value_hex"] == CLIENT_RANDOM.hex()
    assert fields["client_random"]["searchable"] is True
    assert fields["server_random"]["value_hex"] == SERVER_RANDOM.hex()
    assert fields["server_random"]["source"] == SOURCE_SERVER_HELLO
    assert fields["cipher_suite"]["value"] == CIPHER_CODE
    assert fields["cipher_suite"]["type"] == "uint"
    assert fields["cipher_suites"]["value"] == [CIPHER_CODE]
    assert fields["cipher_suites"]["type"] == "uint[]"
    assert fields["client_record_seq"]["source"] == SOURCE_RECORD_LAYER
    # No SNI extension and no cleartext certificate in this synthetic hello.
    assert "sni" not in fields
    assert not [key for key in fields if key.startswith("certificate.")]


def test_empty_session_id_is_a_length_zero_field_not_an_omission(tmp_path):
    """Absence of a VALUE is reported; absence of a MESSAGE is not invented.

    The synthetic hellos offer no session id, which is a normal handshake, so the
    field is present with length 0 and ``searchable`` False. Contrast
    ``certificate.<n>``, which is not emitted at all when there was no
    Certificate message — see the TLS 1.3 note test below.
    """
    pcap = tmp_path / "session.pcap"
    _write_capture(str(pcap))

    fields = _field_map(TlsPcapResource(str(pcap)).describe_fields()[0]["fields"])

    assert fields["client_session_id"]["length"] == 0
    assert fields["client_session_id"]["value_hex"] == ""
    assert fields["client_session_id"]["searchable"] is False


def test_sni_is_parsed_out_of_the_server_name_extension(tmp_path):
    pcap = tmp_path / "sni.pcap"
    _write_flows(str(pcap), [_session_flow_with_extensions(_sni_extension(b"secure.example.com"), b"")])

    fields = _field_map(TlsPcapResource(str(pcap)).describe_fields()[0]["fields"])

    assert fields["sni"]["value"] == "secure.example.com"
    assert fields["sni"]["type"] == "string"
    assert fields["sni"]["value_hex"] == b"secure.example.com".hex()
    assert fields["sni"]["searchable"] is True
    assert fields["sni"]["source"] == SOURCE_CLIENT_HELLO
    # The raw extension payload is still reported alongside the parsed hostname:
    # ``ext.*`` is a complete per-extension dump, ``sni`` is the interpretation.
    assert "client_ext.0x0000" in fields


def test_a_short_hostname_is_reported_but_not_marked_searchable(tmp_path):
    """Measured on the real corpus: its SNI hostname is ``Server`` — six bytes.

    Six bytes of ASCII match everywhere in a real process image, so calling this
    searchable would hand the user a guaranteed false-positive sweep. The field
    is still reported; only the *promise* about it is withheld.
    """
    pcap = tmp_path / "short-sni.pcap"
    _write_flows(str(pcap), [_session_flow_with_extensions(_sni_extension(b"Server"), b"")])

    fields = _field_map(TlsPcapResource(str(pcap)).describe_fields()[0]["fields"])

    assert fields["sni"]["value"] == "Server"
    assert fields["sni"]["length"] == 6
    assert fields["sni"]["searchable"] is False


def test_extension_field_ids_are_unique_across_the_two_hellos(tmp_path):
    """The reason ids are ``client_ext.``/``server_ext.`` prefixed, not bare ``ext.``.

    Extension 0x000b appears in both hellos of a real handshake (it does in every
    corpus capture measured), so unprefixed ids would collide and any id-keyed
    lookup — which is exactly what C2's field index will be — would silently
    resolve to whichever came last.
    """
    shared = _extension(0x000B, b"\x01\x00")
    pcap = tmp_path / "collide.pcap"
    _write_flows(str(pcap), [_session_flow_with_extensions(shared, shared)])

    fields = TlsPcapResource(str(pcap)).describe_fields()[0]["fields"]
    ids = [field["field_id"] for field in fields]

    assert len(ids) == len(set(ids)), f"duplicate field_id in {ids}"
    assert "client_ext.0x000b" in ids
    assert "server_ext.0x000b" in ids


def test_provenance_offsets_locate_the_exact_bytes_they_claim(tmp_path):
    """The property that makes provenance worth carrying, asserted directly.

    For every byte-valued field: the record fragment at ``record_offset`` holds
    exactly ``value_hex``, and the ``stream_offset``/``record_offset`` pair is
    consistent with the 5-byte record header.
    """
    pcap = tmp_path / "sni.pcap"
    _write_flows(str(pcap), [_session_flow_with_extensions(_sni_extension(b"secure.example.com"), b"")])

    resource = TlsPcapResource(str(pcap))
    session = resource._parse_sessions()[0]
    checked = 0
    for field in session_fields(session):
        if field.provenance is None or field.type not in ("bytes", "string"):
            continue
        provenance = field.provenance
        records = (
            session.client_records
            if provenance.direction == "client"
            else session.server_records
        )
        fragment = bytes(records[provenance.record_index].data)
        start = provenance.record_offset
        assert fragment[start : start + field.length].hex() == field.value_hex
        # stream_offset - record_offset - 5 must be where that record's header is.
        header_offset = sum(
            _RECORD_HEADER_LEN + record.length
            for record in records[: provenance.record_index]
        )
        assert provenance.stream_offset - start - _RECORD_HEADER_LEN == header_offset
        checked += 1
    assert checked >= 5, "expected several byte-valued fields to verify"


def test_record_seq_fields_come_from_the_emitter_gate(tmp_path):
    """The numbers reported are the numbers the challenge stream will use.

    Passed in from ``_record_sequences`` rather than re-derived inside
    ``session_fields``, because the gate that produces them depends on the
    resource's record cap. Without ``record_sequences`` the fields are simply
    absent — never guessed.
    """
    pcap = tmp_path / "session.pcap"
    _write_capture(str(pcap))

    resource = TlsPcapResource(str(pcap))
    session = resource._parse_sessions()[0]
    sequences = resource._record_sequences(session)

    # Ground truth straight out of the emitter's own gate.
    gated = [seq for _rec, seq, _n in resource._tls12_gated(session.client_records)]
    assert sequences["client"] == gated == [0]

    with_seq = _field_map(
        field.as_dict()
        for field in session_fields(session, record_sequences=sequences)
    )
    assert with_seq["client_record_seq"]["value"] == [0]
    assert with_seq["server_record_seq"]["value"] == []
    assert with_seq["client_record_seq"]["provenance"] is None

    without_seq = {field.field_id for field in session_fields(session)}
    assert "client_record_seq" not in without_seq


def test_record_cap_narrows_the_reported_sequence_numbers(tmp_path):
    """A cap that clips the challenge stream clips the reported sequences too."""
    from tests.test_tls_pcap_resource import _write_multi_record_capture

    pcap = tmp_path / "many.pcap"
    _write_multi_record_capture(str(pcap), 5)

    uncapped = TlsPcapResource(str(pcap))
    capped = TlsPcapResource(str(pcap), max_records_per_direction=2)

    def client_seq(resource):
        session = resource._parse_sessions()[0]
        return resource._record_sequences(session)["client"]

    assert client_seq(uncapped) == [0, 1, 2, 3, 4]
    assert client_seq(capped) == [0, 1]


def test_session_fields_works_on_a_positionally_built_session(tmp_path):
    """The keyword-only slots default to ``None``, and the fallback covers it.

    Existing tests and library callers construct ``_TlsSession`` with the
    original six positional arguments; a required seventh would have broken
    them, so the locations are optional and re-derived from the record lists
    when absent. This asserts the fallback is equivalent, not merely non-empty.
    """
    pcap = tmp_path / "session.pcap"
    _write_capture(str(pcap))
    parsed = TlsPcapResource(str(pcap))._parse_sessions()[0]

    bare = _TlsSession(
        parsed.client_random,
        parsed.server_random,
        parsed.cipher_code,
        parsed.version,
        parsed.client_records,
        parsed.server_records,
    )

    assert bare.client_hello is None
    assert bare.server_hello is None
    assert bare.certificates is None
    assert session_fields(bare) == session_fields(parsed)
    assert session_notes(bare) == session_notes(parsed)


def test_find_hello_wrapper_agrees_with_the_offset_carrying_form(tmp_path):
    """``_find_hello`` is a thin shim: same body, minus the coordinates."""
    pcap = tmp_path / "session.pcap"
    _write_capture(str(pcap))
    session = TlsPcapResource(str(pcap))._parse_sessions()[0]

    for records, hs_type in (
        (session.client_records, _HS_CLIENT_HELLO),
        (session.server_records, _HS_SERVER_HELLO),
    ):
        body, record_index, stream_offset, raw = _find_hello_with_offset(records, hs_type)
        # A fresh dpkt parse per call, so compare the bytes rather than identity.
        assert bytes(body) == bytes(_find_hello(records, hs_type))
        assert bytes(getattr(body, "random", b"")) == bytes(
            getattr(_find_hello(records, hs_type), "random", b"")
        )
        assert record_index == 0
        # The body sits 5 record-header + 4 handshake-header bytes into record 0.
        assert stream_offset == _RECORD_HEADER_LEN + 4
        assert raw and bytes(records[0].data).endswith(raw)


def test_missing_message_is_a_sentinel_not_an_exception():
    """A record list with no such handshake message yields the documented tuple."""
    assert _find_hello_with_offset([], _HS_CLIENT_HELLO) == (None, -1, -1, b"")
    assert _find_hello([], _HS_CLIENT_HELLO) is None


def test_handshake_messages_packed_in_one_record_get_distinct_offsets(tmp_path):
    """Several handshake messages share one fragment in a real server flight.

    So a message's offset within the fragment is not zero, and a field's
    ``record_offset`` must include it. This is the case that a naive
    "offset = 4" extractor gets silently wrong.
    """
    hello = _handshake(2, _server_hello_body())
    filler = _handshake(14, b"")               # ServerHelloDone, zero-length body
    client_records = [
        _tls_record(22, _handshake(1, _client_hello_body())),
        _tls_record(20, b"\x01"),
    ]
    server_records = [
        _tls_record(22, filler + hello),       # hello is the SECOND message
        _tls_record(20, b"\x01"),
    ]
    pcap = tmp_path / "packed.pcap"
    _write_flows(str(pcap), [(CLIENT_PORT, client_records, server_records)])

    session = TlsPcapResource(str(pcap))._parse_sessions()[0]
    fields = {field.field_id: field for field in session_fields(session)}

    provenance = fields["server_random"].provenance
    assert provenance is not None
    fragment = bytes(session.server_records[provenance.record_index].data)
    assert fragment[provenance.record_offset : provenance.record_offset + 32] == SERVER_RANDOM
    # 4 bytes of ServerHelloDone header + 4 of the ServerHello header + 2 version.
    assert provenance.record_offset == 4 + 4 + 2


# --------------------------------------------------------------------------- #
# The load-bearing guarantee: the field model changed nothing that existed
# --------------------------------------------------------------------------- #

def test_describe_sessions_and_capture_are_untouched_by_the_field_model(tmp_path):
    """Byte-identical output, before and after ``describe_fields`` runs.

    ``describe_sessions``' key set is a frozen contract the web router and the
    React frontend read, which is the whole reason fields ride on a new method.
    This asserts the stronger property too: extracting fields is side-effect
    free, so calling ``describe_fields`` cannot perturb either sibling.
    """
    pcap = tmp_path / "session.pcap"
    _write_capture(str(pcap))
    resource = TlsPcapResource(str(pcap))

    before_sessions = resource.describe_sessions()
    before_capture = resource.describe_capture()
    resource.describe_fields()

    assert resource.describe_sessions() == before_sessions
    assert resource.describe_capture() == before_capture
    # And the frozen key set is still exactly the eight it always was.
    assert set(before_sessions[0]) == {
        "client_random", "server_random", "version", "cipher_suite", "cipher_name",
        "client_app_records", "server_app_records", "has_app_records",
    }
    assert "fields" not in before_sessions[0]
    assert "fields" not in before_capture["sessions"][0]


def test_challenges_are_unchanged_by_the_recorded_locations(tmp_path):
    """The locations ride along on ``_TlsSession``; the challenge stream ignores them."""
    pcap = tmp_path / "session.pcap"
    _write_capture(str(pcap))
    resource = TlsPcapResource(str(pcap))

    challenges = list(resource.challenges())

    assert len(challenges) == 1
    derivation = challenges[0].derivation
    assert derivation is not None
    assert derivation.client_random == CLIENT_RANDOM
    assert derivation.seq_num == 0


# --------------------------------------------------------------------------- #
# Layer 3a — the committed TLS 1.3 fixture (runs everywhere)
# --------------------------------------------------------------------------- #

def test_committed_fixture_client_random_matches_its_manifest():
    """Cross-check against ground truth captured alongside the pcap itself.

    ``manifest.json`` records the ``client_random`` of the session the fixture's
    memory slice was taken from. If the extractor and the manifest disagree, one
    of them is describing a different session — and every downstream proof built
    on that fixture is meaningless.
    """
    manifest = json.loads(_FIXTURE_MANIFEST.read_text())

    described = TlsPcapResource(str(_FIXTURE_PCAP)).describe_fields()

    assert len(described) == 1
    assert described[0]["client_random"] == manifest["client_random"]
    fields = _field_map(described[0]["fields"])
    assert fields["client_random"]["value_hex"] == manifest["client_random"]
    assert fields["client_random"]["length"] == 32
    assert fields["client_random"]["searchable"] is True


def test_tls13_reports_the_certificate_encryption_note_and_no_certificate_field():
    """Hazard 1, on a real TLS 1.3 capture.

    RFC 8446 encrypts the Certificate message, so there is nothing to parse.
    An empty ``certificate.0`` would claim a parse that *failed*; the note says
    the truth instead — nothing was ever visible.
    """
    described = TlsPcapResource(str(_FIXTURE_PCAP)).describe_fields()[0]

    assert not [f for f in described["fields"] if f["field_id"].startswith("certificate.")]
    codes = [note["code"] for note in described["notes"]]
    assert "tls13_certificates_encrypted" in codes
    assert "no_certificate_message" not in codes  # the TLS 1.2 code, not this one
    detail = next(n["detail"] for n in described["notes"] if n["code"] == "tls13_certificates_encrypted")
    assert "8446" in detail


def test_tls13_key_share_extension_is_a_searchable_needle():
    """The real payoff of per-extension fields on a real capture.

    ``key_share`` (0x0033) carries the ephemeral public key — over a kilobyte in
    this ClientHello — while the short negotiation extensions beside it are
    correctly not offered as needles. Neither outcome is hand-coded per
    extension number; both fall out of the one length rule.
    """
    fields = _field_map(TlsPcapResource(str(_FIXTURE_PCAP)).describe_fields()[0]["fields"])

    key_share = fields["client_ext.0x0033"]
    assert key_share["length"] > MIN_SEARCHABLE_LEN
    assert key_share["searchable"] is True
    assert fields["client_ext.0x002d"]["searchable"] is False   # psk_key_exchange_modes, 2 B
    assert fields["server_ext.0x002b"]["searchable"] is False   # supported_versions, 2 B


def test_fixture_reports_the_missing_sni_note():
    """Measured: this capture carries no server_name extension.

    Worth a note rather than silence, because the hostname is usually the first
    needle a user reaches for and its quiet absence reads as a broken extractor.
    """
    described = TlsPcapResource(str(_FIXTURE_PCAP)).describe_fields()[0]

    assert "sni" not in _field_map(described["fields"])
    assert "no_server_name_extension" in [n["code"] for n in described["notes"]]


# --------------------------------------------------------------------------- #
# Layer 3b — the real corpus (certificate chains and real SNI)
# --------------------------------------------------------------------------- #

def _corpus_capture(relpath: str) -> str:
    """Resolve a corpus capture, skipping when this machine has none.

    Resolved through ``tls_dumps_dir()`` — the single spelling of "where the
    corpus lives", and the same resolver that gates ``requires_dataset`` — so
    the marker and the path can never disagree about whether the file exists.
    """
    if dataset_root() is None:  # pragma: no cover - the marker normally skips first
        pytest.skip("no corpus configured")
    path = tls_dumps_dir().expanduser() / relpath
    if not path.exists():
        pytest.skip(f"corpus capture absent: {path}")
    return str(path)


@pytest.mark.requires_dataset
def test_corpus_tls12_certificate_der_is_extracted_with_provenance():
    """A real certificate chain: DER bytes, a searchable needle, real offsets.

    No synthetic capture can stand in for this — the DER encoding, the chain
    framing, and the fact that the Certificate message lands in a *later* record
    than the ServerHello (so ``record_index`` is not 0) are all properties of
    real openssl output.
    """
    path = _corpus_capture(_CORPUS_CERT_PCAP)
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")  # dpkt deprecates .cipher_suite internally
        session = TlsPcapResource(path)._parse_sessions()[0]
        fields = {field.field_id: field for field in session_fields(session)}

    assert session.version == "12"
    leaf = fields["certificate.0"]
    assert leaf.source == SOURCE_CERTIFICATE
    assert leaf.length > 500
    assert leaf.value_hex.startswith("3082")     # DER SEQUENCE, long form
    assert leaf.searchable is True
    provenance = leaf.provenance
    assert provenance is not None
    assert provenance.direction == "server"
    assert provenance.record_index > 0, "the chain is not in the ServerHello record"
    fragment = bytes(session.server_records[provenance.record_index].data)
    assert fragment[provenance.record_offset : provenance.record_offset + leaf.length].hex() == leaf.value_hex
    assert "no_certificate_message" not in [n["code"] for n in session_notes(session)]


@pytest.mark.requires_dataset
def test_corpus_openssl_run_carries_no_sni_and_says_so():
    """Measured, and the reason the SNI proof below uses a botan run instead.

    ``openssl s_client`` sends no server_name unless ``-servername`` is passed,
    so every openssl capture in the corpus lacks SNI. Asserting the *absence*
    plus its note is what stops a future reader from "fixing" a working
    extractor against the wrong capture.
    """
    path = _corpus_capture(_CORPUS_CERT_PCAP)
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        described = TlsPcapResource(path).describe_fields()[0]

    assert "sni" not in _field_map(described["fields"])
    assert "client_ext.0x0000" not in _field_map(described["fields"])
    assert "no_server_name_extension" in [n["code"] for n in described["notes"]]


@pytest.mark.requires_dataset
def test_corpus_tls12_sni_is_parsed_from_a_real_client_hello():
    """A real server_name extension, hand-parsed out of a real ClientHello.

    dpkt hands back the raw extension payload and nothing else, so the hostname
    here is the product of this module's own ServerNameList walk running on
    bytes it did not author. The corpus hostname is ``Server`` — six bytes, so
    correctly NOT offered as a dump needle.
    """
    path = _corpus_capture(_CORPUS_SNI_PCAP)
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        described = TlsPcapResource(path).describe_fields()[0]
    fields = _field_map(described["fields"])

    sni = fields["sni"]
    assert sni["type"] == "string"
    assert sni["value"] == "Server"
    assert sni["value_hex"] == b"Server".hex()
    assert sni["searchable"] is False
    assert "no_server_name_extension" not in [n["code"] for n in described["notes"]]
    # The raw payload is longer than the hostname (it wraps a ServerNameList).
    assert fields["client_ext.0x0000"]["length"] > sni["length"]


@pytest.mark.requires_dataset
def test_corpus_hand_rolled_walk_agrees_with_dpkt_on_every_hello():
    """The cross-check that earns the hand-rolled parser its keep.

    ``protocol_fields`` re-implements the hello structure to recover offsets dpkt
    discards. That is only safe if the *values* still agree with dpkt's own
    parse, on real bytes, for both hellos of a real handshake — randoms, session
    ids, the offered suite list, the negotiated suite, and every extension.
    """
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        for relpath in (_CORPUS_CERT_PCAP, _CORPUS_SNI_PCAP):
            session = TlsPcapResource(_corpus_capture(relpath))._parse_sessions()[0]
            for is_client, records, hs_type in (
                (True, session.client_records, _HS_CLIENT_HELLO),
                (False, session.server_records, _HS_SERVER_HELLO),
            ):
                _body, _index, _offset, raw = _find_hello_with_offset(records, hs_type)
                layout = parse_hello_layout(raw, is_client=is_client)
                parsed = _find_hello(records, hs_type)

                assert layout.truncated is False, relpath
                assert layout.random == bytes(getattr(parsed, "random", b""))
                assert layout.session_id == bytes(getattr(parsed, "session_id", b"") or b"")
                dpkt_exts = [
                    (ext_type, bytes(data))
                    for ext_type, data in (getattr(parsed, "extensions", None) or [])
                ]
                assert [(t, d) for t, d, _o in layout.extensions] == dpkt_exts
                if is_client:
                    codes = [
                        int(getattr(suite, "code", suite))
                        for suite in (getattr(parsed, "ciphersuites", None) or [])
                    ]
                    assert list(layout.cipher_suites) == codes
                else:
                    suite = getattr(parsed, "ciphersuite", None)
                    assert layout.cipher_suite == int(getattr(suite, "code", suite))


@pytest.mark.requires_dataset
def test_corpus_certificate_der_matches_dpkts_own_chain_split():
    """Same cross-check for the certificate walk, against dpkt's ``certificates``."""
    from memdiver.engine.resources.tls_pcap import _iter_handshake_messages

    path = _corpus_capture(_CORPUS_CERT_PCAP)
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        session = TlsPcapResource(path)._parse_sessions()[0]
        mine = [
            bytes.fromhex(field.value_hex)
            for field in session_fields(session)
            if field.field_id.startswith("certificate.")
        ]
        from_dpkt = [
            bytes(cert)
            for record in session.server_records
            if record.type == _CT_HANDSHAKE
            for message in _iter_handshake_messages(bytes(record.data))
            if message.type == 11
            for cert in getattr(message.data, "certificates", [])
        ]

    assert mine, "expected at least one certificate in this TLS 1.2 capture"
    assert mine == from_dpkt


@pytest.mark.requires_dataset
def test_corpus_describe_sessions_is_unchanged_on_real_bytes():
    """The no-drift guarantee, re-asserted where it actually matters.

    The synthetic version of this test proves the shape; this one proves it
    against a capture with certificates, extensions, multiple records per
    fragment, and a real cipher suite — i.e. every path the field model added.
    """
    path = _corpus_capture(_CORPUS_CERT_PCAP)
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        resource = TlsPcapResource(path)
        before = resource.describe_capture()
        resource.describe_fields()
        after = resource.describe_capture()

    assert after == before
    assert set(before["sessions"][0]) >= {
        "client_random", "server_random", "version", "cipher_suite", "cipher_name",
        "client_app_records", "server_app_records", "has_app_records",
    }
    assert "fields" not in before["sessions"][0]


def test_corpus_helper_skips_cleanly_when_the_capture_is_absent(monkeypatch):
    """The corpus tests above degrade to a NAMED skip, never a confusing error.

    ``MEMDIVER_TLS_DUMPS_DIR`` is the single spelling of "where the corpus
    lives"; pointing it somewhere empty is how a machine without the corpus is
    simulated. Asserting the skip (rather than leaving it to chance) is what
    stops a corpus-absent CI run from failing on a missing file.
    """
    monkeypatch.setenv("MEMDIVER_TLS_DUMPS_DIR", "/nonexistent-corpus-root")

    assert str(tls_dumps_dir()) == "/nonexistent-corpus-root"
    with pytest.raises(pytest.skip.Exception):
        _corpus_capture(_CORPUS_CERT_PCAP)

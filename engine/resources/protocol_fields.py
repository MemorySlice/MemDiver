"""A protocol field model for parsed TLS sessions — the handshake, byte-addressed.

``TlsPcapResource.describe_sessions`` answers "what session is this?" with eight
frozen keys. That shape is a contract the web router and the React frontend read,
and it is deliberately *small*: the facts a key derivation needs, nothing else.
This module answers a different question — **"which bytes of this handshake could
I go looking for in a memory dump, and where on the wire did each one come
from?"** — and it answers it without touching that frozen shape at all.

Why the distinction matters. A memory-forensics user hunting a session in a dump
does not only want the master-secret-derivation inputs; they want every
*per-session, high-entropy byte string the process must have held*: the two
randoms, the session ids, the SNI hostname, a key-share blob, the server's
certificate DER. Each of those is a candidate needle. And when a needle *is*
found in a dump, the next question is always "is that the same bytes I saw on the
wire, and at which record?" — which is why every field here carries
:class:`FieldProvenance` rather than just a value.

Layering: this module is **pure**. It imports nothing from ``app/`` or ``api/``
(the engine-layer ratchets in ``tests/test_architecture_invariants.py`` enforce
that), and — less obviously but just as deliberately — it does not import
``dpkt`` either. Every parser below walks raw ``bytes`` with explicit offsets.
That is not asceticism, it is the only way to get provenance: dpkt's
``TLSClientHello`` hands back *values* and throws the offsets away, and an offset
we cannot report is a needle a user cannot cross-check against a dump. It also
means this module is testable from a bytes literal, with no capture on disk.

The three things a naive extractor gets wrong, and how each is handled here:

* **TLS 1.3 certificates are encrypted.** The Certificate handshake message
  moves inside the protected epoch in RFC 8446, so a TLS 1.3 capture simply has
  no cleartext certificate to parse. Emitting an empty ``certificate.0`` would
  claim a parse *failure* where there was nothing to parse; the caller gets a
  ``notes`` entry (see :func:`tls13_certificate_note`) instead.
* **Absence is a fact, not an error.** An empty ``session_id`` (an abbreviated
  handshake that offers no resumption) and a missing SNI extension (an
  IP-addressed connection, or ``openssl s_client`` without ``-servername``) are
  both *normal*. The first is emitted as a real field of length 0 with
  ``searchable=False``; the second is not a field at all, and gets a note. The
  asymmetry is intentional and is documented at each site.
* **A short needle is a useless needle.** ``searchable`` is not "is this bytes?"
  — it is "would handing this hex to a dump search return signal rather than
  noise?". A 2-byte extension payload matches everywhere. See
  :func:`is_searchable`.

Nothing here parses a capture or reassembles a stream; the caller
(``tls_pcap.py``) supplies already-reassembled bytes plus the offsets it walked
them at, and receives :class:`ProtocolField` tuples back.
"""

from __future__ import annotations

from dataclasses import dataclass, replace
from typing import Any, Dict, List, Optional, Sequence, Tuple

__all__ = [
    "FieldProvenance",
    "ProtocolField",
    "HelloLayout",
    "SOURCE_CLIENT_HELLO",
    "SOURCE_SERVER_HELLO",
    "SOURCE_CERTIFICATE",
    "SOURCE_RECORD_LAYER",
    "MIN_SEARCHABLE_LEN",
    "is_searchable",
    "parse_hello_layout",
    "parse_extensions",
    "parse_server_name_list",
    "parse_certificate_list",
    "client_hello_fields",
    "server_hello_fields",
    "certificate_fields",
    "record_seq_field",
    "tls13_certificate_note",
    "absent_certificate_note",
    "truncated_hello_note",
    "missing_sni_note",
]

# -- the ``source`` vocabulary ---------------------------------------------- #
# Named rather than inlined so a consumer can switch on them without matching
# free-text, and so a typo becomes an ImportError instead of a field nobody
# can filter for.
SOURCE_CLIENT_HELLO = "client_hello"
SOURCE_SERVER_HELLO = "server_hello"
SOURCE_CERTIFICATE = "certificate"
SOURCE_RECORD_LAYER = "record_layer"

# -- the ``type`` vocabulary ------------------------------------------------ #
# ``bytes``    a raw byte string (the randoms, session ids, extension payloads,
#              certificate DER) — the searchable case.
# ``uint``     one non-negative integer (the negotiated suite code).
# ``string``   text decoded from bytes (the SNI hostname). Still carries
#              ``value_hex``, because it is the *bytes* a dump search wants.
# ``uint[]``   a list of integers (the offered suite list, the record sequence
#              numbers).
# ``bytes[]``  reserved: a list of byte strings. Nothing emits it today —
#              certificates are emitted individually as ``certificate.<n>`` so
#              each gets its own provenance — but it is part of the agreed
#              vocabulary and a consumer should tolerate it.
TYPE_BYTES = "bytes"
TYPE_UINT = "uint"
TYPE_STRING = "string"
TYPE_UINT_LIST = "uint[]"
TYPE_BYTES_LIST = "bytes[]"

#: Shortest byte string worth handing to a dump search. Eight bytes is the
#: smallest width at which a value from *this* session is unlikely to also occur
#: by chance in an unrelated multi-megabyte dump (2**-64 per position). Below it
#: a "hit" carries no information: a 2-byte extension payload such as
#: ``0x0403`` occurs thousands of times in any real process image, so reporting
#: it as searchable would hand the user a guaranteed false-positive sweep. The
#: threshold is a property of dump search, not of TLS, which is why it lives
#: here as one named constant rather than as a per-field judgement.
MIN_SEARCHABLE_LEN = 8

#: The two field types whose ``value_hex`` is a literal run of bytes the process
#: must have held. ``uint``/``uint[]`` values are wire-encoding artifacts (a
#: cipher-suite list is re-encoded in whatever internal form the TLS library
#: chose), so no dump search over them is meaningful regardless of length.
_SEARCHABLE_TYPES = frozenset({TYPE_BYTES, TYPE_STRING})

# SNI (RFC 6066 §3): the only name_type ever assigned is host_name = 0.
_EXTENSION_SERVER_NAME = 0x0000
_SNI_NAME_TYPE_HOST = 0


def is_searchable(field_type: str, raw: bytes) -> bool:
    """Whether ``raw`` is a byte needle a dump search can usefully take.

    Two clauses, both about the *search*, not about TLS:

    1. the field must be a literal byte run the process held (``bytes`` or
       ``string``) — see :data:`_SEARCHABLE_TYPES`;
    2. it must be at least :data:`MIN_SEARCHABLE_LEN` long, or every dump
       returns hits and none of them mean anything.

    Kept as one function so the rule has a single spelling: when a new field is
    added, ``searchable`` is derived, never hand-set, and cannot drift from what
    the sweep can actually do with it.
    """
    return field_type in _SEARCHABLE_TYPES and len(raw) >= MIN_SEARCHABLE_LEN


@dataclass(frozen=True)
class FieldProvenance:
    """Where on the wire a field's bytes were read from.

    The point of carrying this is cross-checking: a candidate needle found at
    some dump offset is only interesting if the user can say *which* record of
    *which* direction produced the wire bytes it matched.

    ``stream_offset`` and ``record_offset`` are related by the 5-byte TLS record
    header, so the pair is self-checking::

        stream_offset - record_offset - 5 == offset of the record header

    which is exactly the cumulative ``5 + record.length`` walk the caller did.
    """

    direction: str      #: ``"client"`` or ``"server"`` — whose records these are
    record_index: int   #: index into that direction's record list
    stream_offset: int  #: the field's byte offset in the reassembled direction stream
    record_offset: int  #: the field's byte offset inside the record *fragment*

    def as_dict(self) -> Dict[str, Any]:
        return {
            "direction": self.direction,
            "record_index": self.record_index,
            "stream_offset": self.stream_offset,
            "record_offset": self.record_offset,
        }


@dataclass(frozen=True)
class ProtocolField:
    """One extracted protocol field: what it is, its bytes, and where from.

    ``value_hex`` is always the field's raw wire bytes as hex (empty when the
    field has no byte form, e.g. a record-sequence list), and ``value`` is the
    decoded form when there is a more useful one than hex — the hostname for
    ``sni``, the int for ``cipher_suite``, the list for ``cipher_suites``. Both
    are carried because they serve different callers: a dump search wants the
    hex, a human reading a field browser wants the value.
    """

    field_id: str
    label: str
    type: str
    value_hex: str = ""
    value: Any = None
    length: int = 0
    source: str = ""
    provenance: Optional[FieldProvenance] = None
    searchable: bool = False

    def as_dict(self) -> Dict[str, Any]:
        """A JSON-friendly dict — the shape every surface will render."""
        return {
            "field_id": self.field_id,
            "label": self.label,
            "type": self.type,
            "value_hex": self.value_hex,
            "value": self.value,
            "length": self.length,
            "source": self.source,
            "provenance": None if self.provenance is None else self.provenance.as_dict(),
            "searchable": self.searchable,
        }


def _byte_field(
    field_id: str,
    label: str,
    raw: bytes,
    source: str,
    provenance: Optional[FieldProvenance],
    *,
    field_type: str = TYPE_BYTES,
    value: Any = None,
) -> ProtocolField:
    """Build a byte-valued field, deriving ``length`` and ``searchable``.

    The single constructor for every ``bytes``/``string`` field below, so those
    two derived attributes cannot be set inconsistently at one of a dozen call
    sites.
    """
    return ProtocolField(
        field_id=field_id,
        label=label,
        type=field_type,
        value_hex=raw.hex(),
        value=value,
        length=len(raw),
        source=source,
        provenance=provenance,
        searchable=is_searchable(field_type, raw),
    )


# --------------------------------------------------------------------------- #
# Hand-rolled hello parsing
#
# dpkt hands back values without offsets, and for a ClientHello it does not
# expose the SNI hostname at all (only the raw extension payload). Both gaps are
# closed by walking the body ourselves. The walk is written to *stop* rather than
# raise on a truncated body: a capture that lost a packet mid-ClientHello should
# yield the fields that did arrive, not zero fields.
# --------------------------------------------------------------------------- #


@dataclass(frozen=True)
class HelloLayout:
    """A ClientHello/ServerHello body decomposed into values **and** offsets.

    Every ``*_offset`` is relative to the start of the handshake *message body*
    (i.e. after the 4-byte type||length handshake header), which is the only
    frame of reference this module can have — the caller adds the message's
    position inside its record fragment and the record's position in the stream.

    ``truncated`` says the walk ran out of bytes before finishing the structure.
    The fields parsed up to that point are still valid and still reported; the
    flag exists so a caller can say *why* a session yielded fewer fields than
    its sibling instead of showing an unexplained gap.
    """

    legacy_version: int = 0
    random: bytes = b""
    random_offset: int = 0
    session_id: bytes = b""
    session_id_offset: int = 0
    #: ClientHello only — the offered suite codes, in wire order.
    cipher_suites: Tuple[int, ...] = ()
    cipher_suites_raw: bytes = b""
    cipher_suites_offset: int = 0
    #: ServerHello only — the single negotiated code, or ``None``.
    cipher_suite: Optional[int] = None
    cipher_suite_offset: int = 0
    #: ``(ext_type, ext_data, ext_data_offset)`` in wire order.
    extensions: Tuple[Tuple[int, bytes, int], ...] = ()
    truncated: bool = False


def parse_hello_layout(raw: bytes, *, is_client: bool) -> HelloLayout:
    """Walk a hello message body into :class:`HelloLayout`.

    ``is_client`` selects the one place the two structures diverge: a
    ClientHello carries ``cipher_suites`` (a length-prefixed *list*) followed by
    a length-prefixed compression-methods list, where a ServerHello carries a
    single ``cipher_suite`` followed by one compression byte (RFC 5246 §7.4.1).
    Everything before and after that — version, random, session id, extensions —
    is identical, which is why one walker serves both.

    Never raises. The layout starts out flagged ``truncated`` and each step
    widens it; a complete walk clears the flag at the end. So a body too short
    for the next field simply returns early, reporting exactly the fields that
    did arrive and already saying that it stopped short. Writing it that way
    round — rather than as a raise, or as one construction per exit — is what
    makes "the capture lost a packet mid-ClientHello" degrade into fewer fields
    instead of no fields.
    """
    layout = HelloLayout(truncated=True)

    # legacy_version(2) || random(32)
    if len(raw) < 34:
        return layout
    layout = replace(
        layout,
        legacy_version=int.from_bytes(raw[0:2], "big"),
        random=raw[2:34],
        random_offset=2,
    )
    pos = 34

    # session_id: one length byte, then that many bytes. An EMPTY session id is
    # normal (no resumption offered) and is not truncation.
    if pos >= len(raw):
        return layout
    session_id_len = raw[pos]
    pos += 1
    layout = replace(layout, session_id_offset=pos)
    if pos + session_id_len > len(raw):
        return layout
    layout = replace(layout, session_id=raw[pos : pos + session_id_len])
    pos += session_id_len

    if is_client:
        if pos + 2 > len(raw):
            return layout
        suites_len = int.from_bytes(raw[pos : pos + 2], "big")
        pos += 2
        layout = replace(layout, cipher_suites_offset=pos)
        if pos + suites_len > len(raw):
            return layout
        suites_raw = raw[pos : pos + suites_len]
        layout = replace(
            layout,
            cipher_suites_raw=suites_raw,
            # A trailing odd byte would be malformed; ignore it rather than
            # raise, and report the codes that did decode.
            cipher_suites=tuple(
                int.from_bytes(suites_raw[i : i + 2], "big")
                for i in range(0, suites_len - (suites_len % 2), 2)
            ),
        )
        pos += suites_len
        # compression_methods: one length byte, then that many bytes.
        if pos >= len(raw):
            return layout
        pos += 1 + raw[pos]
    else:
        if pos + 2 > len(raw):
            return layout
        layout = replace(
            layout,
            cipher_suite_offset=pos,
            cipher_suite=int.from_bytes(raw[pos : pos + 2], "big"),
        )
        pos += 3  # 2 bytes of suite + exactly 1 compression_method byte

    # The extensions block is OPTIONAL (a TLS 1.0-era hello may simply end
    # here), so running out of bytes at exactly this point is a COMPLETE parse.
    # Only overshooting it — which the compression-methods length above can do
    # on a malformed body — is truncation.
    if pos + 2 > len(raw):
        return replace(layout, truncated=pos > len(raw))
    ext_total = int.from_bytes(raw[pos : pos + 2], "big")
    pos += 2
    block = raw[pos : pos + ext_total]
    extensions, ext_truncated = parse_extensions(block, base_offset=pos)
    return replace(
        layout,
        extensions=extensions,
        truncated=ext_truncated or len(block) < ext_total,
    )


def parse_extensions(
    block: bytes, *, base_offset: int = 0
) -> Tuple[Tuple[Tuple[int, bytes, int], ...], bool]:
    """Split a hello extensions block into ``(type, data, data_offset)`` triples.

    ``base_offset`` is where ``block`` sits in the enclosing message body, so
    the returned ``data_offset`` is already in the caller's frame of reference —
    no second offset arithmetic at the call site, which is where an off-by-five
    would hide.

    Returns ``(triples, truncated)``. A block that ends mid-extension yields the
    complete extensions before it and ``truncated=True``; duplicate types are
    preserved rather than de-duplicated, because a hello legitimately may repeat
    one and hiding that would be a lie about the wire.
    """
    out: List[Tuple[int, bytes, int]] = []
    pos = 0
    while pos + 4 <= len(block):
        ext_type = int.from_bytes(block[pos : pos + 2], "big")
        ext_len = int.from_bytes(block[pos + 2 : pos + 4], "big")
        data_start = pos + 4
        if data_start + ext_len > len(block):
            return tuple(out), True
        out.append(
            (ext_type, block[data_start : data_start + ext_len], base_offset + data_start)
        )
        pos = data_start + ext_len
    # Anything left over is a stray fragment shorter than an extension header.
    return tuple(out), pos != len(block)


def parse_server_name_list(ext_data: bytes) -> Optional[Tuple[bytes, int]]:
    """Extract the SNI host_name from a server_name extension payload.

    RFC 6066 §3 shape: ``list_length(2) || { name_type(1) || name_length(2) ||
    name }*``. Returns ``(hostname_bytes, offset_within_ext_data)`` for the
    first ``host_name`` entry, or ``None`` when the payload carries none.

    ``None`` is a real answer, not a failure: a server_name extension with an
    empty list is exactly what a *ServerHello* echoes back to acknowledge SNI
    (RFC 6066 says the server's copy is empty), so hitting this path on the
    server side is expected. Returning bytes rather than ``str`` keeps the
    decode decision — and the possibility of a non-UTF-8 hostname — at the call
    site.
    """
    if len(ext_data) < 2:
        return None
    list_len = int.from_bytes(ext_data[0:2], "big")
    end = min(2 + list_len, len(ext_data))
    pos = 2
    while pos + 3 <= end:
        name_type = ext_data[pos]
        name_len = int.from_bytes(ext_data[pos + 1 : pos + 3], "big")
        name_start = pos + 3
        if name_start + name_len > end:
            return None
        if name_type == _SNI_NAME_TYPE_HOST:
            return ext_data[name_start : name_start + name_len], name_start
        pos = name_start + name_len
    return None


def parse_certificate_list(raw: bytes) -> Tuple[Tuple[bytes, int], ...]:
    """Split a Certificate handshake body into ``(der, offset)`` pairs.

    RFC 5246 §7.4.2 shape: ``list_length(3) || { cert_length(3) || DER }*``.
    Offsets are relative to the start of the message body, matching
    :class:`HelloLayout`.

    Written by hand rather than read off dpkt's ``TLSCertificate.certificates``
    for the usual reason: dpkt gives the DER blobs but not where they were, and
    a certificate found in a dump is only evidence if it can be tied back to the
    record that carried it.
    """
    if len(raw) < 3:
        return ()
    list_len = int.from_bytes(raw[0:3], "big")
    end = min(3 + list_len, len(raw))
    out: List[Tuple[bytes, int]] = []
    pos = 3
    while pos + 3 <= end:
        cert_len = int.from_bytes(raw[pos : pos + 3], "big")
        start = pos + 3
        if start + cert_len > end:
            break  # truncated tail — keep the certificates already recovered
        out.append((raw[start : start + cert_len], start))
        pos = start + cert_len
    return tuple(out)


# --------------------------------------------------------------------------- #
# Field builders
#
# Each takes already-parsed values plus the offsets needed to place them, and
# returns ProtocolFields. They are pure functions of their arguments so a test
# can drive them from a bytes literal without a capture on disk.
# --------------------------------------------------------------------------- #


def _provenance(
    direction: str,
    record_index: int,
    record_header_offset: int,
    fragment_base: int,
    body_offset: int,
) -> FieldProvenance:
    """Place a field whose offset is ``body_offset`` inside its message body.

    ``record_header_offset`` is where the record's 5-byte header starts in the
    reassembled stream (the caller's cumulative ``5 + record.length`` walk);
    ``fragment_base`` is where the *message body* starts inside the record
    fragment (the handshake message's position in the fragment, plus its 4-byte
    header). The two additions are done here, once, rather than at every builder.
    """
    record_offset = fragment_base + body_offset
    return FieldProvenance(
        direction=direction,
        record_index=record_index,
        stream_offset=record_header_offset + 5 + record_offset,
        record_offset=record_offset,
    )


def client_hello_fields(
    layout: HelloLayout,
    *,
    record_index: int,
    record_header_offset: int,
    fragment_base: int,
    direction: str = "client",
) -> Tuple[ProtocolField, ...]:
    """The fields a ClientHello contributes: random, session id, suites, SNI, exts."""
    place = lambda body_offset: _provenance(  # noqa: E731 - a local alias, not a policy
        direction, record_index, record_header_offset, fragment_base, body_offset
    )
    fields: List[ProtocolField] = []

    if layout.random:
        fields.append(
            _byte_field(
                "client_random", "ClientHello.random", layout.random,
                SOURCE_CLIENT_HELLO, place(layout.random_offset),
            )
        )
    # Emitted even when EMPTY, unlike ``certificate.<n>``: a zero-length session
    # id is a present field with an empty value ("I offer no resumption"),
    # whereas an absent Certificate message is a message that was never sent.
    # Reporting the first as a length-0 field is honest; reporting the second
    # would invent one. ``searchable`` falls out as False either way.
    fields.append(
        _byte_field(
            "client_session_id", "ClientHello.session_id", layout.session_id,
            SOURCE_CLIENT_HELLO, place(layout.session_id_offset),
        )
    )
    if layout.cipher_suites:
        fields.append(
            ProtocolField(
                field_id="cipher_suites",
                label="ClientHello.cipher_suites",
                type=TYPE_UINT_LIST,
                value_hex=layout.cipher_suites_raw.hex(),
                value=list(layout.cipher_suites),
                length=len(layout.cipher_suites),
                source=SOURCE_CLIENT_HELLO,
                provenance=place(layout.cipher_suites_offset),
                # A ``uint[]``: the wire bytes are carried in ``value_hex`` for
                # completeness, but no TLS library stores the offered list in
                # wire form, so searching a dump for it finds nothing.
                searchable=False,
            )
        )
    fields.extend(
        _sni_fields(layout, place=place, source=SOURCE_CLIENT_HELLO)
    )
    fields.extend(
        _extension_fields(layout, place=place, prefix="client_ext", source=SOURCE_CLIENT_HELLO)
    )
    return tuple(fields)


def server_hello_fields(
    layout: HelloLayout,
    *,
    record_index: int,
    record_header_offset: int,
    fragment_base: int,
    negotiated_cipher: Optional[int] = None,
    direction: str = "server",
) -> Tuple[ProtocolField, ...]:
    """The fields a ServerHello contributes: random, session id, suite, exts.

    ``negotiated_cipher`` lets the caller supply the code it already resolved
    through its own (dpkt-backed, defensively written) reader, so the value the
    challenge stream derives keys from and the value shown as a field are the
    same number by construction. When it is ``None`` the hand-rolled
    ``layout.cipher_suite`` is used instead.
    """
    place = lambda body_offset: _provenance(  # noqa: E731 - a local alias, not a policy
        direction, record_index, record_header_offset, fragment_base, body_offset
    )
    fields: List[ProtocolField] = []

    if layout.random:
        fields.append(
            _byte_field(
                "server_random", "ServerHello.random", layout.random,
                SOURCE_SERVER_HELLO, place(layout.random_offset),
            )
        )
    fields.append(
        _byte_field(
            "server_session_id", "ServerHello.session_id", layout.session_id,
            SOURCE_SERVER_HELLO, place(layout.session_id_offset),
        )
    )
    code = negotiated_cipher if negotiated_cipher is not None else layout.cipher_suite
    if code is not None:
        fields.append(
            ProtocolField(
                field_id="cipher_suite",
                label="ServerHello.cipher_suite",
                type=TYPE_UINT,
                value_hex=code.to_bytes(2, "big").hex(),
                value=code,
                length=2,
                source=SOURCE_SERVER_HELLO,
                provenance=place(layout.cipher_suite_offset),
                searchable=False,  # two bytes; see MIN_SEARCHABLE_LEN
            )
        )
    fields.extend(
        _extension_fields(layout, place=place, prefix="server_ext", source=SOURCE_SERVER_HELLO)
    )
    return tuple(fields)


def _sni_fields(layout: HelloLayout, *, place: Any, source: str) -> List[ProtocolField]:
    """The ``sni`` field, when the hello carries a non-empty server_name list.

    Split out because SNI is the one hello field that needs a *second* level of
    hand-rolled parsing (the ServerNameList inside the extension payload) and
    because it is the field most worth searching a dump for: a hostname is
    plain, distinctive ASCII that any TLS client must have held as a string.
    """
    out: List[ProtocolField] = []
    for ext_type, ext_data, ext_offset in layout.extensions:
        if ext_type != _EXTENSION_SERVER_NAME:
            continue
        parsed = parse_server_name_list(ext_data)
        if parsed is None:
            continue  # an empty list — see parse_server_name_list's docstring
        hostname, name_offset = parsed
        out.append(
            _byte_field(
                "sni", "ClientHello.server_name", hostname, source,
                place(ext_offset + name_offset),
                field_type=TYPE_STRING,
                # ``errors="replace"`` rather than a raise: a malformed hostname
                # is still a perfectly good byte needle, and value_hex carries
                # the exact bytes regardless of how the text renders.
                value=hostname.decode("utf-8", errors="replace"),
            )
        )
        break  # first host_name only; a second is not legal SNI
    return out


def _extension_fields(
    layout: HelloLayout, *, place: Any, prefix: str, source: str
) -> List[ProtocolField]:
    """One field per hello extension, id'd ``<prefix>.0xNNNN``.

    The prefix (``client_ext`` / ``server_ext``) is what keeps ``field_id``
    **unique across the session**: extension 0x000b appears in both hellos of a
    real handshake, so an unprefixed ``ext.0x000b`` would collide and any
    id-keyed lookup would silently resolve to whichever came last. It also
    mirrors the ``client_random``/``server_random`` naming already in this
    resource.

    Most extension payloads are short negotiation metadata and fall below
    :data:`MIN_SEARCHABLE_LEN`; a few (notably 0x0033 ``key_share``, which
    carries an ephemeral public key) are long and high-entropy and come out
    searchable. That is decided by :func:`is_searchable`, not by an allowlist of
    extension numbers — a hand-maintained allowlist would go stale the first
    time a new extension mattered.
    """
    return [
        _byte_field(
            f"{prefix}.0x{ext_type:04x}",
            f"{source}.extension 0x{ext_type:04x}",
            ext_data,
            source,
            place(ext_offset),
        )
        for ext_type, ext_data, ext_offset in layout.extensions
    ]


def certificate_fields(
    certificates: Sequence[Tuple[bytes, int]],
    *,
    record_index: int,
    record_header_offset: int,
    fragment_base: int,
    direction: str = "server",
) -> Tuple[ProtocolField, ...]:
    """One ``certificate.<n>`` field per DER blob in a Certificate message.

    Emitted individually rather than as one ``bytes[]`` so each certificate
    carries its own offset — a leaf certificate found in a dump is evidence
    about a session; "one of the certificates in the chain" is not.
    """
    return tuple(
        _byte_field(
            f"certificate.{index}",
            f"Certificate[{index}] (DER)",
            der,
            SOURCE_CERTIFICATE,
            _provenance(
                direction, record_index, record_header_offset, fragment_base, offset
            ),
        )
        for index, (der, offset) in enumerate(certificates)
    )


def record_seq_field(direction: str, sequence_numbers: Sequence[int]) -> ProtocolField:
    """The record sequence numbers the challenge stream will use for a direction.

    Not a needle — a ``uint[]`` with no byte form and no provenance, because
    these numbers are not *in* the capture at all: TLS never transmits the
    record sequence number, each side counts it. They are here because they are
    the other half of what an AEAD nonce is built from, so a user reading the
    field list can see exactly which sequence numbers a recovered key would be
    tried against. ``provenance`` is ``None`` for precisely that reason: there
    is no wire offset to point at, and inventing ``record_index=-1`` would be
    worse than admitting it.

    The caller passes the numbers straight out of its own emitter gate, never
    re-derived here — the same discipline ``describe_capture`` follows — so this
    list and the challenge stream cannot disagree.
    """
    return ProtocolField(
        field_id=f"{direction}_record_seq",
        label=f"{direction} record sequence numbers",
        type=TYPE_UINT_LIST,
        value_hex="",
        value=list(sequence_numbers),
        length=len(sequence_numbers),
        source=SOURCE_RECORD_LAYER,
        provenance=None,
        searchable=False,
    )


# --------------------------------------------------------------------------- #
# Notes — why a field a caller expected is legitimately not here
# --------------------------------------------------------------------------- #
#
# A ``notes`` entry is the same idea as this resource's ``skipped`` list: an
# absence with no explanation is indistinguishable from a bug, and the person
# reading the output is the one least able to tell them apart. Machine-readable
# ``code`` plus human ``detail``, matching the ``reason``-keyed style of
# ``describe_capture``'s drop report.


def tls13_certificate_note() -> Dict[str, str]:
    """Why a TLS 1.3 session has no ``certificate.<n>`` fields.

    RFC 8446 moved the Certificate handshake message inside the protected
    handshake epoch, so it is AEAD-encrypted on the wire and unparseable without
    the handshake traffic secret. There is nothing to extract — which is a very
    different statement from "extraction failed", and the whole reason this note
    exists rather than an empty ``certificate.0``.
    """
    return {
        "code": "tls13_certificates_encrypted",
        "detail": (
            "TLS 1.3 encrypts the Certificate handshake message under the "
            "handshake traffic secret (RFC 8446 §4.4.2), so no certificate "
            "bytes are visible in the capture. This is expected, not a parse "
            "failure."
        ),
    }


def absent_certificate_note() -> Dict[str, str]:
    """Why a *TLS 1.2* session has no ``certificate.<n>`` fields.

    Distinct from :func:`tls13_certificate_note` on purpose. There the message
    is encrypted **by design** and no capture will ever show it; here it should
    have been in the clear, so its absence says something about this capture --
    it started after the server's flight, or the packet carrying it was lost.
    Two codes, because a consumer deciding whether to go looking elsewhere needs
    to tell "impossible" from "missing".
    """
    return {
        "code": "no_certificate_message",
        "detail": (
            "No cleartext Certificate handshake message is present in this "
            "TLS 1.2 capture. Expected when the capture starts after the "
            "server's first flight, or when that packet was not captured."
        ),
    }


def truncated_hello_note(which: str) -> Dict[str, str]:
    """Why a hello yielded fewer fields than its structure implies.

    The hello walk stops instead of raising on a short body (see
    :func:`parse_hello_layout`), so a truncated ClientHello still contributes
    its random and session id. Without this note the missing extensions look
    like an extractor that does not support them.
    """
    return {
        "code": "truncated_hello",
        "detail": (
            f"The {which} body ended before its structure did, so the fields "
            "after that point could not be read. The fields reported are still "
            "exactly what the capture contained."
        ),
    }


def missing_sni_note() -> Dict[str, str]:
    """Why a session has no ``sni`` field.

    Normal for an IP-addressed connection, and normal for a locally-generated
    capture (``openssl s_client`` sends no server_name unless ``-servername`` is
    passed). Worth saying out loud because the hostname is usually the *first*
    needle a user reaches for, so its silent absence reads as a broken extractor.
    """
    return {
        "code": "no_server_name_extension",
        "detail": (
            "The ClientHello carries no server_name (SNI) extension, so no "
            "hostname needle is available. Normal for an IP-addressed "
            "connection or a capture made without a servername."
        ),
    }

"""KeylogParser - parse keylog CSV files into CryptoSecret objects."""

import csv
import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional

from .models import CryptoSecret
from .protocols import REGISTRY

logger = logging.getLogger("memdiver.keylog")


def _get_tls13_secret_types():
    """Lazy lookup to avoid import-order fragility."""
    tls = REGISTRY.get("TLS")
    return tls.secret_types["13"] if tls else set()


def _get_all_secret_types():
    """Lazy lookup to avoid import-order fragility."""
    result = set()
    for name in REGISTRY.list_protocols():
        desc = REGISTRY.get(name)
        if desc:
            result |= desc.all_secret_types()
    return result


# Public constants resolved lazily on first access via __getattr__
def __getattr__(name):
    if name == "TLS13_SECRET_TYPES":
        return _get_tls13_secret_types()
    if name == "ALL_SECRET_TYPES":
        return _get_all_secret_types()
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


#: Outcome vocabulary for :func:`parse_keylog_with_status`.
#:
#: ``KeylogParser.parse`` deliberately swallows every failure and returns a
#: (possibly empty) list, which makes an unreadable key log indistinguishable
#: from a session that genuinely logged nothing. Downstream that difference is
#: load-bearing: a survival sweep renders ``secrets_available == 0`` as
#: "not observed", the same cell a genuine post-KeyUpdate gap produces. These
#: statuses keep the two apart without changing ``parse``'s contract.
KEYLOG_STATUS_OK = "ok"          #: File read end-to-end, every secret line well formed.
KEYLOG_STATUS_MISSING = "missing"      #: No such file.
KEYLOG_STATUS_UNREADABLE = "unreadable"  #: Present but nothing could be recovered.
KEYLOG_STATUS_PARTIAL = "partial"      #: Some secrets recovered, some content lost.

#: Every status, in increasing severity order. A caller may compare against
#: this tuple but must never invent a status of its own.
KEYLOG_STATUSES = (
    KEYLOG_STATUS_OK,
    KEYLOG_STATUS_PARTIAL,
    KEYLOG_STATUS_UNREADABLE,
    KEYLOG_STATUS_MISSING,
)


@dataclass(frozen=True)
class KeylogParseResult:
    """What :func:`parse_keylog_with_status` recovered, and how well it went.

    ``secrets`` is exactly what :meth:`KeylogParser.parse` would have returned
    for the same input — this record only *adds* the provenance that ``parse``
    throws away.
    """

    secrets: List[CryptoSecret] = field(default_factory=list)
    status: str = KEYLOG_STATUS_OK
    detail: str = ""

    #: Non-empty ``line`` rows the parser reached. The one signal that keeps
    #: "the file held nothing" apart from "the file held rows this build could
    #: make nothing of": both land on ``secrets_available == 0``, and only
    #: ``rows_read > 0`` says content was there.
    rows_read: int = 0

    #: Rows that were reached but could not be read as a secret — a bad shape,
    #: a type no protocol declares, or a row lost to an aborted read. Always
    #: ``<= rows_read``, and a lower bound after an aborted read.
    rows_malformed: int = 0

    @property
    def ok(self) -> bool:
        """True only when the whole file parsed cleanly."""
        return self.status == KEYLOG_STATUS_OK

    @property
    def secrets_available(self) -> int:
        """Denominator size — meaningful only when :attr:`ok` (or ``partial``)."""
        return len(self.secrets)

    def to_dict(self) -> dict:
        """JSON-serialisable view (secrets are summarised, not serialised)."""
        return {
            "status": self.status,
            "detail": self.detail,
            "rows_read": self.rows_read,
            "rows_malformed": self.rows_malformed,
            "secrets_available": self.secrets_available,
            "secret_types": sorted({s.secret_type for s in self.secrets}),
        }


def _is_well_formed_keylog_line(line: str, known_types=None) -> bool:
    """True when *line* has the NSS shape **and** names a secret type we know.

    Used only to tell a *malformed* row (``partial``) apart from one the
    caller's template legitimately filtered out (still ``ok``): both make
    :meth:`KeylogParser._parse_line` return ``None``, and only this function
    tells the two reasons apart.

    The type token is therefore checked against the **whole registry
    vocabulary** (:func:`_get_all_secret_types`, or *known_types* when the
    caller has already resolved it), never against the caller's template:

    * a type outside the registry is a row nothing can ever read — **malformed**.
      Judging it well formed is the silent zero this status API exists to
      prevent: a wholly corrupted key log (every type token garbled) would
      report ``ok`` with zero secrets, and ``ok`` means "the session really did
      log this many secrets", which a survival sweep renders as a genuine
      post-KeyUpdate absence.
    * a type inside the registry but outside ``template.secret_types`` was
      filtered on purpose — still ``ok``.

    *known_types* is an optimisation only (the registry lookup is not free and
    the caller resolves it once per file); omitting it resolves the same set.
    """
    parts = line.split()
    if len(parts) != 3:
        return False
    vocabulary = _get_all_secret_types() if known_types is None else known_types
    if parts[0] not in vocabulary:
        return False
    try:
        bytes.fromhex(parts[1])
        bytes.fromhex(parts[2])
    except ValueError:
        return False
    return True


def parse_keylog_with_status(
    keylog_path: Path, template=None, *, log_structure_warnings: bool = True,
) -> KeylogParseResult:
    """Parse a keylog CSV, reporting *why* the result looks the way it does.

    Same parsing rules as :meth:`KeylogParser.parse` (which delegates here), so
    the recovered secrets are identical; the difference is that a failure is
    reported as a typed :data:`KEYLOG_STATUSES` value instead of being flattened
    into an empty list.

    Statuses:
        ``ok``          Header present, every non-empty ``line`` row well formed.
        ``missing``     The file does not exist.
        ``unreadable``  The file exists but yielded nothing usable — no CSV
                        header, no ``line`` column, or an error before the first
                        secret was recovered.
        ``partial``     Secrets were recovered but content was lost: at least
                        one malformed row, or an error part-way through.

    The corpus this was written for is clean (2598/2598 headers exactly
    ``id,line``; 7790/7790 secret lines exactly three whitespace-separated
    fields; zero malformed rows), so this costs nothing today — it is what keeps
    that true.

    Note the CSV shape: the secret type lives *inside* the ``line`` column
    (``1,CLIENT_RANDOM <random> <secret>``), not in column 0.

    Args:
        keylog_path: The CSV to read.
        template: Optional protocol template restricting the accepted secret
            types. A line whose type the template rejects is *filtered*, not
            malformed; a line whose type no protocol in the registry declares
            **is** malformed (see :func:`_is_well_formed_keylog_line`).
        log_structure_warnings: Whether a missing header / missing ``line``
            column is reported at WARNING. True here, where the diagnostic is
            the point. :meth:`KeylogParser.parse` passes False to keep its
            historical log surface — exactly the two warnings below (file not
            found, error parsing) — because it runs once per run over a
            multi-thousand-run corpus, where a systematically headerless corpus
            would otherwise emit one new WARNING per run from a path that was
            always silent. The structural facts are still logged at DEBUG, and
            still returned as :data:`KEYLOG_STATUS_UNREADABLE` either way.
    """
    secrets: List[CryptoSecret] = []
    seen = set()
    rows_read = 0
    rows_malformed = 0
    reading_rows = False
    row_in_flight = False
    structure_log = logger.warning if log_structure_warnings else logger.debug

    try:
        known_types = _get_all_secret_types()
        allowed_types = template.secret_types if template is not None else known_types
        # ``utf-8-sig`` strips a byte-order mark, so a BOM-prefixed header still
        # yields a ``line`` column instead of ``\ufeffline`` — which would type
        # an otherwise perfectly good key log ``unreadable``.
        with open(keylog_path, "r", encoding="utf-8-sig") as f:
            reader = csv.DictReader(f)
            fieldnames = reader.fieldnames
            if fieldnames is None:
                structure_log("Keylog has no CSV header: %s", keylog_path)
                return KeylogParseResult(
                    status=KEYLOG_STATUS_UNREADABLE, detail="no CSV header")
            if "line" not in fieldnames:
                structure_log(
                    "Keylog has no 'line' column (header: %s): %s",
                    ",".join(fieldnames), keylog_path)
                return KeylogParseResult(
                    status=KEYLOG_STATUS_UNREADABLE,
                    detail="no 'line' column (header: %s)" % ",".join(fieldnames))
            reading_rows = True
            for row in reader:
                line = row.get("line", "").strip()
                if not line:
                    continue
                rows_read += 1
                # True only while a row already counted in ``rows_read`` is
                # being handled, so the exception handler below knows whether
                # the row it lost was counted or never reached.
                row_in_flight = True
                secret = KeylogParser._parse_line(line, allowed_types=allowed_types)
                if secret is None:
                    if not _is_well_formed_keylog_line(line, known_types):
                        rows_malformed += 1
                        logger.debug(
                            "Malformed keylog line in %s: %r", keylog_path, line)
                elif (secret.secret_type, secret.secret_value) not in seen:
                    seen.add((secret.secret_type, secret.secret_value))
                    secrets.append(secret)
                row_in_flight = False
    except FileNotFoundError:
        logger.warning("Keylog not found: %s", keylog_path)
        return KeylogParseResult(status=KEYLOG_STATUS_MISSING, detail="file not found")
    except Exception as e:
        logger.warning("Error parsing %s: %s", keylog_path, e)
        # The read aborted part-way: the row that raised — and every row after
        # it — is lost. How many is unknowable, so charge the minimum of one
        # lost row rather than hand back counters a consumer reads as a clean
        # parse. ``rows_malformed == 0`` beside a truncated file is exactly the
        # silent zero the status is here to prevent: the status says something
        # went wrong, only the counters say how much survived, so both are
        # lower bounds and never claim the loss was nothing.
        #
        # ``rows_read`` counts rows the parser reached. The lost row is already
        # in it when the failure struck a row in flight; it is not when the
        # failure came out of the reader itself, so only then does it bump.
        # Nothing at all is charged when the failure preceded the first row (a
        # bad open, an undecodable header) — there was no row to lose.
        lost_rows = 1 if reading_rows else 0
        detail = f"{type(e).__name__}: {e}"
        if lost_rows:
            detail += " (read aborted mid-file; at least 1 row lost)"
        return KeylogParseResult(
            secrets=secrets,
            status=KEYLOG_STATUS_PARTIAL if secrets else KEYLOG_STATUS_UNREADABLE,
            detail=detail,
            rows_read=rows_read + (0 if row_in_flight else lost_rows),
            rows_malformed=rows_malformed + lost_rows,
        )

    return KeylogParseResult(
        secrets=secrets,
        status=KEYLOG_STATUS_PARTIAL if rows_malformed else KEYLOG_STATUS_OK,
        detail=(f"{rows_malformed} malformed row(s)" if rows_malformed else ""),
        rows_read=rows_read,
        rows_malformed=rows_malformed,
    )


def format_keylog_lines(secrets: List[CryptoSecret]) -> str:
    """Render CryptoSecrets as a standard NSS key-log (SSLKEYLOGFILE) body.

    Each secret becomes one ``<LABEL> <client_random_hex> <secret_hex>`` line —
    the exact format Wireshark / ``tshark -o tls.keylog_file=...`` loads to
    decrypt a capture (RFC-adjacent NSS format). This is the emit inverse of
    :meth:`KeylogParser._parse_line`; note the *parser* reads a CSV whose ``line``
    column holds these strings, whereas Wireshark consumes the plaintext lines
    directly — so the artifact this produces is the plaintext key log, not the CSV.

    Secrets with an empty ``secret_type`` or ``secret_value`` are skipped.
    Duplicate ``(secret_type, identifier, secret_value)`` triples are emitted
    once, preserving input order.
    """
    lines: List[str] = []
    seen = set()
    for s in secrets:
        if not s.secret_type or not s.secret_value:
            continue
        key = (s.secret_type, s.identifier, s.secret_value)
        if key in seen:
            continue
        seen.add(key)
        lines.append(f"{s.secret_type} {s.identifier.hex()} {s.secret_value.hex()}")
    return "\n".join(lines) + ("\n" if lines else "")


def write_keylog(secrets: List[CryptoSecret], path: Path) -> int:
    """Write *secrets* to *path* as an NSS key log. Returns the line count."""
    body = format_keylog_lines(secrets)
    Path(path).write_text(body)
    return 0 if not body.strip() else body.count("\n")


class KeylogParser:
    """Parse keylog.csv files into CryptoSecret objects."""

    @staticmethod
    def parse(keylog_path: Path, template=None) -> List[CryptoSecret]:
        """Parse a keylog CSV into secrets, swallowing every failure.

        Contract unchanged and deliberately lossy: a missing, unreadable or
        half-read file all return a (possibly empty) list, because every current
        caller only wants "whatever secrets exist". When the *reason* matters —
        an empty list must not be mistaken for "this session had no secrets" —
        call :func:`parse_keylog_with_status` instead, which this delegates to.

        The log surface is part of that unchanged contract: this path emits at
        most the two historical warnings (file not found, error parsing), so
        ``log_structure_warnings=False`` keeps the newer structural diagnostics
        at DEBUG. They belong to the status API, whose caller asked about them.
        """
        return parse_keylog_with_status(
            keylog_path, template=template, log_structure_warnings=False).secrets

    @staticmethod
    def _parse_line(line: str, allowed_types=None) -> Optional[CryptoSecret]:
        parts = line.split()
        if len(parts) != 3:
            return None

        secret_type, client_random_hex, secret_hex = parts
        effective_types = allowed_types if allowed_types is not None else _get_all_secret_types()
        if secret_type not in effective_types:
            return None

        try:
            identifier = bytes.fromhex(client_random_hex)
            secret_value = bytes.fromhex(secret_hex)
        except ValueError:
            return None

        return CryptoSecret(
            secret_type=secret_type,
            identifier=identifier,
            secret_value=secret_value,
        )


# -- Public single-line entry points ---------------------------------------- #
#
# The ``app`` layer needs to parse ONE key-log line (a user pasting a secret
# into the key-log composer) and needs to tell a malformed row apart from one a
# template legitimately filtered out. Both capabilities already exist here, but
# only behind private names. These two public aliases expose them without
# forking a second parser: :meth:`KeylogParser._parse_line` stays the ONE
# implementation, and the private names keep working for their existing
# in-module caller and for the tests that reference them by name.


def parse_keylog_line(line: str, *, template=None) -> Optional[CryptoSecret]:
    """Parse a single NSS key-log line into a :class:`CryptoSecret`.

    Returns ``None`` both for a malformed line and for a well-formed line whose
    secret type falls outside *template*. Call
    :func:`is_well_formed_keylog_line` to tell those two reasons apart — that is
    the only thing that distinguishes them.

    Args:
        line: One ``LABEL client_random_hex secret_hex`` row.
        template: Optional object with a ``secret_types`` collection. When
            supplied, only those types are accepted; otherwise the whole
            registry vocabulary is.
    """
    allowed = template.secret_types if template is not None else None
    return KeylogParser._parse_line(line, allowed)


#: Public alias of :func:`_is_well_formed_keylog_line` — see that function for
#: why the type token is checked against the whole registry vocabulary rather
#: than against the caller's template.
is_well_formed_keylog_line = _is_well_formed_keylog_line

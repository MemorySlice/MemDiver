"""IOC saved query over the ``strings`` case table (plan T3.6).

One pattern table drives BOTH the DuckDB saved query (``regexp_extract_all``
columns over ``strings.value``) and :func:`ioc_kinds`, the Python-side badge list
that ``strings.table`` rows carry, so the two never disagree.

Every pattern is RE2-compatible (DuckDB's engine): no lookaround, no
backreferences, and it reads identically under Python's :mod:`re`. RE2 has no
lookbehind, so a pattern that needs a left boundary consumes it and reports the
single capture group (``regexp_extract_all(..., 1)`` / ``re.findall`` both return
group 1). A pattern with no group reports the whole match.

Three kinds are two-stage: ``IOC_PATTERNS`` finds a greedy *candidate* token and
``IOC_FILTERS`` then keeps only candidates that satisfy every rule (``full`` =
whole candidate matches, ``has`` = pattern occurs, ``not`` = pattern must not
occur). The SQL applies the same rules with ``list_filter``. Rejected on purpose:

* ``ipv4``: not exactly four dot-separated octets 0-255 without leading zeros, so
  dotted OIDs / versions with 3, 5+ parts (``1.2.840.113549``, ``3.0.13.1.2``) and
  tokens glued to letters or ``-``/``_`` (``v1.2.3.4``) never match. Four-part
  versions such as ``1.3.6.1`` stay indistinguishable from addresses, so they are KEPT
  and merely hinted (:func:`ioc_ambiguity`, ``ambiguity: "oid_like"`` on strings rows).
* ``base64``: tokens shorter than 24, not standard-alphabet or badly padded /
  ``len % 4 == 1``, pure hex (that is ``hex_run``), missing any of upper / lower /
  digit-or-``+/`` (identifiers, relative paths) alphabet constants and tokens starting with ``/`` (paths).
* ``unix_paths``: relative paths cut mid-way (``crypto/dsa/x.c`` -> ``/dsa/x.c``),
  the path part of a URL, a single segment unless it is a known root, and paths
  without a letter (``/1/2``).
* ``hex_run``: a whole token of even-length hex, at least 32 digits (hashes, key material).
"""

from __future__ import annotations

import re
from typing import Dict, List, Optional, Tuple

from memdiver.analysis.queries import SavedQuery

TABLE = "strings"
PRODUCER = "memdiver strings table --case"

_OCTET = r"(?:25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])"
_FILE_STEM = r"[A-Za-z0-9._+-]+"

_B64 = r"[A-Za-z0-9+/]"
_PATH_SEG = r"[A-Za-z0-9._+@~-]+"
_PATH_ROOTS = "etc|usr|opt|var|tmp|home|proc|dev|lib|lib64|bin|sbin|run|srv|root|mnt|sys"

#: ``column -> RE2 pattern`` in output order (candidate patterns for filtered kinds).
IOC_PATTERNS: Dict[str, str] = {
    "urls": r"(?i)\b(?:https?|ftps?|wss?)://[^\s\"'<>\x00-\x1f]{3,}",
    "emails": r"[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,}",
    "ipv4": r"(?:^|[^A-Za-z0-9._-])([0-9]+(?:\.[0-9A-Za-z_-]+)+)",
    "unix_paths": (r"(?:^|[^A-Za-z0-9._+@~/-])"
                   rf"((?:[A-Za-z][A-Za-z0-9+.-]*://[^\s/]*)?(?:/{_PATH_SEG})+/?)"),
    "windows_paths": r"[A-Za-z]:\\[^\s\"<>|*?\x00-\x1f]+|\\\\[A-Za-z0-9._-]+\\[^\s\"<>|*?\x00-\x1f]+",
    "executables": rf"(?i)\b{_FILE_STEM}\.(?:exe|dll|sys|dylib|so(?:\.[0-9]+)*)\b",
    "archives": rf"(?i)\b{_FILE_STEM}\.(?:zip|tar|tgz|gz|bz2|xz|7z|rar|jar|war|apk|deb|rpm|cab)\b",
    "pem_markers": r"-----(?:BEGIN|END) [A-Z0-9 ]+-----",
    "hex_run": r"(?:^|[^0-9A-Za-z_])([0-9A-Za-z_]{32,})",
    "base64": r"(?:^|[^A-Za-z0-9+/_-])([A-Za-z0-9+/_-]{24,}={0,2})",
}

#: ``kind -> ((mode, RE2 pattern), ...)``; a candidate is kept iff every rule holds.
IOC_FILTERS: Dict[str, Tuple[Tuple[str, str], ...]] = {
    "ipv4": (("full", rf"(?:{_OCTET}\.){{3}}{_OCTET}"),),
    "unix_paths": (
        ("full", rf"(?:(?:/{_PATH_SEG}){{2,}}/?|/(?:{_PATH_ROOTS})/?)"),
        ("has", r"[A-Za-z]"),
    ),
    "hex_run": (("full", r"(?:[0-9A-Fa-f]{2}){16,}"),),
    "base64": (
        ("full", rf"(?:{_B64}{{4}})*(?:{_B64}{{2}}(?:==)?|{_B64}{{3}}=?)?"),
        ("has", r"[g-zG-Z+/]"),
        ("has", r"[A-Z]"), ("has", r"[a-z]"), ("has", r"[0-9+/]"),
        ("not", r"ABCDEFGH|abcdefgh|01234567|^/"),
    ),
}

_COMPILED: Dict[str, "re.Pattern[str]"] = {k: re.compile(p) for k, p in IOC_PATTERNS.items()}
_RULES = {k: tuple((m, re.compile(p)) for m, p in rules) for k, rules in IOC_FILTERS.items()}


def _keeps(kind: str, candidate: str) -> bool:
    """Whether ``candidate`` satisfies every filter rule of ``kind`` (always, if it has none)."""
    checks = {"full": lambda rx: rx.fullmatch(candidate), "has": lambda rx: rx.search(candidate),
              "not": lambda rx: not rx.search(candidate)}
    return all(checks[mode](rx) for mode, rx in _RULES.get(kind, ()))


def _found(kind: str, value: str) -> List[str]:
    return [c for c in _COMPILED[kind].findall(value) if _keeps(kind, c)]


def ioc_kinds(value: str) -> List[str]:
    """The IOC columns that match somewhere in ``value``."""
    return [kind for kind in _COMPILED if _found(kind, value)]


def ioc_matches(value: str) -> Dict[str, List[str]]:
    """``kind -> matched substrings`` for the kinds that match (Python-side twin of the SQL)."""
    found = {kind: _found(kind, value) for kind in _COMPILED}
    return {kind: hits for kind, hits in found.items() if hits}


#: Well-known OID arcs found in key / certificate material (``prefix -> meaning``).
OID_PREFIXES: Dict[str, str] = {
    # "1.2.840" and "2.16.840" are real OID arcs but are deliberately absent:
    # 840 is not a valid IPv4 octet, so no ipv4 hit can ever carry them.
    "1.3.6.1": "internet",
    "1.3.101": "Ed25519 / X25519 / 448",
    "1.3.132": "SECG curves",
    "2.5.4": "X.520 attributes",
    "2.5.29": "X.509 extensions",
}

OID_LIKE = "oid_like"


def oid_prefix_of(candidate: str) -> Optional[str]:
    """The :data:`OID_PREFIXES` entry ``candidate`` is (or is under), when it is OID-shaped.

    OID-shaped = first arc 0-2 and, for arcs 0/1, second arc below 40 (ITU-T X.660). A hint
    only: a real address such as ``1.3.6.1`` stays an ``ipv4`` hit.
    """
    arcs = candidate.split(".")
    if not all(a.isdigit() for a in arcs) or int(arcs[0]) > 2:
        return None
    if int(arcs[0]) < 2 and int(arcs[1]) >= 40:
        return None
    return next((p for p in OID_PREFIXES
                 if candidate == p or candidate.startswith(p + ".")), None)


def oid_like_values(value: str) -> List[Tuple[str, str]]:
    """``(hit, oid_prefix)`` for every OID-shaped ``ipv4`` hit in ``value``."""
    shaped = ((hit, oid_prefix_of(hit)) for hit in _found("ipv4", value))
    return [(hit, prefix) for hit, prefix in shaped if prefix]


def ioc_ambiguity(value: str) -> Optional[Tuple[str, str]]:
    """``(ambiguity, oid_prefix)`` when EVERY ``ipv4`` hit in ``value`` is OID-shaped, else None.

    ``oid_prefix`` is the prefix of the first OID-like value. A row that also holds a
    real address (``peer 8.8.8.8 oid 1.3.6.1``) is not ambiguous; its OID-shaped hits are
    still listed by :func:`oid_like_values`. The saved SQL query ``strings_iocs`` does
    not carry this flag (it is applied only on the Python row path).
    """
    hits = _found("ipv4", value)
    like = oid_like_values(value)
    if hits and len(like) == len(hits):
        return OID_LIKE, like[0][1]
    return None


def _literal(pattern: str) -> str:
    return "'" + pattern.replace("'", "''") + "'"


_SQL_RULE = {"full": "regexp_full_match(x, {})", "has": "regexp_matches(x, {})",
             "not": "NOT regexp_matches(x, {})"}


def _column(kind: str, pattern: str) -> str:
    """The SQL column twin of :func:`_found`: group 1 when the pattern has one, then the rules."""
    group = ", 1" if _COMPILED[kind].groups == 1 else ""
    extract = f"regexp_extract_all(value, {_literal(pattern)}{group})"
    rules = [_SQL_RULE[m].format(_literal(p)) for m, p in IOC_FILTERS.get(kind, ())]
    if not rules:
        return f"{extract} AS {kind}"
    return f"list_filter({extract}, lambda x: {' AND '.join(rules)}) AS {kind}"


def _sql() -> str:
    columns = ",\n       ".join(_column(k, p) for k, p in IOC_PATTERNS.items())
    any_hit = " + ".join(f"len({k})" for k in IOC_PATTERNS)
    return (f"SELECT DISTINCT * FROM (\n"
            f"SELECT capture_id, addr, space, encoding, region_path, value,\n       {columns}\n"
            f"FROM {TABLE}\n) WHERE {any_hit} > 0\nORDER BY capture_id, addr, encoding")  # nosec B608 - constant table, fixed IOC columns, quoted literals


STRINGS_IOCS = SavedQuery(
    "strings_iocs",
    "Strings carrying indicators of compromise: one list column per kind "
    "(urls, emails, ipv4, unix_paths, windows_paths, executables, archives, "
    "pem_markers, hex_run, base64), only rows with at least one hit.",
    _sql(),
    {TABLE: PRODUCER})

QUERIES: Tuple[SavedQuery, ...] = (STRINGS_IOCS,)

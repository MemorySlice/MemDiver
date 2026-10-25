"""YARA editor producers: check a rule, scan ONE dump's captured bytes with it.

The ``yara.*`` capabilities. They are the editor-shaped sibling of
``analysis.yara_scan`` (:func:`memdiver.app.tools_pipeline.scan_yara_rule`),
which is a corpus census over N dumps and has no notion of a window, a capture
gap or a virtual address. This module reuses its compiler
(:func:`memdiver.engine.yara_scan.compile_rules`, so the rule cache, the size
guard and the refusal of precompiled ``.yarc`` all apply) and the key finders'
scan plan (:mod:`memdiver.app.tools_keyfinders`), so both honour the same
rules:

* **Coverage is part of the answer; absent bytes are never zeros.** Only
  CAPTURED runs are read, one VA-contiguous run at a time. A pattern that would
  straddle a capture gap is not found rather than found in invented zeros, and
  ``coverage`` reports bytes scanned, runs scanned and gaps skipped.
* **Every address carries its coordinate system** (``space`` + ``location``,
  plus ``va`` and ``vas_offset``), so a client never has to derive one.
* **Truncation says so.** A ``limit`` that cuts the rows sets ``truncated`` and
  stops the scan (``complete: false``); a libyara timeout or a short read does
  the same, naming its reason.
* **A zero is only an absence when it is proven.** A wildcard pattern wider
  than the installed libyara will verify matches NOTHING without any error (see
  :func:`memdiver.engine.yara_scan.regexp_scan_limit`); both producers report
  it in ``warnings`` so a dead rule is not read as "not in this dump".

The rule's ``condition`` is evaluated once per read window (at most
``WINDOW_BYTES``), so a condition that depends on ``filesize`` sees the window,
not the dump.
"""

from __future__ import annotations

import re
from typing import Any, Callable, Dict, List, Optional

from memdiver.app import tools_keyfinders as _tk
from memdiver.core.service_errors import CapabilityError, ErrorCategory
from memdiver.core.service_result import ServiceResult

#: Rows a scan returns before it stops and reports ``truncated``.
DEFAULT_LIMIT = 1_000
#: libyara budget per read window, in seconds.
DEFAULT_TIMEOUT_S = 30
#: Bytes of each hit kept as a hex preview (the true width is ``length``).
PREVIEW_BYTES = 32
#: Error code the compiler wraps a libyara compile failure in.
COMPILE_FAILED = "yara.compile_failed"

_LINE_RE = re.compile(r"line (\d+):\s*(.*)", re.S)


def _compile(rule_source: str):
    if not isinstance(rule_source, str) or not rule_source.strip():
        raise CapabilityError("rule_source is required", category=ErrorCategory.INVALID_INPUT,
                              code="yara.rule_required")
    from memdiver.engine.yara_scan import compile_rules
    return compile_rules(source=rule_source)


def _errors_of(exc: CapabilityError, rule_source: Optional[str] = None) -> List[Dict[str, Any]]:
    """libyara's message as ``[{line, message, ...}]`` (``line`` is ``None`` when it names none).

    Given the *rule_source*, the error is placed on the token that is wrong
    (:func:`memdiver.engine.yara_diagnostics.locate`): ``line`` / ``column`` /
    ``end_column`` are precise, ``reported_line`` keeps libyara's own line,
    ``relocated`` says whether a token was found, ``rule`` / ``hint`` add context.
    """
    from memdiver.engine.yara_diagnostics import locate

    text = str(exc)
    body = text.split("): ", 1)[1] if "): " in text else text
    found = _LINE_RE.search(body)
    reported = int(found.group(1)) if found else None
    if reported is not None and reported < 1:
        reported = None          # libyara's "line 0" names no line
    message = found.group(2).strip() if found else body.strip()
    where = locate(rule_source or "", reported, message)
    return [{"line": where["line"], "message": message, "column": where["column"],
             "end_column": where["end_column"], "reported_line": reported,
             "relocated": where["relocated"], "rule": where["rule"], "hint": where["hint"]}]


def _warnings(rule_source: str) -> List[Dict[str, Any]]:
    """A wildcard pattern wider than libyara verifies is a rule that can never match."""
    from memdiver.engine.yara_scan import measure_hex_string_widths, regexp_scan_limit

    widths, unmeasured = measure_hex_string_widths(rule_source)
    limit = regexp_scan_limit()
    out: List[Dict[str, Any]] = []
    if limit is not None and widths and max(widths) > limit:
        out.append({"code": "yara.pattern_over_scan_limit", "severity": "warning",
                    "details": {"pattern_length": max(widths), "scan_limit": limit},
                    "message": (f"a wildcard hex string is {max(widths)} bytes wide, over the "
                                f"{limit} bytes the installed libyara will verify: it matches "
                                "NOTHING, so zero hits here is not an absence")})
    if unmeasured:
        out.append({"code": "yara.pattern_unmeasured", "severity": "info",
                    "details": {"blocks": unmeasured},
                    "message": (f"{unmeasured} wildcard hex string(s) use jumps, alternation or "
                                "negation and could not be checked against the scan limit")})
    return out


def yara_check_result(rule_source: Optional[str] = None, rule_name: Optional[str] = None,
                      case_dir: Optional[str] = None) -> "ServiceResult":
    """Compile *rule_source* without scanning: ``valid`` plus the errors with their lines.

    A rule that does not compile is an ANSWER, not a failure: ``valid: false`` and
    ``errors: [{line, message}]`` (``line`` is 1-based, ``None`` if libyara names none).
    Only an unusable request (empty or oversized source, yara-python missing) raises.
    ``rule_name`` (+ ``case_dir``) checks a STORED rule instead of ``rule_source`` (give
    exactly one); the result then echoes ``rule_name`` and ``scope``.
    """
    from memdiver.app.tools_yara_rules import resolve_rule_source
    from memdiver.engine.yara_scan import regexp_scan_limit, rule_names

    rule_source, origin = resolve_rule_source(rule_source, rule_name, case_dir)
    try:
        rules = _compile(rule_source)
    except CapabilityError as exc:
        if exc.code != COMPILE_FAILED:
            raise
        return ServiceResult.ok({"valid": False, "rule_names": [], "errors": _errors_of(exc, rule_source),
                                 "warnings": [], **(origin or {})})
    return ServiceResult.ok({"valid": True, "rule_names": list(rule_names(rules)), "errors": [],
                             "warnings": _warnings(rule_source),
                             "scan_limit": regexp_scan_limit(), **(origin or {})})


class _Tally:
    """What a scan did, beyond its rows."""

    def __init__(self) -> None:
        self.rows: List[Dict[str, Any]] = []
        self.matched_rules: set = set()
        self.errors: List[str] = []
        self.bytes_scanned = 0
        self.runs_scanned = 0
        self.short_reads = 0
        self.timed_out = False
        self.truncated = False


def _row(plan: Any, regions: Any, seg: Any, window: int, rule: str, tags: Any,
         string_id: str, instance: Any) -> Dict[str, Any]:
    rel = window + instance.offset
    addr = seg.addr + rel
    location = plan.location(addr)
    va = None if seg.va is None else seg.va + rel
    data = bytes(instance.matched_data)
    return {"rule": rule, "tags": list(tags), "string_id": string_id, "addr": addr,
            "space": location.space.value, "location": location.to_dict(),
            "length": int(instance.matched_length), "matched_hex": data[:PREVIEW_BYTES].hex(),
            "va": va, "vas_offset": seg.vas + rel, "region": regions.at(va)}


def _scan_window(plan: Any, rules: Any, regions: Any, seg: Any, window: int, last: bool,
                 timeout_s: int, tally: _Tally, limit: int) -> None:
    import yara

    step = _tk.WINDOW_BYTES - _tk.WINDOW_OVERLAP
    want = min(_tk.WINDOW_BYTES, seg.length - window)
    data = plan.source.read_range(seg.vas + window, want, plan.read_view)
    tally.short_reads += int(len(data) < want)      # never pad: scan only what came back
    owned = len(data) if last else min(step, len(data))
    try:
        found = rules.match(data=bytes(data), timeout=timeout_s)
    except yara.TimeoutError:
        tally.timed_out = True
        tally.errors.append(f"window at {seg.addr + window:#x} timed out after {timeout_s}s; "
                            f"its {owned} bytes are unscanned")
        return
    except yara.Error as exc:
        tally.errors.append(f"window at {seg.addr + window:#x} failed: {exc}")
        return
    tally.bytes_scanned += owned
    fresh = []
    for match in found:
        tally.matched_rules.add(match.rule)
        for string in match.strings:
            for instance in string.instances:
                if last or instance.offset < step:
                    fresh.append((instance.offset, match.rule, string.identifier, match.tags,
                                  instance))
    for _, rule, string_id, tags, instance in sorted(fresh, key=lambda f: f[:3]):
        if len(tally.rows) >= limit:
            tally.truncated = True
            return
        tally.rows.append(_row(plan, regions, seg, window, rule, tags, string_id, instance))


def _scan_plan(plan: Any, rules: Any, timeout_s: int, limit: int,
               progress: Optional[Callable[[float, str], None]] = None,
               cancel: Optional[Callable[[], bool]] = None) -> _Tally:
    """Scan every captured run window by window.

    ``progress(fraction, text)`` fires after each window (bytes scanned over the captured
    bytes in scope, held below 1.0). ``cancel()`` is polled before each window; a cancelled
    scan raises ``CapabilityError(code="cancelled")`` so it can never be read as complete.
    """
    tally, regions = _Tally(), _tk._regions_of(plan)
    total = sum(s.length for s in plan.segments)
    for seg in plan.segments:
        tally.runs_scanned += 1
        for window in _tk._windows(seg):
            if cancel is not None and cancel():
                raise CapabilityError("yara scan cancelled", category=ErrorCategory.PRECONDITION,
                                      code="cancelled")
            last = window + min(_tk.WINDOW_BYTES, seg.length - window) >= seg.length
            _scan_window(plan, rules, regions, seg, window, last, timeout_s, tally, limit)
            if progress is not None:
                progress(min(tally.bytes_scanned / max(total, 1), 0.99), "scanning")
            if tally.truncated:
                return tally
    return tally


def _incomplete_reason(tally: _Tally) -> Optional[str]:
    if tally.truncated:
        return "truncated"
    if tally.timed_out:
        return "timed_out"
    if tally.errors:
        return "errors"
    return "short_reads" if tally.short_reads else None


def yara_scan_dump_result(
    dump_path: str, rule_source: Optional[str] = None, view: Optional[str] = None,
    offset: Optional[int] = None, length: Optional[int] = None,
    limit: int = DEFAULT_LIMIT, timeout_s: int = DEFAULT_TIMEOUT_S,
    rule_name: Optional[str] = None, case_dir: Optional[str] = None,
    progress: Optional[Callable[[float, str], None]] = None,
    cancel: Optional[Callable[[], bool]] = None,
) -> "ServiceResult":
    """Scan the CAPTURED bytes of one dump with a YARA rule.

    ``view`` / ``offset`` / ``length`` select the window in the view's coordinates
    (``va`` default for an ``.msl`` / ``.mdview``, ``vas`` also offered for an ``.msl``,
    ``raw`` for a flat file). Each row: ``rule``, ``string_id``, ``addr`` + ``space`` +
    ``location``, ``length``, ``matched_hex`` (first ``PREVIEW_BYTES`` bytes), ``va``,
    ``vas_offset``, ``region``. ``coverage``, ``truncated`` / ``complete`` /
    ``incomplete_reason``, ``errors`` and ``warnings`` are always present, and
    ``matched_rules`` names rules whose condition held (including rules with no strings).
    A rule that does not compile raises INVALID_INPUT (``yara.compile_failed``); use
    :func:`yara_check_result` to get the failing line instead. ``rule_name`` (+ ``case_dir``)
    scans with a STORED rule instead of ``rule_source`` (give exactly one); the result then
    echoes ``rule_name`` and ``scope``. ``progress`` / ``cancel`` are the job route's hooks
    (see :func:`_scan_plan`); a cancel raises ``CapabilityError`` with ``code="cancelled"``.
    """
    from memdiver.app.composition import raise_if_locked
    from memdiver.app.tools_yara_rules import resolve_rule_source
    from memdiver.core.dump_source import open_dump
    from memdiver.engine.yara_scan import rule_names

    if limit < 1 or timeout_s < 1:
        raise _tk._invalid("limit and timeout_s must be >= 1", "yara.bad_limit")
    if (offset is not None and offset < 0) or (length is not None and length < 1):
        raise _tk._invalid("offset must be >= 0 and length >= 1", "yara.bad_range")
    rule_source, origin = resolve_rule_source(rule_source, rule_name, case_dir)
    rules = _compile(rule_source)
    path = _tk._dump_file(dump_path)
    with open_dump(path) as source:
        raise_if_locked(source)
        plan = _tk._build_plan(source, path, view, offset, length)
        tally = _scan_plan(plan, rules, timeout_s, limit, progress, cancel)
    coverage = _tk._coverage(plan, _tk._Scan(bytes_scanned=tally.bytes_scanned,
                                             runs_scanned=tally.runs_scanned,
                                             short_reads=tally.short_reads), offset, length)
    return ServiceResult.ok({
        "dump_path": str(path), "format": source.format_name, "view": plan.view,
        "space": plan.location(0).space.value, "capture_id": plan.capture_id,
        "rule_names": list(rule_names(rules)), "matched_rules": sorted(tally.matched_rules),
        "rows": tally.rows, "row_count": len(tally.rows), "limit": limit,
        "truncated": tally.truncated, "timed_out": tally.timed_out,
        "complete": _incomplete_reason(tally) is None,
        "incomplete_reason": _incomplete_reason(tally), "errors": tally.errors,
        "warnings": _warnings(rule_source), "coverage": coverage, **(origin or {}),
    })


__all__ = ["DEFAULT_LIMIT", "DEFAULT_TIMEOUT_S", "yara_check_result", "yara_scan_dump_result"]

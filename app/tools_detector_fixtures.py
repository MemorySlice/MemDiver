"""Detector fixtures: run, add, list, remove (plan T3.7, D13).

The ``detector_fixtures.*`` capabilities. This generalises the oracle smoke test
(:mod:`memdiver.app.oracle_smoke_test`: a positive control and decoys with a
known-correct verdict, so "the detector finds nothing" cannot be mistaken for
"the detector works") to YARA rules and key finders, in the shape the vol3 plugin
fixtures established (:mod:`memdiver.app.tools_vol3_fixtures`): stored in the case,
a ``pass`` / ``fail`` / ``indeterminate`` verdict, the newest one kept as
``last_verdict``. The stores are shared with the vol3 fixtures (the safe-directory,
archive-on-overwrite and atomic-write primitives of the plugin store); the
PREDICATES are not, because a vol3 predicate asserts table rows and a detector
fixture asserts byte offsets in a sample.

Verdict vocabulary — the same words, so one UI badge shows both:

* ``pass`` — every fixture held (positives found exactly where expected, decoys
  silent);
* ``fail`` — a fixture was contradicted: a missing or extra match, or a detector
  that does not compile / raises on the sample;
* ``indeterminate`` — nothing could be proven: NO fixtures apply (never a silent
  pass), the sample could not be read (or was not wholly captured: a padded byte
  is never evidence), or the YARA engine is unavailable.

A key-finder fixture runs the registry algorithm over the sample bytes with the
fixture's ``params`` (call-level ``params`` win). A YARA fixture names a RULE; the
rule text under test is the ``artifact`` of the run, so a fixture keeps applying as
the rule is edited. Offsets are relative to the sample.
"""

from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Sequence, Tuple

from memdiver.analysis.detector_fixture_store import (
    ARTIFACT_KINDS,
    DetectorFixtureStore,
    decoded_inline_sample,
    validated_fixture,
)
from memdiver.analysis.detector_fixtures_bundled import bundled_fixtures
from memdiver.core.service_errors import CapabilityError, ErrorCategory
from memdiver.core.service_result import ServiceResult

PASS, FAIL, INDETERMINATE = "pass", "fail", "indeterminate"
NO_FIXTURES = "no_fixtures"
YARA_TIMEOUT_S = 30
#: Errors that mean "could not evaluate", not "the detector is wrong".
_UNEVALUABLE = (ErrorCategory.NOT_FOUND, ErrorCategory.UNSUPPORTED, ErrorCategory.PRECONDITION)


class _Unevaluable(Exception):
    """A fixture whose verdict cannot be decided (reported as ``indeterminate``)."""

    def __init__(self, reason: str, code: str) -> None:
        super().__init__(reason)
        self.code = code


def _invalid(message: str, code: str) -> CapabilityError:
    return CapabilityError(message, category=ErrorCategory.INVALID_INPUT, code=code)


def _store(case_dir: str) -> DetectorFixtureStore:
    from memdiver.app.tools_case import _open
    return DetectorFixtureStore(_open(case_dir).dir)


def _check_kind(artifact_kind: str) -> None:
    if artifact_kind not in ARTIFACT_KINDS:
        raise _invalid(f"artifact_kind must be one of {', '.join(ARTIFACT_KINDS)}",
                       "detector_fixture.bad_kind")


# -- samples ------------------------------------------------------------------


def _capture_bytes(sample: Dict[str, Any]) -> bytes:
    """The bytes of a capture range; refuses a range the dump did not wholly capture."""
    from memdiver.core.dump_source import open_dump, read_range_with_validity
    path, length = Path(str(sample["dump_path"])).expanduser(), int(sample["length"])
    try:
        with open_dump(path) as source:
            view = sample.get("view") or ("vas" if hasattr(source, "captured_runs") else "raw")
            data, runs = read_range_with_validity(source, int(sample["offset"]), length, view)
    except (OSError, ValueError, RuntimeError) as exc:
        raise _Unevaluable(f"cannot read the capture sample: {exc}",
                           "detector_fixture.sample_unreadable") from exc
    if len(data) != length or runs != [(0, length)]:
        raise _Unevaluable("the sample range is not wholly captured (short read or padded "
                           "bytes); padding is never evidence", "detector_fixture.sample_padded")
    return data


def _sample_bytes(fixture: Dict[str, Any]) -> bytes:
    sample = fixture["sample"]
    return _capture_bytes(sample) if "dump_path" in sample else decoded_inline_sample(sample)


# -- running a detector over bytes --------------------------------------------


def _observed_keyfinder(finder: str, params: Dict[str, Any], data: bytes) -> List[Dict[str, Any]]:
    from memdiver.algorithms.base import AnalysisContext
    from memdiver.app.tools_keyfinders import _finders
    context = AnalysisContext(library="", protocol_version="", phase="", extra=dict(params))
    try:
        matches = _finders()[finder].run(data, context).matches
    except Exception as exc:   # a finder that raises on valid bytes is a broken finder
        raise _Broken(f"{finder} raised {type(exc).__name__}: {exc}", "keyfinder.raised") from exc
    return [{"offset": m.offset, "length": m.length, "label": m.label,
             "key_hex": m.metadata.get("key_hex")} for m in matches]


class _Broken(Exception):
    """The artifact under test is itself wrong (reported as ``fail``)."""

    def __init__(self, reason: str, code: str) -> None:
        super().__init__(reason)
        self.code = code


def _observed_yara(rules: Any, rule: str, data: bytes) -> List[Dict[str, Any]]:
    import yara

    from memdiver.engine.yara_scan import _extract_matches
    try:
        raw = rules.match(data=data, timeout=YARA_TIMEOUT_S)
    except yara.TimeoutError as exc:
        raise _Unevaluable(f"libyara timed out after {YARA_TIMEOUT_S}s", "yara.timeout") from exc
    return [{"offset": m.offset, "length": m.length, "label": m.rule, "string_id": m.string_id,
             "key_hex": m.matched_hex}
            for m in _extract_matches(raw, chunk_start=0, own_len=None) if m.rule == rule]


# -- comparing ----------------------------------------------------------------


def _satisfies(expected: Dict[str, Any], seen: Dict[str, Any]) -> bool:
    if expected["offset"] != seen["offset"]:
        return False
    if "length" in expected and expected["length"] != seen["length"]:
        return False
    if "key_hex" in expected and str(expected["key_hex"]).lower() != str(seen["key_hex"]).lower():
        return False
    labels = {seen.get("label"), seen.get("string_id")}
    return "label" not in expected or expected["label"] in labels


def _compare(expect: Dict[str, Any], observed: List[Dict[str, Any]]
             ) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
    """``(missing expected, unexpected observed)`` — an observed match satisfies one expectation."""
    remaining = list(observed)
    missing: List[Dict[str, Any]] = []
    for want in expect.get("matches", []):
        hit = next((s for s in remaining if _satisfies(want, s)), None)
        if hit is None:
            missing.append(want)
        else:
            remaining.remove(hit)
    return missing, remaining


# -- one fixture --------------------------------------------------------------


def _result(fixture: Dict[str, Any], verdict: str, **extra: Any) -> Dict[str, Any]:
    return {"fixture": fixture["name"], "source": fixture.get("source", "inline"),
            "artifact_kind": fixture["artifact_kind"], "artifact": fixture["artifact"],
            "verdict": verdict, "reason": None, "reason_code": None, "expected": fixture["expect"],
            "observed": [], "missing": [], "unexpected": [], **extra}


def _judge(fixture: Dict[str, Any], observed: List[Dict[str, Any]]) -> Dict[str, Any]:
    missing, unexpected = _compare(fixture["expect"], observed)
    verdict = PASS if not missing and not unexpected else FAIL
    reason = None
    if verdict == FAIL:
        reason = (f"{len(missing)} expected match(es) not found" if missing else "") + \
                 ("; " if missing and unexpected else "") + \
                 (f"{len(unexpected)} unexpected match(es)" if unexpected else "")
    return _result(fixture, verdict, reason=reason, observed=observed, missing=missing,
                   unexpected=unexpected)


def _run_one(fixture: Dict[str, Any], detect: Callable[[Dict[str, Any], bytes], List[Dict[str, Any]]]
             ) -> Dict[str, Any]:
    try:
        return _judge(fixture, detect(fixture, _sample_bytes(fixture)))
    except _Unevaluable as exc:
        return _result(fixture, INDETERMINATE, reason=str(exc), reason_code=exc.code)
    except _Broken as exc:
        return _result(fixture, FAIL, reason=str(exc), reason_code=exc.code)
    except CapabilityError as exc:
        if exc.category in _UNEVALUABLE:
            return _result(fixture, INDETERMINATE, reason=str(exc), reason_code=exc.code)
        raise


# -- detectors ----------------------------------------------------------------


def _keyfinder_detector(finder: str, call_params: Dict[str, Any]):
    def detect(fixture: Dict[str, Any], data: bytes) -> List[Dict[str, Any]]:
        return _observed_keyfinder(finder, {**fixture["params"], **call_params}, data)
    return detect


def _yara_detector(rules: Any):
    def detect(fixture: Dict[str, Any], data: bytes) -> List[Dict[str, Any]]:
        return _observed_yara(rules, fixture["artifact"], data)
    return detect


def _compiled_rules(source: str) -> Tuple[Any, Tuple[str, ...], Optional[Dict[str, Any]]]:
    """``(rules, rule names, None)`` or ``(None, (), failure)`` when the rule is broken."""
    from memdiver.engine.yara_scan import compile_rules, rule_names
    try:
        rules = compile_rules(source=source)
    except CapabilityError as exc:
        if exc.code == "yara.compile_failed":
            return None, (), {"reason": str(exc), "reason_code": exc.code}
        raise
    return rules, rule_names(rules), None


# -- fixture selection --------------------------------------------------------


def _inline(fixtures: Sequence[Dict[str, Any]], artifact_kind: str,
            default_artifact: Optional[str]) -> List[Dict[str, Any]]:
    out = []
    for index, item in enumerate(fixtures):
        if not isinstance(item, dict):
            raise _invalid(f"fixtures[{index}] must be an object", "detector_fixture.bad_fixture")
        merged = {"name": f"inline_{index}", "artifact_kind": artifact_kind,
                  "artifact": default_artifact, **item}
        out.append({**validated_fixture(
            merged["name"], merged["artifact_kind"], merged["artifact"] or "",
            merged.get("sample"), merged.get("expect"), merged.get("params")),
            "source": "inline"})
    return out


def _applicable(artifact_kind: str, targets: Sequence[str], case: Optional[DetectorFixtureStore]
                ) -> List[Dict[str, Any]]:
    """Bundled then stored fixtures whose ``artifact`` is one of ``targets``."""
    chosen: List[Dict[str, Any]] = []
    for target in targets:
        chosen.extend(bundled_fixtures(artifact_kind, target))
    if case is not None:
        chosen.extend({**f, "source": "stored"} for f in case.list()
                      if f.get("artifact_kind") == artifact_kind and f.get("artifact") in targets)
    return chosen


def _overall(results: List[Dict[str, Any]]) -> Tuple[str, Optional[str], Optional[str]]:
    if not results:
        return INDETERMINATE, "no fixtures apply to this detector: nothing was proven", NO_FIXTURES
    verdicts = {r["verdict"] for r in results}
    if FAIL in verdicts:
        return FAIL, f"{sum(r['verdict'] == FAIL for r in results)} fixture(s) failed", None
    if INDETERMINATE in verdicts:
        return INDETERMINATE, "a fixture could not be evaluated", None
    return PASS, None, None


def _overall_key(artifact_kind: str, artifact: str) -> str:
    stem = artifact if artifact_kind == "keyfinder" else hashlib.sha256(
        artifact.encode("utf-8")).hexdigest()[:12]
    return f"overall_{artifact_kind}_{stem}"


def _record(case: DetectorFixtureStore, results: List[Dict[str, Any]], key: str,
            summary: Dict[str, Any], default_run: bool) -> bool:
    """Persist verdicts of a DEFAULT run only; True when anything was stored.

    An inline fixture or a call-level ``params`` override is not the stored fixture of
    the same name, so it must never overwrite that fixture's ``last_verdict``; the
    whole-detector verdict goes to its own namespace.
    """
    if not default_run:
        return False
    for item in results:
        if item["source"] != "inline":
            case.put_verdict(item["fixture"], {k: item[k] for k in ("verdict", "reason", "source")})
    case.put_overall_verdict(key, summary)
    return True


# -- producers ----------------------------------------------------------------


def detector_fixtures_run_result(
    artifact_kind: str, artifact: str, fixtures: Optional[List[Dict[str, Any]]] = None,
    params: Optional[Dict[str, Any]] = None, case_dir: Optional[str] = None,
) -> "ServiceResult":
    """Run the fixtures of one detector; verdict ``pass`` / ``fail`` / ``indeterminate``.

    ``artifact`` is a key-finder name (``artifact_kind="keyfinder"``) or the YARA
    rule SOURCE under test (``"yara"``). ``fixtures`` (inline definitions) replaces
    the default selection — the bundled fixtures plus, with ``case_dir``, the stored
    ones that name this finder / one of this source's rules. ``params`` override each
    key-finder fixture's own params. With ``case_dir`` the verdicts are stored
    (``recorded``) and reported later as ``last_verdict``.
    """
    _check_kind(artifact_kind)
    if not isinstance(artifact, str) or not artifact.strip():
        raise _invalid("artifact is required (a finder name or YARA rule source)",
                       "detector_fixture.bad_artifact")
    case = _store(case_dir) if case_dir else None
    if artifact_kind == "keyfinder":
        results = _run_keyfinder(artifact, fixtures, params or {}, case)
        failure: Optional[Dict[str, Any]] = None
    else:
        results, failure = _run_yara(artifact, fixtures, case)
    verdict, reason, code = _overall(results)
    if failure is not None:
        verdict, reason, code = FAIL, failure["reason"], failure["reason_code"]
    summary = {"verdict": verdict, "reason": reason, "reason_code": code}
    recorded = case is not None and _record(
        case, results, _overall_key(artifact_kind, artifact), summary,
        default_run=fixtures is None and not params)
    counts = {v: sum(r["verdict"] == v for r in results) for v in (PASS, FAIL, INDETERMINATE)}
    return ServiceResult.ok({
        "artifact_kind": artifact_kind,
        "artifact": artifact if artifact_kind == "keyfinder" else None,
        **summary, "counts": {**counts, "total": len(results)}, "results": results,
        "recorded": recorded})


def _run_keyfinder(finder: str, fixtures: Optional[List[Dict[str, Any]]],
                   params: Dict[str, Any], case: Optional[DetectorFixtureStore]
                   ) -> List[Dict[str, Any]]:
    from memdiver.app.tools_keyfinders import _finders
    if finder not in _finders():
        raise _invalid(f"unknown key finder {finder!r}; choose one of: "
                       f"{', '.join(sorted(_finders()))}", "keyfinders.unknown_finder")
    selected = (_inline(fixtures, "keyfinder", finder) if fixtures is not None
                else _applicable("keyfinder", [finder], case))
    detect = _keyfinder_detector(finder, params)
    return [_run_one(f, detect) for f in selected]


def _run_yara(source: str, fixtures: Optional[List[Dict[str, Any]]],
              case: Optional[DetectorFixtureStore]
              ) -> Tuple[List[Dict[str, Any]], Optional[Dict[str, Any]]]:
    rules, names, failure = _compiled_rules(source)
    if failure is not None:
        return [], failure
    default = names[0] if len(names) == 1 else None
    selected = (_inline(fixtures, "yara", default) if fixtures is not None
                else _applicable("yara", names, case))
    detect = _yara_detector(rules)
    results = []
    for fixture in selected:
        if fixture["artifact"] not in names:
            results.append(_result(fixture, FAIL, reason=f"the rule source has no rule "
                                   f"{fixture['artifact']!r}", reason_code="yara.rule_missing"))
        else:
            results.append(_run_one(fixture, detect))
    return results, None


def detector_fixtures_add_result(
    case_dir: str, name: str, artifact_kind: str, artifact: str, sample: Dict[str, Any],
    expect: Dict[str, Any], params: Optional[Dict[str, Any]] = None,
) -> "ServiceResult":
    """Store a fixture at ``<case>/fixtures/detectors/<name>.json`` (validated, versioned).

    ``artifact`` is a key-finder name or a YARA RULE name. ``sample`` is
    ``{"hex"}`` | ``{"base64"}`` | ``{"dump_path", "offset", "length"[, "view"]}``;
    ``expect`` is ``{"matches": [{"offset", "length"?, "label"?, "key_hex"?}]}`` or
    ``{"no_match": true}`` (a decoy). A name used by a bundled fixture is refused.
    """
    fixture = validated_fixture(name, artifact_kind, artifact, sample, expect, params)
    if any(b["name"] == name for b in bundled_fixtures("keyfinder", "aes_schedule")):
        raise _invalid(f"{name!r} is the name of a bundled fixture; choose another",
                       "detector_fixture.name_reserved")
    return ServiceResult.ok(_store(case_dir).put(fixture))


def detector_fixtures_list_result(
    case_dir: Optional[str] = None, artifact_kind: Optional[str] = None,
    artifact: Optional[str] = None,
) -> "ServiceResult":
    """Bundled and (with ``case_dir``) stored fixtures, each with ``last_verdict`` or ``None``.

    ``artifact_kind`` / ``artifact`` (a finder or YARA rule name) narrow the list.
    """
    if artifact_kind is not None:
        _check_kind(artifact_kind)
    case = _store(case_dir) if case_dir else None
    verdicts = case.verdicts() if case else {}
    rows = [{**b, "source": "bundled"} for b in bundled_fixtures("keyfinder", "aes_schedule")]
    rows += [{**f, "source": "stored"} for f in (case.list() if case else [])]
    rows = [{**r, "last_verdict": verdicts.get(r["name"])} for r in rows
            if artifact_kind in (None, r["artifact_kind"]) and artifact in (None, r["artifact"])]
    return ServiceResult.ok({"case_dir": case_dir, "fixtures": rows, "count": len(rows)})


def detector_fixtures_remove_result(case_dir: str, name: str) -> "ServiceResult":
    """Retire a stored fixture (its definition is archived under ``history/``, never lost)."""
    return ServiceResult.ok(_store(case_dir).remove(name))

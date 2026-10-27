"""Case-scoped store of detector fixtures: YARA rules and key finders (plan T3.7, D13).

A detector fixture is the byte-level sibling of the vol3 plugin fixture
(:mod:`memdiver.analysis.fixture_store`): where a plugin fixture asserts rows of
a table, a detector fixture asserts WHERE a detector fires in a sample::

    {name, artifact_kind: "yara" | "keyfinder", artifact, params, sample, expect}

* ``artifact`` — a key-finder registry name, or a YARA *rule name* (the rule text
  under test is supplied at run time, so a fixture survives edits of the rule);
* ``params`` — key-finder ``extra`` parameters (ignored for YARA);
* ``sample`` — exactly one of ``{"hex": ...}``, ``{"base64": ...}`` or
  ``{"dump_path": ..., "offset": N, "length": N[, "view": ...]}`` (a capture
  range; the field is named ``dump_path`` so the REST read-path sandbox sees it);
* ``expect`` — ``{"matches": [{"offset", "length"?, "label"?, "key_hex"?}, ...]}``
  (offsets are relative to the sample) or ``{"no_match": true}`` (a decoy).

Files live at ``<case>/fixtures/detectors/<name>.json``; the newest verdict of a
fixture at ``<case>/fixtures/detectors/verdicts/<name>.json``. The safety posture
(identifier names, no symlinks, 0600 atomic writes, an overwrite or a removal
archives the previous definition under ``history/``) is the plugin store's,
imported rather than copied.
"""

from __future__ import annotations

import base64
import binascii
import json
from pathlib import Path
from typing import Any, Dict, List, Optional

from memdiver.analysis.plugin_store import (
    FILE_MODE,
    HISTORY_DIR,
    archive_previous,
    json_dicts_in,
    put_versioned_json,
    read_json_dict,
    safe_directory,
    safe_file,
    store_error,
    validate_name,
)
from memdiver.analysis.record import utc_now
from memdiver.core.artifact_util import atomic_write_text
from memdiver.core.service_errors import ErrorCategory

FIXTURES_SUBPATH = "fixtures/detectors"
VERDICTS_SUBPATH = "fixtures/detectors/verdicts"
#: Whole-detector verdicts live in their own directory, never beside the per-fixture ones,
#: so no fixture name can collide with (or forge) an overall verdict.
OVERALL_VERDICTS_SUBPATH = "fixtures/detectors/verdicts/overall"
ARTIFACT_KINDS = ("yara", "keyfinder")
MAX_INLINE_SAMPLE_BYTES = 1024 * 1024
MAX_CAPTURE_SAMPLE_BYTES = 16 * 1024 * 1024
_MATCH_KEYS = ("offset", "length", "label", "key_hex")


def _is_int(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def validated_sample(sample: Any) -> Dict[str, Any]:
    """The sample when it is one well-formed form; INVALID_INPUT otherwise."""
    if not isinstance(sample, dict):
        raise store_error("sample must be an object", "detector_fixture.bad_sample")
    forms = [k for k in ("hex", "base64", "dump_path") if k in sample]
    if len(forms) != 1:
        raise store_error("sample needs exactly one of hex, base64 or dump_path",
                          "detector_fixture.bad_sample")
    form = forms[0]
    if form == "dump_path":
        if not str(sample["dump_path"]).strip() or not _is_int(sample.get("offset")) \
                or not _is_int(sample.get("length")) or sample["offset"] < 0 \
                or not 0 < sample["length"] <= MAX_CAPTURE_SAMPLE_BYTES:
            raise store_error("a capture sample needs dump_path, offset >= 0 and "
                              f"0 < length <= {MAX_CAPTURE_SAMPLE_BYTES}",
                              "detector_fixture.bad_sample")
        return dict(sample)
    if len(decoded_inline_sample(sample)) > MAX_INLINE_SAMPLE_BYTES:
        raise store_error(f"inline sample over {MAX_INLINE_SAMPLE_BYTES} bytes",
                          "detector_fixture.sample_too_large")
    return {form: str(sample[form])}


def decoded_inline_sample(sample: Dict[str, Any]) -> bytes:
    """The bytes of a ``hex`` / ``base64`` sample; INVALID_INPUT when undecodable."""
    try:
        if "hex" in sample:
            return bytes.fromhex(str(sample["hex"]))
        return base64.b64decode(str(sample["base64"]), validate=True)
    except (ValueError, binascii.Error) as exc:
        raise store_error(f"sample is not valid {'hex' if 'hex' in sample else 'base64'}: {exc}",
                          "detector_fixture.bad_sample") from exc


def validated_expect(expect: Any) -> Dict[str, Any]:
    """``{"no_match": True}`` or ``{"matches": [...]}`` (non-empty, known keys only)."""
    if not isinstance(expect, dict):
        raise store_error("expect must be an object", "detector_fixture.bad_expect")
    if expect.get("no_match") is True and "matches" not in expect:
        return {"no_match": True}
    matches = expect.get("matches")
    if "no_match" in expect or not isinstance(matches, list) or not matches:
        raise store_error('expect is {"no_match": true} or {"matches": [non-empty list]}',
                          "detector_fixture.bad_expect")
    clean: List[Dict[str, Any]] = []
    for index, item in enumerate(matches):
        if not isinstance(item, dict) or not _is_int(item.get("offset")) or item["offset"] < 0 \
                or set(item) - set(_MATCH_KEYS):
            raise store_error(f"expect.matches[{index}] needs an integer offset >= 0 and only "
                              f"{', '.join(_MATCH_KEYS)}", "detector_fixture.bad_expect")
        clean.append(dict(item))
    return {"matches": clean}


def validated_fixture(name: str, artifact_kind: str, artifact: str, sample: Any, expect: Any,
                      params: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """A normalised fixture definition (without store metadata)."""
    validate_name(name, "detector_fixture")
    if artifact_kind not in ARTIFACT_KINDS:
        raise store_error(f"artifact_kind must be one of {', '.join(ARTIFACT_KINDS)}",
                          "detector_fixture.bad_kind")
    if not isinstance(artifact, str) or not artifact.strip():
        raise store_error("artifact (finder name or YARA rule name) is required",
                          "detector_fixture.bad_artifact")
    if params is not None and not isinstance(params, dict):
        raise store_error("params must be an object", "detector_fixture.bad_params")
    return {"name": name, "artifact_kind": artifact_kind, "artifact": artifact.strip(),
            "params": dict(params or {}), "sample": validated_sample(sample),
            "expect": validated_expect(expect)}


class DetectorFixtureStore:
    """The ``fixtures/detectors/`` directory of one case."""

    def __init__(self, case_dir: Path) -> None:
        self._case_dir = Path(case_dir)

    def _dir(self, create: bool) -> Path:
        return safe_directory(self._case_dir, FIXTURES_SUBPATH, create=create)

    def _verdict_dir(self, create: bool) -> Path:
        return safe_directory(self._case_dir, VERDICTS_SUBPATH, create=create)

    def put(self, fixture: Dict[str, Any]) -> Dict[str, Any]:
        """Store a validated fixture (see :func:`validated_fixture`); returns it with metadata."""
        path = safe_file(self._dir(create=True), f"{fixture['name']}.json")
        return put_versioned_json(path, fixture["name"], fixture)

    def get(self, name: str) -> Dict[str, Any]:
        validate_name(name, "detector_fixture")
        path = safe_file(self._dir(create=False), f"{name}.json")
        body = read_json_dict(path)
        if body is None:
            raise store_error(f"no stored detector fixture {name!r}",
                              "detector_fixture.not_found", ErrorCategory.NOT_FOUND)
        return {**body, "path": str(path)}

    def list(self) -> List[Dict[str, Any]]:
        return [{**body, "path": str(path)}
                for path, body in json_dicts_in(self._dir(create=False))]

    def remove(self, name: str) -> Dict[str, Any]:
        """Retire a fixture: its definition is archived under ``history/`` first."""
        stored = self.get(name)
        directory = self._dir(create=False)
        path = safe_file(directory, f"{name}.json")
        archive_previous(path, directory / HISTORY_DIR, name, ".json",
                         path.read_text(encoding="utf-8"))
        path.unlink()
        return {"name": name, "removed": True, "archived_version": stored.get("version")}

    def put_verdict(self, name: str, verdict: Dict[str, Any]) -> None:
        """Overwrite the newest verdict of fixture ``name`` (verdicts are not archived)."""
        validate_name(name, "detector_fixture")
        directory = self._verdict_dir(create=True)
        body = {**verdict, "fixture": name, "created": utc_now()}
        atomic_write_text(safe_file(directory, f"{name}.json"),
                          json.dumps(body, indent=2, sort_keys=True) + "\n", mode=FILE_MODE)

    def put_overall_verdict(self, key: str, verdict: Dict[str, Any]) -> None:
        """Overwrite the newest whole-detector verdict (separate namespace from fixtures)."""
        validate_name(key, "detector_fixture")
        directory = safe_directory(self._case_dir, OVERALL_VERDICTS_SUBPATH, create=True)
        body = {**verdict, "detector": key, "created": utc_now()}
        atomic_write_text(safe_file(directory, f"{key}.json"),
                          json.dumps(body, indent=2, sort_keys=True) + "\n", mode=FILE_MODE)

    def overall_verdicts(self) -> Dict[str, Dict[str, Any]]:
        """Newest whole-detector verdict per key."""
        directory = safe_directory(self._case_dir, OVERALL_VERDICTS_SUBPATH, create=False)
        return {path.stem: body for path, body in json_dicts_in(directory)}

    def verdicts(self) -> Dict[str, Dict[str, Any]]:
        """Newest verdict per fixture name."""
        return {path.stem: body for path, body in json_dicts_in(self._verdict_dir(create=False))}

"""Transport-free logic of the opt-in READ-path sandbox.

``api/path_policy.py`` (REST) and ``mcp_server/path_guard.py`` (MCP) both apply
the policy described there; this module owns the parts that need no web
framework: which argument names carry server paths, how to walk an argument
tree for them, which roots are admitted implicitly, and the one denial message.

The policy is OFF unless ``MEMDIVER_ALLOWED_ROOTS`` is set (callers pass an
empty root list then, and every helper here admits everything).
"""

from __future__ import annotations

import os
import tempfile
from pathlib import Path
from typing import Any, Iterable, Iterator, Optional

from memdiver.core.service_errors import CapabilityError, ErrorCategory

#: Argument names (query params / JSON keys / MCP tool parameters, at any depth)
#: that carry a filesystem path the server will READ.
READ_PATH_KEYS = frozenset({
    "path", "paths", "dump_path", "dump_paths", "msl_path", "anchor_path",
    "additional_paths", "source_paths", "selected_dump_paths", "pcap_path",
    "root", "library_dir", "library_dirs", "input_path", "dataset_root",
    "variance_path", "plugin_path", "rule_paths", "case_dir",
    "image_path", "view_path", "isf",
    "isf_path", "against_isf", "ground_truth", "type_hints_isf",
    "capture_id", "keylog_path", "per_dump",
    "model_path", "needles", "related", "key_material_by_path",
    "key_file", "kem_key_file", "maps_path", "oracle_config_path",
    "oracle_path", "hits_path", "candidates_path", "raw_path",
    # reference_path (MCP search_reduce/brute_force/emit_plugin/auto_floor) and
    # reference_dump (REST /api/pipeline/auto-floor) are opened server-side;
    # ``dumps`` (aligned-window / consensus) holds paths (ints are indices and
    # are skipped); ``state_path`` is the brute-force Welford state read.
    "reference_path", "reference_dump", "dumps", "state_path",
})

#: Argument names that carry a filesystem path the server will WRITE. REST
#: confines these itself (upload dir / case roots); the MCP guard confines them
#: to the sandbox roots when the sandbox is ON (policy OFF: unrestricted).
WRITE_PATH_KEYS = frozenset({
    "out_path", "output_path", "out_dir", "output_dir", "candidates_out",
})

#: Keys whose value is a mapping ``{path: path}``: BOTH keys and values are paths.
PATH_MAPPING_KEYS = frozenset({"per_dump"})

#: Keys whose value is a mapping whose KEYS (at the given nesting depth) are
#: paths and whose values are not: ``needles`` = ``{dump_path: hex}``,
#: ``related`` = ``{name: {dump_path: hex}}`` (depth 2), ``key_material_by_path``
#: = ``{dump_path: {key_file, ...}}`` (the inner ``key_file`` is its own key).
PATH_KEYED_MAPPINGS = {"needles": 1, "related": 2, "key_material_by_path": 1}

#: Keys whose value is usually NOT a path (a bare case name / a sha256): admitted
#: as is; only a path-shaped value goes through the sandbox.
NAME_OR_PATH_KEYS = frozenset({"case_dir", "capture_id"})

ADMIT_HOW_TO = (
    "add its directory to MEMDIVER_ALLOWED_ROOTS (os.pathsep-separated), or add it "
    "as a favourite in the file browser"
)

#: Where the server process was started; captured ONCE at import (the sandbox
#: admits it so a relative path typed in the launch directory keeps working).
STARTUP_CWD = os.getcwd()


def temp_roots() -> list[str]:
    """The system temp dir (plus ``$TMPDIR``); resolution adds macOS ``/private/...``."""
    roots = [tempfile.gettempdir()]
    if os.environ.get("TMPDIR"):
        roots.append(os.environ["TMPDIR"])
    return roots


def implicit_roots() -> list[str]:
    """Roots admitted whenever the sandbox is on: startup cwd + temp dirs."""
    return [STARTUP_CWD, *temp_roots()]


def resolve_roots(raw_roots: Iterable[str]) -> list[Path]:
    """Resolve and de-duplicate *raw_roots* (order preserved)."""
    roots: list[Path] = []
    for raw in raw_roots:
        resolved = Path(raw).expanduser().resolve(strict=False)
        if resolved not in roots:
            roots.append(resolved)
    return roots


def within(candidate: Path, roots: Iterable[Path]) -> bool:
    return any(candidate == root or candidate.is_relative_to(root) for root in roots)


def denial_message(path: str | Path, roots: Iterable[Path]) -> str:
    """The actionable text of a read-sandbox denial."""
    listed = ", ".join(str(r) for r in roots) or "(none)"
    return (
        f"read path {str(path)!r} is outside the read sandbox "
        f"(MEMDIVER_ALLOWED_ROOTS is set). Admitted roots: {listed}. "
        f"To admit it, {ADMIT_HOW_TO}."
    )


def admit(path: str | Path, roots: list[Path]) -> Path:
    """Return *path* resolved, or raise a 403 ``CapabilityError`` if outside *roots*.

    An empty *roots* (sandbox off) passes the path through unresolved.
    """
    candidate = Path(path).expanduser()
    if not roots:
        return candidate
    resolved = candidate.resolve(strict=False)
    if not within(resolved, roots):
        raise CapabilityError(
            denial_message(path, roots), category=ErrorCategory.PRECONDITION,
            status=403, code="path.outside_sandbox")
    return resolved


def is_path_shaped(key: str, value: str) -> bool:
    """True when *value* under *key* must be sandbox-checked."""
    if key not in NAME_OR_PATH_KEYS:
        return True
    return "/" in value or "\\" in value or value.startswith((".", "~"))


def _mapping_keys(value: Any, depth: int) -> Iterator[str]:
    """The dict keys *depth* levels down (1 = this dict's own keys)."""
    if not isinstance(value, dict):
        return
    for key, child in value.items():
        if depth <= 1:
            if isinstance(key, str) and key.strip():
                yield key
        else:
            yield from _mapping_keys(child, depth - 1)


def iter_path_values(value: Any, key_matches: "bool | str") -> Iterator[str]:
    """Yield every non-blank string under a READ_PATH_KEYS key, recursively."""
    if isinstance(value, dict) and key_matches in PATH_MAPPING_KEYS:
        for key, child in value.items():
            yield from iter_path_values(key, key_matches)
            yield from iter_path_values(child, key_matches)
    elif isinstance(value, dict) and key_matches in PATH_KEYED_MAPPINGS:
        yield from _mapping_keys(value, PATH_KEYED_MAPPINGS[str(key_matches)])
        if key_matches == "key_material_by_path":
            yield from iter_path_values(value, False)
    elif key_matches in PATH_KEYED_MAPPINGS:
        return  # a path-keyed mapping field holding a non-mapping: nothing to check
    elif isinstance(value, dict):
        for key, child in value.items():
            yield from iter_path_values(child, key if key in READ_PATH_KEYS else False)
    elif isinstance(value, list):
        for child in value:
            yield from iter_path_values(child, key_matches)
    elif key_matches and isinstance(value, str) and value.strip():
        if is_path_shaped(str(key_matches), value):
            yield value


def iter_write_values(value: Any) -> Iterator[str]:
    """Yield every non-blank string under a WRITE_PATH_KEYS key, recursively."""
    if isinstance(value, dict):
        for key, child in value.items():
            if key in WRITE_PATH_KEYS and isinstance(child, str) and child.strip():
                yield child
            else:
                yield from iter_write_values(child)
    elif isinstance(value, list):
        for child in value:
            yield from iter_write_values(child)


def check_write_arguments(arguments: Optional[dict], roots: list[Path]) -> None:
    """Admit every write path named in an argument mapping under *roots*."""
    if not roots or not arguments:
        return
    for value in iter_write_values(arguments):
        admit(value, roots)


def check_arguments(arguments: Optional[dict], roots: list[Path]) -> None:
    """Admit every read path named in an argument mapping; raise on the first denial."""
    if not roots or not arguments:
        return
    for value in iter_path_values(arguments, False):
        admit(value, roots)

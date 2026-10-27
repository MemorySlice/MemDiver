"""Append-only JSONL store for :class:`~memdiver.analysis.record.AnalysisEntry`.

One file per capture: ``<case_dir>/annotations/<capture_id>.jsonl``. Nothing is
ever rewritten or deleted; a correction is a new entry whose ``supersedes``
names the old one, a withdrawal is a ``retraction`` entry.

Semantics (plan T1.5, D6/D9):

* ``append`` writes exactly one line with a single ``write`` call on a file
  opened in append mode, under a per-path lock, so concurrent threads never
  interleave a line. It refuses a ``supersedes`` id that is not in that
  capture's file.
* ``append_many`` files a batch: it reads each capture's existing ids once,
  runs the same duplicate / ``supersedes`` checks in batch order (a later
  entry may supersede an earlier one of the same batch; a repeated id in the
  batch is a ``duplicate_entry_id``), and only when EVERY entry passes writes
  all lines with one ``write`` per file under the same per-path locks. A
  failing entry raises the error the sequential ``append`` loop would have
  raised for it, but nothing of the batch is written (all-or-nothing).
  ``append(e)`` is ``append_many([e])[0]``.
* Superseding an entry that is already superseded is ALLOWED: two entries may
  supersede the same parent (a branch). :meth:`AnalysisRecord.latest` returns
  every chain tip, so a branch yields two tips, and along any single chain the
  last writer wins because only the tip is current.
* A corrupt line raises :class:`CapabilityError` naming file and line number;
  it is never skipped.
* Cross-process appends rely on ``O_APPEND`` atomicity for single small writes;
  the lock only serialises threads.
"""

from __future__ import annotations

import json
import threading
from contextlib import ExitStack
from pathlib import Path
from typing import Dict, List, Optional, Sequence, Set, Tuple

from memdiver.analysis.record import RETRACTION, AnalysisEntry, _CAPTURE_ID
from memdiver.core.service_errors import CapabilityError, ErrorCategory

ANNOTATIONS_DIR = "annotations"
_SUFFIX = ".jsonl"

_locks: Dict[str, threading.Lock] = {}
_locks_guard = threading.Lock()


def _lock_for(path: Path) -> threading.Lock:
    key = str(path)
    with _locks_guard:
        return _locks.setdefault(key, threading.Lock())


def _invalid(message: str, code: str = "invalid_analysis_entry") -> CapabilityError:
    return CapabilityError(message, category=ErrorCategory.INVALID_INPUT, code=code)


def _not_found(capture_id: str, entry_id: str) -> CapabilityError:
    return CapabilityError(
        f"no entry {entry_id!r} in capture {capture_id!r}",
        category=ErrorCategory.NOT_FOUND, code="analysis_entry_not_found")


class AnalysisRecord:
    """The analysis record of one case directory."""

    def __init__(self, case_dir: Path) -> None:
        self.case_dir = Path(case_dir)

    # -- paths ---------------------------------------------------------------

    def path_for(self, capture_id: str) -> Path:
        if not _CAPTURE_ID.match(capture_id or ""):
            raise _invalid(f"invalid capture_id {capture_id!r}", "invalid_capture_id")
        return self.case_dir / ANNOTATIONS_DIR / f"{capture_id}{_SUFFIX}"

    def captures(self) -> List[str]:
        folder = self.case_dir / ANNOTATIONS_DIR
        if not folder.is_dir():
            return []
        return sorted(p.name[:-len(_SUFFIX)] for p in folder.glob(f"*{_SUFFIX}"))

    # -- writing -------------------------------------------------------------

    def append(self, entry: AnalysisEntry) -> AnalysisEntry:
        return self.append_many([entry])[0]

    def append_many(self, entries: Sequence[AnalysisEntry]) -> List[AnalysisEntry]:
        """Validate the whole batch in order, then write it (all-or-nothing).

        Raises the same error, for the same entry, as ``for e in entries:
        append(e)`` would, but then nothing of the batch has been written.
        """
        batch = list(entries)
        paths, path_error = self._paths_of(batch)
        with ExitStack() as stack:
            for path in sorted(set(paths), key=str):
                stack.enter_context(_lock_for(path))
            known: Dict[Path, Set[str]] = {}
            for entry, path in zip(batch, paths):
                if path not in known:
                    known[path] = {e.id for e in _read_file(path)}
                _check_supersedes(known[path], entry)
            if path_error is not None:
                raise path_error
            for path, group in _grouped(batch, paths).items():
                _write_lines(path, group)
        return batch

    def _paths_of(self, batch: Sequence[AnalysisEntry]
                  ) -> Tuple[List[Path], Optional[CapabilityError]]:
        """Each entry's file, stopping at the first invalid ``capture_id`` (its error)."""
        paths: List[Path] = []
        for entry in batch:
            try:
                paths.append(self.path_for(entry.capture_id))
            except CapabilityError as exc:
                return paths, exc
        return paths, None

    # -- reading -------------------------------------------------------------

    def entries(self, capture_id: str, kind: Optional[str] = None) -> List[AnalysisEntry]:
        """Every entry of a capture in file order, optionally of one ``kind``."""
        found = _read_file(self.path_for(capture_id))
        return [e for e in found if kind is None or e.kind == kind]

    def latest(self, capture_id: str, kind: Optional[str] = None) -> List[AnalysisEntry]:
        """Current entries: chain tips, minus retractions and what they withdrew."""
        everything = self.entries(capture_id)
        superseded: Set[str] = {e.supersedes for e in everything if e.supersedes}
        return [e for e in everything
                if e.id not in superseded and e.kind != RETRACTION
                and (kind is None or e.kind == kind)]

    def get(self, capture_id: str, entry_id: str) -> AnalysisEntry:
        for entry in self.entries(capture_id):
            if entry.id == entry_id:
                return entry
        raise _not_found(capture_id, entry_id)

    def history(self, capture_id: str, entry_id: str) -> List[AnalysisEntry]:
        """The supersede chain through ``entry_id``, oldest first.

        Walks back to the chain's root, then forward through the most recently
        appended child at each step (last writer wins on a branch).
        """
        by_id = {e.id: e for e in self.entries(capture_id)}
        if entry_id not in by_id:
            raise _not_found(capture_id, entry_id)
        chain = _ancestors(by_id, entry_id)
        return chain + _descendants(list(by_id.values()), entry_id)


def _check_supersedes(existing: Set[str], entry: AnalysisEntry) -> None:
    """Refuse a duplicate id or an unknown parent; on success ``existing`` gains the id."""
    if entry.id in existing:
        raise _invalid(f"entry id {entry.id!r} already exists", "duplicate_entry_id")
    if entry.supersedes is not None and entry.supersedes not in existing:
        raise _invalid(
            f"supersedes {entry.supersedes!r}: no such entry in capture "
            f"{entry.capture_id!r}", "unknown_supersedes")
    existing.add(entry.id)


def _grouped(batch: Sequence[AnalysisEntry], paths: Sequence[Path]
             ) -> Dict[Path, List[AnalysisEntry]]:
    groups: Dict[Path, List[AnalysisEntry]] = {}
    for entry, path in zip(batch, paths):
        groups.setdefault(path, []).append(entry)
    return groups


def _write_lines(path: Path, group: Sequence[AnalysisEntry]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "a", encoding="utf-8") as handle:
        handle.write("".join(e.to_json_line() + "\n" for e in group))


def _ancestors(by_id: Dict[str, AnalysisEntry], entry_id: str) -> List[AnalysisEntry]:
    chain: List[AnalysisEntry] = []
    current: Optional[str] = entry_id
    while current is not None:
        entry = by_id[current]
        chain.append(entry)
        current = entry.supersedes
    chain.reverse()
    return chain


def _descendants(ordered: List[AnalysisEntry], entry_id: str) -> List[AnalysisEntry]:
    chain: List[AnalysisEntry] = []
    current = entry_id
    while True:
        children = [e for e in ordered if e.supersedes == current]
        if not children:
            return chain
        chain.append(children[-1])
        current = children[-1].id


def _read_file(path: Path) -> List[AnalysisEntry]:
    if not path.is_file():
        return []
    out: List[AnalysisEntry] = []
    with open(path, "r", encoding="utf-8") as handle:
        for number, line in enumerate(handle, start=1):
            if line.strip():
                out.append(_parse_line(path, number, line))
    return out


def _parse_line(path: Path, number: int, line: str) -> AnalysisEntry:
    try:
        return AnalysisEntry.from_dict(json.loads(line))
    except (ValueError, KeyError, TypeError) as exc:
        raise CapabilityError(
            f"corrupt analysis record {path} line {number}: {exc}",
            category=ErrorCategory.INTERNAL, code="analysis_record_corrupt",
            details={"file": str(path), "line": number}) from exc

"""Cross-reference resolver for linked MSL dump files."""

import logging
from dataclasses import dataclass, field
from enum import IntEnum
from pathlib import Path
from typing import Dict, List, Optional
from uuid import UUID

from .hashing import hash_file
from .reader import MslReader

_ZERO_HASH = b"\x00" * 32

logger = logging.getLogger("memdiver.msl.xref_resolver")


class Relationship(IntEnum):
    """MSL dump relationship types (spec Table 15)."""
    PARENT_PROCESS = 0x01
    CHILD_PROCESS = 0x02
    SIBLING_PROCESS = 0x03
    SAME_PROCESS_LATER = 0x04
    SAME_PROCESS_EARLIER = 0x05


@dataclass
class XrefEntry:
    """A resolved cross-reference between two MSL dumps.

    `target_hash` carries the 32-byte BLAKE3 digest pinned by the
    RELATED_DUMP block at index time. `hash_verified` reflects the
    result of the optional re-hash performed by `XrefResolver.resolve`:
    True/False when verification ran, None when it didn't (no target
    file on disk, or no pinned hash).
    """
    source_uuid: UUID
    source_path: Path
    target_uuid: UUID
    target_path: Optional[Path]  # None if unresolved
    relationship: int
    related_pid: int
    target_hash: bytes = field(default_factory=lambda: b"\x00" * 32)
    hash_verified: Optional[bool] = None


class XrefResolver:
    """Build and resolve cross-references across a directory of MSL files."""

    def __init__(self):
        self._uuid_to_path: Dict[UUID, Path] = {}
        self._entries: List[XrefEntry] = []

    def index_file(self, path: Path) -> None:
        """Add a single MSL file to the UUID index and collect its related dump entries."""
        try:
            reader = MslReader(path)
            reader.open()
            try:
                file_uuid = reader.file_header.dump_uuid
                self._uuid_to_path[file_uuid] = path

                for related in reader.collect_related_dumps():
                    self._entries.append(XrefEntry(
                        source_uuid=file_uuid,
                        source_path=path,
                        target_uuid=related.related_dump_uuid,
                        target_path=None,
                        relationship=related.relationship,
                        related_pid=related.related_pid,
                        target_hash=related.target_hash,
                    ))
            finally:
                reader.close()
        except Exception as exc:
            logger.debug("Skipping %s: %s", path, exc)

    def index_directory(self, directory: Path) -> int:
        """Scan directory for .msl files and build index. Returns count of files indexed."""
        count = 0
        for msl_file in sorted(directory.rglob("*.msl")):
            self.index_file(msl_file)
            count += 1
        return count

    def resolve(self, verify: bool = False) -> List[XrefEntry]:
        """Resolve all cross-references, populating target_path from the UUID index.

        When *verify* is True, re-hash each resolved target file via
        streamed reads and compare against the pinned `target_hash`,
        setting `hash_verified` to True on match or False on mismatch.
        Entries whose target_path is None or whose pinned hash is
        all-zero are left with `hash_verified=None`. A per-call cache
        keyed on target_path ensures hub-and-spoke graphs hash each
        unique target only once.
        """
        digest_cache: Dict[Path, bytes] = {}
        for entry in self._entries:
            entry.target_path = self._uuid_to_path.get(entry.target_uuid)
            if not verify:
                continue
            if entry.target_path is None or entry.target_hash == _ZERO_HASH:
                continue
            actual = digest_cache.get(entry.target_path)
            if actual is None:
                try:
                    actual = hash_file(entry.target_path)
                except OSError as exc:
                    logger.debug("verify: cannot read %s: %s",
                                 entry.target_path, exc)
                    continue
                digest_cache[entry.target_path] = actual
            entry.hash_verified = (actual == entry.target_hash)
        return list(self._entries)

    def get_related(self, dump_uuid: UUID) -> List[XrefEntry]:
        """Return all resolved entries where source_uuid matches."""
        return [e for e in self._entries if e.source_uuid == dump_uuid]

    def get_graph(self) -> Dict[UUID, List[UUID]]:
        """Return adjacency list of the relationship graph."""
        graph: Dict[UUID, List[UUID]] = {}
        for entry in self._entries:
            graph.setdefault(entry.source_uuid, []).append(entry.target_uuid)
        return graph

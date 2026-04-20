"""Session save/load for MemDiver analysis sessions."""

import datetime
import gzip
import json
import logging
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

logger = logging.getLogger("memdiver.engine.session_store")

CURRENT_SCHEMA_VERSION = 1
_MAGIC = "_memdiver_session"
_EXT = ".memdiver"


@dataclass
class SessionSnapshot:
    """Serializable session state snapshot."""

    schema_version: int = CURRENT_SCHEMA_VERSION
    memdiver_version: str = ""
    created_at: str = ""
    session_name: str = ""

    # Input config
    input_mode: str = ""
    input_path: str = ""
    dataset_root: str = ""
    keylog_filename: str = ""
    template_name: str = ""

    # Selections
    protocol_name: str = ""
    protocol_version: str = ""
    scenario: str = ""
    selected_libraries: List[str] = field(default_factory=list)
    selected_phase: str = ""
    algorithm: str = ""
    mode: str = "testing"
    max_runs: int = 10
    normalize_phases: bool = False

    # File-specific
    single_file_format: str = ""
    ground_truth_mode: str = "auto"

    # Analysis results (serialized)
    analysis_result: Optional[Dict[str, Any]] = None

    # Algorithm selection
    selected_algorithms: List[str] = field(default_factory=list)

    # Investigation state
    bookmarks: List[Dict[str, Any]] = field(default_factory=list)
    investigation_offset: Optional[int] = None


class SessionStore:
    """Save and load MemDiver session snapshots."""

    @staticmethod
    def save(snapshot: SessionSnapshot, path: Path,
             compress: bool = True) -> Path:
        """Serialize snapshot to a .memdiver file."""
        data = {_MAGIC: True}
        data.update(asdict(snapshot))
        payload = json.dumps(data, indent=2, default=str)
        path = Path(path)
        if not path.suffix:
            path = path.with_suffix(_EXT)
        path.parent.mkdir(parents=True, exist_ok=True)
        if compress:
            path.write_bytes(gzip.compress(payload.encode("utf-8")))
        else:
            path.write_text(payload)
        logger.info("Session saved to %s", path)
        return path

    @staticmethod
    def load(path: Path) -> SessionSnapshot:
        """Deserialize a .memdiver file into a SessionSnapshot."""
        raw = Path(path).read_bytes()
        if raw[:2] == b"\x1f\x8b":  # gzip magic
            text = gzip.decompress(raw).decode("utf-8")
        else:
            text = raw.decode("utf-8")
        data = json.loads(text)
        if not data.get(_MAGIC):
            raise ValueError("Not a MemDiver session file")
        if data.get("schema_version", 0) > CURRENT_SCHEMA_VERSION:
            raise ValueError(
                f"Session file version {data['schema_version']} "
                f"is newer than supported {CURRENT_SCHEMA_VERSION}"
            )
        data.pop(_MAGIC, None)
        return SessionSnapshot(**{
            k: v for k, v in data.items()
            if k in SessionSnapshot.__dataclass_fields__
        })

    @staticmethod
    def delete(name: str, directory: Optional[Path] = None) -> Path:
        """Delete a saved session file by stem name.

        Args:
            name: Session stem (no extension).
            directory: Session directory. Defaults to ``default_dir()``.

        Returns:
            The path that was deleted.

        Raises:
            FileNotFoundError: if no matching session file exists.
        """
        d = Path(directory) if directory else SessionStore.default_dir()
        path = d / f"{name}{_EXT}"
        if not path.is_file():
            raise FileNotFoundError(f"Session not found: {name}")
        path.unlink()
        logger.info("Session deleted: %s", path)
        return path

    @staticmethod
    def default_dir() -> Path:
        """Return default session directory."""
        from core.constants import memdiver_home
        d = memdiver_home() / "sessions"
        d.mkdir(parents=True, exist_ok=True)
        return d

    @staticmethod
    def auto_save_path(name: str = "") -> Path:
        """Generate a timestamped session file path."""
        ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        fname = f"{name}_{ts}" if name else f"session_{ts}"
        return SessionStore.default_dir() / f"{fname}{_EXT}"

    @staticmethod
    def list_sessions(directory: Path = None) -> List[Dict[str, str]]:
        """List available session files with basic metadata.

        Uses lightweight parsing — extracts only header fields without
        constructing full SessionSnapshot objects.
        """
        d = Path(directory) if directory else SessionStore.default_dir()
        if not d.exists():
            return []
        sessions = []
        for f in sorted(d.glob(f"*{_EXT}"), reverse=True):
            try:
                raw = f.read_bytes()
                text = gzip.decompress(raw).decode("utf-8") if raw[:2] == b"\x1f\x8b" else raw.decode("utf-8")
                data = json.loads(text)
                if data.get(_MAGIC):
                    sessions.append({
                        "path": str(f),
                        "name": f.stem,
                        "display_name": data.get("session_name") or f.stem,
                        "created_at": data.get("created_at", ""),
                        "mode": data.get("mode", ""),
                        "input_mode": data.get("input_mode", ""),
                        "input_path": data.get("input_path", ""),
                    })
            except Exception:
                sessions.append({"path": str(f), "name": f.stem,
                                 "display_name": f.stem,
                                 "created_at": "", "mode": "", "input_mode": "",
                                 "input_path": ""})
        return sessions


def snapshot_from_state(state) -> SessionSnapshot:
    """Create a SessionSnapshot from an AppState instance."""
    bookmarks = []
    if state.bookmarks:
        for b in state.bookmarks.bookmarks:
            bookmarks.append({
                "offset": b.offset, "length": b.length, "label": b.label,
            })
    # Serialize analysis result if present
    result_dict = None
    if state.analysis_result:
        try:
            from engine.serializer import serialize_result
            result_dict = serialize_result(state.analysis_result)
        except Exception:
            pass
    return SessionSnapshot(
        created_at=datetime.datetime.now().isoformat(),
        input_mode=getattr(state, "input_mode", ""),
        input_path=getattr(state, "input_path", ""),
        single_file_format=getattr(state, "single_file_format", ""),
        ground_truth_mode=getattr(state, "ground_truth_mode", "auto"),
        dataset_root=state.dataset_root,
        keylog_filename=state.keylog_filename,
        template_name=state.template_name,
        protocol_name=state.protocol_name,
        protocol_version=state.protocol_version,
        scenario=state.scenario,
        selected_libraries=state.selected_libraries,
        selected_phase=state.selected_phase,
        algorithm=state.algorithm,
        mode=state.mode,
        max_runs=state.max_runs,
        normalize_phases=state.normalize_phases,
        analysis_result=result_dict,
        bookmarks=bookmarks,
        investigation_offset=state.investigation_offset,
    )


def restore_state(state, snapshot: SessionSnapshot, mode_mgr=None):
    """Write SessionSnapshot values into a live AppState."""
    state.input_mode = snapshot.input_mode
    state.input_path = snapshot.input_path
    state.dataset_root = snapshot.dataset_root
    state.keylog_filename = snapshot.keylog_filename
    state.template_name = snapshot.template_name
    state.protocol_name = snapshot.protocol_name
    state.protocol_version = snapshot.protocol_version
    state.scenario = snapshot.scenario
    state.selected_libraries = list(snapshot.selected_libraries)
    state.selected_phase = snapshot.selected_phase
    state.algorithm = snapshot.algorithm
    state.mode = snapshot.mode
    state.max_runs = snapshot.max_runs
    state.normalize_phases = snapshot.normalize_phases
    state.investigation_offset = snapshot.investigation_offset
    state.single_file_format = getattr(snapshot, "single_file_format", "")
    state.ground_truth_mode = getattr(snapshot, "ground_truth_mode", "auto")
    if mode_mgr:
        mode_mgr.mode = snapshot.mode

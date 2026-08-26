"""ProjectDB - DuckDB + Ibis persistent analysis database."""

import datetime
import json
import logging
import os
import uuid
from pathlib import Path
from typing import Dict, List, Optional

from memdiver.core.install_hints import BASE_INSTALL_HINT

logger = logging.getLogger("memdiver.engine.project_db")

try:
    import duckdb
    import ibis
    HAS_DUCKDB = True
except ImportError:
    HAS_DUCKDB = False


def check_deps() -> Dict[str, bool]:
    """Check which optional dependencies are available.

    Reuses the module-level :data:`HAS_DUCKDB` probe (both ``duckdb`` and
    ``ibis`` are imported together there) rather than re-importing.
    """
    deps: Dict[str, object] = {"duckdb": HAS_DUCKDB, "ibis": HAS_DUCKDB}
    if HAS_DUCKDB:
        deps["duckdb_version"] = duckdb.__version__
        deps["ibis_version"] = ibis.__version__
    deps["ready"] = deps["duckdb"] and deps["ibis"]
    return deps

def default_db_path() -> Path:
    """Return default DB path (~/.memdiver/project.duckdb)."""
    from memdiver.core.constants import memdiver_home
    return memdiver_home() / "project.duckdb"

def install_hint() -> str:
    """Return a user-friendly install command string.

    DuckDB + Ibis are base dependencies, so a missing one is a broken
    environment rather than an un-installed extra; point at the repair.
    """
    return BASE_INSTALL_HINT

_SCHEMA_SQL = [
    "CREATE TABLE IF NOT EXISTS projects(project_id VARCHAR PRIMARY KEY, name VARCHAR, created_at VARCHAR, description VARCHAR DEFAULT '')",
    "CREATE TABLE IF NOT EXISTS dumps(dump_id VARCHAR PRIMARY KEY, project_id VARCHAR, file_path VARCHAR, file_type VARCHAR, file_size BIGINT, added_at VARCHAR, metadata_json VARCHAR DEFAULT '{}')",
    "CREATE TABLE IF NOT EXISTS analysis_runs(run_id VARCHAR PRIMARY KEY, project_id VARCHAR, dump_id VARCHAR, started_at VARCHAR, finished_at VARCHAR, status VARCHAR DEFAULT 'running', config_json VARCHAR DEFAULT '{}')",
    "CREATE TABLE IF NOT EXISTS findings(finding_id VARCHAR PRIMARY KEY, run_id VARCHAR, finding_type VARCHAR, \"offset\" BIGINT, \"length\" INTEGER, value_hex VARCHAR, value_text VARCHAR, confidence DOUBLE DEFAULT 1.0, metadata_json VARCHAR DEFAULT '{}', created_at VARCHAR)",
    "CREATE TABLE IF NOT EXISTS ground_truth(gt_id VARCHAR PRIMARY KEY, run_id VARCHAR, \"offset\" BIGINT, \"length\" INTEGER, key_hex VARCHAR, secret_type VARCHAR, cipher VARCHAR, confirmed_by VARCHAR, library VARCHAR, version VARCHAR, created_at VARCHAR)",
]

_now_iso = lambda: datetime.datetime.now(datetime.timezone.utc).isoformat()
_new_id = lambda: uuid.uuid4().hex


def _confirmed_by(hit: dict) -> Optional[str]:
    """Provenance label for a hit: the explicit one, else ``"verifier"`` if verified."""
    return hit.get("confirmed_by") or ("verifier" if hit.get("verified") else None)


def _finding_row_from_hit(hit: dict) -> dict:
    """Build a ``findings``-table row dict from a serialized hit dict.

    Shared by :meth:`ProjectDB.persist_report` and
    ``pipeline.AnalysisPipeline._persist_report`` so both persistence paths
    carry ``value_hex`` plus confirmed-key metadata identically (rather than
    diverging on whether the key bytes and confirmation marker are kept).

    The ``metadata`` field records whether the hit is a confirmed ground-truth
    key: ``confirmed`` (bool from ``verified``), ``confirmed_by`` (explicit
    label, else ``"verifier"`` when verified), and ``cipher``. ``None`` values
    are dropped.
    """
    metadata = {
        "confirmed": bool(hit.get("verified")),
        "confirmed_by": _confirmed_by(hit),
        "cipher": hit.get("cipher"),
    }
    metadata = {k: v for k, v in metadata.items() if v is not None}
    return {
        "finding_type": hit.get("secret_type", ""),
        "offset": hit.get("offset"),
        "length": hit.get("length"),
        "value_hex": hit.get("value_hex"),
        "value_text": hit.get("value_text"),
        "confidence": hit.get("confidence", 1.0),
        "metadata": metadata,
    }


class ProjectDB:
    """DuckDB-backed project database with Ibis query interface.

    Append-only for findings. Only ``finish_run`` performs an UPDATE.
    If DuckDB is not installed, all operations degrade gracefully to no-ops.
    """

    def __init__(self, db_path: Path):
        self._db_path = Path(db_path)
        self._conn = None
        self._ibis = None
        self._available = False

    def open(self) -> None:
        if not HAS_DUCKDB:
            logger.warning("DuckDB not installed — ProjectDB disabled"); return
        self._conn = duckdb.connect(str(self._db_path))
        for ddl in _SCHEMA_SQL: self._conn.execute(ddl)
        self._ibis = ibis.duckdb.from_connection(self._conn)
        self._available = True

    def close(self) -> None:
        if self._conn is not None: self._conn.close(); self._conn = None
        self._ibis = None; self._available = False

    def __enter__(self): self.open(); return self
    def __exit__(self, *args): self.close()

    # -- write (append-only) ---------------------------------------------

    def create_project(self, name: str, description: str = "") -> str:
        if not self._available: return ""
        pid = _new_id()
        self._conn.execute("INSERT INTO projects VALUES ($1,$2,$3,$4)",
                           [pid, name, _now_iso(), description])
        return pid

    def add_dump(self, project_id: str, file_path: Path, file_type: str) -> str:
        if not self._available: return ""
        did, p = _new_id(), Path(file_path)
        size = p.stat().st_size if p.exists() else 0
        self._conn.execute("INSERT INTO dumps VALUES ($1,$2,$3,$4,$5,$6,$7)",
                           [did, project_id, str(file_path), file_type, size, _now_iso(), "{}"])
        return did

    def start_run(self, project_id: str, dump_id: str = None, config: dict = None) -> str:
        if not self._available: return ""
        rid = _new_id()
        self._conn.execute("INSERT INTO analysis_runs VALUES ($1,$2,$3,$4,$5,$6,$7)",
                           [rid, project_id, dump_id or "", _now_iso(), None, "running",
                            json.dumps(config or {})])
        return rid

    def finish_run(self, run_id: str, status: str = "completed") -> None:
        if not self._available: return
        self._conn.execute("UPDATE analysis_runs SET status=$1, finished_at=$2 WHERE run_id=$3",
                           [status, _now_iso(), run_id])

    def add_finding(self, run_id: str, finding_type: str, offset: int = None,
                    length: int = None, value_hex: str = None, value_text: str = None,
                    confidence: float = 1.0, metadata: dict = None) -> str:
        if not self._available: return ""
        fid = _new_id()
        self._conn.execute("INSERT INTO findings VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)",
                           [fid, run_id, finding_type, offset, length, value_hex,
                            value_text, confidence, json.dumps(metadata or {}), _now_iso()])
        return fid

    def add_findings_batch(self, run_id: str, findings: list) -> int:
        """Bulk insert findings using executemany."""
        if not self._available or not findings:
            return 0
        ts = _now_iso()
        rows = [
            [_new_id(), run_id, f.get("finding_type", ""), f.get("offset"),
             f.get("length"), f.get("value_hex"), f.get("value_text"),
             f.get("confidence", 1.0), json.dumps(f.get("metadata", {})), ts]
            for f in findings
        ]
        self._conn.executemany(
            "INSERT INTO findings VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)", rows)
        return len(rows)

    def persist_report(self, result, persist_ground_truth_labels: bool = False) -> None:
        """Persist a serialized AnalysisResult dict with transaction wrapping.

        When *persist_ground_truth_labels* is True, each confirmed hit (those
        with ``verified``/``confirmed`` set) is additionally recorded in the
        opt-in ``ground_truth`` table as a first-class label. The default keeps
        the historical behavior of writing findings only.
        """
        if not self._available or result is None:
            return
        self._conn.execute("BEGIN TRANSACTION")
        try:
            for lib in result.get("libraries", []):
                name = f"{lib.get('library', 'unknown')}_{lib.get('protocol_version', '')}"
                pid = self.create_project(name)
                rid = self.start_run(pid, config={"phase": lib.get("phase", "")})
                hits = lib.get("hits", [])
                self.add_findings_batch(rid, [_finding_row_from_hit(h) for h in hits])
                if persist_ground_truth_labels:
                    confirmed = [h for h in hits if h.get("verified") or h.get("confirmed")]
                    self.persist_ground_truth(
                        rid, confirmed,
                        library=lib.get("library", ""),
                        version=lib.get("protocol_version", ""),
                    )
                self.finish_run(rid)
            self._conn.execute("COMMIT")
        except Exception:
            self._conn.execute("ROLLBACK")
            raise

    def persist_ground_truth(self, run_id: str, hits: list,
                             *, library: str = "", version: str = "") -> None:
        """Record confirmed key locations as first-class ground-truth labels.

        Inserts one ``ground_truth`` row per hit. No-op when DuckDB is absent
        or *hits* is empty. ``confirmed_by`` falls back to ``"verifier"`` when a
        hit is verified but carries no explicit label.
        """
        if not self._available or not hits:
            return
        ts = _now_iso()
        rows = [
            [_new_id(), run_id, h.get("offset"), h.get("length"),
             h.get("value_hex"), h.get("secret_type", ""), h.get("cipher"),
             _confirmed_by(h), library, version, ts]
            for h in hits
        ]
        self._conn.executemany(
            "INSERT INTO ground_truth VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)", rows)

    def record_ground_truth_run(self, hits: list, *, confirmed_by: str,
                                project_name: str = "oracle-run",
                                library: str = "", version: str = "") -> str:
        """File oracle/pcap-confirmed brute-force hits as ground-truth labels.

        The brute-force path owns confirmed hits but no project/run context, so
        this convenience wrapper creates a fresh project + run, normalizes the
        brute-force hit shape (``key_hex``) onto the ground_truth schema
        (``value_hex``), stamps every row with *confirmed_by*, and closes the
        run. Returns the run_id, or ``""`` when the DB is unavailable or there
        are no hits.
        """
        if not self._available or not hits:
            return ""
        pid = self.create_project(project_name)
        rid = self.start_run(pid, config={"source": confirmed_by})
        rows = [
            {
                "offset": h.get("offset"),
                "length": h.get("length"),
                "value_hex": h.get("value_hex") or h.get("key_hex"),
                "secret_type": h.get("secret_type", ""),
                "cipher": h.get("cipher"),
                "confirmed_by": confirmed_by,
                "verified": True,
            }
            for h in hits
        ]
        self.persist_ground_truth(rid, rows, library=library, version=version)
        self.finish_run(rid)
        return rid

    # -- read (Ibis) -----------------------------------------------------

    def get_project(self, project_id: str) -> Optional[dict]:
        if not self._available:
            return None
        t = self._ibis.table("projects")
        rows = t.filter(t.project_id == project_id).execute().to_dict("records")
        return rows[0] if rows else None

    def list_projects(self) -> List[dict]:
        if not self._available:
            return []
        return self._ibis.table("projects").order_by("created_at").execute().to_dict("records")

    def query_findings(self, run_id: str, finding_type: str = None) -> List[dict]:
        if not self._available:
            return []
        t = self._ibis.table("findings")
        expr = t.filter(t.run_id == run_id)
        if finding_type is not None:
            expr = expr.filter(t.finding_type == finding_type)
        return expr.order_by("created_at").execute().to_dict("records")

    def project_timeline(self, project_id: str) -> List[dict]:
        if not self._available:
            return []
        t = self._ibis.table("analysis_runs")
        return t.filter(t.project_id == project_id).order_by("started_at").execute().to_dict("records")

    def list_ground_truth(self, run_id: Optional[str] = None) -> List[dict]:
        """Return ground-truth key labels, optionally filtered by *run_id*."""
        if not self._available:
            return []
        t = self._ibis.table("ground_truth")
        expr = t if run_id is None else t.filter(t.run_id == run_id)
        return expr.order_by("created_at").execute().to_dict("records")

    def finding_counts(self, run_id: str) -> dict:
        if not self._available:
            return {}
        t = self._ibis.table("findings")
        f = t.filter(t.run_id == run_id)
        rows = f.group_by("finding_type").agg(count=f.count()).execute().to_dict("records")
        return {r["finding_type"]: r["count"] for r in rows}

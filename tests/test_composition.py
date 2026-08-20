"""Unit tests for the composition root ``app/composition.py``.

The composition root is purely additive wiring: it constructs the object
graphs (``ToolSession``, ``DatasetScanner``, ``AnalysisPipeline``, optional
``ProjectDB``) and re-exports the single dump-open / key-material import
surface. These tests pin the builder contracts and assert that the re-exports
are the *same* objects as their canonical homes (identity, not copies).
"""

from pathlib import Path

import memdiver.app.composition as composition


# ── build_tool_session ────────────────────────────────────────────────
def test_build_tool_session_returns_fresh_toolsession():
    from memdiver.app.session import ToolSession

    session = composition.build_tool_session()
    assert isinstance(session, ToolSession)


def test_build_tool_session_returns_distinct_instances():
    first = composition.build_tool_session()
    second = composition.build_tool_session()
    assert first is not second


# ── build_dataset_scanner ─────────────────────────────────────────────
def test_build_dataset_scanner_carries_root_and_keylog(tmp_path):
    from memdiver.core.discovery import DatasetScanner

    scanner = composition.build_dataset_scanner(tmp_path, "custom.csv")
    assert isinstance(scanner, DatasetScanner)
    assert scanner.root == tmp_path
    assert scanner.keylog_filename == "custom.csv"
    assert callable(scanner.fast_scan)


def test_build_dataset_scanner_default_keylog(tmp_path):
    scanner = composition.build_dataset_scanner(tmp_path)
    assert scanner.keylog_filename == "keylog.csv"


# ── build_analysis_pipeline ───────────────────────────────────────────
def test_build_analysis_pipeline_passes_project_db_and_defaults_auto_persist():
    sentinel = object()
    pipeline = composition.build_analysis_pipeline(project_db=sentinel)
    assert pipeline._project_db is sentinel
    assert pipeline._auto_persist is True


def test_build_analysis_pipeline_honours_auto_persist_false():
    pipeline = composition.build_analysis_pipeline(auto_persist=False)
    assert pipeline._project_db is None
    assert pipeline._auto_persist is False


def test_build_analysis_pipeline_defaults():
    pipeline = composition.build_analysis_pipeline()
    assert pipeline._project_db is None
    assert pipeline._auto_persist is True


# ── resolve_project_db ────────────────────────────────────────────────
def test_resolve_project_db_returns_none_when_deps_not_ready(monkeypatch):
    import memdiver.engine.project_db as project_db_mod

    monkeypatch.setattr(project_db_mod, "check_deps", lambda: {"ready": False})
    assert composition.resolve_project_db() is None


def test_resolve_project_db_opens_and_returns_db_when_ready(monkeypatch):
    import memdiver.engine.project_db as project_db_mod

    opened = {"called": False}

    class FakeProjectDB:
        def __init__(self, db_path):
            self.db_path = db_path

        def open(self):
            opened["called"] = True

    monkeypatch.setattr(project_db_mod, "check_deps", lambda: {"ready": True})
    monkeypatch.setattr(project_db_mod, "ProjectDB", FakeProjectDB)
    monkeypatch.setattr(project_db_mod, "default_db_path", lambda: Path("/tmp/fake.duckdb"))

    db = composition.resolve_project_db()
    assert isinstance(db, FakeProjectDB)
    assert opened["called"] is True


def test_resolve_project_db_guard_swallows_exceptions(monkeypatch):
    import memdiver.engine.project_db as project_db_mod

    def boom():
        raise RuntimeError("dependency probe blew up")

    monkeypatch.setattr(project_db_mod, "check_deps", boom)
    assert composition.resolve_project_db() is None


# ── Re-export identity (single import surface) ────────────────────────
def test_reexports_are_the_same_objects():
    import memdiver.app.key_material as app_km
    import memdiver.app.reader_cache as reader_cache
    import memdiver.core.dump_source as dump_source
    import memdiver.core.key_material as core_km

    assert composition.open_dump is dump_source.open_dump
    assert composition.key_material_from_files is core_km.from_files
    assert composition.key_material_from_hex is core_km.from_hex
    assert composition.cached_dump_source is reader_cache.cached_dump_source
    assert composition.cached_msl_reader is reader_cache.cached_msl_reader
    assert composition.key_material_scope is reader_cache.key_material_scope
    assert composition.open_dump_source is app_km.open_dump_source
    assert composition.open_msl_reader is app_km.open_msl_reader
    assert composition.key_material_kwargs is app_km.key_material_kwargs
    assert composition.has_key_material is app_km.has_key_material


def test_all_lists_every_public_symbol():
    for name in composition.__all__:
        assert hasattr(composition, name), f"__all__ names missing attr: {name}"

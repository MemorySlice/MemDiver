"""Pins the reconciled corpus resolver in ``tests/_paths.py``.

Two resolvers used to disagree: ``dataset_root()`` (which gates the
``requires_dataset`` marker) and ``tls_ground_truth.tls_dumps_dir()`` (which the
corpus test BODIES read). With ``config.json["dataset_root"] == "."`` correctly
rejected, the first returned ``None`` while the second happily pointed at a
present corpus, so four real-corpus tests reported "no dataset" while standing
on the very tree they would have opened.

These tests pin the seam: the ``"."`` rejection still holds, step 3 now falls
through to ``tls_dumps_dir()``, and an EXPLICIT override that fails to resolve
still means "no dataset" (which is how a corpus-less machine is simulated).
"""
from __future__ import annotations

from pathlib import Path

import pytest

from tests import _paths


@pytest.fixture
def clean_resolver(monkeypatch):
    """Isolate ``dataset_root()`` from the ambient machine and leave no residue."""
    monkeypatch.delenv("MEMDIVER_DATASET_ROOT", raising=False)
    monkeypatch.setattr(_paths, "_CLI_OVERRIDE", None, raising=False)
    monkeypatch.setattr(_paths, "_CLI_OVERRIDE_REQUESTED", False, raising=False)
    monkeypatch.setattr(_paths, "_load_config_dataset_root", lambda: None)
    _paths.dataset_root.cache_clear()
    yield
    _paths.dataset_root.cache_clear()


def _corpus_tree(tmp_path: Path, name: str = "tls_dumps") -> Path:
    root = tmp_path / name
    (root / "TLS13" / "scenario" / "openssl" / "openssl_run_13_1").mkdir(parents=True)
    return root


def _point_fallback_at(monkeypatch, path: Path) -> None:
    from tests.fixtures import tls_ground_truth

    monkeypatch.setattr(tls_ground_truth, "tls_dumps_dir", lambda: path)


# --------------------------------------------------------------------------- #
# The reconciliation itself
# --------------------------------------------------------------------------- #

def test_falls_back_to_the_tls_corpus_when_nothing_else_resolves(
    clean_resolver, monkeypatch, tmp_path
):
    corpus = _corpus_tree(tmp_path)
    _point_fallback_at(monkeypatch, corpus)
    assert _paths.dataset_root() == corpus


def test_the_fallback_is_none_when_the_corpus_is_absent(
    clean_resolver, monkeypatch, tmp_path
):
    _point_fallback_at(monkeypatch, tmp_path / "not-here")
    assert _paths.dataset_root() is None


def test_an_env_root_still_wins_over_the_fallback(
    clean_resolver, monkeypatch, tmp_path
):
    corpus = _corpus_tree(tmp_path)
    other = tmp_path / "explicit"
    other.mkdir()
    _point_fallback_at(monkeypatch, corpus)
    monkeypatch.setenv("MEMDIVER_DATASET_ROOT", str(other))
    assert _paths.dataset_root() == other


def test_a_config_root_still_wins_over_the_fallback(
    clean_resolver, monkeypatch, tmp_path
):
    corpus = _corpus_tree(tmp_path)
    from_config = tmp_path / "from_config"
    from_config.mkdir()
    _point_fallback_at(monkeypatch, corpus)
    monkeypatch.setattr(_paths, "_load_config_dataset_root", lambda: from_config)
    assert _paths.dataset_root() == from_config


# --------------------------------------------------------------------------- #
# An EXPLICIT request is honoured as given -- including its failure
# --------------------------------------------------------------------------- #

def test_a_nonexistent_env_root_suppresses_the_fallback(
    clean_resolver, monkeypatch, tmp_path
):
    """`MEMDIVER_DATASET_ROOT=/nonexistent` must still mean "no dataset"."""
    _point_fallback_at(monkeypatch, _corpus_tree(tmp_path))
    monkeypatch.setenv("MEMDIVER_DATASET_ROOT", "/nonexistent")
    assert _paths.dataset_root() is None


def test_a_nonexistent_cli_root_suppresses_the_fallback(
    clean_resolver, monkeypatch, tmp_path
):
    _point_fallback_at(monkeypatch, _corpus_tree(tmp_path))
    monkeypatch.setattr(_paths, "_CLI_OVERRIDE_REQUESTED", True)
    assert _paths.dataset_root() is None


def test_set_cli_override_records_the_request_even_when_the_path_is_bogus():
    """This one touches the real module globals, so it restores them exactly.

    A blanket ``_set_cli_override(None)`` would silently discard a session
    started with ``--dataset-root=PATH``.
    """
    prior_override = _paths._CLI_OVERRIDE
    prior_requested = _paths._CLI_OVERRIDE_REQUESTED
    try:
        _paths._set_cli_override("/nonexistent")
        assert _paths._CLI_OVERRIDE is None
        assert _paths._CLI_OVERRIDE_REQUESTED is True

        _paths._set_cli_override(None)
        assert _paths._CLI_OVERRIDE_REQUESTED is False
    finally:
        _paths._CLI_OVERRIDE = prior_override
        _paths._CLI_OVERRIDE_REQUESTED = prior_requested
        _paths.dataset_root.cache_clear()


# --------------------------------------------------------------------------- #
# The `"."` rejection is preserved, and the fallback mirrors its spirit
# --------------------------------------------------------------------------- #

def test_repo_root_is_never_a_corpus_root():
    assert not _paths._looks_like_a_corpus_root(_paths.REPO_ROOT)


def test_a_dot_config_root_is_still_rejected(monkeypatch, tmp_path):
    """The load-bearing rule: `dataset_root: "."` is REPO_ROOT, not a dataset."""
    cfg = tmp_path / "config.json"
    cfg.write_text('{"dataset_root": "."}')
    monkeypatch.setattr(_paths, "REPO_ROOT", tmp_path)
    assert _paths._load_config_dataset_root() is None


@pytest.mark.parametrize("child", ["TLS13", "TLS12", "SSH2", "dataset_memory_slice"])
def test_a_protocol_directory_makes_a_root_plausible(tmp_path, child):
    (tmp_path / child).mkdir()
    assert _paths._looks_like_a_corpus_root(tmp_path)


def test_an_empty_directory_is_not_a_corpus_root(tmp_path):
    assert not _paths._looks_like_a_corpus_root(tmp_path)


def test_an_unrelated_directory_is_not_a_corpus_root(tmp_path):
    (tmp_path / "Downloads").mkdir()
    (tmp_path / "notes.txt").write_text("x")
    assert not _paths._looks_like_a_corpus_root(tmp_path)


def test_a_missing_directory_is_not_a_corpus_root(tmp_path):
    assert not _paths._looks_like_a_corpus_root(tmp_path / "absent")


def test_a_file_is_not_a_corpus_root(tmp_path):
    f = tmp_path / "tls_dumps"
    f.write_text("not a tree")
    assert not _paths._looks_like_a_corpus_root(f)

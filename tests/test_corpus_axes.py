"""Tests for core/corpus_axes.py — the canonical corpus-axis vocabulary.

Most cases are pure path parsing and need no filesystem: a non-existent
``meta.json`` and a non-existent ``keylog.csv`` are both legitimate states
(the real TLS corpus has zero ``meta.json`` files), so the parser is exercised
against synthetic path strings. The few cases that assert on sidecar presence
build a real directory under ``tmp_path``, and one marker-gated case runs
against the real corpus when a dataset root is configured.
"""

from __future__ import annotations

import dataclasses
from pathlib import Path

import pytest

from memdiver.core.corpus_axes import (
    UNKNOWN_LIBRARY_VERSION,
    VERSION_AXIS_LIBRARY,
    VERSION_AXIS_PROTOCOL,
    CorpusAxes,
    axes_from_dump_path,
    axes_from_run_dir,
    with_canonical_phase,
)

CORPUS_ROOT = Path("/corpus/tls_dumps")

TLS13_SCENARIO = "100_iterations_Abort_KeyUpdate"
TLS12_SCENARIO = "100_iterations_Abort"

TLS13_RUN_DIR = CORPUS_ROOT / "TLS13" / TLS13_SCENARIO / "openssl" / "openssl_run_13_1"
TLS13_DUMP = TLS13_RUN_DIR / "20251020_171845_606711_pre_server_key_update.dump"

TLS12_RUN_DIR = CORPUS_ROOT / "TLS12" / TLS12_SCENARIO / "wolfssl" / "wolfssl_run_12_42"
TLS12_DUMP = TLS12_RUN_DIR / "20251020_090000_000001_post_cleanup.dump"


class TestAxesFromDumpPath:
    def test_tls13_dump_path(self):
        axes = axes_from_dump_path(TLS13_DUMP)
        assert axes is not None
        assert axes.protocol == "TLS"
        assert axes.protocol_version == "13"
        assert axes.library == "openssl"
        assert axes.scenario == TLS13_SCENARIO
        assert axes.run_number == 1
        assert axes.run_dir == TLS13_RUN_DIR
        assert axes.dump_path == TLS13_DUMP
        assert axes.phase == "pre_server_key_update"
        assert axes.phase_timestamp == "20251020_171845_606711"

    def test_tls12_dump_path(self):
        axes = axes_from_dump_path(TLS12_DUMP)
        assert axes is not None
        assert axes.protocol == "TLS"
        assert axes.protocol_version == "12"
        assert axes.library == "wolfssl"
        assert axes.scenario == TLS12_SCENARIO
        assert axes.run_number == 42
        assert axes.phase == "post_cleanup"
        assert axes.phase_timestamp == "20251020_090000_000001"

    def test_accepts_a_string_path(self):
        axes = axes_from_dump_path(str(TLS13_DUMP))
        assert axes is not None
        assert axes.dump_path == TLS13_DUMP

    def test_non_phased_dump_still_resolves_with_empty_phase(self):
        # Dataset-style dumps carry no timestamp/phase markers; the run-level
        # axes still resolve.
        axes = axes_from_dump_path(TLS13_RUN_DIR / "gcore.core")
        assert axes is not None
        assert axes.phase == ""
        assert axes.phase_timestamp == ""
        assert axes.dump_path == TLS13_RUN_DIR / "gcore.core"


class TestAxesFromRunDir:
    def test_run_dir(self):
        axes = axes_from_run_dir(TLS13_RUN_DIR)
        assert axes is not None
        assert axes.run_dir == TLS13_RUN_DIR
        assert axes.dump_path is None
        assert axes.phase == ""
        assert axes.phase_timestamp == ""
        assert axes.scenario == TLS13_SCENARIO

    def test_keylog_path_is_none_when_absent(self):
        assert axes_from_run_dir(TLS13_RUN_DIR).keylog_path is None

    def test_keylog_path_resolves_when_present(self, tmp_path):
        run_dir = tmp_path / "TLS13" / TLS13_SCENARIO / "openssl" / "openssl_run_13_7"
        run_dir.mkdir(parents=True)
        keylog = run_dir / "keylog.csv"
        keylog.write_text("label,client_random,secret\n")
        axes = axes_from_run_dir(run_dir)
        assert axes is not None
        assert axes.keylog_path == keylog


class TestNonConforming:
    def test_dataset_style_run_dir_returns_none(self):
        # ``run_0001`` does not match the ``<lib>_run_<ver>_<num>`` shape.
        bad = CORPUS_ROOT / "TLS13" / TLS13_SCENARIO / "openssl" / "run_0001"
        assert axes_from_run_dir(bad) is None
        assert axes_from_dump_path(bad / "gcore.core") is None

    def test_unrelated_path_returns_none(self):
        assert axes_from_dump_path(Path("/tmp/whatever.bin")) is None
        assert axes_from_run_dir(Path("/tmp")) is None

    def test_too_shallow_path_returns_none(self):
        # Conforming run dirname, but no library/scenario/protocol ancestors.
        assert axes_from_run_dir(Path("openssl_run_13_1")) is None

    def test_unknown_protocol_dir_returns_none(self):
        bad = CORPUS_ROOT / "QUIC13" / TLS13_SCENARIO / "openssl" / "openssl_run_13_1"
        assert axes_from_run_dir(bad) is None

    def test_unregistered_version_returns_none(self):
        bad = CORPUS_ROOT / "TLS99" / TLS13_SCENARIO / "openssl" / "openssl_run_99_1"
        assert axes_from_run_dir(bad) is None

    def test_version_mismatch_returns_none(self):
        # Protocol dir says 12, the run dirname says 13.
        bad = CORPUS_ROOT / "TLS12" / TLS12_SCENARIO / "openssl" / "openssl_run_13_1"
        assert axes_from_run_dir(bad) is None

    def test_never_raises_on_odd_input(self):
        for candidate in ("", ".", "/", "openssl_run_13_1/../x"):
            assert axes_from_run_dir(Path(candidate)) is None


class TestVersionAxis:
    def test_defaults_to_protocol_version_axis(self):
        axes = axes_from_dump_path(TLS13_DUMP)
        assert axes.library_version == UNKNOWN_LIBRARY_VERSION
        assert axes.version_axis == VERSION_AXIS_PROTOCOL

    def test_explicit_override_flips_both_fields(self):
        axes = axes_from_dump_path(TLS13_DUMP, library_version="3.0.13")
        assert axes.library_version == "3.0.13"
        assert axes.version_axis == VERSION_AXIS_LIBRARY

    def test_override_also_applies_to_run_dir_entry_point(self):
        axes = axes_from_run_dir(TLS13_RUN_DIR, library_version="3.5.0")
        assert axes.library_version == "3.5.0"
        assert axes.version_axis == VERSION_AXIS_LIBRARY

    def test_explicit_unknown_override_keeps_protocol_axis(self):
        axes = axes_from_run_dir(
            TLS13_RUN_DIR, library_version=UNKNOWN_LIBRARY_VERSION,
        )
        assert axes.library_version == UNKNOWN_LIBRARY_VERSION
        assert axes.version_axis == VERSION_AXIS_PROTOCOL

    def test_meta_json_library_version_is_consulted(self, tmp_path, monkeypatch):
        """The forward-compatibility hook: a ``meta.json`` build field wins
        over the ``unknown`` fallback (no corpus run carries one today)."""
        from memdiver.core import corpus_axes

        run_dir = tmp_path / "TLS13" / TLS13_SCENARIO / "openssl" / "openssl_run_13_9"
        run_dir.mkdir(parents=True)

        class _FakeMeta:
            library_version = "9.9.9"

        monkeypatch.setattr(corpus_axes, "load_run_meta", lambda _p: _FakeMeta())
        axes = corpus_axes.axes_from_run_dir(run_dir)
        assert axes.library_version == "9.9.9"
        assert axes.version_axis == VERSION_AXIS_LIBRARY

    def test_meta_without_the_field_falls_back_to_unknown(self, tmp_path, monkeypatch):
        from memdiver.core import corpus_axes

        run_dir = tmp_path / "TLS12" / TLS12_SCENARIO / "openssl" / "openssl_run_12_9"
        run_dir.mkdir(parents=True)

        class _FakeMeta:
            pass

        monkeypatch.setattr(corpus_axes, "load_run_meta", lambda _p: _FakeMeta())
        axes = corpus_axes.axes_from_run_dir(run_dir)
        assert axes.library_version == UNKNOWN_LIBRARY_VERSION
        assert axes.version_axis == VERSION_AXIS_PROTOCOL


class TestCanonicalPhase:
    def test_parsers_leave_canonical_phase_empty(self):
        # Canonical phases are positional across a run's siblings, so a single
        # path can never determine one (see the CorpusAxes docstring).
        assert axes_from_dump_path(TLS13_DUMP).canonical_phase == ""
        assert axes_from_run_dir(TLS13_RUN_DIR).canonical_phase == ""

    def test_with_canonical_phase_sets_without_mutating(self):
        original = axes_from_dump_path(TLS13_DUMP)
        updated = with_canonical_phase(original, "pre_key_update")
        assert updated.canonical_phase == "pre_key_update"
        assert original.canonical_phase == ""
        assert updated is not original
        # Every other axis is carried over unchanged.
        assert dataclasses.replace(updated, canonical_phase="") == original

    def test_axes_are_frozen(self):
        axes = axes_from_dump_path(TLS13_DUMP)
        with pytest.raises(dataclasses.FrozenInstanceError):
            axes.canonical_phase = "pre_cleanup"

    def test_axes_are_hashable_identity_keys(self):
        a = axes_from_dump_path(TLS13_DUMP)
        b = axes_from_dump_path(TLS13_DUMP)
        assert a == b
        assert len({a, b}) == 1


class TestBothProtocolVersions:
    @pytest.mark.parametrize(
        "proto_dir,scenario,library,run_name,expected_version",
        [
            ("TLS12", TLS12_SCENARIO, "boringssl", "boringssl_run_12_100", "12"),
            ("TLS13", TLS13_SCENARIO, "boringssl", "boringssl_run_13_100", "13"),
        ],
    )
    def test_protocol_and_scenario_resolve(
        self, proto_dir, scenario, library, run_name, expected_version,
    ):
        run_dir = CORPUS_ROOT / proto_dir / scenario / library / run_name
        axes = axes_from_run_dir(run_dir)
        assert axes is not None
        assert axes.protocol == "TLS"
        assert axes.protocol_version == expected_version
        assert axes.scenario == scenario
        assert axes.library == library
        assert axes.run_number == 100


@pytest.mark.requires_dataset
def test_real_corpus_run_resolves(dataset_root):
    """Resolve axes against a real corpus run when a dataset root is set.

    Auto-skips when no dataset resolves (see the ``requires_dataset`` marker
    registered in tests/conftest.py).
    """
    run_dirs = sorted(dataset_root.glob("TLS*/*/*/*_run_*_*"))
    run_dirs = [p for p in run_dirs if p.is_dir()]
    if not run_dirs:
        pytest.skip(f"No corpus-layout run directories under {dataset_root}")

    run_dir = run_dirs[0]
    axes = axes_from_run_dir(run_dir)
    assert axes is not None, f"real corpus run did not resolve: {run_dir}"
    assert axes.protocol == "TLS"
    assert axes.protocol_version in ("12", "13")
    assert axes.protocol_version == run_dir.parent.parent.parent.name[len("TLS"):]
    assert axes.library == run_dir.parent.name
    assert axes.scenario == run_dir.parent.parent.name
    assert axes.run_number >= 1
    # No corpus run records a library build today.
    assert axes.library_version == UNKNOWN_LIBRARY_VERSION
    assert axes.version_axis == VERSION_AXIS_PROTOCOL

    dumps = sorted(run_dir.glob("*.dump")) + sorted(run_dir.glob("*.msl"))
    if dumps:
        dump_axes = axes_from_dump_path(dumps[0])
        assert dump_axes is not None
        assert dump_axes.run_dir == run_dir
        assert dump_axes.dump_path == dumps[0]
        assert dump_axes.phase, f"expected a raw phase from {dumps[0].name}"
        assert dump_axes.phase_timestamp
        assert dump_axes.canonical_phase == ""
    assert isinstance(axes, CorpusAxes)

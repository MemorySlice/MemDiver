"""Tests for engine/sweep_plan.py - corpus sweep units and idempotency digests.

The fast cases build small synthetic corpus trees under ``tmp_path`` (the real
corpus is ~170 GB and machine-local), shaped exactly like the real one::

    <root>/TLS13/100_iterations_Abort_KeyUpdate/openssl/openssl_run_13_1/
        20251020_171845_606711_pre_server_key_update.dump
        keylog.csv

One marker-gated case runs against the real corpus and pins the measured
denominator (18,917 dumps over 2,600 runs).
"""

from __future__ import annotations

import dataclasses
import inspect
import os
import shutil
from pathlib import Path
from typing import List, Optional

import pytest

from memdiver.core.phase_normalizer import CANONICAL_PHASE_ORDER
from memdiver.engine.sweep_plan import (
    DIGEST_LEVELS,
    SWEEP_SCHEMA_VERSION,
    DigestComparison,
    IncomparableDigestError,
    InputsDigest,
    SweepUnit,
    config_digest,
    count_units,
    enumerate_units,
    inputs_digest,
    inputs_digest_with_level,
    parse_phase_timestamp,
    resolve_digest_level,
    unit_key,
)
from tests.fixtures.tls_ground_truth import tls_dumps_dir

TLS13_SCENARIO = "100_iterations_Abort_KeyUpdate"
TLS12_SCENARIO = "100_iterations_Abort"

#: A phase-style dump filename, matching the real corpus convention.
DUMP_A = "20251020_171845_606711_pre_server_key_update.dump"
DUMP_B = "20251020_171846_606711_post_server_key_update.dump"
#: Two dumps with GENERIC (non key-update, non cleanup) phase names. The
#: normalizer hands generic canonical suffixes out positionally by timestamp, so
#: inserting ``GENERIC_EARLY`` in front of ``GENERIC_LATE`` re-maps the latter
#: from ``pre_handshake_end`` to ``pre_second_event`` without touching its bytes.
GENERIC_LATE = "20251020_171845_606711_pre_shutdown.dump"
GENERIC_EARLY = "20251020_100000_000001_pre_abort.dump"

#: Two dumps one second apart in the same run whose microsecond fields have
#: DIFFERENT widths - ``DUMP_PATTERN`` captures ``(\d{8}_\d{6}_\d+)``, so a
#: five-digit field is a legal name. ``90000`` us (0.090 s) is chronologically
#: EARLIER than ``606711`` us (0.607 s), but sorts later as text because
#: ``"9" > "6"``.
MICROS_5_DIGITS = "20251020_171845_90000_pre_abort.dump"
MICROS_6_DIGITS = "20251020_171845_606711_pre_shutdown.dump"

#: DATASET-style dump filenames: no timestamp, no phase markers. Two spellings
#: are in circulation and BOTH are admitted by
#: ``core.discovery._infer_dump_kind``, which matches ``gdb_raw.bin`` WITHOUT a
#: leading dot:
#:
#: * bare (``gdb_raw.bin``) - what the committed fixture
#:   ``tests/fixtures/datasets/gocryptfs/run_0001/`` actually contains;
#: * dotted (``openssl.gdb_raw.bin``) - the spelling
#:   ``core.discovery.DATASET_DUMP_SUFFIXES`` is written in.
#:
#: The count used to re-derive admission from ``DATASET_DUMP_SUFFIXES`` and so
#: recognised only the dotted half. Every case below keeps both in play; the
#: two lists live in DIFFERENT runs because a case-insensitive filesystem
#: (APFS, NTFS) would collapse ``gdb_raw.bin`` and ``GDB_RAW.BIN`` onto one file.
BARE_DATASET_DUMPS = [
    "gdb_raw.bin",
    "lldb_raw.bin",
    "gcore.core",
    "memslicer.msl",
]
DOTTED_DATASET_DUMPS = [
    "GDB_RAW.BIN",
    "openssl.gdb_raw.bin",
    "openssl.lldb_raw.bin",
    "openssl.gcore.core",
    "openssl.msl",
    "openssl.core",
]


# ---------------------------------------------------------------------------
# Synthetic corpus builders
# ---------------------------------------------------------------------------


def _make_run(
    root: Path,
    *,
    protocol_dir: str = "TLS13",
    scenario: str = TLS13_SCENARIO,
    library: str = "openssl",
    version: str = "13",
    run_number: int = 1,
    dumps: Optional[List[str]] = None,
    keylog: bool = True,
    dump_size: int = 128,
) -> Path:
    """Create one conforming run directory and return it."""
    run_dir = (
        root
        / protocol_dir
        / scenario
        / library
        / f"{library}_run_{version}_{run_number}"
    )
    run_dir.mkdir(parents=True, exist_ok=True)
    for name in dumps if dumps is not None else [DUMP_A]:
        (run_dir / name).write_bytes(b"\xab" * dump_size)
    if keylog:
        (run_dir / "keylog.csv").write_text("label,value\nCLIENT_RANDOM,00\n")
    return run_dir


def _corpus(tmp_path: Path, name: str = "tls_dumps") -> Path:
    """An empty corpus root named like the real one."""
    root = tmp_path / name
    root.mkdir(parents=True, exist_ok=True)
    return root


def _skip_if_root() -> None:
    """chmod-based unreadable-directory cases are meaningless as root."""
    if hasattr(os, "geteuid") and os.geteuid() == 0:
        pytest.skip("running as root: chmod 000 does not deny access")


def _only_unit(root: Path, **kwargs) -> SweepUnit:
    units = list(enumerate_units(root, **kwargs))
    assert len(units) == 1, [u.unit_key for u in units]
    return units[0]


# ---------------------------------------------------------------------------
# unit_key: stability under a corpus move, sensitivity to a rename
# ---------------------------------------------------------------------------


class TestUnitKeyStability:
    def test_key_shape(self, tmp_path: Path) -> None:
        root = _corpus(tmp_path)
        _make_run(root)
        unit = _only_unit(root)
        assert unit.unit_key == (
            f"u2/tls_dumps/13/{TLS13_SCENARIO}/openssl/unknown/0001/{DUMP_A}"
        )
        assert unit_key(unit) == unit.unit_key

    def test_key_carries_the_library_version(self, tmp_path: Path) -> None:
        """``library_version`` sits between ``library`` and ``run_number``.

        Without it a future multi-build corpus would collide two builds of the
        same library at the same run number onto one key and one ledger row.
        Every run measured today resolves to ``"unknown"``, which is exactly
        why the ``u1`` -> ``u2`` bump was free.
        """
        root = _corpus(tmp_path)
        _make_run(root)
        unit = _only_unit(root)
        assert unit.library_version == "unknown"
        parts = unit.unit_key.split("/")
        assert parts[0] == "u2"
        assert parts[5] == unit.library_version
        assert parts[4] == unit.library
        assert parts[6] == "0001"

        renamed = dataclasses.replace(unit, library_version="3.5.2")
        assert unit_key(renamed) != unit.unit_key
        assert "/3.5.2/" in unit_key(renamed)

    def test_key_is_stable_when_the_corpus_root_moves(self, tmp_path: Path) -> None:
        """The headline property: copying the corpus elsewhere keeps every key.

        An absolute-path-derived key would invalidate all 18,917 units the
        moment the corpus is moved to an external drive, for no reason at all.
        """
        original = _corpus(tmp_path / "here")
        _make_run(original, dumps=[DUMP_A, DUMP_B])
        _make_run(original, library="wolfssl", protocol_dir="TLS12",
                  scenario=TLS12_SCENARIO, version="12", run_number=42)

        moved = tmp_path / "elsewhere" / "deeper" / "tls_dumps"
        moved.parent.mkdir(parents=True, exist_ok=True)
        shutil.copytree(original, moved)

        before = [u.unit_key for u in enumerate_units(original)]
        after = [u.unit_key for u in enumerate_units(moved)]
        assert before == after
        assert len(before) == 3
        assert not any(str(tmp_path) in key for key in before)

    def test_key_changes_when_the_dump_is_renamed(self, tmp_path: Path) -> None:
        root = _corpus(tmp_path)
        run_dir = _make_run(root)
        before = _only_unit(root).unit_key

        os.rename(run_dir / DUMP_A, run_dir / DUMP_B)
        after = _only_unit(root).unit_key
        assert after != before
        assert after.endswith(DUMP_B)

    def test_key_unchanged_when_a_sibling_dump_appears(self, tmp_path: Path) -> None:
        """Proves ``canonical_phase`` is NOT in the key.

        ``PhaseNormalizer`` assigns generic canonical suffixes positionally
        across a run's siblings, so inserting an EARLIER dump re-maps the
        canonical phase of the existing ones. The key must not move with it -
        otherwise a resumed sweep re-scans work it already finished.
        """
        root = _corpus(tmp_path)
        run_dir = _make_run(root, dumps=[GENERIC_LATE])
        before = {u.dump_path.name: u for u in enumerate_units(root)}
        assert before[GENERIC_LATE].canonical_phase == "pre_handshake_end"

        (run_dir / GENERIC_EARLY).write_bytes(b"\xab" * 128)
        after = {u.dump_path.name: u for u in enumerate_units(root)}

        assert set(before) < set(after)
        for name, unit in before.items():
            assert after[name].unit_key == unit.unit_key
        # The canonical phase of the untouched dump really did move: without
        # that, the assertion above would be vacuous.
        assert after[GENERIC_LATE].canonical_phase == "pre_second_event"

    def test_corpus_id_override_is_used_verbatim(self, tmp_path: Path) -> None:
        root = _corpus(tmp_path, name="whatever_the_mount_is_called")
        _make_run(root)
        unit = _only_unit(root, corpus_id="tls_dumps")
        assert unit.unit_key.startswith("u2/tls_dumps/")

    def test_corpus_root_is_recorded_but_not_in_the_key(self, tmp_path: Path) -> None:
        root = _corpus(tmp_path)
        _make_run(root)
        unit = _only_unit(root)
        assert unit.corpus_root == root
        assert str(root) not in unit.unit_key


# ---------------------------------------------------------------------------
# config_digest
# ---------------------------------------------------------------------------


class TestConfigDigest:
    def test_deterministic_and_short(self) -> None:
        first = config_digest(expand_keys=True, memdiver_version="0.6.0")
        second = config_digest(memdiver_version="0.6.0", expand_keys=True)
        assert first == second
        assert len(first) == 16
        int(first, 16)  # hex

    def test_flips_when_expand_keys_changes(self) -> None:
        assert config_digest(expand_keys=False) != config_digest(expand_keys=True)

    def test_flips_when_normalize_changes(self) -> None:
        """``normalize`` changes WHICH dump a phase request resolves to.

        It is in neither the unit key (which names a concrete file) nor - until
        this test - the config digest, so flipping it left a resumed sweep
        skipping every unit as "already done" against results produced under
        the other setting. That is a skip-if-done correctness hole, not a
        performance knob.
        """
        assert config_digest(normalize=False) != config_digest(normalize=True)
        assert config_digest(normalize=False) == config_digest()

    def test_does_not_flip_when_workers_changes(self) -> None:
        """Parallelism is not an output-affecting setting.

        If it were folded in, raising the worker count mid-sweep - the single
        most likely operator adjustment - would invalidate every completed unit.
        """
        base = config_digest(expand_keys=True)
        assert config_digest(expand_keys=True, workers=1) == base
        assert config_digest(expand_keys=True, workers=64) == base

    @pytest.mark.parametrize(
        "ignored",
        ["use_processes", "max_inflight", "fsync_policy", "output_dir"],
    )
    def test_other_performance_settings_are_ignored(self, ignored: str) -> None:
        base = config_digest(expand_keys=True)
        assert config_digest(expand_keys=True, **{ignored: "anything"}) == base

    def test_omitted_settings_use_defaults(self) -> None:
        assert config_digest() == config_digest(
            expand_keys=False,
            normalize=False,
            algorithms=(),
            keylog_filename="keylog.csv",
            template_name="",
            min_secret_len=0,
            memdiver_version="",
        )

    def test_algorithms_order_does_not_matter(self) -> None:
        assert config_digest(algorithms=["aes", "chacha"]) == config_digest(
            algorithms=("chacha", "aes")
        )

    @pytest.mark.parametrize(
        "kwargs",
        [
            {"normalize": True},
            {"algorithms": ["aes"]},
            {"keylog_filename": "other.csv"},
            {"template_name": "nss"},
            {"min_secret_len": 16},
            {"memdiver_version": "9.9.9"},
            {"sweep_schema_version": 99},
        ],
    )
    def test_each_output_affecting_setting_flips_the_digest(self, kwargs) -> None:
        assert config_digest(**kwargs) != config_digest()

    def test_the_schema_version_is_the_one_the_envelope_was_settled_at(
        self,
    ) -> None:
        """Pinned so a silent revert to 1 is a test failure, not a data bug.

        ``1`` -> ``2`` bought ``elapsed_s`` and the ``secret_types_*`` counters
        on ``engine.survival_scan.DumpScanResult`` while NOTHING had been
        swept. Reverting it would let results written under two envelope shapes
        merge into one indistinguishable pile, which is the exact failure
        ``config_digest`` folds this constant in to prevent.
        """
        assert SWEEP_SCHEMA_VERSION == 2

    def test_the_schema_version_default_really_reaches_the_digest(self) -> None:
        """Not merely present in the defaults: it must CHANGE the digest.

        Passing the current value explicitly must be a no-op, and passing any
        other value must invalidate every stored digest — that is what forces
        the re-sweep an envelope change requires.
        """
        assert config_digest(
            sweep_schema_version=SWEEP_SCHEMA_VERSION
        ) == config_digest()
        assert config_digest(
            sweep_schema_version=SWEEP_SCHEMA_VERSION + 1
        ) != config_digest()

    def test_unknown_setting_is_ignored_with_a_warning(self, caplog) -> None:
        with caplog.at_level("WARNING", logger="memdiver.engine.sweep_plan"):
            assert config_digest(expandkeys=True) == config_digest()
        assert "expandkeys" in caplog.text


# ---------------------------------------------------------------------------
# inputs_digest
# ---------------------------------------------------------------------------


class TestInputsDigest:
    def test_off_level_is_empty(self, tmp_path: Path) -> None:
        root = _corpus(tmp_path)
        _make_run(root)
        assert inputs_digest(_only_unit(root), "off") == ""

    def test_unknown_level_raises_and_lists_the_valid_ones(self, tmp_path: Path) -> None:
        root = _corpus(tmp_path)
        _make_run(root)
        unit = _only_unit(root)
        with pytest.raises(ValueError) as excinfo:
            inputs_digest(unit, "mtime")
        message = str(excinfo.value)
        for level in DIGEST_LEVELS:
            assert repr(level) in message

    def test_size_digest_flips_when_the_dump_size_changes(self, tmp_path: Path) -> None:
        root = _corpus(tmp_path)
        run_dir = _make_run(root)
        before = inputs_digest(_only_unit(root))

        (run_dir / DUMP_A).write_bytes(b"\xab" * 129)
        assert inputs_digest(_only_unit(root)) != before

    def test_size_digest_flips_when_the_keylog_size_changes(self, tmp_path: Path) -> None:
        root = _corpus(tmp_path)
        run_dir = _make_run(root)
        before = inputs_digest(_only_unit(root))

        (run_dir / "keylog.csv").write_text("label,value\nCLIENT_RANDOM,0000\n")
        assert inputs_digest(_only_unit(root)) != before

    def test_size_digest_ignores_mtime(self, tmp_path: Path) -> None:
        """An ``rsync``/``cp`` of the corpus rewrites every mtime.

        Reacting to that would force a ~170 GB re-sweep after a move that
        changed no bytes.
        """
        root = _corpus(tmp_path)
        run_dir = _make_run(root)
        before = inputs_digest(_only_unit(root))

        for name in (DUMP_A, "keylog.csv"):
            os.utime(run_dir / name, (1_600_000_000, 1_600_000_000))
        assert inputs_digest(_only_unit(root)) == before

    def test_size_digest_survives_a_corpus_move(self, tmp_path: Path) -> None:
        original = _corpus(tmp_path / "here")
        _make_run(original)
        moved = tmp_path / "elsewhere" / "tls_dumps"
        moved.parent.mkdir(parents=True)
        shutil.copytree(original, moved)
        assert inputs_digest(_only_unit(moved)) == inputs_digest(_only_unit(original))

    def test_content_digest_flips_on_a_same_size_rewrite(self, tmp_path: Path) -> None:
        root = _corpus(tmp_path)
        run_dir = _make_run(root)
        unit = _only_unit(root)
        size_before = inputs_digest(unit, "size")
        content_before = inputs_digest(unit, "content")

        (run_dir / DUMP_A).write_bytes(b"\xcd" * 128)
        assert inputs_digest(unit, "size") == size_before  # documented blind spot
        assert inputs_digest(unit, "content") != content_before

    def test_the_level_is_hashed_into_the_digest(self, tmp_path: Path) -> None:
        """THE TRAP: raising the level changes every digest on its own.

        ``inputs_digest`` folds ``level`` into the hashed payload, so a
        ``"content"`` digest of untouched bytes differs from the ``"size"``
        digest of the same bytes. A consumer that stored the digest alone would
        read an operator raising ``recheck_inputs`` as "all 18,917 inputs
        changed" and silently re-read ~170 GB.
        """
        root = _corpus(tmp_path)
        _make_run(root)
        unit = _only_unit(root)
        assert inputs_digest(unit, "size") != inputs_digest(unit, "content")

    def test_recheck_inputs_is_the_named_spelling_of_level(
        self, tmp_path: Path
    ) -> None:
        root = _corpus(tmp_path)
        _make_run(root)
        unit = _only_unit(root)

        assert inputs_digest(unit, recheck_inputs="off") == ""
        assert inputs_digest(unit, recheck_inputs="content") == inputs_digest(
            unit, "content"
        )
        # The positional parameter keeps working untouched for existing
        # callers, and the named setting wins when both are supplied.
        assert inputs_digest(unit) == inputs_digest(unit, "size")
        assert inputs_digest(unit, "size", recheck_inputs="content") == inputs_digest(
            unit, "content"
        )

    def test_recheck_inputs_rejects_an_unknown_level(self, tmp_path: Path) -> None:
        root = _corpus(tmp_path)
        _make_run(root)
        with pytest.raises(ValueError) as excinfo:
            inputs_digest(_only_unit(root), recheck_inputs="mtime")
        assert "mtime" in str(excinfo.value)

    def test_resolve_digest_level_prefers_the_named_setting(self) -> None:
        assert resolve_digest_level() == "size"
        assert resolve_digest_level("content") == "content"
        assert resolve_digest_level("size", "content") == "content"
        assert resolve_digest_level("size", None) == "size"
        with pytest.raises(ValueError):
            resolve_digest_level("nonsense")

    def test_digest_with_level_records_the_level_that_produced_it(
        self, tmp_path: Path
    ) -> None:
        root = _corpus(tmp_path)
        _make_run(root)
        unit = _only_unit(root)

        recorded = inputs_digest_with_level(unit)
        assert isinstance(recorded, InputsDigest)
        assert recorded.level == "size"
        assert recorded.digest == inputs_digest(unit, "size")
        assert inputs_digest_with_level(unit, recheck_inputs="content") == InputsDigest(
            digest=inputs_digest(unit, "content"), level="content",
        )

    def test_a_level_change_is_not_comparable_rather_than_changed(
        self, tmp_path: Path
    ) -> None:
        """The whole point of :class:`InputsDigest`.

        Two digests taken at different levels answer different questions, so
        the honest verdict is "not comparable" - never "the inputs changed",
        which is what would trigger the spurious full re-sweep.

        This case used to assert ``not at_size.matches(at_content)``, which
        ENCODED the conflation it was written to forbid: a plain ``False`` is
        indistinguishable from the "the inputs changed" answer, and ``matches``
        is the one boolean a ledger is likely to branch on. The distinction is
        now structural - :meth:`InputsDigest.compare` is tri-state, and
        ``matches`` refuses to answer at all across a level change.
        """
        root = _corpus(tmp_path)
        _make_run(root)
        unit = _only_unit(root)

        at_size = inputs_digest_with_level(unit, "size")
        at_content = inputs_digest_with_level(unit, "content")

        assert not at_size.comparable_with(at_content)
        assert at_size.compare(at_content) is DigestComparison.NOT_COMPARABLE
        # NOT "changed" - and not silently False either.
        assert at_size.compare(at_content) is not DigestComparison.CHANGED
        with pytest.raises(IncomparableDigestError):
            at_size.matches(at_content)

        same_level = inputs_digest_with_level(unit, "size")
        assert at_size.comparable_with(same_level)
        assert at_size.compare(same_level) is DigestComparison.MATCH
        assert at_size.matches(same_level)

    def test_the_three_verdicts_are_distinguishable(self, tmp_path: Path) -> None:
        """MATCH / CHANGED / NOT_COMPARABLE are three values, not two.

        A ledger that cannot tell CHANGED from NOT_COMPARABLE re-sweeps ~170 GB
        the first time an operator raises ``recheck_inputs``.
        """
        root = _corpus(tmp_path)
        run_dir = _make_run(root)
        unit = _only_unit(root)
        at_size = inputs_digest_with_level(unit, "size")
        at_content = inputs_digest_with_level(unit, "content")
        unchanged = inputs_digest_with_level(unit, "size")

        (run_dir / DUMP_A).write_bytes(b"\xab" * 129)
        changed = inputs_digest_with_level(_only_unit(root), "size")

        assert at_size.compare(unchanged) is DigestComparison.MATCH
        assert at_size.compare(changed) is DigestComparison.CHANGED
        assert at_size.compare(at_content) is DigestComparison.NOT_COMPARABLE
        assert len({DigestComparison.MATCH, DigestComparison.CHANGED,
                    DigestComparison.NOT_COMPARABLE}) == 3

    def test_matches_is_false_when_the_inputs_really_changed(
        self, tmp_path: Path
    ) -> None:
        root = _corpus(tmp_path)
        run_dir = _make_run(root)
        before = inputs_digest_with_level(_only_unit(root))

        (run_dir / DUMP_A).write_bytes(b"\xab" * 129)
        after = inputs_digest_with_level(_only_unit(root))
        assert after.comparable_with(before)
        assert after.compare(before) is DigestComparison.CHANGED
        assert not after.matches(before)

    @pytest.mark.parametrize("bad", ["conten", "SIZE", "", "none", "full"])
    def test_an_invalid_level_is_rejected_at_construction(self, bad: str) -> None:
        """A typo'd level must not construct.

        ``InputsDigest("deadbeef", "conten")`` used to build happily and was
        then permanently NOT_COMPARABLE with every digest the sweep computes -
        a permanent full re-sweep from one mistyped character, reported as
        "not comparable" rather than as the error it is.
        """
        with pytest.raises(ValueError) as excinfo:
            InputsDigest(digest="deadbeef", level=bad)
        # The message must name the valid levels, like resolve_digest_level's.
        for level in DIGEST_LEVELS:
            assert repr(level) in str(excinfo.value)

    def test_every_valid_level_constructs(self) -> None:
        for level in DIGEST_LEVELS:
            assert InputsDigest(digest="", level=level).level == level

    def test_off_level_digests_identically_for_every_unit(
        self, tmp_path: Path
    ) -> None:
        """``off`` is a documented no-op, and it is corpus-wide.

        At ``"off"`` the digest is ``""`` for EVERY unit, so two units that
        share nothing still compare MATCH. That is intended - ``off`` means
        "skip-if-done rests on the unit key plus the config digest alone",
        which is only correct for an immutable corpus - but it means a digest
        taken at ``off`` proves nothing whatsoever about the bytes. The unit
        KEY, not the digest, is what keeps two different dumps apart.
        """
        root = _corpus(tmp_path)
        _make_run(root, dumps=[DUMP_A, DUMP_B], dump_size=128)
        _make_run(root, library="wolfssl", dumps=[DUMP_A], dump_size=999)
        units = list(enumerate_units(root))
        assert len(units) == 3

        recorded = [inputs_digest_with_level(u, "off") for u in units]
        assert {r.digest for r in recorded} == {""}
        assert {r.level for r in recorded} == {"off"}
        # Every pair compares MATCH, across different dumps and different runs.
        for other in recorded[1:]:
            assert recorded[0].compare(other) is DigestComparison.MATCH
            assert recorded[0].matches(other)
        # Distinctness survives only in the unit key.
        assert len({u.unit_key for u in units}) == 3
        # And an ``off`` digest is still not comparable with a real one.
        assert recorded[0].compare(
            inputs_digest_with_level(units[0], "size")
        ) is DigestComparison.NOT_COMPARABLE

    def test_off_level_survives_the_dump_vanishing(self, tmp_path: Path) -> None:
        """The flip side of the same fact, stated where it bites."""
        root = _corpus(tmp_path)
        run_dir = _make_run(root)
        unit = _only_unit(root)
        before = inputs_digest_with_level(unit, "off")
        (run_dir / DUMP_A).unlink()
        assert inputs_digest_with_level(unit, "off").matches(before)

    def test_missing_keylog_still_digests(self, tmp_path: Path) -> None:
        root = _corpus(tmp_path)
        _make_run(root, keylog=False)
        unit = _only_unit(root)
        assert unit.keylog_path is None
        assert len(inputs_digest(unit)) == 64

    def test_vanished_dump_digests_without_raising(self, tmp_path: Path) -> None:
        root = _corpus(tmp_path)
        run_dir = _make_run(root)
        unit = _only_unit(root)
        before = inputs_digest(unit)
        (run_dir / DUMP_A).unlink()
        assert inputs_digest(unit) != before


# ---------------------------------------------------------------------------
# Laziness
# ---------------------------------------------------------------------------


class TestLaziness:
    def test_returns_a_generator(self, tmp_path: Path) -> None:
        root = _corpus(tmp_path)
        _make_run(root)
        result = enumerate_units(root)
        assert inspect.isgenerator(result)

    def test_taking_one_unit_does_not_walk_the_whole_tree(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """18,917 units must never all be resident, and the first unit must be
        available before the last directory has been listed."""
        root = _corpus(tmp_path)
        for run_number in range(1, 6):
            _make_run(root, run_number=run_number)
        for library in ("wolfssl", "gnutls", "nss"):
            _make_run(root, library=library, run_number=1)

        loaded: List[str] = []
        from memdiver.core.discovery import RunDiscovery

        original = RunDiscovery.load_run_directory

        def counting_load(run_path, *args, **kwargs):
            loaded.append(run_path.name)
            return original(run_path, *args, **kwargs)

        monkeypatch.setattr(
            RunDiscovery, "load_run_directory", staticmethod(counting_load)
        )

        first = next(enumerate_units(root))
        assert first is not None
        assert len(loaded) == 1, loaded

        assert len(list(enumerate_units(root))) == 8
        assert len(loaded) == 1 + 8

    def test_a_poisoned_later_directory_is_never_reached(self, tmp_path: Path) -> None:
        """A directory that would break the walk proves nothing beyond the first
        unit was touched."""
        _skip_if_root()
        root = _corpus(tmp_path)
        _make_run(root, library="aaa_first", version="13", run_number=1)
        poisoned = root / "TLS13" / TLS13_SCENARIO / "zzz_last"
        poisoned.mkdir(parents=True)
        run_dir = poisoned / "zzz_last_run_13_1"
        run_dir.mkdir()
        (run_dir / DUMP_A).write_bytes(b"\xab" * 8)
        os.chmod(run_dir, 0o000)
        try:
            first = next(enumerate_units(root))
            assert first.library == "aaa_first"
        finally:
            os.chmod(run_dir, 0o755)


# ---------------------------------------------------------------------------
# Filters
# ---------------------------------------------------------------------------


@pytest.fixture()
def multi_corpus(tmp_path: Path) -> Path:
    """A corpus with both protocol versions, 3 libraries and 3 runs each."""
    root = _corpus(tmp_path)
    for run_number in (1, 2, 3):
        for library in ("openssl", "wolfssl", "gnutls"):
            _make_run(
                root, library=library, run_number=run_number,
                dumps=[DUMP_A, DUMP_B],
            )
            _make_run(
                root, protocol_dir="TLS12", scenario=TLS12_SCENARIO,
                library=library, version="12", run_number=run_number,
                dumps=[DUMP_A, DUMP_B],
            )
    return root


@pytest.fixture()
def mixed_name_corpus(tmp_path: Path) -> Path:
    """A corpus whose runs mix phase-style and dataset-style dump names.

    Named differently from ``multi_corpus`` so both can be requested in one
    test without sharing a root directory.
    """
    root = _corpus(tmp_path, name="tls_dumps_mixed")
    for library in ("openssl", "wolfssl"):
        _make_run(
            root, library=library, run_number=1,
            dumps=[DUMP_A, DUMP_B, GENERIC_EARLY, *BARE_DATASET_DUMPS],
        )
        _make_run(
            root, library=library, run_number=2,
            dumps=[DUMP_A, GENERIC_LATE, *DOTTED_DATASET_DUMPS],
        )
        _make_run(
            root, protocol_dir="TLS12", scenario=TLS12_SCENARIO,
            library=library, version="12", run_number=1,
            dumps=[*BARE_DATASET_DUMPS],
        )
    return root


class TestFilters:
    def test_unfiltered_totals(self, multi_corpus: Path) -> None:
        assert count_units(multi_corpus) == 2 * 3 * 3 * 2
        assert len(list(enumerate_units(multi_corpus))) == 36

    def test_libraries_filter(self, multi_corpus: Path) -> None:
        units = list(enumerate_units(multi_corpus, libraries=["wolfssl"]))
        assert {u.library for u in units} == {"wolfssl"}
        assert len(units) == 12
        assert count_units(multi_corpus, libraries=["wolfssl"]) == 12

    def test_protocol_versions_filter_accepts_both_spellings(
        self, multi_corpus: Path
    ) -> None:
        by_version = list(enumerate_units(multi_corpus, protocol_versions=["13"]))
        by_dirname = list(enumerate_units(multi_corpus, protocol_versions=["TLS13"]))
        assert [u.unit_key for u in by_version] == [u.unit_key for u in by_dirname]
        assert {u.protocol_version for u in by_version} == {"13"}
        assert len(by_version) == 18
        assert count_units(multi_corpus, protocol_versions=["tls13"]) == 18

    def test_scenarios_filter(self, multi_corpus: Path) -> None:
        units = list(enumerate_units(multi_corpus, scenarios=[TLS12_SCENARIO]))
        assert {u.scenario for u in units} == {TLS12_SCENARIO}
        assert len(units) == 18
        assert count_units(multi_corpus, scenarios=[TLS12_SCENARIO]) == 18

    def test_canonical_phases_filter(self, multi_corpus: Path) -> None:
        units = list(enumerate_units(multi_corpus, canonical_phases=["pre_key_update"]))
        assert {u.canonical_phase for u in units} == {"pre_key_update"}
        assert {u.raw_phase for u in units} == {"pre_server_key_update"}
        assert len(units) == 18
        assert count_units(multi_corpus, canonical_phases=["pre_key_update"]) == 18

    def test_max_runs_per_library(self, multi_corpus: Path) -> None:
        units = list(enumerate_units(multi_corpus, max_runs_per_library=1))
        assert {u.run_number for u in units} == {1}
        assert len(units) == 2 * 3 * 2
        assert count_units(multi_corpus, max_runs_per_library=1) == 12

    def test_max_units(self, multi_corpus: Path) -> None:
        units = list(enumerate_units(multi_corpus, max_units=5))
        assert len(units) == 5
        assert count_units(multi_corpus, max_units=5) == 5

    def test_combined_filters(self, multi_corpus: Path) -> None:
        units = list(
            enumerate_units(
                multi_corpus,
                protocol_versions=["12"],
                libraries=["gnutls"],
                canonical_phases=["post_key_update"],
                max_runs_per_library=2,
            )
        )
        assert len(units) == 2
        assert {(u.protocol_version, u.library, u.canonical_phase) for u in units} == {
            ("12", "gnutls", "post_key_update")
        }

    def test_empty_filter_iterable_means_no_filter(self, multi_corpus: Path) -> None:
        assert len(list(enumerate_units(multi_corpus, libraries=[]))) == 36
        assert count_units(multi_corpus, libraries=[]) == 36

    @pytest.mark.parametrize("fixture_name", ["multi_corpus", "mixed_name_corpus"])
    def test_count_matches_enumerate_for_every_filter(
        self, fixture_name: str, request: pytest.FixtureRequest
    ) -> None:
        """The denominator and the enumeration must never disagree.

        Run over BOTH corpora on purpose. ``multi_corpus`` uses phase-style
        ``.dump`` names only, which is exactly the input space where a
        re-derived admission rule and the real one happen to agree - a suite
        confined to it is green over the one region that cannot expose a drift.
        ``mixed_name_corpus`` adds the dataset-style names (bare AND dotted),
        where the two implementations parted company.
        """
        root = request.getfixturevalue(fixture_name)
        for kwargs in (
            {},
            {"libraries": ["openssl", "gnutls"]},
            {"protocol_versions": ["13"]},
            {"scenarios": [TLS13_SCENARIO]},
            {"canonical_phases": ["pre_key_update", "post_key_update"]},
            {"canonical_phases": ["pre_handshake_end", "post_handshake_end"]},
            {"canonical_phases": ["full_handshake_end", "full_second_event"]},
            {"max_runs_per_library": 2},
        ):
            assert count_units(root, **kwargs) == len(
                list(enumerate_units(root, **kwargs))
            ), (fixture_name, kwargs)

    def test_every_canonical_phase_present_agrees_one_at_a_time(
        self, mixed_name_corpus: Path
    ) -> None:
        """Per-phase, not just in aggregate.

        Aggregate equality can hide two errors that cancel. The drift this
        pins INVERTS under a phase filter - the short name list the count
        works from re-maps the positional generic suffixes, so the denominator
        can promise a unit the enumeration never yields - which shows up only
        when each phase is checked on its own.
        """
        phases = {u.canonical_phase for u in enumerate_units(mixed_name_corpus)}
        assert phases, "fixture produced no canonical phases"
        for phase in sorted(phases):
            assert count_units(mixed_name_corpus, canonical_phases=[phase]) == len(
                list(enumerate_units(mixed_name_corpus, canonical_phases=[phase]))
            ), phase


# ---------------------------------------------------------------------------
# Tolerance of a malformed corpus
# ---------------------------------------------------------------------------


class TestMalformedCorpus:
    def test_empty_root(self, tmp_path: Path) -> None:
        root = _corpus(tmp_path)
        assert list(enumerate_units(root)) == []
        assert count_units(root) == 0

    def test_missing_root(self, tmp_path: Path) -> None:
        missing = tmp_path / "nope"
        assert list(enumerate_units(missing)) == []
        assert count_units(missing) == 0

    def test_unparseable_run_dirname_is_skipped_not_fatal(self, tmp_path: Path) -> None:
        root = _corpus(tmp_path)
        _make_run(root)
        junk = root / "TLS13" / TLS13_SCENARIO / "openssl" / "not-a-run-dir"
        junk.mkdir(parents=True)
        (junk / DUMP_A).write_bytes(b"\xab" * 8)

        units = list(enumerate_units(root))
        assert len(units) == 1
        assert count_units(root) == 1

    def test_unknown_protocol_dir_is_skipped(self, tmp_path: Path) -> None:
        root = _corpus(tmp_path)
        _make_run(root)
        _make_run(root, protocol_dir="NOTATLS", version="13", run_number=7)
        assert len(list(enumerate_units(root))) == 1
        assert count_units(root) == 1

    def test_version_disagreement_is_skipped(self, tmp_path: Path) -> None:
        """A ``TLS13`` directory holding a ``_run_12_`` directory is
        non-conforming; ``axes_from_run_dir`` refuses to pick a side."""
        root = _corpus(tmp_path)
        _make_run(root, protocol_dir="TLS13", version="12", run_number=3)
        assert list(enumerate_units(root)) == []
        assert count_units(root) == 0

    def test_run_with_no_dumps_yields_nothing(self, tmp_path: Path) -> None:
        root = _corpus(tmp_path)
        _make_run(root, dumps=[])
        assert list(enumerate_units(root)) == []
        assert count_units(root) == 0

    def test_non_dump_files_are_not_units(self, tmp_path: Path) -> None:
        """Sidecars are excluded - and the dataset-style dumps beside them are NOT.

        The exclusion half is only half the rule. This case also plants every
        dataset-style spelling next to the sidecars, because an admission rule
        that under-counts looks identical to one that correctly excludes: both
        just produce a smaller number.
        """
        root = _corpus(tmp_path)
        run_dir = _make_run(
            root, dumps=[DUMP_A, *BARE_DATASET_DUMPS]
        )
        (run_dir / "notes.txt").write_text("hello")
        (run_dir / "keylog.csv").write_text("label,value\n")
        (run_dir / "meta.json").write_text("{}")
        (run_dir / "plain.core.txt").write_text("not a core")
        (run_dir / "core").write_bytes(b"\x7fELF")  # no dot: not a dump
        (run_dir / "run_data").mkdir()
        (run_dir / "run_data" / "traffic.pcap").write_bytes(b"\xd4\xc3\xb2\xa1")

        expected = 1 + len(BARE_DATASET_DUMPS)
        assert count_units(root) == expected
        assert len(list(enumerate_units(root))) == expected

    def test_a_dotted_run_counts_and_enumerates_alike(self, tmp_path: Path) -> None:
        """The dotted spelling, kept in a run of its own (case-insensitive FS)."""
        root = _corpus(tmp_path)
        _make_run(root, dumps=[DUMP_A, *DOTTED_DATASET_DUMPS])
        expected = 1 + len(DOTTED_DATASET_DUMPS)
        assert count_units(root) == expected
        assert len(list(enumerate_units(root))) == expected

    def test_bare_dataset_dumps_are_counted_not_only_enumerated(
        self, tmp_path: Path
    ) -> None:
        """The exact drift the count-vs-enumerate suite could not see.

        ``core.discovery.DATASET_DUMP_SUFFIXES`` spells its entries with a
        LEADING DOT (``".gdb_raw.bin"``), but discovery's real admission rule
        (``_infer_dump_kind``) matches ``name.endswith("gdb_raw.bin")`` without
        one - and the committed fixture
        ``tests/fixtures/datasets/gocryptfs/run_0001/`` contains bare
        ``gdb_raw.bin`` / ``lldb_raw.bin``. A count that re-derived admission
        from the suffix tuple enumerated those four dumps but counted two.

        Under a ``canonical_phases`` filter the drift INVERTS into a silent
        zero: the count re-maps the positional generic suffixes over its
        SHORTER name list, so the denominator promises a unit that the
        enumeration - working from the full list - never yields.
        """
        root = _corpus(tmp_path)
        _make_run(
            root, dumps=["gdb_raw.bin", "lldb_raw.bin", GENERIC_EARLY, GENERIC_LATE],
        )

        assert count_units(root) == 4
        assert len(list(enumerate_units(root))) == 4

        for phase in ("pre_handshake_end", "pre_second_event", "full_handshake_end"):
            enumerated = len(list(enumerate_units(root, canonical_phases=[phase])))
            assert count_units(root, canonical_phases=[phase]) == enumerated, phase

    def test_uppercase_dataset_dumps_are_admitted(self, tmp_path: Path) -> None:
        """Admission is case-insensitive on BOTH sides of the seam."""
        root = _corpus(tmp_path)
        _make_run(root, dumps=["GDB_RAW.BIN", "GCORE.CORE"])
        assert count_units(root) == 2
        assert len(list(enumerate_units(root))) == 2

    def test_unreadable_run_directory_is_skipped_not_fatal(self, tmp_path: Path) -> None:
        _skip_if_root()
        root = _corpus(tmp_path)
        _make_run(root)
        blocked = root / "TLS13" / TLS13_SCENARIO / "openssl" / "openssl_run_13_9"
        blocked.mkdir()
        (blocked / DUMP_A).write_bytes(b"\xab" * 8)
        os.chmod(blocked, 0o000)
        try:
            assert len(list(enumerate_units(root))) == 1
            assert count_units(root) == 1
        finally:
            os.chmod(blocked, 0o755)


# ---------------------------------------------------------------------------
# Unit contents
# ---------------------------------------------------------------------------


class TestUnitContents:
    def test_axes_and_sidecars(self, tmp_path: Path) -> None:
        root = _corpus(tmp_path)
        run_dir = _make_run(root, dumps=[DUMP_A, DUMP_B])
        units = {u.dump_path.name: u for u in enumerate_units(root)}

        unit = units[DUMP_A]
        assert unit.corpus_id == "tls_dumps"
        assert unit.protocol_version == "13"
        assert unit.scenario == TLS13_SCENARIO
        assert unit.library == "openssl"
        assert unit.library_version == "unknown"
        assert unit.run_number == 1
        assert unit.dump_path == run_dir / DUMP_A
        assert unit.raw_phase == "pre_server_key_update"
        assert unit.canonical_phase == "pre_key_update"
        assert unit.phase_timestamp == "20251020_171845_606711"
        assert unit.keylog_path == run_dir / "keylog.csv"
        assert unit.run_dir == run_dir

        assert units[DUMP_B].canonical_phase == "post_key_update"

    def test_units_are_frozen(self, tmp_path: Path) -> None:
        root = _corpus(tmp_path)
        _make_run(root)
        unit = _only_unit(root)
        with pytest.raises(dataclasses.FrozenInstanceError):
            unit.canonical_phase = "pre_cleanup"  # type: ignore[misc]

    def test_missing_keylog_is_none(self, tmp_path: Path) -> None:
        root = _corpus(tmp_path)
        _make_run(root, keylog=False)
        assert _only_unit(root).keylog_path is None

    def test_enumeration_is_deterministic(self, multi_corpus: Path) -> None:
        first = [u.unit_key for u in enumerate_units(multi_corpus)]
        second = [u.unit_key for u in enumerate_units(multi_corpus)]
        assert first == second
        assert len(set(first)) == len(first)


# ---------------------------------------------------------------------------
# count_units is genuinely cheap
# ---------------------------------------------------------------------------


class TestCountUnitsIsCheap:
    """``count_units`` must not pay what the sweep itself pays.

    Its docstring promises no ``meta.json`` probe and no keylog stat. Until
    this was fixed the promise was false: ``count_units`` -> ``_walk_runs`` ->
    ``_sorted_runs`` -> ``axes_from_run_dir`` ->
    ``core.corpus_axes._resolve_library_version`` -> ``load_run_meta``, i.e.
    two syscalls per run (~5,200 over the measured corpus) to resolve a
    ``library_version`` that is ``"unknown"`` for every run in it and a
    ``keylog_path`` a count cannot use.
    """

    @staticmethod
    def _count_meta_loads(monkeypatch: pytest.MonkeyPatch) -> List[Path]:
        """Count ``load_run_meta`` calls through EVERY binding that can make one.

        ``load_run_meta`` is reachable under three names, because both importers
        do ``from .dataset_metadata import load_run_meta`` and so hold their own
        module-level reference:

        * ``core.dataset_metadata.load_run_meta`` - the definition;
        * ``core.corpus_axes.load_run_meta`` - reached by
          ``_resolve_library_version`` on the full-axes path;
        * ``core.discovery.load_run_meta`` - reached by
          ``RunDiscovery.load_run_directory``, one probe per run.

        Patching fewer than all three makes this test vacuous in exactly the
        direction it is meant to guard. With only the first two patched, a
        regression in which ``count_units`` started calling
        ``load_run_directory`` - which probes ``meta.json`` per run, the very
        cost the docstring forbids - recorded ZERO probes and left the
        assertion green.
        """
        from memdiver.core import corpus_axes, dataset_metadata, discovery

        seen: List[Path] = []
        original = dataset_metadata.load_run_meta

        def counting_load_run_meta(run_dir, *args, **kwargs):
            seen.append(Path(run_dir))
            return original(run_dir, *args, **kwargs)

        monkeypatch.setattr(dataset_metadata, "load_run_meta", counting_load_run_meta)
        monkeypatch.setattr(corpus_axes, "load_run_meta", counting_load_run_meta)
        monkeypatch.setattr(discovery, "load_run_meta", counting_load_run_meta)
        return seen

    def test_the_probe_counter_sees_load_run_directory(
        self, multi_corpus: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Guard on the guard: the ``discovery`` binding really is patched.

        Without this, the two "never probes meta.json" cases below could go on
        passing for the wrong reason.
        """
        from memdiver.core.discovery import RunDiscovery

        seen = self._count_meta_loads(monkeypatch)
        run_dir = next(iter(enumerate_units(multi_corpus))).run_dir
        RunDiscovery.load_run_directory(run_dir, extract_secrets=False)
        assert run_dir in seen

    def test_count_units_never_probes_meta_json(
        self, multi_corpus: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        seen = self._count_meta_loads(monkeypatch)
        assert count_units(multi_corpus) == 36
        assert seen == []

    def test_count_units_never_probes_meta_json_with_a_phase_filter(
        self, multi_corpus: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The canonical-phase filter is pure CPU over already-listed names."""
        seen = self._count_meta_loads(monkeypatch)
        assert count_units(multi_corpus, canonical_phases=["pre_key_update"]) == 18
        assert seen == []

    def test_enumerate_units_still_probes_it(
        self, multi_corpus: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Guards the test above against being vacuous.

        ``enumerate_units`` legitimately needs full axes, so it keeps the
        probe; if the patch above were ineffective this assertion is what would
        notice.
        """
        seen = self._count_meta_loads(monkeypatch)
        assert len(list(enumerate_units(multi_corpus))) == 36
        # TWO probes per run directory, one through each binding:
        # ``corpus_axes`` (_resolve_library_version) and ``discovery``
        # (load_run_directory).
        assert len(seen) == 2 * 18
        assert len(set(seen)) == 18

    def test_count_units_never_resolves_full_axes(
        self, multi_corpus: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The structural version of the same claim.

        ``axes_from_run_dir`` is the function that reaches the filesystem; the
        counting path must not call it at all, whatever it happens to do
        internally today.
        """
        from memdiver.engine import sweep_plan

        calls: List[Path] = []

        def exploding_axes_from_run_dir(run_dir, **kwargs):
            calls.append(Path(run_dir))
            raise AssertionError(f"count_units resolved full axes for {run_dir}")

        monkeypatch.setattr(
            sweep_plan, "axes_from_run_dir", exploding_axes_from_run_dir
        )
        assert count_units(multi_corpus) == 36
        assert calls == []

    def test_cheap_count_still_rejects_the_same_runs(self, tmp_path: Path) -> None:
        """The dirname-only path keeps both admission rules of the axes path."""
        root = _corpus(tmp_path)
        _make_run(root)
        _make_run(root, protocol_dir="NOTATLS", version="13", run_number=7)
        _make_run(root, protocol_dir="TLS13", version="12", run_number=3)
        junk = root / "TLS13" / TLS13_SCENARIO / "openssl" / "not-a-run-dir"
        junk.mkdir(parents=True)
        (junk / DUMP_A).write_bytes(b"\xab" * 8)

        assert count_units(root) == 1
        assert count_units(root) == len(list(enumerate_units(root)))


# ---------------------------------------------------------------------------
# Timestamp ordering
# ---------------------------------------------------------------------------


class TestPhaseTimestampOrdering:
    def test_parses_the_three_numeric_fields(self) -> None:
        assert parse_phase_timestamp("20251020_171845_606711") == (
            20251020, 171845, 606711,
        )
        assert parse_phase_timestamp("20251020_171845_90000") == (
            20251020, 171845, 90000,
        )

    @pytest.mark.parametrize("bad", ["", "not-a-timestamp", "20251020_171845", "a_b_c"])
    def test_an_unparseable_prefix_sorts_first_instead_of_raising(
        self, bad: str
    ) -> None:
        assert parse_phase_timestamp(bad) == (-1, -1, -1)
        assert parse_phase_timestamp(bad) < parse_phase_timestamp(
            "20251020_171845_606711"
        )

    def test_a_five_digit_microsecond_field_sorts_chronologically(self) -> None:
        r"""The bug the string comparison hides.

        ``DUMP_PATTERN`` captures the microsecond field as ``\d+``, so it is
        variable width. All 18,917 measured dumps carry six digits, which is
        the only reason lexicographic order has worked so far.
        """
        assert parse_phase_timestamp("20251020_171845_90000") < parse_phase_timestamp(
            "20251020_171845_606711"
        )
        # As TEXT the very same pair sorts the other way round - which is
        # exactly what makes this a silent defect rather than a visible one.
        assert "20251020_171845_90000" > "20251020_171845_606711"

    def test_units_are_emitted_in_parsed_timestamp_order(self, tmp_path: Path) -> None:
        root = _corpus(tmp_path)
        _make_run(root, dumps=[MICROS_5_DIGITS, MICROS_6_DIGITS])

        emitted = [u.dump_path.name for u in enumerate_units(root)]
        assert emitted == [MICROS_5_DIGITS, MICROS_6_DIGITS]
        # A plain string sort of the same two names is the wrong order, so this
        # assertion would fail against the previous implementation.
        assert sorted(emitted) == [MICROS_6_DIGITS, MICROS_5_DIGITS]

    def test_canonical_labels_are_assigned_chronologically(
        self, tmp_path: Path
    ) -> None:
        """The consequential half: the LABELS, not just the emission order.

        Emitting in chronological order is not enough. ``canonical_phase`` is
        what ``canonical_phases=`` filters on and what every consumer groups
        by, and it is assigned positionally over the normalizer's OWN sort. So
        long as that sort compared raw strings, the chronologically FIRST dump
        (``..._90000_pre_abort``, 0.090 s) was labelled ``pre_second_event``
        and the chronologically SECOND (``..._606711_pre_shutdown``, 0.607 s)
        was labelled ``pre_handshake_end`` - backwards, silently, in the field
        Wave 5's phase-transition detector keys off.
        """
        root = _corpus(tmp_path)
        _make_run(root, dumps=[MICROS_5_DIGITS, MICROS_6_DIGITS])

        by_name = {u.dump_path.name: u.canonical_phase for u in enumerate_units(root)}
        assert by_name[MICROS_5_DIGITS] == "pre_handshake_end"
        assert by_name[MICROS_6_DIGITS] == "pre_second_event"

        # And the filter agrees with the count on both labels.
        for phase in ("pre_handshake_end", "pre_second_event"):
            assert count_units(root, canonical_phases=[phase]) == len(
                list(enumerate_units(root, canonical_phases=[phase]))
            ) == 1, phase


# ---------------------------------------------------------------------------
# Public seams
# ---------------------------------------------------------------------------


#: What ``RunDiscovery.dump_file_for`` must answer for each filename:
#: ``(kind, full_phase)``, or ``None`` for "not a dump". Written out rather
#: than compared against another implementation, so the rule itself is pinned.
#: The bare ``gdb_raw.bin`` / ``lldb_raw.bin`` rows are the ones the count used
#: to disagree about.
DUMP_ADMISSION_CASES = [
    (DUMP_A, ("raw", "pre_server_key_update")),
    (MICROS_5_DIGITS, ("raw", "pre_abort")),
    ("20251020_171845_606711_post_cleanup.msl", ("msl", "post_cleanup")),
    ("gdb_raw.bin", ("gdb_raw", "full_gdb_raw")),
    ("lldb_raw.bin", ("lldb_raw", "full_lldb_raw")),
    ("GDB_RAW.BIN", ("gdb_raw", "full_gdb_raw")),
    ("openssl.gdb_raw.bin", ("gdb_raw", "full_gdb_raw")),
    ("openssl.lldb_raw.bin", ("lldb_raw", "full_lldb_raw")),
    ("gcore.core", ("gcore", "full_gcore")),
    ("openssl.gcore.core", ("gcore", "full_gcore")),
    ("openssl.core", ("gcore", "full_gcore")),
    ("memslicer.msl", ("msl", "full_msl")),
    ("notes.txt", None),
    ("keylog.csv", None),
    ("meta.json", None),
    ("core", None),          # no dot, no recognised tail
    ("plain.core.txt", None),
    ("stray.dump", None),    # a ``.dump`` with no phase prefix is not a dump
    ("", None),
]

#: Protocol DIRECTORY names and what the registry must resolve them to.
#: Covers the near-miss shapes a ``startswith``-based resolver gets wrong:
#: a bare prefix, a truncated version, a version with a trailing digit, the
#: wrong case, a prefix that is not at the start, and one prefix followed by
#: another.
PROTOCOL_DIR_CASES = [
    ("TLS12", ("TLS", "12")),
    ("TLS13", ("TLS", "13")),
    ("SSH2", ("SSH", "2")),
    ("AES256", ("AES", "256")),
    ("TLS", None),
    ("TLS1", None),
    ("TLS130", None),
    ("TLS12x", None),
    ("tls13", None),
    ("NOTATLS", None),
    ("TLSSSH2", None),
    ("", None),
]


class TestPublicSeams:
    @pytest.mark.parametrize("name,expected", DUMP_ADMISSION_CASES)
    def test_dump_file_for_pins_the_admission_rule(self, name, expected) -> None:
        """What the public seam must ANSWER, not merely that it delegates.

        ``sweep_plan``'s count is only as correct as this rule, so the rule is
        written out here instead of being compared against a second copy of
        itself.
        """
        from memdiver.core.discovery import RunDiscovery

        dump = RunDiscovery.dump_file_for(Path(name))
        if expected is None:
            assert dump is None, name
            return
        assert dump is not None, name
        assert (dump.kind, dump.full_phase) == expected, name

    def test_dump_file_for_is_public_and_agrees_with_the_private_one(self) -> None:
        """SMOKE CHECK ONLY: the public seam is a one-line delegation.

        It cannot fail while ``dump_file_for`` is ``return
        RunDiscovery._dump_file_for(path)``; the rule it delegates is pinned by
        :meth:`test_dump_file_for_pins_the_admission_rule` above. This case
        exists to notice the day the delegation stops being one, e.g. if either
        side grows a filter of its own.
        """
        from memdiver.core.discovery import RunDiscovery

        for name, _expected in DUMP_ADMISSION_CASES:
            public = RunDiscovery.dump_file_for(Path(name))
            private = RunDiscovery._dump_file_for(Path(name))
            assert (public is None) == (private is None), name
            if public is not None and private is not None:
                assert public.full_phase == private.full_phase
                assert public.kind == private.kind

    def test_sweep_plan_does_not_reach_into_private_discovery_api(self) -> None:
        """No private discovery API, and no LOCAL COPY of the rule either.

        The old assertion (``"RunDiscovery.dump_file_for" in source``) was
        satisfied by a single occurrence in a docstring, so it stayed green
        while ``_is_dump_filename`` re-derived the admission rule beside it and
        bypassed the seam entirely. Assert the absence of the private name -
        which a docstring mention cannot fake into passing - and the presence
        of an actual CALL.
        """
        source = Path(inspect.getfile(count_units)).read_text()
        assert "_dump_file_for" not in source
        assert "RunDiscovery.dump_file_for(" in source

    @pytest.mark.parametrize("dirname,expected", PROTOCOL_DIR_CASES)
    def test_resolve_protocol_dir_pins_the_registry_edges(
        self, dirname, expected
    ) -> None:
        """The protocol-directory rule, resolved through the public seam."""
        from memdiver.core.corpus_axes import resolve_protocol_dir

        assert resolve_protocol_dir(dirname) == expected, dirname

    @pytest.mark.parametrize("dirname,expected", PROTOCOL_DIR_CASES)
    def test_sweep_plan_resolves_protocol_dirs_through_the_seam(
        self, dirname, expected
    ) -> None:
        """The cheap counting path must not hold its own copy of that rule.

        ``_protocol_dir_axes`` used to be a near-verbatim duplicate of
        ``corpus_axes._resolve_protocol_dir``, with nothing asserting the two
        stayed equal - the same duplication class as the dump-admission rule,
        and the same way a denominator drifts. It now delegates to the public
        seam; both halves are pinned here so a future divergence fails.
        """
        from memdiver.core.corpus_axes import resolve_protocol_dir
        from memdiver.engine import sweep_plan

        assert sweep_plan._protocol_dir_axes(dirname) == expected, dirname
        assert sweep_plan._protocol_dir_axes(dirname) == resolve_protocol_dir(dirname)

    def test_the_shared_timestamp_parse_has_exactly_one_definition(self) -> None:
        """``sweep_plan`` and ``phase_normalizer`` order dumps identically.

        The parse used to be defined in ``engine.sweep_plan`` while
        ``PhaseNormalizer`` went on sorting by the raw string - so the
        emission order was chronological but the canonical LABELS, handed out
        positionally by that other sort, were not. One object, one order.
        """
        from memdiver.core import phase_normalizer
        from memdiver.engine import sweep_plan

        assert (
            sweep_plan.parse_phase_timestamp
            is phase_normalizer.parse_phase_timestamp
        )


# ---------------------------------------------------------------------------
# Real corpus (gated)
# ---------------------------------------------------------------------------

#: Measured directly on the corpus at ~/Desktop/tls_dumps: 2,600 runs
#: (13 libraries x 2 protocol versions x 100 runs) and 18,917 dumps.
REAL_DUMP_COUNT = 18917


@pytest.mark.requires_dataset
class TestRealCorpus:
    @staticmethod
    def _root() -> Path:
        root = tls_dumps_dir()
        if not root.is_dir():
            pytest.skip(f"TLS corpus not present at {root}")
        return root

    # The only FULL-corpus pass in this file: it walks all 2,600 run dirs to
    # reach 18,917 dumps. `slow` (deselected by the default addopts) keeps a
    # plain `pytest` off the corpus. Its sibling below is deliberately NOT
    # `slow`: it stops after 5 units, so it costs nothing, and marking it would
    # remove it from `make test` -- the one command a developer WITH the corpus
    # actually runs. See the `test-corpus` target in the Makefile.
    @pytest.mark.slow
    def test_count_units_matches_the_measured_denominator(self) -> None:
        assert count_units(self._root()) == REAL_DUMP_COUNT

    def test_first_units_have_sane_axes(self) -> None:
        root = self._root()
        units = []
        for unit in enumerate_units(root):
            units.append(unit)
            if len(units) == 5:
                break
        assert len(units) == 5
        for unit in units:
            assert unit.corpus_id == root.name
            assert unit.protocol_version in {"12", "13"}
            assert unit.scenario in {TLS12_SCENARIO, TLS13_SCENARIO}
            assert unit.library
            assert 1 <= unit.run_number <= 100
            assert unit.dump_path.is_file()
            assert unit.raw_phase.startswith(("pre_", "post_"))
            assert unit.canonical_phase in CANONICAL_PHASE_ORDER
            assert unit.phase_timestamp
            assert unit.keylog_path is not None and unit.keylog_path.is_file()
            assert unit.unit_key.startswith(f"u2/{root.name}/")
            assert len(inputs_digest(unit)) == 64

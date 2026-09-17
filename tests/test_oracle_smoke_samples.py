"""Tests for ``app.oracle_smoke_test``.

The module under test composes the samples a smoke test is graded on: one
**positive control** (the run's recorded master key, which a working oracle
MUST accept) and N **negative controls** (real byte windows read out of the
dump, which a working oracle MUST reject). Everything that can go wrong with
that composition -- no corpus, no key, a malformed key, a thin dump, an
all-zero dump, an unreadable file -- is a *degradation* with a named reason,
never an exception, because a smoke test that 500s tells the analyst nothing.

Like ``tests/test_oracle_autoconfig.py``, every test builds its own throwaway
run (run dir + ``meta.json`` + a flat dump) under ``tmp_path`` rather than
reaching for the author's corpus, so the rules stay readable next to the
assertion that exercises them and the file passes on a machine that has never
seen the real dataset.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from memdiver.app.oracle_smoke_test import compose_smoke_samples

#: A 32-byte master key with 32 distinct bytes, so a window that happens to
#: contain it is never mistaken for low-variety filler.
KEY = bytes(range(0x40, 0x60))
KEY_HEX = KEY.hex()


# -- Fixtures ------------------------------------------------------------------


def _varied_bytes(length: int) -> bytes:
    """Deterministic filler in which every 32-byte window is high-variety.

    A stride of 7 modulo the prime 251 means 32 consecutive values never
    repeat, so these windows survive the ``_MIN_DISTINCT_BYTES`` rejection and
    the tests grade the rules they mean to grade rather than the reserve path.
    """
    return bytes((i * 7 + 13) % 251 for i in range(length))


def _make_run(
    tmp_path: Path,
    run_id: str = "run_0001",
    *,
    cipher: str = "aes",
    master_key_hex: str | None = KEY_HEX,
    dump_bytes: bytes | None = None,
    dump_name: str = "memslicer.bin",
    with_meta: bool = True,
    write_dump: bool = True,
) -> Path:
    """One corpus run directory; returns the dump path inside it.

    The dump is a flat binary so ``open_dump`` resolves it to
    ``RawDumpSource`` -- the format whose ``"vas"`` view is the file itself,
    which keeps the offsets in these assertions checkable by hand.
    """
    run_dir = tmp_path / run_id
    run_dir.mkdir(parents=True, exist_ok=True)

    dump = run_dir / dump_name
    if write_dump:
        dump.write_bytes(_varied_bytes(4096) if dump_bytes is None else dump_bytes)

    if with_meta:
        payload: dict = {
            "run_id": run_id,
            "cipher": cipher,
            "password": "hunter2",
            "aslr_base": 0,
            "pid": 1234,
            "dumps": {},
        }
        if master_key_hex is not None:
            payload["master_key_hex"] = master_key_hex
        (run_dir / "meta.json").write_text(json.dumps(payload))
    return dump


# -- The positive control ------------------------------------------------------


def test_positive_control_is_the_runs_recorded_master_key(tmp_path: Path):
    """The one sample a working oracle must accept comes from ``meta.json``.

    Protects the premise of the whole endpoint: without a candidate whose
    correct verdict is known in advance, a smoke test cannot tell a working
    oracle from one wired to ``return False``.
    """
    dump = _make_run(tmp_path)

    samples = compose_smoke_samples([str(dump)], seed=1)

    assert samples.positive is not None
    assert samples.positive.sample == KEY
    assert samples.positive.source == "meta.json"
    assert samples.no_positive_reason is None


def test_provenance_label_names_the_run_directory(tmp_path: Path):
    """"Where did this key come from?" must be answerable without arithmetic.

    The label names the run DIRECTORY (``run_0001``), not ``meta.run_id``
    (``"1"``), so the analyst can match it against the file picker they
    selected the dump in.
    """
    dump = _make_run(tmp_path, "run_0007")

    samples = compose_smoke_samples([str(dump)], seed=1)

    assert samples.positive is not None
    label = samples.positive.provenance_label
    assert "run_0007/meta.json" in label
    assert "master_key_hex" in label
    assert "32 bytes" in label
    assert "cipher=aes" in label


def test_missing_meta_json_degrades_to_negatives_only(tmp_path: Path):
    """A dump outside the corpus still yields a useful negative-only test.

    No ground truth means no positive control, but the negatives alone still
    catch an oracle that accepts arbitrary memory -- so this must degrade with
    a named reason rather than refuse to run.
    """
    dump = _make_run(tmp_path, with_meta=False)

    samples = compose_smoke_samples([str(dump)], seed=1)

    assert samples.positive is None
    assert samples.no_positive_reason is not None
    assert "meta.json" in samples.no_positive_reason
    assert dump.name in samples.no_positive_reason
    assert len(samples.negatives) == 15


@pytest.mark.parametrize(
    "master_key_hex, label",
    [
        (None, "absent"),
        ("", "empty"),
        (KEY_HEX[:-1], "odd-length"),
        ("zz" * 32, "non-hex"),
    ],
)
def test_unusable_master_key_is_reported_not_raised(
    tmp_path: Path, master_key_hex: str | None, label: str
):
    """An absent or malformed ``master_key_hex`` is "no key", never a crash.

    ``core.dataset_metadata._decode_hex`` returns ``b""`` for odd-length and
    non-hex values rather than front-padding them, because a nibble-misaligned
    key is a WRONG key -- and a wrong positive control manufactures a failing
    grade for a working oracle.
    """
    dump = _make_run(tmp_path, master_key_hex=master_key_hex)

    samples = compose_smoke_samples([str(dump)], seed=1)

    assert samples.positive is None, label
    assert samples.no_positive_reason is not None
    assert "master key" in samples.no_positive_reason
    assert "run_0001" in samples.no_positive_reason
    # The test still has teeth: the negatives are composed regardless.
    assert len(samples.negatives) == 15


def test_key_shorter_than_key_size_is_submitted_whole_with_a_caveat(
    tmp_path: Path,
):
    """A 16-byte key must NOT be padded or truncated to the 32-byte sweep size.

    Truncating it would submit bytes that are not the key, the oracle would
    rightly reject them, and the smoke test would report a working oracle as
    broken. The mismatch is disclosed as a caveat instead.
    """
    short_key = bytes(range(0x10, 0x20))
    dump = _make_run(tmp_path, master_key_hex=short_key.hex())

    samples = compose_smoke_samples([str(dump)], key_size=32, seed=1)

    assert samples.positive is not None
    assert samples.positive.sample == short_key
    assert len(samples.positive.sample) == 16
    assert any(
        "16 bytes" in c and "32 bytes" in c for c in samples.caveats
    ), samples.caveats


def test_cipher_mismatch_is_disclosed_as_a_caveat(tmp_path: Path):
    """An oracle that cannot speak the run's cipher makes a rejection meaningless.

    The key is still submitted (so the caller sees the real verdict), but the
    analyst has to be told that "the oracle rejected the real key" was the
    expected outcome here, not evidence of a bug.
    """
    dump = _make_run(tmp_path, cipher="xchacha")

    samples = compose_smoke_samples([str(dump)], requires_cipher="aes", seed=1)

    assert samples.positive is not None
    assert any(
        "xchacha" in c and "aes" in c for c in samples.caveats
    ), samples.caveats


def test_cipher_agreement_adds_no_caveat(tmp_path: Path):
    """The mismatch caveat must not fire when the run and oracle agree."""
    dump = _make_run(tmp_path, cipher="aes")

    samples = compose_smoke_samples([str(dump)], requires_cipher="aes", seed=1)

    assert samples.caveats == ()


def test_include_positive_control_false_skips_the_key_entirely(tmp_path: Path):
    """Opting out must not silently read the key anyway."""
    dump = _make_run(tmp_path)

    samples = compose_smoke_samples(
        [str(dump)], include_positive_control=False, seed=1
    )

    assert samples.positive is None
    assert samples.no_positive_reason is None
    assert KEY not in samples.negatives


# -- The negative controls -----------------------------------------------------


def test_negatives_are_key_sized_in_bounds_and_distinct(tmp_path: Path):
    """Every negative must be a real, whole, distinctly-located dump window.

    A short read, an offset past the tail or the same window submitted twice
    would each inflate the sample count without adding evidence.
    """
    dump = _make_run(tmp_path)

    samples = compose_smoke_samples([str(dump)], negatives=15, seed=1)

    assert len(samples.negatives) == 15
    assert len(samples.negative_offsets) == 15
    assert all(len(n) == 32 for n in samples.negatives)
    assert len(set(samples.negative_offsets)) == 15
    assert all(0 <= off <= samples.dump_size - 32 for off in samples.negative_offsets)
    assert samples.dump_size == 4096
    assert samples.low_entropy_included == 0


def test_negatives_are_drawn_from_the_vas_view_not_va(tmp_path: Path):
    """``"va"`` pads unmapped space with synthesized zeroes -- invented evidence.

    ``"vas"`` is the only projection whose offsets name real captured process
    bytes, so it is what the draw must report having used.
    """
    dump = _make_run(tmp_path)

    samples = compose_smoke_samples([str(dump)], seed=1)

    assert samples.view == "vas"
    assert samples.dump_format == "raw"
    assert samples.dump_path == str(dump)


def test_negatives_match_the_bytes_at_their_reported_offsets(tmp_path: Path):
    """The reported offsets must actually name the submitted windows.

    Offsets are what an analyst uses to go look at the byte the oracle
    accepted; a decorative offset would send them to the wrong place.
    """
    body = _varied_bytes(4096)
    dump = _make_run(tmp_path, dump_bytes=body)

    samples = compose_smoke_samples([str(dump)], negatives=5, seed=1)

    for offset, sample in zip(samples.negative_offsets, samples.negatives):
        assert body[offset:offset + 32] == sample


def test_the_real_key_is_never_returned_as_a_negative(tmp_path: Path):
    """The aliasing guard: the key genuinely occurs in these dumps.

    That is the entire premise of the tool, so an unguarded random draw can
    land on the key itself -- and an oracle that correctly accepted it would
    then be recorded as "accepts arbitrary noise", a false accusation against
    a working oracle. Every draw is compared against the positive control and
    resampled on a match.
    """
    dump = _make_run(tmp_path, dump_bytes=KEY * 8)

    samples = compose_smoke_samples([str(dump)], negatives=15, seed=2)

    assert samples.negatives, "no negatives drawn -- the guard was not exercised"
    assert KEY not in samples.negatives
    # Every 32-aligned window of this dump IS the key, so the guard is exactly
    # what keeps those offsets out.
    assert all(off % 32 != 0 for off in samples.negative_offsets)


def test_without_a_positive_control_the_same_draw_does_hit_the_key(
    tmp_path: Path,
):
    """Makes the aliasing guard non-vacuous: the same RNG stream lands on it.

    Identical dump, identical seed, positive control switched off -- the guard
    has nothing to compare against, and the key-aligned offsets the previous
    test proves are excluded now show up. Without this, that test could pass
    simply because the draw never went near a key-aligned offset.
    """
    dump = _make_run(tmp_path, dump_bytes=KEY * 8)

    samples = compose_smoke_samples(
        [str(dump)], negatives=15, include_positive_control=False, seed=2
    )

    assert any(off % 32 == 0 for off in samples.negative_offsets)
    assert KEY in samples.negatives


def test_all_zero_dump_reports_low_entropy_instead_of_raising(tmp_path: Path):
    """Fifteen zero-blocks prove nothing about an oracle's discrimination.

    A degenerate dump must still produce a result, but the weakening has to
    reach the analyst rather than be presented as a full-strength test.
    """
    dump = _make_run(tmp_path, dump_bytes=b"\x00" * 4096)

    samples = compose_smoke_samples([str(dump)], negatives=15, seed=1)

    assert len(samples.negatives) == 15
    assert samples.low_entropy_included == 15
    assert any("low-variety" in c for c in samples.caveats), samples.caveats


def test_dump_smaller_than_the_key_yields_no_negatives(tmp_path: Path):
    """A dump too thin to hold one sample degrades; it must not raise.

    ``rng.randrange(0, size - key_size + 1)`` would raise on a negative bound,
    so this is the guard that keeps a stub dump from 500-ing the endpoint.
    """
    dump = _make_run(tmp_path, dump_bytes=b"\x01" * 8)

    samples = compose_smoke_samples([str(dump)], key_size=32, seed=1)

    assert samples.negatives == ()
    assert samples.negative_offsets == ()
    assert samples.dump_size == 8
    assert any(
        "fewer than" in c and "32-byte" in c for c in samples.caveats
    ), samples.caveats
    # The positive control is unaffected by a thin dump.
    assert samples.positive is not None


def test_thin_dump_shortfall_is_disclosed(tmp_path: Path):
    """Drawing fewer negatives than asked for must be said out loud.

    A test that quietly returns 3 of 15 samples reads as a clean pass on a
    fraction of the evidence.
    """
    # 33 bytes: exactly two in-bounds offsets for a 32-byte window.
    dump = _make_run(tmp_path, dump_bytes=_varied_bytes(33))

    samples = compose_smoke_samples([str(dump)], negatives=15, seed=1)

    assert len(samples.negatives) < 15
    assert any(
        "of the 15 requested" in c for c in samples.caveats
    ), samples.caveats


def test_unreadable_dump_degrades_with_a_caveat(tmp_path: Path):
    """A dump path that cannot be opened is a caveat, not a traceback.

    The run's ``meta.json`` is still readable here, so the positive control
    survives and the caller is told the oracle was never tested against real
    memory.
    """
    dump = _make_run(tmp_path, write_dump=False)

    samples = compose_smoke_samples([str(dump)], seed=1)

    assert samples.negatives == ()
    assert samples.positive is not None
    assert any(
        "could not be read" in c and dump.name in c for c in samples.caveats
    ), samples.caveats


def test_no_source_paths_composes_nothing_and_says_so(tmp_path: Path):
    """An empty selection must be a named reason, not an IndexError."""
    samples = compose_smoke_samples([], seed=1)

    assert samples.positive is None
    assert samples.no_positive_reason == "no dump was selected"
    assert samples.negatives == ()
    assert samples.dump_path is None
    assert samples.caveats


def test_zero_negatives_requested_draws_none(tmp_path: Path):
    """``negatives=0`` must not spin the draw loop or trip the shortfall caveat."""
    dump = _make_run(tmp_path)

    samples = compose_smoke_samples([str(dump)], negatives=0, seed=1)

    assert samples.negatives == ()
    assert samples.caveats == ()


# -- Reproducibility and the reference-run rule --------------------------------


def test_same_seed_gives_identical_offsets(tmp_path: Path):
    """A seeded draw must be reproducible, so a test can assert on it.

    This is what makes the HTTP surface testable at all, and what makes the
    UI's "run it again" button comparable to the previous run.
    """
    dump = _make_run(tmp_path)

    first = compose_smoke_samples([str(dump)], negatives=15, seed=4242)
    second = compose_smoke_samples([str(dump)], negatives=15, seed=4242)

    assert first.negative_offsets == second.negative_offsets
    assert first.negatives == second.negatives


def test_different_seeds_give_different_offsets(tmp_path: Path):
    """Non-vacuity for the determinism test: the seed really does steer the draw."""
    dump = _make_run(tmp_path)

    first = compose_smoke_samples([str(dump)], negatives=15, seed=1)
    second = compose_smoke_samples([str(dump)], negatives=15, seed=2)

    assert first.negative_offsets != second.negative_offsets


def test_only_the_first_source_path_is_used(tmp_path: Path):
    """Each run has its own password and therefore its own master key.

    The sweep verifies against ``source_paths[0]`` alone, so a key or a byte
    taken from any other run would be graded against an oracle that was never
    configured for it.
    """
    other_key = bytes(range(0x80, 0xA0))
    first = _make_run(tmp_path, "run_0001")
    _make_run(tmp_path, "run_0002", master_key_hex=other_key.hex())
    second = tmp_path / "run_0002" / "memslicer.bin"

    samples = compose_smoke_samples([str(first), str(second)], seed=1)

    assert samples.positive is not None
    assert samples.positive.sample == KEY
    assert "run_0001" in samples.positive.provenance_label
    assert samples.dump_path == str(first)

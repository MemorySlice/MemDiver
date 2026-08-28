"""MemDiver must be able to SCAN with the YARA rules it emits, not just print them.

Before ``engine/yara_scan.py`` the only ``yara.compile`` in the tree lived
inside a generated Volatility3 plugin template and never executed, so an
emitted detector could never be measured. These tests therefore lean on the
real emitter (``PatternGenerator`` -> ``YaraExporter``) rather than hand-written
rule text wherever the assertion is about the closed loop.

``import yara`` is a hard import, deliberately NOT ``pytest.importorskip``:
yara-python is a declared BASE dependency (see ``tests/test_install_contract.py``
and ``pyproject.toml``), so its absence is a broken environment that must fail
loudly. Quiet skipping is how a dependency goes undeclared in the first place.

The load-bearing test in here is :func:`test_chunk_straddling_match_found_once`
and its negative twin: the chunked strategy stitches an overlap onto each chunk
so a match spanning a boundary is seen whole, then drops any instance that
*begins* inside that overlap because the next chunk owns it. Get that wrong in
either direction and a corpus sweep either double-counts every boundary hit or
loses it entirely, silently, in a number nobody can audit afterwards.
"""

from __future__ import annotations

import random
import sys
import time
from pathlib import Path

import pytest
import yara

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from memdiver.architect.pattern_generator import PatternGenerator  # noqa: E402
from memdiver.architect.yara_exporter import YaraExporter  # noqa: E402
from memdiver.core.dump_source import open_dump  # noqa: E402
from memdiver.core.service_errors import CapabilityError  # noqa: E402
from memdiver.engine.yara_scan import (  # noqa: E402
    DEFAULT_OVERLAP_BYTES,
    MAX_RULE_SOURCE_BYTES,
    ScanResult,
    clear_rule_cache,
    compile_rules,
    max_pattern_length,
    rule_names,
    scan_chunked,
    scan_source,
)
from tests.fixtures.generate_msl_fixtures import write_msl_fixture  # noqa: E402
from tests.fixtures.tls_ground_truth import tls_dumps_dir  # noqa: E402

# One spelling of "where the corpus lives", shared with tests/_paths.py's
# dataset_root() fallback and honouring MEMDIVER_TLS_DUMPS_DIR.
REAL_CORPUS = tls_dumps_dir()


# ---------------------------------------------------------------------------
# Helpers: build rules the way the product builds them
# ---------------------------------------------------------------------------


def _emitted_rule(
    reference: bytes,
    static_mask: list,
    *,
    name: str = "planted_pattern",
    key_offset: int | None = None,
    key_length: int | None = None,
) -> str:
    """Run the REAL emitter chain and return its rule text."""
    pattern = PatternGenerator.generate(reference, static_mask, name=name)
    assert pattern is not None, "pattern generator rejected the fixture mask"
    return YaraExporter.export(
        pattern, key_offset=key_offset, key_length=key_length
    )


def _static_rule(reference: bytes, *, name: str = "exact_pattern") -> str:
    """An all-static (no wildcard) emitted rule for *reference*."""
    return _emitted_rule(reference, [True] * len(reference), name=name)


def _keyish_reference(rng: random.Random, *, total: int = 48, key_len: int = 16):
    """A 48-byte window whose middle 16 bytes are the volatile "key".

    Static ratio 32/48 = 0.667, comfortably over the generator's 0.3 floor, and
    the first and last bytes are static so the emitted hex string neither
    begins nor ends with a wildcard.
    """
    reference = bytes(rng.randrange(256) for _ in range(total))
    key_at = (total - key_len) // 2
    mask = [True] * total
    for i in range(key_at, key_at + key_len):
        mask[i] = False
    return reference, mask, key_at, key_len


def _write_dump(path: Path, size: int, plants: dict, *, seed: int = 7) -> Path:
    """Write a random-filled raw dump with *plants* = {offset: bytes}."""
    rng = random.Random(seed)
    buf = bytearray(rng.randrange(256) for _ in range(size))
    for offset, blob in plants.items():
        buf[offset:offset + len(blob)] = blob
    path.write_bytes(bytes(buf))
    return path


def _offsets(result: ScanResult) -> list:
    return [m.offset for m in result.matches]


# ---------------------------------------------------------------------------
# compile_rules: intake contract
# ---------------------------------------------------------------------------


def test_compile_rules_accepts_inline_source():
    rules = compile_rules(source=_static_rule(bytes(range(8)), name="inline_rule"))
    assert rule_names(rules) == ("inline_rule",)


def test_compile_rules_accepts_paths_with_per_file_namespaces(tmp_path):
    """Two files may define the SAME rule name; namespaces keep both alive."""
    shared = _static_rule(bytes(range(8)), name="same_name")
    (tmp_path / "first.yar").write_text(shared)
    (tmp_path / "second.yar").write_text(shared.replace("00 01", "10 11"))

    rules = compile_rules(paths=[tmp_path / "first.yar", tmp_path / "second.yar"])
    # Both rules survive compilation despite the identical identifier, which is
    # exactly what the ``filepaths={namespace: path}`` dict form buys.
    assert rule_names(rules) == ("same_name", "same_name")


def test_compile_rules_rejects_both_source_and_paths(tmp_path):
    (tmp_path / "r.yar").write_text(_static_rule(b"\x01\x02\x03\x04"))
    with pytest.raises(CapabilityError) as exc:
        compile_rules(source="rule r { condition: true }", paths=[tmp_path / "r.yar"])
    assert "exactly one" in str(exc.value)


def test_compile_rules_rejects_neither_source_nor_paths():
    with pytest.raises(CapabilityError) as exc:
        compile_rules()
    assert "exactly one" in str(exc.value)


def test_compile_rules_rejects_empty_path_list():
    with pytest.raises(CapabilityError) as exc:
        compile_rules(paths=[])
    # An empty sequence is not None, so it passes the exactly-one gate and must
    # be caught separately rather than compiling an empty rule set.
    assert "at least one" in str(exc.value)


def test_compile_rules_rejects_oversize_source():
    oversize = "// pad\n" * ((MAX_RULE_SOURCE_BYTES // 7) + 2)
    assert len(oversize.encode()) > MAX_RULE_SOURCE_BYTES
    with pytest.raises(CapabilityError) as exc:
        compile_rules(source=oversize)
    assert str(MAX_RULE_SOURCE_BYTES) in str(exc.value)


def test_compile_rules_maps_bad_rule_to_clear_error():
    with pytest.raises(CapabilityError) as exc:
        compile_rules(source="rule broken { condition: undefined_thing }")
    message = str(exc.value)
    assert "compilation failed" in message
    # libyara's own diagnostic is preserved, not replaced by a generic message.
    assert "undefined identifier" in message


def test_compile_rules_rejects_colliding_namespaces(tmp_path):
    """Two paths with the same stem would silently collapse in the dict form."""
    a = tmp_path / "a"
    b = tmp_path / "b"
    a.mkdir()
    b.mkdir()
    (a / "rules.yar").write_text(_static_rule(b"\x01\x02\x03\x04", name="ra"))
    (b / "rules.yar").write_text(_static_rule(b"\x05\x06\x07\x08", name="rb"))
    with pytest.raises(CapabilityError) as exc:
        compile_rules(paths=[a / "rules.yar", b / "rules.yar"])
    assert "namespace" in str(exc.value)


def test_compile_rules_rejects_unreadable_path(tmp_path):
    with pytest.raises(CapabilityError) as exc:
        compile_rules(paths=[tmp_path / "does_not_exist.yar"])
    assert "cannot read" in str(exc.value)


# ---------------------------------------------------------------------------
# compile_rules: the in-process cache
# ---------------------------------------------------------------------------


def test_cache_returns_the_same_object_for_the_same_source():
    clear_rule_cache()
    source = _static_rule(bytes(range(16)), name="cached_rule")
    first = compile_rules(source=source)
    second = compile_rules(source=source)
    assert first is second


def test_cache_key_ignores_cosmetic_whitespace():
    clear_rule_cache()
    source = _static_rule(bytes(range(16)), name="ws_rule")
    first = compile_rules(source=source)
    second = compile_rules(source="\n" + source + "   \n\n")
    assert first is second


def test_cache_distinguishes_different_sources():
    clear_rule_cache()
    a = compile_rules(source=_static_rule(bytes(range(16)), name="rule_a"))
    b = compile_rules(source=_static_rule(bytes(range(16, 32)), name="rule_b"))
    assert a is not b


def test_cache_evicts_fifo_past_eight_entries():
    clear_rule_cache()
    sources = [
        _static_rule(bytes([i] * 8), name=f"evict_rule_{i}") for i in range(9)
    ]
    compiled = [compile_rules(source=s) for s in sources]
    # The 9th compile evicted the 1st, so recompiling it yields a NEW object...
    assert compile_rules(source=sources[0]) is not compiled[0]
    # ...while the most recent entry is still cached.
    assert compile_rules(source=sources[8]) is compiled[8]


# ---------------------------------------------------------------------------
# Round trip: emitter -> compiler -> scanner
# ---------------------------------------------------------------------------


def test_emitted_pattern_round_trips_to_a_single_match(tmp_path):
    """The full loop: generate -> export -> compile -> scan -> exact offset."""
    rng = random.Random(1234)
    reference, mask, key_at, key_len = _keyish_reference(rng)
    rule = _emitted_rule(
        reference, mask, key_offset=key_at, key_length=key_len
    )
    rules = compile_rules(source=rule)

    plant_at = 9000
    dump = _write_dump(tmp_path / "planted.dump", 32768, {plant_at: reference})

    with open_dump(dump) as source:
        result = scan_source(source, rules)

    assert _offsets(result) == [plant_at]
    hit = result.matches[0]
    assert hit.rule == "planted_pattern"
    assert hit.string_id == "$key"
    assert hit.length == len(reference)
    assert bytes.fromhex(hit.matched_hex) == reference
    # The metas emitted by YaraExporter survive compilation and are lifted onto
    # the match, so a containment metric can locate the key inside the window.
    assert hit.key_offset == key_at
    assert hit.key_length == key_len
    assert reference[key_at:key_at + key_len] == bytes.fromhex(hit.matched_hex)[
        hit.key_offset:hit.key_offset + hit.key_length
    ]
    assert result.errors == ()
    assert result.truncated is False
    assert result.timed_out is False


def test_key_metas_are_none_when_the_emitter_omits_them(tmp_path):
    rng = random.Random(99)
    reference, mask, _key_at, _key_len = _keyish_reference(rng)
    rules = compile_rules(source=_emitted_rule(reference, mask))
    dump = _write_dump(tmp_path / "nometa.dump", 16384, {4321: reference})
    with open_dump(dump) as source:
        result = scan_source(source, rules)
    assert len(result.matches) == 1
    assert result.matches[0].key_offset is None
    assert result.matches[0].key_length is None


def test_wildcards_really_are_wildcards(tmp_path):
    """A different key in the same window still matches; a changed STATIC byte does not."""
    rng = random.Random(555)
    reference, mask, key_at, key_len = _keyish_reference(rng)
    rules = compile_rules(source=_emitted_rule(reference, mask, key_offset=key_at,
                                               key_length=key_len))
    other_key = bytes(rng.randrange(256) for _ in range(key_len))
    variant = bytearray(reference)
    variant[key_at:key_at + key_len] = other_key

    broken = bytearray(reference)
    broken[0] ^= 0xFF  # a STATIC byte

    dump = _write_dump(
        tmp_path / "variants.dump", 24576,
        {2048: bytes(variant), 12288: bytes(broken)},
    )
    with open_dump(dump) as source:
        result = scan_source(source, rules)
    assert _offsets(result) == [2048]


# ---------------------------------------------------------------------------
# Chunk-boundary correctness
# ---------------------------------------------------------------------------


CHUNK = 4096


def _straddling_setup(tmp_path, seed=4242):
    """A dump with one pattern deliberately spanning the first chunk boundary."""
    rng = random.Random(seed)
    reference, mask, key_at, key_len = _keyish_reference(rng)
    rules = compile_rules(
        source=_emitted_rule(reference, mask, name="straddler",
                             key_offset=key_at, key_length=key_len)
    )
    plant_at = CHUNK - 16  # 32 of its 48 bytes live in the SECOND chunk
    assert plant_at < CHUNK < plant_at + len(reference)
    # A DIFFERENT filler seed than the reference seed: sharing one seed makes
    # the first 48 filler bytes identical to the reference, planting a second,
    # accidental match at offset 0 (which is exactly how this comment got here).
    dump = _write_dump(
        tmp_path / "straddle.dump", CHUNK * 3, {plant_at: reference}, seed=seed + 1
    )
    return rules, dump, plant_at, len(reference)


def test_chunk_straddling_match_found_once(tmp_path):
    """Adequate overlap -> found EXACTLY once, at the true absolute offset.

    "Once" is the whole assertion. The naive fix (stitch an overlap on and
    report everything) finds it twice, because the second chunk also sees the
    tail; the ownership rule copied from ``GCoreDumpSource._find_all_vas``
    (drop any instance whose local offset lands in the overlap) is what makes
    it once.
    """
    rules, dump, plant_at, plant_len = _straddling_setup(tmp_path)
    with open_dump(dump) as source:
        result = scan_chunked(
            source, rules, chunk_bytes=CHUNK, overlap_bytes=plant_len * 2
        )
    assert _offsets(result) == [plant_at]
    assert result.strategy == "chunked"
    assert result.chunks == 3
    assert result.scanned_bytes == CHUNK * 3
    assert result.errors == ()


def test_chunk_straddling_match_missed_when_overlap_too_small(tmp_path):
    """The documented limitation, pinned rather than pretended away.

    With an overlap narrower than the pattern, neither chunk holds the match
    whole and it is simply not found. An explicit ``overlap_bytes`` is honoured
    verbatim precisely so this trade-off stays visible and testable; the
    ``overlap_bytes=0`` auto mode sizes itself off the ``pattern_length`` meta
    to avoid it (see the test below).
    """
    rules, dump, plant_at, _plant_len = _straddling_setup(tmp_path)
    with open_dump(dump) as source:
        result = scan_chunked(source, rules, chunk_bytes=CHUNK, overlap_bytes=4)
    assert result.matches == ()
    assert plant_at not in _offsets(result)


def test_auto_overlap_sizes_itself_from_pattern_length_meta(tmp_path):
    """``overlap_bytes=0`` derives the overlap and finds the straddling match."""
    rules, dump, plant_at, plant_len = _straddling_setup(tmp_path)
    assert max_pattern_length(rules) == plant_len
    with open_dump(dump) as source:
        result = scan_chunked(source, rules, chunk_bytes=CHUNK, overlap_bytes=0)
    assert _offsets(result) == [plant_at]
    # DEFAULT_OVERLAP_BYTES exceeds half of this deliberately tiny chunk, so the
    # auto path capped it and SAID SO instead of silently degrading.
    assert DEFAULT_OVERLAP_BYTES > CHUNK // 2
    assert any("overlap capped" in e for e in result.errors)


def test_overlap_at_or_past_chunk_size_is_rejected(tmp_path):
    rules, dump, _plant_at, _plant_len = _straddling_setup(tmp_path)
    with open_dump(dump) as source:
        with pytest.raises(CapabilityError) as exc:
            scan_chunked(source, rules, chunk_bytes=CHUNK, overlap_bytes=CHUNK)
    assert "smaller than" in str(exc.value)


def test_match_fully_inside_one_chunk_is_not_double_reported(tmp_path):
    """A hit inside chunk 1's body must not also be claimed by chunk 0's overlap."""
    rng = random.Random(777)
    reference, mask, _k, _kl = _keyish_reference(rng)
    rules = compile_rules(source=_emitted_rule(reference, mask, name="owned"))
    plant_at = CHUNK + 8  # inside chunk 1, but within chunk 0's overlap window
    dump = _write_dump(tmp_path / "owned.dump", CHUNK * 3, {plant_at: reference})
    with open_dump(dump) as source:
        result = scan_chunked(source, rules, chunk_bytes=CHUNK, overlap_bytes=256)
    assert _offsets(result) == [plant_at]


# ---------------------------------------------------------------------------
# Strategy selection
# ---------------------------------------------------------------------------


def test_strategy_is_filepath_for_a_raw_dump(tmp_path):
    rng = random.Random(31337)
    reference, mask, _k, _kl = _keyish_reference(rng)
    rules = compile_rules(source=_emitted_rule(reference, mask, name="raw_strategy"))
    dump = _write_dump(tmp_path / "plain.dump", 8192, {1000: reference})
    with open_dump(dump) as source:
        result = scan_source(source, rules)
    assert result.strategy == "filepath"
    assert result.view == "raw"
    assert result.chunks == 1
    assert result.scanned_bytes == 8192
    assert _offsets(result) == [1000]


def test_strategy_is_chunked_for_an_msl_container(tmp_path):
    """An ``.msl`` must go through read_range: its bytes are VAS-projected.

    The rule is built from bytes read back out of the ``.msl``'s own VAS view,
    so a match proves the scanner saw the projected plaintext -- not the
    container bytes libyara would have mapped from the file.
    """
    msl = write_msl_fixture(tmp_path / "capture.msl")
    with open_dump(msl) as source:
        needle_at = 128
        needle = source.read_range(needle_at, 32, "vas")
        assert len(needle) == 32
        rules = compile_rules(source=_static_rule(needle, name="msl_needle"))
        result = scan_source(source, rules)

    assert result.strategy == "chunked"
    assert result.view == "vas"
    assert _offsets(result) == [needle_at]
    # The container on disk is larger than the VAS stream, proving the scan did
    # not simply read the raw file.
    assert result.scanned_bytes == 4096
    assert msl.stat().st_size > result.scanned_bytes


# ---------------------------------------------------------------------------
# Caps are reported, never hidden
# ---------------------------------------------------------------------------


def _repeated_plants(count: int, blob: bytes, *, stride: int = 512, base: int = 64):
    return {base + i * stride: blob for i in range(count)}


def test_truncated_is_true_only_when_the_cap_is_exceeded(tmp_path):
    blob = bytes.fromhex("c0ffee11deadbe57")
    rules = compile_rules(source=_static_rule(blob, name="repeated"))
    plants = _repeated_plants(20, blob)
    dump = _write_dump(tmp_path / "many.dump", 16384, plants)

    with open_dump(dump) as source:
        full = scan_source(source, rules, max_matches=100)
        capped = scan_source(source, rules, max_matches=5)

    assert len(full.matches) == 20
    assert full.truncated is False
    assert len(capped.matches) == 5
    assert capped.truncated is True
    assert _offsets(capped) == sorted(plants)[:5]


def test_matches_stay_ascending_and_unique_across_chunks(tmp_path):
    blob = bytes.fromhex("a1b2c3d4e5f60718")
    rules = compile_rules(source=_static_rule(blob, name="ascending"))
    plants = _repeated_plants(30, blob, stride=397, base=100)
    dump = _write_dump(tmp_path / "ascending.dump", 16384, plants)

    with open_dump(dump) as source:
        result = scan_chunked(source, rules, chunk_bytes=CHUNK, overlap_bytes=64)

    offsets = _offsets(result)
    assert offsets == sorted(plants)
    assert offsets == sorted(offsets)
    assert len(set(offsets)) == len(offsets)


def test_truncation_reports_through_the_chunked_path_too(tmp_path):
    blob = bytes.fromhex("0f1e2d3c4b5a6978")
    rules = compile_rules(source=_static_rule(blob, name="chunk_capped"))
    plants = _repeated_plants(24, blob, stride=397, base=100)
    dump = _write_dump(tmp_path / "chunkcap.dump", 16384, plants)
    with open_dump(dump) as source:
        result = scan_chunked(
            source, rules, chunk_bytes=CHUNK, overlap_bytes=64, max_matches=7
        )
    assert result.truncated is True
    assert len(result.matches) == 7


# ---------------------------------------------------------------------------
# The rebase proof: chunked offsets == filepath offsets
# ---------------------------------------------------------------------------


def test_chunked_offsets_equal_filepath_offsets_for_the_same_raw_dump(tmp_path):
    """The strongest single check that the rebase arithmetic is right.

    libyara maps the whole file itself in the filepath strategy, so its offsets
    are ground truth. Running the chunked strategy over the SAME raw dump must
    reproduce them exactly -- every ``chunk_start + instance.offset`` and every
    overlap-ownership decision included.
    """
    rng = random.Random(20260827)
    reference, mask, key_at, key_len = _keyish_reference(rng)
    exact = bytes.fromhex("13579bdf02468ace")
    rules = compile_rules(
        source=_emitted_rule(reference, mask, name="window", key_offset=key_at,
                             key_length=key_len)
        + "\n\n"
        + _static_rule(exact, name="exact")
    )
    plants = {
        CHUNK - 3: reference,             # straddles boundary 1
        CHUNK * 2 - 1: exact,             # straddles boundary 2
        CHUNK + 100: exact,               # squarely inside chunk 1
        CHUNK * 3 + 7: reference,         # squarely inside chunk 3
        CHUNK * 4 - len(exact): exact,    # ends exactly on a boundary
    }
    dump = _write_dump(tmp_path / "rebase.dump", CHUNK * 5, plants, seed=5)

    with open_dump(dump) as source:
        by_filepath = scan_source(source, rules)
        by_chunk = scan_chunked(
            source, rules, chunk_bytes=CHUNK, overlap_bytes=256
        )

    assert by_filepath.strategy == "filepath"
    assert by_chunk.strategy == "chunked"
    key = lambda r: [(m.rule, m.string_id, m.offset, m.length, m.matched_hex)  # noqa: E731
                     for m in r.matches]
    assert key(by_chunk) == key(by_filepath)
    assert len(by_chunk.matches) == len(plants)
    assert _offsets(by_chunk) == sorted(plants)


# ---------------------------------------------------------------------------
# Failures are collected, not swallowed
# ---------------------------------------------------------------------------


class _EmptyReadSource:
    """A source that advertises bytes it then refuses to hand over.

    Stands in for the real-world case this module must not paper over: a
    region that fails to read (a locked ``.msl``, a truncated core). There is
    no ``try/except/pass`` in the scanner, so the failure has to surface in
    ``ScanResult.errors``.
    """

    format_name = "synthetic"

    def __init__(self, path: Path, size: int):
        self.path = path
        self._size = size

    def size_for(self, view: str = "vas") -> int:
        return self._size

    def read_range(self, offset: int, length: int, view: str = "vas") -> bytes:
        return b""


def test_empty_reads_are_reported_as_errors_not_silently_skipped(tmp_path):
    rules = compile_rules(source=_static_rule(b"\x01\x02\x03\x04", name="never"))
    source = _EmptyReadSource(tmp_path / "ghost.msl", CHUNK * 2)
    result = scan_chunked(source, rules, chunk_bytes=CHUNK, overlap_bytes=64)
    assert result.matches == ()
    assert result.chunks == 0
    assert result.scanned_bytes == 0
    assert len(result.errors) == 2
    assert all("empty read" in e for e in result.errors)
    # The default view is read off the source's own ``size_for`` signature.
    assert result.view == "vas"


def test_zero_sized_view_yields_an_empty_result(tmp_path):
    rules = compile_rules(source=_static_rule(b"\x09\x08\x07\x06", name="nothing"))
    source = _EmptyReadSource(tmp_path / "empty.msl", 0)
    result = scan_chunked(source, rules)
    assert result.chunks == 0
    assert result.matches == ()
    assert result.errors == ()


def test_to_dict_round_trips_the_whole_result(tmp_path):
    rng = random.Random(8)
    reference, mask, key_at, key_len = _keyish_reference(rng)
    rules = compile_rules(source=_emitted_rule(reference, mask, name="serialized",
                                               key_offset=key_at, key_length=key_len))
    dump = _write_dump(tmp_path / "ser.dump", 8192, {2000: reference})
    with open_dump(dump) as source:
        payload = scan_source(source, rules).to_dict()

    assert payload["strategy"] == "filepath"
    assert payload["match_count"] == 1
    assert payload["rule_names"] == ["serialized"]
    assert payload["matches"][0]["offset"] == 2000
    assert payload["matches"][0]["key_offset"] == key_at
    assert payload["errors"] == []
    # Everything is JSON-ready (tuples became lists, bytes became hex).
    import json

    json.dumps(payload)


# ---------------------------------------------------------------------------
# Real corpus smoke test
# ---------------------------------------------------------------------------


def _pick_real_dump(min_size: int = 8 * 1024 * 1024) -> Path | None:
    if not REAL_CORPUS.is_dir():
        return None
    for candidate in sorted(REAL_CORPUS.rglob("*.dump")):
        try:
            if candidate.stat().st_size >= min_size:
                return candidate
        except OSError:
            continue
    return None


# `requires_dataset` is ADDITIVE here: the pre-existing `e2e` marker already
# keeps this out of a plain `pytest`, and this test is a full-corpus rglob, so
# `slow` would add nothing it does not already have. What the marker buys is the
# shared, informative auto-skip from tests/conftest.py when no corpus resolves.
@pytest.mark.e2e
@pytest.mark.requires_dataset
def test_real_dump_scan_finds_bytes_read_from_that_same_dump():
    """READ-ONLY smoke test against the real TLS corpus.

    Bytes are read out of a real multi-megabyte dump, turned into a rule by the
    real emitter, and scanned for in the same dump. It is a tautology by
    construction, which is the point: the only thing that can make it fail is
    the scanner itself.
    """
    dump = _pick_real_dump()
    if dump is None:
        pytest.skip(f"real corpus not present at {REAL_CORPUS}")

    with open_dump(dump) as source:
        size = source.size_for("raw")
        needle_at = size // 3
        needle = source.read_range(needle_at, 40, "raw")
        assert len(needle) == 40
        rules = compile_rules(source=_static_rule(needle, name="real_needle"))
        started = time.perf_counter()
        result = scan_source(source, rules)
        elapsed = time.perf_counter() - started

    assert needle_at in _offsets(result)
    assert result.strategy == "filepath"
    assert result.errors == ()
    print(
        f"\nreal-corpus scan: {dump.name} {result.scanned_bytes / 1e6:.1f} MB "
        f"in {elapsed:.3f}s ({result.scanned_bytes / 1e6 / max(elapsed, 1e-9):.0f} MB/s), "
        f"{len(result.matches)} match(es)"
    )


def test_matched_hex_is_capped_by_libyara_but_length_is_not(tmp_path):
    """``matched_hex`` can be shorter than ``length`` -- documented, now pinned.

    libyara caps ``matched_data`` at its ``max_match_data`` setting (512 bytes
    in 4.5.4, verified here rather than assumed), while ``matched_length`` is
    the true width. MemDiver's key-window patterns sit far below the cap, but a
    caller rebuilding bytes from ``matched_hex`` must trust ``length``, so the
    divergence is asserted instead of being discovered later.
    """
    long_pattern = bytes(i % 256 for i in range(600))
    rules = compile_rules(source=_static_rule(long_pattern, name="long_one"))
    dump = _write_dump(tmp_path / "long.dump", 8192, {1024: long_pattern}, seed=11)
    with open_dump(dump) as source:
        result = scan_source(source, rules)

    assert len(result.matches) == 1
    hit = result.matches[0]
    assert hit.offset == 1024
    assert hit.length == 600
    assert len(bytes.fromhex(hit.matched_hex)) == 512
    assert long_pattern.startswith(bytes.fromhex(hit.matched_hex))

"""D3 — ``analysis.verify_plugin`` on all four surfaces.

MemDiver has been able to EMIT a Volatility3 plugin since the architect layer
landed, and two engine modules could RUN one: ``engine/vol3_verify.py`` in this
process and ``engine/vol3_subproc.py`` through a real ``vol`` launcher. Between
the emitter and those two sat nothing — 794 lines, fully tested, reachable from
NO surface at all — which is the identical hole ``engine/yara_scan.py`` sat in
before D1 (``tests/test_yara_scan_surfaces.py``). ``verify_vol3_plugin`` is that
missing middle, and this module is its four-surface proof.

The reason this capability exists at all is Phase B's hardest lesson: **never
trust an emitted plugin you have not run.** Four real bugs there survived a
fully green suite and were found only by executing things, because for most of
this repo's life an emitted plugin was checked by ``ast.parse`` and substring
assertions over its generated text — so one that could not even be IMPORTED
passed everything.

What these tests pin, in order:

* the exactly-one-of guard over ``plugin_path`` / ``plugin_source`` — both
  forms, and neither, refused BY NAME rather than resolved by precedence;
* that a ~20 KB inline ``plugin_source`` mistakenly passed as ``plugin_path``
  is a refusal and not an ``OSError``: ``Path.is_file()`` RAISES ENAMETOOLONG
  above ``NAME_MAX`` rather than returning ``False``;
* the closed loop: a plugin built by the REAL emitter (``emit_plugin_for_hit``)
  imported, constructed through Volatility3's own requirement gate, and run to
  a hit at a KNOWN planted offset. A hand-written plugin would prove the
  harness works and say nothing about the product's own output;
* the THREE-valued row model and the FOUR-valued verdict. ``"unsupported"`` is
  the member that carries the capability: ``vol`` takes a bare file path and
  never goes through MemDiver's container layer, so on an ``.msl`` it scans the
  CONTAINER FILE and reports the key at the wrong offset (measured — see
  :func:`test_subprocess_over_a_container_is_REFUSED_not_reported_as_zero`).
  A confident wrong offset is worse than a zero, so such a row is refused;
* **runtime provenance**, which is the part a reader must not have to guess at.
  Three Volatility3 trees commonly coexist on one machine and they disagree; on
  the machine this was developed on the in-process framework is 2.27.0 and the
  author's own ``vol.py`` answers 2.27.1. Every row therefore carries its
  ``mode_used`` and its RESOLVED ``framework_version``, and the payload carries
  the launcher's path, cwd and interpreter;
* that a locked encrypted ``.msl`` RAISES in BOTH modes rather than reporting a
  confident zero — the ``test_g9_producers_surface_locked_dump`` class of silent
  false negative, and the single most consequential assertion here;
* the four surfaces routing to one producer, MCP and web byte-for-byte included;
* and, on the real corpus, that the emitted plugin agrees with the YARA rule it
  EMBEDS about where the key is. That disagreement was Phase B bug #4, caught
  once by hand; here it is a standing test of BEHAVIOUR rather than of constants
  (``tests/test_vol3_emit.py`` pins the constants).

``volatility3`` is imported through ``pytest.importorskip``, unlike D1's hard
``import yara``: it is an OPTIONAL extra (``memdiver[vol]``), so its absence is
a forgotten install option rather than a broken environment. The producer says
so too — it raises ``UNSUPPORTED``, not ``PRECONDITION``.

The subprocess tests carry ``requires_vol3``, which auto-skips when no launcher
resolves (``tests/conftest.py``). That is a CONDITIONAL gate and deliberately
not ``slow``: putting the out-of-process proof behind a marker ``addopts``
deselects would mean it never runs on the one machine that has the launcher.
"""

from __future__ import annotations

import ast
import json
import os
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from memdiver.app.tools_pipeline import (  # noqa: E402
    DEFAULT_INCLUDE_HITS,
    VERIFY_HIT,
    VERIFY_INCONCLUSIVE,
    VERIFY_INTAKE_PATH,
    VERIFY_INTAKE_SOURCE,
    VERIFY_NO_HIT,
    VERIFY_NOT_RUN,
    VERIFY_PLUGIN_KEY_MISSING_CODE,
    VERIFY_PLUGIN_NOT_RUN_CODE,
    VERIFY_PLUGIN_PID_UNPROVEN_CODE,
    VERIFY_PLUGIN_STATUSES,
    VERIFY_PLUGIN_UNSUPPORTED_CODE,
    VERIFY_PLUGIN_VERDICTS,
    VERIFY_PLUGIN_VERSION_SKEW_CODE,
    VERIFY_UNREADABLE,
    VERIFY_UNSUPPORTED,
    VERIFY_VERIFIED,
    VOL3_MAX_HITS,
    VOL3_MODE_AUTO,
    VOL3_MODE_IN_PROCESS,
    VOL3_MODE_SUBPROCESS,
    VOL3_MODES,
    VOL3_SUBPROC_TIMEOUT_S,
    scan_yara_rule,
    verify_vol3_plugin,
)
from memdiver.core.service_errors import (  # noqa: E402
    CapabilityError,
    EncryptedDumpLockedError,
    ErrorCategory,
    FileNotFoundServiceError,
)
from memdiver.engine.vol3_emit import emit_plugin_for_hit  # noqa: E402
from tests._emit_pins import synth_hit  # noqa: E402
from tests.fixtures.tls_ground_truth import tls_dumps_dir  # noqa: E402

pytest.importorskip("volatility3")

_ROUTE = "/api/scan/verify-plugin"

#: The measured ground-truth run: 8 dumps, 11,223,040 B each, a 48-byte master
#: secret at offset 370,672 that is present in the two ``*_abort`` dumps and
#: provably absent from the six ``*_cleanup`` ones.
_REAL_RUN = "TLS12/100_iterations_Abort/openssl/openssl_run_12_1"
_REAL_KEY_OFFSET = 370_672
_REAL_KEY_HEX = (
    "aba18d0859926fcef9ae33c7459809e9bc1611933c2a68980ec68d49f14f2654"
    "ed7a61fa8b27870140ea09136aa57a4d"
)
#: ``--context 256``. The emitter's DEFAULT 64 is a known non-detector on this
#: key: the bytes around 370,672 are a 583-byte zero run, so at pad 64 the whole
#: window is inside it and the anchor carries ONE distinct byte value.
_REAL_CONTEXT = 256


# --------------------------------------------------------------------------- #
# Plugins built the way the PRODUCT builds them, and dumps to find them in
# --------------------------------------------------------------------------- #

def emitted_plugin(tmp_path: Path, name: str = "SurfacePlugin"):
    """``(plugin_path, reference_bytes, key_offset, key_length)``.

    Runs the REAL emitter (``engine.vol3_emit.emit_plugin_for_hit``) over the
    shared synthetic hit from ``tests/_emit_pins.py``, never hand-written plugin
    text: the claim this module exists to make is about the product's own output
    being runnable.
    """
    reference, hit, _ = synth_hit()
    path = emit_plugin_for_hit(hit, reference, name, tmp_path / f"{name}.py")
    return path, reference, int(hit["offset"]), 32


def write_dump(path: Path, plants: dict, *, size: int = 65536, fill: int = 0x5A) -> Path:
    """A raw dump of *fill* bytes with *plants* = ``{offset: bytes}`` written in.

    A CONSTANT fill rather than random noise, unlike D1's ``write_dump``: an
    emitted vol3 plugin walks the whole layer with a regex built from its static
    mask, and random bytes would give a wildcarded window spurious extra places
    to land. The planted window is the only thing that should match.
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    buf = bytearray([fill]) * size
    for offset, blob in plants.items():
        buf[offset:offset + len(blob)] = blob
    path.write_bytes(bytes(buf))
    return path


def planted(tmp_path: Path, name: str = "planted"):
    """``(plugin_path, dump_path, key_absolute_offset, key_length)``.

    The window is planted at offset 0 of a synthetic dump, so the key's absolute
    position is the hit's own ``key_offset`` — which is what makes
    ``expected_offset`` assertable without re-deriving the emitter's arithmetic.
    """
    plugin, reference, key_offset, key_length = emitted_plugin(tmp_path, "PlantedP")
    dump = write_dump(tmp_path / f"{name}.dump", {0: reference})
    return plugin, dump, key_offset, key_length


def _embedded_yara_rule(plugin_source: str) -> str:
    """Lift the plugin's own ``YARA_RULE`` string via the AST, not a regex.

    The AST is the only extraction that cannot drift from what Python would see,
    and it is the same lift ``tests/test_vol3_emit.py`` uses. This is the input
    to the plugin-vs-its-own-rule cross-check below.
    """
    for node in ast.parse(plugin_source).body:
        if not isinstance(node, ast.Assign):
            continue
        targets = [t.id for t in node.targets if isinstance(t, ast.Name)]
        if "YARA_RULE" in targets and isinstance(node.value, ast.Constant):
            return str(node.value.value)
    raise AssertionError("generated plugin has no YARA_RULE string assignment")


def _write_encrypted_msl(path: Path, key: bytes, *, data=b"\xCD" * 4096) -> None:
    """An AES-256-GCM ``.msl``. Same helper shape as the G9 invariant test's."""
    from memdiver.msl.writer import MslEncryptionConfig, MslWriter

    cfg = MslEncryptionConfig(raw_key=key)
    writer = MslWriter(str(path), pid=7, encryption=cfg)
    writer.add_memory_region(0x1000, data)
    writer.add_end_of_capture()
    writer.write()


@pytest.fixture
def encrypted_msl(tmp_path):
    """A locked encrypted container plus the key file that would open it."""
    from memdiver.msl import crypto
    from memdiver.msl.enums import EncAlgo

    if not crypto.cipher_is_available(EncAlgo.AES_256_GCM):
        pytest.skip("AES-256-GCM backend not installed")
    key = os.urandom(32)
    keyfile = tmp_path / "cek.bin"
    keyfile.write_bytes(key)
    msl = tmp_path / "enc.msl"
    _write_encrypted_msl(msl, key)
    return str(msl), str(keyfile)


@pytest.fixture
def plain_msl(tmp_path):
    """An UNencrypted ``.msl`` holding a planted emitted window.

    The container case that must WORK in-process and be REFUSED in subprocess
    mode — the two halves of the capability difference this producer exists to
    model.
    """
    from memdiver.msl.writer import MslWriter

    plugin, reference, key_offset, key_length = emitted_plugin(tmp_path, "MslP")
    path = tmp_path / "planted.msl"
    writer = MslWriter(str(path), pid=11)
    # The region's VA base is 0, so the projected ``vas`` offset of the planted
    # window is 0 and the key's absolute position is its own ``key_offset``.
    # Padded to a whole 4 KiB page count, which ``MslWriter`` requires (MSL
    # spec 5.1) when no explicit page-state table is supplied.
    payload = bytes(reference) + b"\x5A" * (8192 - len(reference))
    writer.add_memory_region(0, payload)
    writer.add_end_of_capture()
    writer.write()
    return plugin, path, key_offset, key_length


# --------------------------------------------------------------------------- #
# (a) exactly ONE plugin form, and the input guards
# --------------------------------------------------------------------------- #

def test_producer_refuses_both_plugin_forms(tmp_path):
    """Both forms is an INVALID_INPUT naming BOTH, with no precedence.

    Silently preferring one would hand the caller a confident verification of a
    plugin they did not mean to test — the same failure ``scan_yara_rule``'s
    rule-form guard exists to prevent.
    """
    plugin, dump, _, _ = planted(tmp_path)

    with pytest.raises(CapabilityError) as exc:
        verify_vol3_plugin(
            dump_paths=[str(dump)],
            plugin_path=str(plugin),
            plugin_source=plugin.read_text(),
        )
    assert exc.value.category is ErrorCategory.INVALID_INPUT
    assert "plugin_path" in str(exc.value)
    assert "plugin_source" in str(exc.value)
    assert "both were supplied" in str(exc.value)


def test_producer_refuses_neither_plugin_form(tmp_path):
    dump = write_dump(tmp_path / "no_form.dump", {})

    with pytest.raises(CapabilityError) as exc:
        verify_vol3_plugin(dump_paths=[str(dump)])
    assert exc.value.category is ErrorCategory.INVALID_INPUT
    assert "neither was" in str(exc.value)


def test_producer_refuses_zero_dumps(tmp_path):
    plugin, _, _, _ = planted(tmp_path)

    with pytest.raises(CapabilityError) as exc:
        verify_vol3_plugin(dump_paths=[], plugin_path=str(plugin))
    assert exc.value.category is ErrorCategory.PRECONDITION


def test_producer_refuses_an_unknown_mode(tmp_path):
    plugin, dump, _, _ = planted(tmp_path)

    with pytest.raises(CapabilityError) as exc:
        verify_vol3_plugin(
            dump_paths=[str(dump)], plugin_path=str(plugin), mode="both")
    assert exc.value.category is ErrorCategory.INVALID_INPUT
    for mode in VOL3_MODES:
        assert mode in str(exc.value)


def test_a_missing_dump_is_reported_before_anything_is_opened(tmp_path):
    plugin, _, _, _ = planted(tmp_path)

    with pytest.raises(FileNotFoundServiceError):
        verify_vol3_plugin(
            dump_paths=[str(tmp_path / "nope.dump")], plugin_path=str(plugin))


def test_a_long_inline_source_passed_as_plugin_path_is_REFUSED_not_a_crash(tmp_path):
    """The ENAMETOOLONG guard, and it is not hypothetical.

    An emitted plugin's source is ~20 KB, far longer than ``NAME_MAX`` on every
    ordinary filesystem, and ``Path.is_file()`` RAISES ``OSError`` for such a
    value rather than returning ``False``. Without the guard the natural
    mistake — putting the source text in ``plugin_path=`` — surfaces as a bare
    traceback out of a path check instead of this module's own refusal. Same
    guard, for the same measured reason, as ``_score_json_from_args``.
    """
    plugin, dump, _, _ = planted(tmp_path)
    source = plugin.read_text()
    assert len(source) > 255, "premise: the source must exceed NAME_MAX"

    with pytest.raises(FileNotFoundServiceError):
        verify_vol3_plugin(dump_paths=[str(dump)], plugin_path=source)


def test_a_plugin_with_no_class_is_refused_by_name(tmp_path):
    dump = write_dump(tmp_path / "no_class.dump", {})

    with pytest.raises(CapabilityError) as exc:
        verify_vol3_plugin(
            dump_paths=[str(dump)], plugin_source="X = 1\n")
    assert exc.value.category is ErrorCategory.INVALID_INPUT
    assert "no class" in str(exc.value)


# --------------------------------------------------------------------------- #
# (b) the closed loop — an EMITTED plugin actually runs and finds the key
# --------------------------------------------------------------------------- #

def test_an_emitted_plugin_runs_and_hits_the_planted_offset(tmp_path):
    """The assertion the whole capability is for.

    Not "the generated text contains PluginInterface" — that was the old,
    vacuous check — but: the source EXECS, Volatility3's own
    ``PluginInterface.__init__`` requirement gate passes, ``run()`` returns a
    TreeGrid, and the row's key offset is the one that was planted.
    """
    plugin, dump, key_offset, key_length = planted(tmp_path)

    payload = verify_vol3_plugin(
        dump_paths=[str(dump)],
        plugin_path=str(plugin),
        mode=VOL3_MODE_IN_PROCESS,
        expected_offset=key_offset,
    )

    assert payload["verdict"] == VERIFY_HIT
    assert payload["intake"] == VERIFY_INTAKE_PATH
    row = payload["dumps"][0]
    assert row["status"] == VERIFY_VERIFIED
    assert row["run"]["match_count"] == 1, row["run"]
    assert row["run"]["expected_offset_reported"] is True
    hit = row["run"]["hits"][0]
    assert hit["key_absolute_offset"] == key_offset
    assert hit["offset"] + hit["key_offset"] == hit["key_absolute_offset"]
    assert hit["key_length"] == key_length


def test_the_inline_source_intake_reaches_the_same_hit(tmp_path):
    """``plugin_source`` and ``plugin_path`` are two spellings of one input."""
    plugin, dump, key_offset, _ = planted(tmp_path)

    from_path = verify_vol3_plugin(
        dump_paths=[str(dump)], plugin_path=str(plugin),
        mode=VOL3_MODE_IN_PROCESS, expected_offset=key_offset)
    from_source = verify_vol3_plugin(
        dump_paths=[str(dump)], plugin_source=plugin.read_text(),
        mode=VOL3_MODE_IN_PROCESS, expected_offset=key_offset)

    assert from_source["intake"] == VERIFY_INTAKE_SOURCE
    # The plugin identity differs by ``path`` alone (``None`` for the inline
    # form), and the runs must otherwise be identical.
    assert from_source["plugin"]["path"] is None
    assert from_path["plugin"]["path"] == str(plugin)
    assert from_source["dumps"][0]["run"] == from_path["dumps"][0]["run"]


def test_key_recovered_is_the_claim_that_match_count_cannot_make(tmp_path):
    """``match_count`` says it FIRED; ``key_recovered`` says it returned the KEY.

    These are different facts and on a real corpus they disagree, because an
    emitted pattern WILDCARDS the key: the window still matches a dump the key
    was wiped from. That is measured on the ground-truth run below (8 of 8 fire,
    2 of 8 recover); here it is forced synthetically by overwriting the key bytes
    while leaving the anchor intact.
    """
    plugin, reference, key_offset, key_length = emitted_plugin(tmp_path, "KeyP")
    true_key = bytes(reference)[key_offset:key_offset + key_length]

    intact = write_dump(tmp_path / "intact.dump", {0: reference})
    wiped_bytes = bytearray(reference)
    wiped_bytes[key_offset:key_offset + key_length] = b"\x00" * key_length
    wiped = write_dump(tmp_path / "wiped.dump", {0: bytes(wiped_bytes)})

    payload = verify_vol3_plugin(
        dump_paths=[str(intact), str(wiped)],
        plugin_path=str(plugin),
        mode=VOL3_MODE_IN_PROCESS,
        expected_offset=key_offset,
        key_hex=true_key.hex(),
    )

    rows = {r["name"]: r for r in payload["dumps"]}
    # BOTH fired, at the same offset: the anchor is what matches.
    assert rows["intact.dump"]["run"]["match_count"] == 1
    assert rows["wiped.dump"]["run"]["match_count"] == 1
    assert rows["intact.dump"]["run"]["expected_offset_reported"] is True
    assert rows["wiped.dump"]["run"]["expected_offset_reported"] is True
    # Only one returned the key. Reading match_count alone would call this 2/2.
    assert rows["intact.dump"]["run"]["key_recovered"] is True
    assert rows["wiped.dump"]["run"]["key_recovered"] is False
    assert payload["counts"]["dumps_key_recovered"] == 1
    codes = [d["code"] for d in payload["diagnostics"]]
    assert VERIFY_PLUGIN_KEY_MISSING_CODE in codes


def test_key_recovered_is_None_and_never_False_when_no_key_was_supplied(tmp_path):
    """``None`` is "you asked nothing"; ``False`` would be "the key was absent"."""
    plugin, dump, _, _ = planted(tmp_path)

    payload = verify_vol3_plugin(
        dump_paths=[str(dump)], plugin_path=str(plugin),
        mode=VOL3_MODE_IN_PROCESS)

    assert payload["dumps"][0]["run"]["key_recovered"] is None
    assert payload["counts"]["dumps_key_recovered"] is None
    assert payload["counts"]["dumps_expected_offset_reported"] is None


def test_expected_offset_membership_is_EXACT_with_no_tolerance(tmp_path):
    """A hit one byte away is a MISS, not a near miss.

    The failure this instrument exists to catch is "the plugin reported a hit 64
    bytes from the real key"; a tolerance would score that as almost right.
    """
    plugin, dump, key_offset, _ = planted(tmp_path)

    payload = verify_vol3_plugin(
        dump_paths=[str(dump)], plugin_path=str(plugin),
        mode=VOL3_MODE_IN_PROCESS, expected_offset=key_offset + 1)

    assert payload["dumps"][0]["run"]["match_count"] == 1
    assert payload["dumps"][0]["run"]["expected_offset_reported"] is False


def test_anchor_stats_are_reported_beside_the_hit(tmp_path):
    """``anchor_distinct_bytes`` is the selectivity number, and it is published.

    A high static ratio over 128 zero bytes looks healthy and matches anywhere a
    long zero run exists; the distinct-value count is what exposes that, so it
    travels with every run rather than being left to be re-derived.
    """
    plugin, dump, _, _ = planted(tmp_path)

    payload = verify_vol3_plugin(
        dump_paths=[str(dump)], plugin_path=str(plugin),
        mode=VOL3_MODE_IN_PROCESS)

    identity = payload["plugin"]
    assert identity["window_length"] == 160, identity
    assert identity["anchor_bytes"] == 128, identity
    assert identity["anchor_distinct_bytes"] > 1, identity
    assert payload["dumps"][0]["run"]["anchor_distinct_bytes"] == (
        identity["anchor_distinct_bytes"])


# --------------------------------------------------------------------------- #
# (c) the three-valued row model and the four-valued verdict
# --------------------------------------------------------------------------- #

def test_the_status_and_verdict_vocabularies_are_closed(tmp_path):
    assert VERIFY_PLUGIN_STATUSES == (
        VERIFY_VERIFIED, VERIFY_UNREADABLE, VERIFY_UNSUPPORTED)
    assert VERIFY_PLUGIN_VERDICTS == (
        VERIFY_HIT, VERIFY_NO_HIT, VERIFY_INCONCLUSIVE, VERIFY_NOT_RUN)
    assert VOL3_MODES == (
        VOL3_MODE_AUTO, VOL3_MODE_IN_PROCESS, VOL3_MODE_SUBPROCESS)
    # ``auto`` FIRST, and that ordering is the user-facing contract: the default
    # prefers the PyPI volatility3 and falls back to the external launcher.
    assert VOL3_MODES[0] == VOL3_MODE_AUTO


def test_a_measured_absence_is_no_hit_and_carries_hits_as_an_empty_list(tmp_path):
    plugin, _, _, _ = planted(tmp_path)
    empty = write_dump(tmp_path / "no_window.dump", {})

    payload = verify_vol3_plugin(
        dump_paths=[str(empty)], plugin_path=str(plugin),
        mode=VOL3_MODE_IN_PROCESS)

    assert payload["verdict"] == VERIFY_NO_HIT
    row = payload["dumps"][0]
    assert row["status"] == VERIFY_VERIFIED
    assert row["run"]["match_count"] == 0
    # Zero hits over a layer that WAS covered: the list is empty and the row is
    # not degraded, which together are what make this zero a measurement.
    assert row["run"]["hits"] == []
    assert row["run"]["layer_bytes"] == 65536


def test_an_unreadable_dump_is_a_ROW_with_no_run_payload(tmp_path):
    """A directory, not a dump. It keeps the denominator honest instead of
    vanishing, and there is no ``match_count: 0`` for a falsy check to misread."""
    plugin, _, _, _ = planted(tmp_path)
    directory = tmp_path / "not_a_dump"
    directory.mkdir()

    payload = verify_vol3_plugin(
        dump_paths=[str(directory)], plugin_path=str(plugin),
        mode=VOL3_MODE_IN_PROCESS)

    assert payload["verdict"] == VERIFY_NOT_RUN
    row = payload["dumps"][0]
    assert row["status"] == VERIFY_UNREADABLE
    assert row["run"] is None
    assert row["detail"]
    assert row["mode_used"] is None
    assert payload["counts"]["dumps_unreadable"] == 1
    assert payload["counts"]["dumps_verified"] == 0
    assert VERIFY_PLUGIN_NOT_RUN_CODE in [
        d["code"] for d in payload["diagnostics"]]


def test_a_zero_byte_layer_is_INCONCLUSIVE_and_never_no_hit(tmp_path):
    """The quiet false-absence channel.

    A view that sizes to 0 is handed to the plugin, reports no error, finds
    nothing, and would otherwise fall straight into ``dumps_no_hit``. Declaring
    a plugin non-firing having compared ZERO bytes is the worst instance of a
    silent all-clear, so it is its own verdict.
    """
    plugin, _, _, _ = planted(tmp_path)
    empty = tmp_path / "empty.dump"
    empty.write_bytes(b"")

    payload = verify_vol3_plugin(
        dump_paths=[str(empty)], plugin_path=str(plugin),
        mode=VOL3_MODE_IN_PROCESS)

    assert payload["verdict"] == VERIFY_INCONCLUSIVE
    assert payload["dumps"][0]["run"]["layer_bytes"] == 0
    assert payload["counts"]["dumps_zero_bytes"] == 1
    assert payload["counts"]["dumps_no_hit"] == 0


def test_rows_keep_the_supplied_order_and_the_counts_add_up(tmp_path):
    plugin, reference, key_offset, _ = emitted_plugin(tmp_path, "OrderP")
    hit_dump = write_dump(tmp_path / "z_hit.dump", {0: reference})
    miss_dump = write_dump(tmp_path / "a_miss.dump", {})
    directory = tmp_path / "m_dir"
    directory.mkdir()
    paths = [str(hit_dump), str(directory), str(miss_dump)]

    payload = verify_vol3_plugin(
        dump_paths=paths, plugin_path=str(plugin),
        mode=VOL3_MODE_IN_PROCESS, expected_offset=key_offset)

    assert [r["dump_path"] for r in payload["dumps"]] == paths
    counts = payload["counts"]
    assert counts["dumps_total"] == 3
    assert counts["dumps_verified"] == 2
    assert counts["dumps_hit"] == 1
    assert counts["dumps_no_hit"] == 1
    assert counts["dumps_unreadable"] == 1
    # A mixed set with one hit is still a hit verdict; the partial diagnostic is
    # what says the other dumps were silent.
    assert payload["verdict"] == VERIFY_HIT
    assert counts["dumps_expected_offset_reported"] == 1


# --------------------------------------------------------------------------- #
# (d) runtime provenance — WHICH framework answered
# --------------------------------------------------------------------------- #

def test_every_verified_row_names_its_runtime_and_resolved_version(tmp_path):
    """The single most important field in the payload.

    Three Volatility3 trees commonly coexist on one machine and they disagree —
    measured here: the in-process framework is 2.27.0 while the author's own
    ``vol.py`` answers 2.27.1 (and a bare ``import volatility3`` in that same
    venv answers 2.28.2, from an editable install pointing at a sibling). A row
    that says "1 hit at 370672" without saying which framework produced it
    cannot be reproduced, so ``mode_used`` and ``framework_version`` are per-ROW
    and never optional.
    """
    from memdiver.engine.vol3_verify import framework_version

    plugin, dump, _, _ = planted(tmp_path)

    payload = verify_vol3_plugin(
        dump_paths=[str(dump)], plugin_path=str(plugin),
        mode=VOL3_MODE_IN_PROCESS)

    row = payload["dumps"][0]
    assert row["mode_used"] == VOL3_MODE_IN_PROCESS
    assert row["framework_version"] == list(framework_version())
    assert row["framework_version"][0] == 2
    # And the request-level block agrees with the row it produced.
    assert payload["runtime"]["in_process"]["framework_version"] == (
        row["framework_version"])
    assert payload["runtime"]["mode_requested"] == VOL3_MODE_IN_PROCESS


def test_the_runtime_block_describes_BOTH_runtimes_and_the_launcher_fully(tmp_path):
    """A launcher's path is not enough: ``cwd`` and ``python`` decide which
    framework a checkout's ``vol.py`` loads, so all three are reported."""
    plugin, dump, _, _ = planted(tmp_path)

    payload = verify_vol3_plugin(
        dump_paths=[str(dump)], plugin_path=str(plugin), mode=VOL3_MODE_AUTO)

    runtime = payload["runtime"]
    assert set(runtime) == {
        "mode_requested", "in_process", "subprocess", "versions_agree",
        "launcher",
    }
    assert set(runtime["subprocess"]) == {
        "available", "framework_version", "launcher", "argv", "cwd", "python",
        "source",
    }
    # ``versions_agree`` is THREE-valued: ``None`` is "we could not tell",
    # which is a different fact from "they match".
    assert runtime["versions_agree"] in (True, False, None)
    if not runtime["subprocess"]["available"]:
        assert runtime["versions_agree"] is None
        assert "not found" in runtime["launcher"]


def test_auto_mode_prefers_in_process(tmp_path):
    """The user's stated default: "by default the pypi version should be used".

    It is also the only order that can serve a container, since the launcher
    cannot address one at all — so the preference is a capability decision, not
    just a performance one.
    """
    plugin, dump, _, _ = planted(tmp_path)

    payload = verify_vol3_plugin(
        dump_paths=[str(dump)], plugin_path=str(plugin), mode=VOL3_MODE_AUTO)

    assert payload["dumps"][0]["mode_used"] == VOL3_MODE_IN_PROCESS


def test_vol_bin_and_vol_python_are_FIRST_CLASS_parameters(tmp_path, monkeypatch):
    """Env-only configuration is unreachable from web and MCP, so it cannot be
    the only channel — and an explicit request is honoured INCLUDING its
    failure rather than falling back to ``PATH``."""
    import inspect

    from memdiver.engine.vol3_subproc import VOL3_BIN_ENV, VOL3_PYTHON_ENV

    params = inspect.signature(verify_vol3_plugin).parameters
    assert "vol_bin" in params and "vol_python" in params

    plugin, dump, _, _ = planted(tmp_path)
    # A real launcher on PATH must NOT rescue a bad explicit request.
    monkeypatch.delenv(VOL3_BIN_ENV, raising=False)
    monkeypatch.delenv(VOL3_PYTHON_ENV, raising=False)
    monkeypatch.setattr(
        "memdiver.engine.vol3_subproc.shutil.which", lambda name: "/usr/bin/vol")

    payload = verify_vol3_plugin(
        dump_paths=[str(dump)], plugin_path=str(plugin),
        mode=VOL3_MODE_IN_PROCESS,
        vol_bin=str(tmp_path / "nope" / "vol.py"))

    assert payload["runtime"]["subprocess"]["available"] is False
    assert payload["runtime"]["subprocess"]["launcher"] is None


def test_an_explicit_vol_bin_is_reported_as_its_own_provenance(tmp_path):
    """``source`` distinguishes "the caller told us" from "the environment did".

    A fake launcher is enough, because resolution only stats the file — and the
    version it reports is then the HAZARD this whole block exists for, made
    visible: ``probe_version`` asks the launcher's own INTERPRETER, with ``cwd``
    set to the launcher's directory. Point ``vol_python`` at MemDiver's own
    python and the answer is MemDiver's own framework, whatever ``vol.py``
    itself contains. That is not a defect in the probe; it is precisely why the
    interpreter is reported alongside the path, and why pointing at a checkout
    without pointing at its venv is the mistake ``MEMDIVER_VOL3_PYTHON`` exists
    to prevent.
    """
    plugin, dump, _, _ = planted(tmp_path)
    fake = tmp_path / "checkout" / "vol.py"
    fake.parent.mkdir()
    fake.write_text("# not a real launcher\n")

    payload = verify_vol3_plugin(
        dump_paths=[str(dump)], plugin_path=str(plugin),
        mode=VOL3_MODE_IN_PROCESS,
        vol_bin=str(fake), vol_python=sys.executable)

    block = payload["runtime"]["subprocess"]
    assert block["available"] is True
    assert block["source"] == "vol_bin="
    assert block["cwd"] == str(fake.parent.resolve())
    assert block["python"] == sys.executable
    # Probed through THIS interpreter, so it resolves THIS framework -- and the
    # two runtimes therefore agree, which is the honest answer for that request.
    from memdiver.engine.vol3_verify import framework_version

    assert block["framework_version"] == list(framework_version())
    assert payload["runtime"]["versions_agree"] is True


def test_a_forced_subprocess_with_no_launcher_is_UNSUPPORTED(tmp_path, monkeypatch):
    """CLASS 1 gating: a missing runtime is a forgotten install option, so the
    category is UNSUPPORTED and the message names the remedy."""
    from memdiver.engine.vol3_subproc import VOL3_BIN_ENV, VOL3_PYTHON_ENV

    plugin, dump, _, _ = planted(tmp_path)
    monkeypatch.delenv(VOL3_BIN_ENV, raising=False)
    monkeypatch.delenv(VOL3_PYTHON_ENV, raising=False)
    monkeypatch.setattr(
        "memdiver.engine.vol3_subproc.shutil.which", lambda name: None)

    with pytest.raises(CapabilityError) as exc:
        verify_vol3_plugin(
            dump_paths=[str(dump)], plugin_path=str(plugin),
            mode=VOL3_MODE_SUBPROCESS)
    assert exc.value.category is ErrorCategory.UNSUPPORTED
    assert VOL3_BIN_ENV in str(exc.value)


def test_auto_with_NEITHER_runtime_names_BOTH_remedies(tmp_path, monkeypatch):
    """One refusal, two ways to fix it.

    ``mode="auto"`` is the only request that had two ways to be satisfied, so it
    is the only place a composed message is right: install the extra, OR point
    at an existing launcher.
    """
    from memdiver.engine.vol3_subproc import VOL3_BIN_ENV, VOL3_PYTHON_ENV

    plugin, dump, _, _ = planted(tmp_path)
    monkeypatch.delenv(VOL3_BIN_ENV, raising=False)
    monkeypatch.delenv(VOL3_PYTHON_ENV, raising=False)
    monkeypatch.setattr(
        "memdiver.engine.vol3_subproc.shutil.which", lambda name: None)
    monkeypatch.setattr(
        "memdiver.engine.vol3_verify.HAS_VOLATILITY3", False)

    with pytest.raises(CapabilityError) as exc:
        verify_vol3_plugin(
            dump_paths=[str(dump)], plugin_path=str(plugin),
            mode=VOL3_MODE_AUTO)
    message = str(exc.value)
    assert exc.value.category is ErrorCategory.UNSUPPORTED
    assert 'memdiver[vol]' in message, message
    assert VOL3_BIN_ENV in message
    assert "vol_bin=" in message


def test_a_forced_in_process_without_the_extra_propagates_the_ENGINE_message(
    tmp_path, monkeypatch,
):
    """No second message invented here: ``engine.vol3_verify`` owns the
    "``pip install "memdiver[vol]"``" wording and this producer defers to it."""
    from memdiver.engine.vol3_verify import VOL3_MISSING

    plugin, dump, _, _ = planted(tmp_path)
    monkeypatch.setattr(
        "memdiver.engine.vol3_verify.HAS_VOLATILITY3", False)

    with pytest.raises(CapabilityError) as exc:
        verify_vol3_plugin(
            dump_paths=[str(dump)], plugin_path=str(plugin),
            mode=VOL3_MODE_IN_PROCESS)
    assert str(exc.value) == VOL3_MISSING
    assert exc.value.category is ErrorCategory.UNSUPPORTED


# --------------------------------------------------------------------------- #
# (e) the CONTAINER capability difference — and the refusal it forces
# --------------------------------------------------------------------------- #

def test_in_process_verifies_a_container_in_VIEW_coordinates(plain_msl):
    """The branch that makes ``mode="auto"`` prefer in-process.

    A container's bytes must be decrypted and/or VAS-projected before an offset
    means anything, and only the in-process runtime can be handed the projected
    view.
    """
    plugin, msl, key_offset, _ = plain_msl

    payload = verify_vol3_plugin(
        dump_paths=[str(msl)], plugin_path=str(plugin),
        mode=VOL3_MODE_IN_PROCESS, expected_offset=key_offset)

    assert payload["verdict"] == VERIFY_HIT
    row = payload["dumps"][0]
    assert row["view"] == "vas", "the .msl default view must be projected"
    assert row["run"]["expected_offset_reported"] is True


def test_subprocess_over_a_container_is_REFUSED_not_reported_as_zero(plain_msl):
    """MEASURED, and the measurement is why this is a refusal.

    ``vol`` gets a bare file path and never goes through MemDiver's container
    layer. Run against the ground-truth ``.msl`` it does NOT return zero rows —
    it returns one row at ``KeyOffset 371752`` where every MemDiver coordinate
    says 370672 — skewed by the container's own header size, 1080 bytes for
    that import (and not a constant: it tracks the header, not the format). A
    confident wrong offset is
    worse than a zero and far worse than a refusal, so the row is refused with
    the reason attached and the verdict claims nothing.

    The refusal is decided from the dump's FORMAT, before ``vol`` is spawned —
    but note the ordering: with no launcher at all, a forced ``subprocess``
    request never reaches this row and raises UNSUPPORTED instead (see
    :func:`test_a_forced_subprocess_with_no_launcher_is_UNSUPPORTED`). The
    runtime gate comes first because it is a fact about the REQUEST; this
    refusal is a fact about one dump.
    """
    plugin, msl, _, _ = plain_msl

    payload = verify_vol3_plugin(
        dump_paths=[str(msl)], plugin_path=str(plugin),
        mode=VOL3_MODE_SUBPROCESS)

    assert payload["verdict"] == VERIFY_NOT_RUN
    row = payload["dumps"][0]
    assert row["status"] == VERIFY_UNSUPPORTED
    assert row["run"] is None, "a refusal must not carry a zero"
    assert "container" in row["detail"].lower()
    assert "in_process" in row["detail"]
    assert payload["counts"]["dumps_unsupported"] == 1
    assert payload["counts"]["dumps_verified"] == 0
    assert VERIFY_PLUGIN_UNSUPPORTED_CODE in [
        d["code"] for d in payload["diagnostics"]]


def test_a_mixed_set_refuses_only_the_container_row(plain_msl, tmp_path):
    """The reason the refusal is a ROW and not an exception: a corpus sweep over
    a mixed set must still report every dump it CAN address."""
    plugin, msl, key_offset, _ = plain_msl
    reference = synth_hit()[0]
    flat = write_dump(tmp_path / "flat.dump", {0: reference})

    payload = verify_vol3_plugin(
        dump_paths=[str(msl), str(flat)], plugin_path=str(plugin),
        mode=VOL3_MODE_SUBPROCESS, expected_offset=key_offset)

    statuses = [r["status"] for r in payload["dumps"]]
    assert statuses[0] == VERIFY_UNSUPPORTED
    # The flat dump is addressable; whether a launcher exists to run it decides
    # whether it verified or errored, and either way it is not silently dropped.
    assert statuses[1] in (VERIFY_VERIFIED, VERIFY_UNREADABLE)
    assert len(payload["dumps"]) == 2


# --------------------------------------------------------------------------- #
# (f) the locked container — the silent-false-negative guard
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize(
    "mode", [VOL3_MODE_AUTO, VOL3_MODE_IN_PROCESS, VOL3_MODE_SUBPROCESS])
def test_a_locked_msl_RAISES_in_EVERY_mode(encrypted_msl, tmp_path, mode):
    """The single most consequential assertion in this file.

    A locked ``.msl`` reads back EMPTY rather than failing, so without
    ``raise_if_locked`` an in-process run reports a confident ``no_hit`` over
    bytes nobody decrypted — no error, no diagnostic, nothing to audit — and a
    subprocess run hands ``vol`` a container it cannot address. The guard runs
    BEFORE the per-row mode split, which is what makes it impossible for one
    mode to regress on its own; the parametrization asserts that rather than
    assuming it. ``test_g9_producers_surface_locked_dump`` carries the same
    ratchet at the architecture level.
    """
    msl_path, _keyfile = encrypted_msl
    plugin, _, _, _ = planted(tmp_path)

    with pytest.raises(EncryptedDumpLockedError):
        verify_vol3_plugin(
            dump_paths=[msl_path], plugin_path=str(plugin), mode=mode)


def test_the_same_container_verifies_once_UNLOCKED(encrypted_msl, tmp_path):
    """The control for the guard above: with the key it opens, so the refusal was
    about the LOCK and not about encrypted containers being unsupported."""
    msl_path, keyfile = encrypted_msl
    plugin, _, _, _ = planted(tmp_path)

    payload = verify_vol3_plugin(
        dump_paths=[msl_path], plugin_path=str(plugin),
        mode=VOL3_MODE_IN_PROCESS, key_file=keyfile)

    # The fixture's payload is 4 KiB of 0xCD, so the plugin finds nothing — but
    # it RAN, over decrypted bytes, and that is what makes this zero a
    # measurement rather than a lock.
    assert payload["verdict"] == VERIFY_NO_HIT
    assert payload["dumps"][0]["status"] == VERIFY_VERIFIED
    assert payload["dumps"][0]["run"]["layer_bytes"] > 0


# --------------------------------------------------------------------------- #
# (g) the count-only census
# --------------------------------------------------------------------------- #

def test_count_only_REMOVES_hits_rather_than_emptying_it(tmp_path):
    """An ABSENT key cannot be misread as an empty one.

    ``hits: []`` would make a count-only row with thousands of firings
    indistinguishable from a proven-clean one to ``len(run["hits"])``, which is
    the same silent false absence ``run: None`` on an unsupported row prevents.
    """
    plugin, dump, _, _ = planted(tmp_path)

    full = verify_vol3_plugin(
        dump_paths=[str(dump)], plugin_path=str(plugin),
        mode=VOL3_MODE_IN_PROCESS)
    counted = verify_vol3_plugin(
        dump_paths=[str(dump)], plugin_path=str(plugin),
        mode=VOL3_MODE_IN_PROCESS, include_hits=False)

    assert "hits" in full["dumps"][0]["run"]
    assert "hits_omitted" not in full["dumps"][0]["run"]
    assert "hits" not in counted["dumps"][0]["run"]
    assert counted["dumps"][0]["run"]["hits_omitted"] is True
    # Every count and flag survives, so the verdict and counts are identical.
    assert counted["verdict"] == full["verdict"]
    assert counted["counts"] == full["counts"]
    assert DEFAULT_INCLUDE_HITS is True


# --------------------------------------------------------------------------- #
# (h) the web surface — POST /api/scan/verify-plugin
# --------------------------------------------------------------------------- #

@pytest.fixture(scope="module")
def client():
    from fastapi.testclient import TestClient

    from memdiver.api.main import create_app

    return TestClient(create_app())


def test_route_returns_the_producer_payload(client, tmp_path):
    plugin, dump, key_offset, _ = planted(tmp_path)

    resp = client.post(_ROUTE, json={
        "dump_paths": [str(dump)],
        "plugin_path": str(plugin),
        "mode": VOL3_MODE_IN_PROCESS,
        "expected_offset": key_offset,
    })

    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["verdict"] == VERIFY_HIT
    assert body["dumps"][0]["run"]["expected_offset_reported"] is True
    # The provenance a browser needs in order to render a reproducible result.
    assert body["dumps"][0]["mode_used"] == VOL3_MODE_IN_PROCESS
    assert body["dumps"][0]["framework_version"][0] == 2


def test_route_is_NOT_on_the_architect_router():
    """``architect`` is on ``EXEMPT_ROUTERS`` with the reason "NO APP-LAYER
    PRODUCER", so a registered capability behind it would make that coarse
    exemption illegal (``test_exempt_routers_are_not_capability_bearing``)."""
    assert _ROUTE.startswith("/api/scan/")


def test_route_returns_200_for_a_measured_absence(client, tmp_path):
    """A ``no_hit`` is a RESULT, not an error, so it must not become a 4xx."""
    plugin, _, _, _ = planted(tmp_path)
    empty = write_dump(tmp_path / "web_empty.dump", {})

    resp = client.post(_ROUTE, json={
        "dump_paths": [str(empty)], "plugin_path": str(plugin),
        "mode": VOL3_MODE_IN_PROCESS})

    assert resp.status_code == 200, resp.text
    assert resp.json()["verdict"] == VERIFY_NO_HIT


def test_route_rejects_both_plugin_forms_through_the_GLOBAL_funnel(client, tmp_path):
    """The modern error contract: no ``try``/``except`` in the route, so the
    producer's ``CapabilityError`` is rendered as ``{error, code, category}``
    with the category's own status — not as the legacy ``{"detail": ...}``."""
    plugin, dump, _, _ = planted(tmp_path)

    resp = client.post(_ROUTE, json={
        "dump_paths": [str(dump)],
        "plugin_path": str(plugin),
        "plugin_source": plugin.read_text(),
    })

    assert resp.status_code == 400, resp.text
    body = resp.json()
    assert "detail" not in body
    assert body["category"] == ErrorCategory.INVALID_INPUT.name
    assert "plugin_source" in body["error"]


def test_route_takes_vol_bin_so_a_browser_can_pick_a_launcher(client, tmp_path):
    """The env-var-only alternative would leave this capability unreachable from
    the web surface entirely — an HTTP body cannot set an environment variable."""
    plugin, dump, _, _ = planted(tmp_path)
    fake = tmp_path / "web_checkout" / "vol.py"
    fake.parent.mkdir()
    fake.write_text("# fake\n")

    resp = client.post(_ROUTE, json={
        "dump_paths": [str(dump)],
        "plugin_path": str(plugin),
        "mode": VOL3_MODE_IN_PROCESS,
        "vol_bin": str(fake),
        "vol_python": sys.executable,
    })

    assert resp.status_code == 200, resp.text
    assert resp.json()["runtime"]["subprocess"]["source"] == "vol_bin="


# --------------------------------------------------------------------------- #
# (i) the MCP surface
# --------------------------------------------------------------------------- #

@pytest.fixture(scope="module")
def mcp_tool():
    """The registered MCP tool's callable, funnel and all."""
    pytest.importorskip("mcp")
    from memdiver.mcp_server.server import create_server

    tools = {t.name: t for t in create_server()._tool_manager.list_tools()}
    assert "verify_vol3_plugin" in tools, sorted(tools)
    return tools["verify_vol3_plugin"].fn


def test_mcp_tool_returns_a_json_string_payload(mcp_tool, tmp_path):
    plugin, dump, key_offset, _ = planted(tmp_path)

    raw = mcp_tool(
        dump_paths=[str(dump)], plugin_path=str(plugin),
        mode=VOL3_MODE_IN_PROCESS, expected_offset=key_offset)

    assert isinstance(raw, str)
    payload = json.loads(raw)
    assert "error" not in payload, payload
    assert payload["verdict"] == VERIFY_HIT
    assert payload["counts"]["dumps_hit"] == 1


def test_mcp_tool_funnels_the_both_forms_error(mcp_tool, tmp_path):
    plugin, dump, _, _ = planted(tmp_path)

    raw = mcp_tool(
        dump_paths=[str(dump)], plugin_path=str(plugin),
        plugin_source=plugin.read_text())

    payload = json.loads(raw)
    assert payload["category"] == ErrorCategory.INVALID_INPUT.name, payload
    assert "plugin_path" in payload["error"]


def test_mcp_and_web_payloads_are_BYTE_IDENTICAL(mcp_tool, client, tmp_path):
    """Two transports over one producer. Byte-for-byte, not merely equivalent:
    the MCP tool ``json.dumps`` the same dict FastAPI serialises, so any
    per-surface shaping — a rounded float, a dropped key, a re-ordered row —
    shows up here rather than in a UI."""
    plugin, reference, key_offset, _ = emitted_plugin(tmp_path, "ParityP")
    hit_dump = write_dump(tmp_path / "parity_hit.dump", {0: reference})
    miss_dump = write_dump(tmp_path / "parity_miss.dump", {})
    body = {
        "dump_paths": [str(hit_dump), str(miss_dump)],
        "plugin_path": str(plugin),
        "mode": VOL3_MODE_IN_PROCESS,
        "expected_offset": key_offset,
    }

    from_mcp = json.loads(mcp_tool(**body))
    from_web = client.post(_ROUTE, json=body).json()

    # ``elapsed_s`` is wall-clock and is the ONLY field allowed to differ.
    from_mcp.pop("elapsed_s")
    from_web.pop("elapsed_s")
    assert json.dumps(from_mcp, sort_keys=True) == json.dumps(
        from_web, sort_keys=True)


# --------------------------------------------------------------------------- #
# (j) the CLI surface
# --------------------------------------------------------------------------- #

def _run_cli(argv, tmp_path):
    """Invoke the ``verify-plugin`` handler and return ``(exit, payload)``."""
    from memdiver.cli import _cmd_verify_plugin, build_parser

    out = tmp_path / f"cli_{abs(hash(tuple(argv))) % 10**8}.json"
    args = build_parser().parse_args(["verify-plugin", *argv, "-o", str(out)])
    code = _cmd_verify_plugin(args)
    return code, json.loads(out.read_text())


def test_cli_is_a_TOP_LEVEL_command_not_an_inspect_action():
    """``inspect`` is single-dump, session-first and ``ServiceResult``-shaped,
    none of which an N-dump verification can express. ``verify-plugin`` follows
    the ``scan-yara`` / ``locate-field-pairs`` precedent instead."""
    from memdiver.cli import _INSPECT_HANDLERS, build_parser

    assert "verify_plugin" not in _INSPECT_HANDLERS
    assert "plugin" not in _INSPECT_HANDLERS
    args = build_parser().parse_args(
        ["verify-plugin", "/a.dump", "--plugin", "/p.py"])
    assert args.command == "verify-plugin"


def test_cli_exits_zero_on_a_hit_and_prints_the_RUNTIME_line(tmp_path, capsys):
    """Exit 0 = fired, and the runtime line goes to STDERR unconditionally.

    Unconditionally because a verification that does not say which framework
    answered is not reproducible — and on this machine the two runtimes answer
    with different versions.
    """
    plugin, dump, key_offset, _ = planted(tmp_path)

    code, payload = _run_cli(
        [str(dump), "--plugin", str(plugin), "--mode", VOL3_MODE_IN_PROCESS,
         "--expected-offset", str(key_offset)],
        tmp_path)

    assert code == 0
    assert payload["verdict"] == VERIFY_HIT
    captured = capsys.readouterr()
    assert "verdict=hit" in captured.err
    assert "runtime in_process=2." in captured.err
    assert "launcher=" in captured.err
    # The payload goes to --output, never to stdout, so a piped JSON consumer
    # is not fed the human lines.
    assert captured.out == ""


def test_cli_exits_three_on_a_measured_absence(tmp_path):
    """``3`` = ``_CLI_EXIT[NOT_FOUND]``: a MEASURED absence, and the full payload
    is still written — a non-zero exit is a verdict, not a failure."""
    plugin, _, _, _ = planted(tmp_path)
    empty = write_dump(tmp_path / "cli_empty.dump", {})

    code, payload = _run_cli(
        [str(empty), "--plugin", str(plugin), "--mode", VOL3_MODE_IN_PROCESS],
        tmp_path)

    assert code == 3
    assert payload["verdict"] == VERIFY_NO_HIT


def test_cli_exits_two_when_a_container_forces_a_subprocess_refusal(plain_msl, tmp_path):
    """``2`` is the caller-correctable code, and this is where it earns its keep:
    the fix is in the invocation (drop to ``--mode in_process``), not in the
    plugin."""
    plugin, msl, _, _ = plain_msl

    code, payload = _run_cli(
        [str(msl), "--plugin", str(plugin), "--mode", VOL3_MODE_SUBPROCESS],
        tmp_path)

    assert code == 2
    assert payload["verdict"] == VERIFY_NOT_RUN
    assert payload["dumps"][0]["status"] == VERIFY_UNSUPPORTED


def test_cli_count_only_is_the_NEGATION_of_the_producer_default(tmp_path):
    plugin, dump, _, _ = planted(tmp_path)

    _, payload = _run_cli(
        [str(dump), "--plugin", str(plugin), "--mode", VOL3_MODE_IN_PROCESS,
         "--count-only"],
        tmp_path)

    assert "hits" not in payload["dumps"][0]["run"]
    assert payload["dumps"][0]["run"]["hits_omitted"] is True


def test_cli_advertises_the_producers_OWN_defaults(tmp_path):
    """A re-literalled cap in the parser is exactly how a surface starts
    advertising a budget the library does not apply."""
    from memdiver.cli import build_parser

    args = build_parser().parse_args(
        ["verify-plugin", "/a.dump", "--plugin", "/p.py"])
    assert args.mode == VOL3_MODE_AUTO
    assert args.max_hits == VOL3_MAX_HITS
    assert args.timeout == VOL3_SUBPROC_TIMEOUT_S
    assert args.count_only is not DEFAULT_INCLUDE_HITS


def test_cli_and_library_agree(tmp_path):
    plugin, reference, key_offset, _ = emitted_plugin(tmp_path, "CliLibP")
    dumps = [
        str(write_dump(tmp_path / "cl_hit.dump", {0: reference})),
        str(write_dump(tmp_path / "cl_miss.dump", {})),
    ]

    code, from_cli = _run_cli(
        [*dumps, "--plugin", str(plugin), "--mode", VOL3_MODE_IN_PROCESS,
         "--expected-offset", str(key_offset)],
        tmp_path)
    from_lib = verify_vol3_plugin(
        dump_paths=dumps, plugin_path=str(plugin),
        mode=VOL3_MODE_IN_PROCESS, expected_offset=key_offset)

    assert code == 0
    from_cli.pop("elapsed_s")
    from_lib.pop("elapsed_s")
    assert from_cli == from_lib


# --------------------------------------------------------------------------- #
# (k) the library surface
# --------------------------------------------------------------------------- #

def test_the_library_surface_reaches_the_same_object():
    import memdiver
    from memdiver import services
    from memdiver.app import tools_pipeline

    assert services.verify_vol3_plugin is tools_pipeline.verify_vol3_plugin
    assert memdiver.verify_vol3_plugin is tools_pipeline.verify_vol3_plugin
    assert "verify_vol3_plugin" in services.__all__
    assert "verify_vol3_plugin" in memdiver.__all__


def test_the_capability_is_registered_on_all_FOUR_surfaces():
    """No ``KNOWN_PARITY_GAPS`` entry — and it could not have one, since that
    baseline is shrink-only."""
    from memdiver.app.capabilities import CAPABILITIES

    cap = next(c for c in CAPABILITIES if c.name == "analysis.verify_plugin")
    assert cap.producer == "memdiver.app.tools_pipeline.verify_vol3_plugin"
    assert set(cap.surfaces) == {"library", "cli", "web", "mcp"}


def test_pid_is_passed_through_but_marked_UNPROVEN(tmp_path):
    """Out of scope by design, and SAID so rather than quietly implied.

    ``--pid`` needs a kernel image plus a matching ISF so the OS ``PsList`` can
    hand back a process layer; neither this repo nor the machine it was
    developed on has one, and the emitted plugin itself logs a warning and scans
    the whole layer when its ``kernel`` requirement is unfilled. So the value is
    forwarded and a WARNING diagnostic says the rows are not restricted — which
    is the honest alternative to a test that cannot really exercise it.
    """
    plugin, dump, _, _ = planted(tmp_path)

    payload = verify_vol3_plugin(
        dump_paths=[str(dump)], plugin_path=str(plugin),
        mode=VOL3_MODE_IN_PROCESS, pid=1)

    assert payload["caps"]["pid"] == 1
    unproven = [
        d for d in payload["diagnostics"]
        if d["code"] == VERIFY_PLUGIN_PID_UNPROVEN_CODE
    ]
    assert unproven, payload["diagnostics"]
    assert unproven[0]["severity"] == "warning"
    assert "UNPROVEN" in unproven[0]["message"]


# --------------------------------------------------------------------------- #
# (l) the plugin vs the YARA rule it EMBEDS — Phase B bug #4, as a standing test
# --------------------------------------------------------------------------- #

def test_the_plugin_and_its_own_embedded_yara_rule_agree_on_the_key(tmp_path):
    """Phase B bug #4 was a vol3 export that disagreed with its embedded rule.

    That was caught once, by hand, by running both. ``tests/test_vol3_emit.py``
    pins the CONSTANTS the two share; this pins the BEHAVIOUR — the plugin is
    run by ``verify_vol3_plugin`` and its own ``YARA_RULE`` is run by
    ``scan_yara_rule`` over the same dump, and the two detectors must land on
    the same key offset. Two independent engines (Volatility3's scanners and
    libyara) reading one emission is a far stronger check than either alone.
    """
    plugin, dump, key_offset, _ = planted(tmp_path)
    rule = _embedded_yara_rule(plugin.read_text())

    verified = verify_vol3_plugin(
        dump_paths=[str(dump)], plugin_path=str(plugin),
        mode=VOL3_MODE_IN_PROCESS, expected_offset=key_offset)
    scanned = scan_yara_rule(dump_paths=[str(dump)], rule_source=rule)

    plugin_keys = sorted(
        h["key_absolute_offset"] for h in verified["dumps"][0]["run"]["hits"])
    rule_keys = sorted(
        m["offset"] + (m["key_offset"] or 0)
        for m in scanned["dumps"][0]["scan"]["matches"]
    )
    assert plugin_keys == [key_offset], verified["dumps"][0]["run"]
    assert rule_keys == plugin_keys, (rule_keys, plugin_keys)


# --------------------------------------------------------------------------- #
# (m) the REAL corpus — both runtimes, on bytes nobody synthesised
# --------------------------------------------------------------------------- #

def _real_run_dir() -> Path:
    return tls_dumps_dir() / _REAL_RUN


def _real_dumps() -> list:
    directory = _real_run_dir()
    if not directory.is_dir():
        pytest.skip(f"ground-truth run not present: {directory}")
    dumps = sorted(str(p) for p in directory.glob("*.dump"))
    if len(dumps) != 8:
        pytest.skip(f"expected the 8-dump ground-truth run, found {len(dumps)}")
    return dumps


def _real_plugin(tmp_path: Path) -> Path:
    """Emit a plugin for the real key at ``--context 256``.

    256 and not the emitter's default 64: the bytes around 370,672 are a
    583-byte zero run, so at pad 64 the whole window is inside it and the anchor
    carries ONE distinct byte value — a non-detector that fires 825,779 times in
    a single 11 MB dump. Phase B's acceptance used 256 and got ``KeyOffset
    370672``, ``KeyLength 48``, ``KeyEntropy 5.4183``.
    """
    from memdiver.app.tools_pipeline import export_key_pattern

    export = export_key_pattern(
        dump_paths=_real_dumps(),
        key_hex=_REAL_KEY_HEX,
        context=_REAL_CONTEXT,
        fmt="vol3",
        name="Pad256",
    )
    path = tmp_path / "Pad256.py"
    path.write_text(export["content"])
    return path


@pytest.mark.requires_dataset
@pytest.mark.slow
def test_the_real_plugin_finds_the_real_key_IN_PROCESS(tmp_path):
    """The acceptance measurement, reproduced through the producer.

    Note the shape of the answer, which is the whole reason ``key_recovered``
    exists: the plugin fires on ALL EIGHT dumps at offset 370,672, because the
    emitted pattern wildcards the key and the surrounding zero run is identical
    everywhere — but the key's own bytes are only there in the two ``*_abort``
    dumps. ``match_count`` alone would report 8 of 8 survival for a secret that
    survived in 2.
    """
    plugin = _real_plugin(tmp_path)
    dumps = _real_dumps()

    payload = verify_vol3_plugin(
        dump_paths=dumps,
        plugin_path=str(plugin),
        mode=VOL3_MODE_IN_PROCESS,
        expected_offset=_REAL_KEY_OFFSET,
        key_hex=_REAL_KEY_HEX,
    )

    assert payload["verdict"] == VERIFY_HIT
    assert payload["counts"]["dumps_verified"] == 8
    assert payload["counts"]["dumps_hit"] == 8
    assert payload["counts"]["dumps_expected_offset_reported"] == 8
    # 2 of 8, and the two are the aborts.
    assert payload["counts"]["dumps_key_recovered"] == 2
    recovered = sorted(
        r["name"] for r in payload["dumps"] if r["run"]["key_recovered"])
    assert all("abort" in name for name in recovered), recovered
    # One row per 11 MB dump: the selectivity claim at pad 256.
    for row in payload["dumps"]:
        assert row["run"]["match_count"] == 1, (row["name"], row["run"])
        assert row["run"]["layer_bytes"] == 11_223_040
        assert row["run"]["hits"][0]["key_length"] == 48
    # And the entropy of the bytes at the key position is the wipe signature,
    # measured: 5.4183 on the two aborts (Phase B's acceptance number) and
    # ``-0.0`` on the six cleanups, where the 48 bytes are all zero and a
    # single-symbol distribution gives Shannon 0 with a negated float sign. So
    # the plugin's OWN entropy column separates survival from a wipe without
    # any key being supplied at all -- which is what makes it worth carrying.
    by_name = {r["name"]: r["run"]["hits"][0]["key_entropy"]
               for r in payload["dumps"]}
    for name, entropy in by_name.items():
        if "abort" in name:
            assert entropy == pytest.approx(5.4183), name
        else:
            assert abs(entropy) < 1e-9, (name, entropy)


@pytest.mark.requires_dataset
@pytest.mark.requires_vol3
@pytest.mark.slow
def test_the_real_plugin_finds_the_real_key_through_the_REAL_vol(tmp_path):
    """The out-of-process half, and the ``ET_DYN`` / ``LayerStacker`` hazard.

    ``vol`` runs its ``LayerStacker`` automagic first, and MemDiver's flat dumps
    begin ``7f 45 4c 46`` with ``e_type = ET_DYN``, so the stacker wraps the dump
    in an ``Elf64Layer`` whose sections have no size. A plugin bound to
    ``primary`` therefore reported ZERO hits on a dump that provably contains
    the key. The emitted plugin walks ``layer.dependencies`` down to the lowest
    layer, which is what makes the row below exist at all — and ``--virtual``,
    which opts back into the stacked layer, still returns nothing (measured).

    The version fact this asserts is the one the whole ``runtime`` block is for:
    the framework reported here is the LAUNCHER's, which on the author's machine
    is 2.27.1 while in-process is 2.27.0. Both find the key at the same offset.
    """
    plugin = _real_plugin(tmp_path)
    dumps = _real_dumps()
    assert Path(dumps[0]).read_bytes()[:4] == b"\x7fELF", (
        "premise: the stacker fires because these are ELF files — without that "
        "this test no longer exercises the layer walk at all"
    )

    payload = verify_vol3_plugin(
        dump_paths=dumps,
        plugin_path=str(plugin),
        mode=VOL3_MODE_SUBPROCESS,
        expected_offset=_REAL_KEY_OFFSET,
        key_hex=_REAL_KEY_HEX,
    )

    assert payload["verdict"] == VERIFY_HIT
    assert payload["counts"]["dumps_verified"] == 8
    assert payload["counts"]["dumps_expected_offset_reported"] == 8
    assert payload["counts"]["dumps_key_recovered"] == 2
    for row in payload["dumps"]:
        assert row["mode_used"] == VOL3_MODE_SUBPROCESS
        # The framework that ANSWERED, not the one MemDiver imports.
        assert row["framework_version"] == (
            payload["runtime"]["subprocess"]["framework_version"])
        assert row["run"]["match_count"] == 1, (row["name"], row["run"])
        assert row["view"] is None, "`vol` mapped the file, not a MemDiver view"


@pytest.mark.requires_dataset
@pytest.mark.requires_vol3
@pytest.mark.slow
def test_the_two_runtimes_AGREE_on_the_real_key_and_say_if_they_disagree_on_version(
    tmp_path,
):
    """The cross-runtime differential, which is the point of having two.

    Measured on the author's machine: in-process framework 2.27.0, launcher
    2.27.1 — DIFFERENT versions reaching the SAME offset. That is the good
    outcome, and it is only legible because every row names its own framework.
    The version-skew diagnostic fires when they differ and is silent when they
    do not; either way the hits must match.
    """
    plugin = _real_plugin(tmp_path)
    # One dump is enough for the differential and keeps this test to ~2 runs.
    dump = next(d for d in _real_dumps() if "post_abort" in d)

    common = {
        "dump_paths": [dump],
        "plugin_path": str(plugin),
        "expected_offset": _REAL_KEY_OFFSET,
        "key_hex": _REAL_KEY_HEX,
    }
    in_proc = verify_vol3_plugin(mode=VOL3_MODE_IN_PROCESS, **common)
    subproc = verify_vol3_plugin(mode=VOL3_MODE_SUBPROCESS, **common)

    in_hits = in_proc["dumps"][0]["run"]["hits"]
    sub_hits = subproc["dumps"][0]["run"]["hits"]
    assert len(in_hits) == len(sub_hits) == 1
    for field in ("offset", "key_offset", "key_absolute_offset", "key_length",
                  "key_hex", "key_entropy", "static_ratio", "length"):
        assert in_hits[0][field] == sub_hits[0][field], field
    assert in_hits[0]["key_absolute_offset"] == _REAL_KEY_OFFSET
    assert in_proc["dumps"][0]["run"]["key_recovered"] is True
    assert subproc["dumps"][0]["run"]["key_recovered"] is True

    runtime = subproc["runtime"]
    codes = [d["code"] for d in subproc["diagnostics"]]
    if runtime["versions_agree"] is False:
        assert VERIFY_PLUGIN_VERSION_SKEW_CODE in codes, codes
        assert (in_proc["dumps"][0]["framework_version"]
                != subproc["dumps"][0]["framework_version"])
    else:
        assert VERIFY_PLUGIN_VERSION_SKEW_CODE not in codes, codes


@pytest.mark.requires_dataset
@pytest.mark.slow
def test_the_real_plugin_agrees_with_its_own_embedded_rule_on_the_real_key(tmp_path):
    """Phase B bug #4 on real bytes, and the sharper version of it.

    The synthetic pairing above proves the two detectors agree on a planted
    window. This proves it where it actually mattered: on the corpus the pattern
    was derived from, where the plugin fires on 8 dumps and only 2 hold the key.
    The libyara run is COUNT-ONLY where it can be, because at this pad the rule
    is selective (one hit per dump) but the count-only form is what keeps this
    honest if a future pad change makes it otherwise.
    """
    plugin = _real_plugin(tmp_path)
    dumps = _real_dumps()
    rule = _embedded_yara_rule(plugin.read_text())

    verified = verify_vol3_plugin(
        dump_paths=dumps, plugin_path=str(plugin),
        mode=VOL3_MODE_IN_PROCESS, expected_offset=_REAL_KEY_OFFSET)
    scanned = scan_yara_rule(dump_paths=dumps, rule_source=rule)

    # Same dumps fired on, in the same order.
    assert [r["run"]["match_count"] for r in verified["dumps"]] == [
        r["scan"]["match_count"] for r in scanned["dumps"]]
    for plugin_row, rule_row in zip(verified["dumps"], scanned["dumps"]):
        plugin_keys = sorted(
            h["key_absolute_offset"] for h in plugin_row["run"]["hits"])
        rule_keys = sorted(
            m["offset"] + (m["key_offset"] or 0)
            for m in rule_row["scan"]["matches"])
        assert plugin_keys == [_REAL_KEY_OFFSET], plugin_row["name"]
        assert rule_keys == plugin_keys, (plugin_row["name"], rule_keys)

"""Golden pin for the artifacts ``engine.vol3_emit`` emits at the DEFAULT pad.

Why this file exists
--------------------
``DEFAULT_NEIGHBORHOOD_PAD`` (64 bytes per side) flows into every byte MemDiver
emits::

    _load_neighborhood_variance -> Hit.neighborhood_start/.neighborhood_variance
      -> vol3_emit: window = reference_data[nb_start:nb_end]
      -> static_mask -> infer_fields -> _build_vtypes
      -> PatternGenerator.generate -> YaraExporter.export
      -> Volatility3Exporter.export

Move the pad and ``PATTERN_LENGTH``, ``KEY_OFFSET``, the whole
``hex_pattern``/``wildcard_pattern``, ``static_ratio``, ``VTYPES``,
``NEEDLE``/``NEEDLE_OFFSET`` and the YARA ``$key`` string all move with it.
Before this module nothing pinned any of that: ``test_vol3_emit`` asserted
``PATTERN_LENGTH = 160`` / ``KEY_OFFSET = 64``, but its synthetic hit
hand-built the neighborhood from a *local* ``64`` literal, so a pad change
moved both sides together and the suite stayed green.

**Read this before regenerating anything:**

    This golden file is a **review artifact** for template changes, not a
    certificate that the pinned signature is any good. It is emitted from the
    synthetic hit at the default pad, whose anchor is healthy by construction.
    On real key material the default pad is frequently degenerate. Signature
    *quality* is asserted elsewhere. Do not regenerate this file to make the
    suite green — a diff here means the emitted plugin changed for every user
    who re-emits, and the commit that changes it must say why.

The pin runs off the synthetic hit deliberately: CI has no corpus, and a pin
that skips in CI is not a pin. Emitting from a construction that is healthy by
design also stops the golden from being misread as a quality bar.
"""

from __future__ import annotations

import ast
from pathlib import Path

import numpy as np
import pytest

from memdiver.engine.brute_force import (
    DEFAULT_NEIGHBORHOOD_PAD,
    NEIGHBORHOOD_PAD,
    run_brute_force,
)
from memdiver.engine.vol3_emit import emit_plugin_for_hit
from tests._emit_pins import strip_timestamp, synth_hit

GOLDEN_DIR = Path(__file__).parent / "fixtures" / "vol3_plugin_pin"
PLUGIN_GOLDEN = GOLDEN_DIR / "default_pad_plugin.py.golden"
YARA_GOLDEN = GOLDEN_DIR / "default_pad_rule.yar.golden"

#: Fixed across the pin so the golden's class/rule names never move for an
#: unrelated reason.
PIN_NAME = "MemDiverPinnedKey"
PIN_DESCRIPTION = "golden pin — synthetic hit at the default neighborhood pad"


def _emit_pin(tmp_path: Path, **synth_kwargs) -> str:
    """Emit the pinned plugin from the synthetic hit and return its source."""
    ref, hit, _ = synth_hit(**synth_kwargs)
    out = emit_plugin_for_hit(
        hit, ref, PIN_NAME, tmp_path / "plugin.py", description=PIN_DESCRIPTION,
    )
    return out.read_text()


def _embedded_yara_rule(plugin_source: str) -> str:
    """Lift the plugin's ``YARA_RULE`` string via the AST, not a regex."""
    for node in ast.parse(plugin_source).body:
        if not isinstance(node, ast.Assign):
            continue
        if "YARA_RULE" in [t.id for t in node.targets if isinstance(t, ast.Name)]:
            assert isinstance(node.value, ast.Constant)
            return node.value.value
    raise AssertionError("generated plugin has no YARA_RULE string assignment")


def _plugin_int(plugin_source: str, name: str) -> int:
    """Read a module-level ``NAME = <int>`` out of the generated plugin."""
    for node in ast.parse(plugin_source).body:
        if not isinstance(node, ast.Assign):
            continue
        if name in [t.id for t in node.targets if isinstance(t, ast.Name)]:
            return int(ast.literal_eval(node.value))
    raise AssertionError(f"generated plugin has no {name} assignment")


# ---------------------------------------------------------------------------
# 1 + 2 + 3: the golden itself, reached with the parameter UNSPECIFIED
# ---------------------------------------------------------------------------


def test_default_pad_plugin_matches_golden(tmp_path):
    """The emitted vol3 plugin is byte-for-byte the checked-in golden.

    Only the exporter's ``Generated:`` UTC line is normalised out (see
    ``architect.volatility3_exporter``, its single source of nondeterminism);
    everything else — ``PATTERN_LENGTH``, ``KEY_OFFSET``, the hex/wildcard
    patterns, ``static_ratio``, ``VTYPES``, ``NEEDLE``, ``NEEDLE_OFFSET`` and
    the embedded YARA rule — is pinned exactly.

    A diff here is not a test failure to be papered over: it means every user
    who re-emits a plugin now gets different bytes. See this module's docstring.
    """
    got = strip_timestamp(_emit_pin(tmp_path))
    assert PLUGIN_GOLDEN.exists(), (
        f"missing golden {PLUGIN_GOLDEN}; it is checked in, not generated on demand"
    )
    assert got == PLUGIN_GOLDEN.read_text(), (
        "emitted vol3 plugin no longer matches the golden at the default "
        f"neighborhood pad ({DEFAULT_NEIGHBORHOOD_PAD}). Do NOT regenerate to "
        "go green — explain the change in the commit that moves it."
    )


def test_default_pad_yara_rule_matches_golden(tmp_path):
    """The embedded YARA rule is pinned verbatim (no timestamp normalisation).

    ``YaraExporter`` has no clock/uuid/random input, so its output is
    reproducible byte-for-byte and the golden needs no stripping at all.
    """
    rule = _embedded_yara_rule(_emit_pin(tmp_path))
    assert YARA_GOLDEN.exists(), (
        f"missing golden {YARA_GOLDEN}; it is checked in, not generated on demand"
    )
    assert rule == YARA_GOLDEN.read_text(), (
        "emitted YARA rule no longer matches the golden at the default "
        f"neighborhood pad ({DEFAULT_NEIGHBORHOOD_PAD})."
    )


def test_yara_and_vol3_exporters_have_no_nondeterminism():
    """Guard the assumption the goldens rest on.

    The vol3 exporter's ``Generated:`` timestamp is the ONE tolerated source of
    nondeterminism (hence ``strip_timestamp``). If a clock / uuid / RNG appears
    in ``YaraExporter`` — or a second one in the vol3 exporter — the pins above
    start flapping, and this test says so before they do.
    """
    import inspect

    from memdiver.architect import volatility3_exporter, yara_exporter

    yara_src = inspect.getsource(yara_exporter)
    for token in ("datetime", "uuid", "random", "time.time", "monotonic"):
        assert token not in yara_src, (
            f"YaraExporter gained a nondeterministic source ({token!r}); the "
            "verbatim YARA golden can no longer hold"
        )
    vol3_src = inspect.getsource(volatility3_exporter)
    for token in ("uuid", "random", "monotonic"):
        assert token not in vol3_src, (
            f"Volatility3Exporter gained a nondeterministic source ({token!r}) "
            "that strip_timestamp does not neutralise"
        )
    # The known one, asserted present so strip_timestamp never becomes a no-op
    # silently (a renamed "Generated:" line would make the stripper vacuous).
    assert "datetime.now" in vol3_src
    assert "Generated:" in vol3_src


def test_explicit_default_pad_is_byte_identical(tmp_path):
    """Passing the default explicitly must change nothing.

    ``synth_hit()`` (parameter unspecified) and
    ``synth_hit(neighborhood_pad=DEFAULT_NEIGHBORHOOD_PAD)`` must emit
    byte-identical plugins — the whole point of making the pad configurable
    "both ways" is that naming today's value is a no-op.
    """
    implicit = strip_timestamp(_emit_pin(tmp_path / "implicit"))
    explicit = strip_timestamp(
        _emit_pin(tmp_path / "explicit", neighborhood_pad=DEFAULT_NEIGHBORHOOD_PAD)
    )
    assert implicit == explicit
    assert implicit == PLUGIN_GOLDEN.read_text()


def test_legacy_alias_is_the_same_default():
    """``NEIGHBORHOOD_PAD`` stays importable and stays equal to the default.

    Kept as an alias so nothing that imported the historical name breaks; if the
    two ever diverge, half the call sites would silently use the other value.
    """
    assert NEIGHBORHOOD_PAD == DEFAULT_NEIGHBORHOOD_PAD == 64


# ---------------------------------------------------------------------------
# 4: the REAL path binds the constant (not a literal 64)
# ---------------------------------------------------------------------------


def _write_state(tmp_path: Path, size: int = 1024, num_dumps: int = 3):
    """A minimal on-disk Welford state with variance planted over the key."""
    import json
    import os

    m2_path = tmp_path / "cons.m2.npy"
    mean_path = tmp_path / "cons.mean.npy"
    state_path = tmp_path / "cons.state"
    m2 = np.zeros(size, dtype=np.float32)
    m2[256:288] = 45000.0  # variance = 15000 at N=3
    np.save(m2_path, m2)
    np.save(mean_path, np.zeros(size, dtype=np.float32))
    state_path.write_text(json.dumps({
        "size": size, "num_dumps": num_dumps,
        "mean_path": str(mean_path), "m2_path": str(m2_path),
    }))
    oracle = tmp_path / "oracle.py"
    oracle.write_text("TARGET = bytes(range(32))\ndef verify(c): return c == TARGET\n")
    os.chmod(oracle, 0o644)

    ref = bytearray(np.random.RandomState(77).randint(0, 256, size, dtype=np.uint8).tobytes())
    ref[256:288] = bytes(range(32))
    cand_path = tmp_path / "cands.json"
    cand_path.write_text(json.dumps({"regions": [
        {"offset": 256, "length": 32, "mean_variance": 15000.0, "mean_entropy": 4.8},
    ]}))
    return bytes(ref), cand_path, oracle, state_path


@pytest.mark.parametrize("pad_kwargs", [{}, {"neighborhood_pad": DEFAULT_NEIGHBORHOOD_PAD}])
def test_real_brute_force_neighborhood_binds_the_constant(tmp_path, pad_kwargs):
    """``run_brute_force`` attaches exactly ``DEFAULT_NEIGHBORHOOD_PAD`` per side.

    Expectations are computed from the IMPORTED constant, never from a literal
    ``64`` — that literal is precisely the mistake that let the pad drift
    unnoticed (``tests/test_api_pipeline.py`` recomputed its own ``nb_pad = 64``).
    """
    ref, cand_path, oracle, state_path = _write_state(tmp_path)
    key_offset, key_length = 256, 32

    result = run_brute_force(
        candidates_path=cand_path,
        reference_data=ref,
        oracle_path=oracle,
        state_path=state_path,
        stride=8,
        **pad_kwargs,
    )
    hit = result.hits[0]
    assert hit.neighborhood_start == key_offset - DEFAULT_NEIGHBORHOOD_PAD
    assert len(hit.neighborhood_variance) == (
        DEFAULT_NEIGHBORHOOD_PAD + key_length + DEFAULT_NEIGHBORHOOD_PAD
    )
    key_slice = hit.neighborhood_variance[
        DEFAULT_NEIGHBORHOOD_PAD:DEFAULT_NEIGHBORHOOD_PAD + key_length
    ]
    assert all(abs(v - 15000.0) < 0.1 for v in key_slice)


def test_real_brute_force_honours_a_non_default_pad(tmp_path):
    """The engine knob is live end to end, not just accepted and ignored."""
    ref, cand_path, oracle, state_path = _write_state(tmp_path)
    pad = 16
    assert pad != DEFAULT_NEIGHBORHOOD_PAD

    result = run_brute_force(
        candidates_path=cand_path,
        reference_data=ref,
        oracle_path=oracle,
        state_path=state_path,
        stride=8,
        neighborhood_pad=pad,
    )
    hit = result.hits[0]
    assert hit.neighborhood_start == 256 - pad
    assert len(hit.neighborhood_variance) == pad + 32 + pad


# ---------------------------------------------------------------------------
# 5: a non-default pad really does change the emitted artifact
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("pad", [16, 128])
def test_non_default_pad_changes_emitted_pattern_arithmetic(tmp_path, pad):
    """A different pad yields a different ``PATTERN_LENGTH`` / ``KEY_OFFSET``.

    Asserted as arithmetic rather than a second golden: the point is that the
    knob reaches the emitted template, not that any particular non-default
    signature is blessed.
    """
    assert pad != DEFAULT_NEIGHBORHOOD_PAD
    key_length = 32
    src = _emit_pin(tmp_path / f"pad{pad}", neighborhood_pad=pad)

    assert _plugin_int(src, "PATTERN_LENGTH") == pad + key_length + pad
    assert _plugin_int(src, "KEY_OFFSET") == pad
    assert _plugin_int(src, "KEY_LENGTH") == key_length

    # And the default really is the golden's arithmetic, so the two branches of
    # this comparison cannot both be wrong in the same direction.
    default_src = _emit_pin(tmp_path / "default")
    assert _plugin_int(default_src, "PATTERN_LENGTH") == (
        DEFAULT_NEIGHBORHOOD_PAD + key_length + DEFAULT_NEIGHBORHOOD_PAD
    )
    assert _plugin_int(default_src, "KEY_OFFSET") == DEFAULT_NEIGHBORHOOD_PAD
    assert strip_timestamp(src) != strip_timestamp(default_src)

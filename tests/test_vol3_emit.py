"""Tests for engine.vol3_emit — vol3 plugin emission from hits."""

import ast
import json

import pytest
import yara

from memdiver.engine.vol3_emit import emit_plugin_for_hit, emit_plugin_from_hits_file
from tests._emit_pins import emitted_requirements, synth_hit


def _embedded_yara_meta(plugin_source: str) -> dict:
    """Compile the plugin's embedded YARA_RULE and return its meta dict.

    Read via the AST (not a regex) so the extraction cannot drift from what
    Python would see, then compiled for real -- the generated plugin wraps
    its own ``yara.compile`` in ``except Exception: pass``, so a broken rule
    would otherwise degrade silently to the BytesScanner path.
    """
    tree = ast.parse(plugin_source)
    for node in tree.body:
        if not isinstance(node, ast.Assign):
            continue
        targets = [t.id for t in node.targets if isinstance(t, ast.Name)]
        if "YARA_RULE" in targets and isinstance(node.value, ast.Constant):
            rules = list(yara.compile(source=node.value.value))
            assert len(rules) == 1, f"expected one rule, got {len(rules)}"
            return dict(rules[0].meta)
    raise AssertionError("generated plugin has no YARA_RULE string assignment")


#: The synthetic hit builder now lives in ``tests/_emit_pins.py`` so
#: ``tests/test_vol3_emit_golden.py`` reuses the exact same construction (and so
#: it derives its neighborhood from ``DEFAULT_NEIGHBORHOOD_PAD`` instead of the
#: local ``64`` literal it used to hardcode, which meant a pad change left the
#: ``PATTERN_LENGTH = 160`` / ``KEY_OFFSET = 64`` assertions below green).
_synth_hit = synth_hit


def test_emit_for_hit_writes_parseable_plugin(tmp_path):
    ref, hit, _ = _synth_hit()
    out = emit_plugin_for_hit(hit, ref, "TestKey", tmp_path / "plugin.py")
    src = out.read_text()
    ast.parse(src)
    assert "interfaces.plugins.PluginInterface" in src
    assert "YARA_RULE" in src
    assert "PATTERN_LENGTH = 160" in src


def test_emit_includes_key_offset_and_length(tmp_path):
    """Generated plugin must contain KEY_OFFSET and KEY_LENGTH attributes."""
    ref, hit, _ = _synth_hit()
    out = emit_plugin_for_hit(hit, ref, "TestKey", tmp_path / "plugin.py")
    src = out.read_text()
    assert "KEY_OFFSET = 64" in src
    assert "KEY_LENGTH = 32" in src


def test_emit_yara_rule_carries_key_locator_metas(tmp_path):
    """GAP C: the *embedded YARA rule* must carry the key locator too.

    ``emit_plugin_for_hit`` knows the key's position exactly (the hit is what
    defined the neighborhood window), so the rule it emits must be
    indistinguishable from one exported through ``app.export_service`` --
    otherwise the same detector scores differently depending on the surface
    that emitted it (``engine.yara_scan`` lifts these metas into
    ``Match.key_offset``/``key_length``).
    """
    ref, hit, _ = _synth_hit()
    out = emit_plugin_for_hit(hit, ref, "TestKey", tmp_path / "plugin.py")
    meta = _embedded_yara_meta(out.read_text())
    # key_offset is relative to the pattern window start: hit 256 - nb 192.
    assert meta["key_offset"] == 64
    assert meta["key_length"] == 32


def test_emit_yara_key_locator_agrees_with_plugin_constants(tmp_path):
    """The YARA metas and the plugin's KEY_OFFSET/KEY_LENGTH must not diverge."""
    ref, hit, _ = _synth_hit(key_offset=512, key_length=16)
    out = emit_plugin_for_hit(hit, ref, "TestKey", tmp_path / "plugin.py")
    src = out.read_text()
    meta = _embedded_yara_meta(src)
    assert f"KEY_OFFSET = {meta['key_offset']}" in src
    assert f"KEY_LENGTH = {meta['key_length']}" in src


def test_emit_includes_vtypes(tmp_path):
    """Generated plugin must embed a VTYPES dict with at least a key field."""
    ref, hit, _ = _synth_hit()
    out = emit_plugin_for_hit(hit, ref, "TestKey", tmp_path / "plugin.py")
    src = out.read_text()
    assert "VTYPES = " in src
    assert "'key'" in src


def test_emit_pid_is_an_optional_int_requirement(tmp_path):
    """``pid`` is declared as an OPTIONAL IntRequirement -- pinned via the AST.

    Replaces ``test_emit_pid_required``, which was vacuous *and* wrong. It
    asserted ``'name="pid"' in src`` and ``"optional=False" in src`` and its
    name/docstring claimed "must require PID by default (optional=False)".
    ``pid`` has always been ``optional=True``; the ``optional=False`` that
    satisfied the second assertion belongs to the ``TranslationLayerRequirement``
    on ``primary``, a different requirement on a different line of a ~7 KB
    generated file. Every part of the old test disagreed with the code, and it
    passed for years.

    ``emitted_requirements`` parses ``get_requirements`` with the AST, so an
    assertion about ``pid`` can no longer be satisfied by a line about
    ``primary``.
    """
    ref, hit, _ = _synth_hit()
    out = emit_plugin_for_hit(hit, ref, "TestKey", tmp_path / "plugin.py")
    reqs = emitted_requirements(out.read_text())

    assert "pid" in reqs, sorted(reqs)
    assert reqs["pid"]["kind"] == "Int"
    assert reqs["pid"]["optional"] is True
    # An explicit ``default=None``: the plugin's ``run()`` branches on
    # ``pid is not None``, so the default is part of the contract.
    assert reqs["pid"]["has_default"] is True
    assert reqs["pid"]["default"] is None
    # The claim the old test *thought* it was making, stated where it is true.
    assert reqs["primary"]["optional"] is False


def test_emit_requirement_map_is_pinned(tmp_path):
    """Full requirement map of the emitted plugin, pinned whole.

    Updated by B5.2, which added the two requirements the fixes needed:

    * ``kernel`` -- a ``ModuleRequirement``, and ``optional=True`` is
      LOAD-BEARING. ``--pid`` needs a real kernel module to enumerate processes
      through, but a *mandatory* ``ModuleRequirement`` would make
      ``PluginInterface.__init__`` fail its requirement gate on exactly the flat
      process dumps this plugin exists to scan. Optional still gets FILLED by
      vol3's ``KernelModule`` automagic when a kernel image plus symbols exist
      (it calls ``requirement.unsatisfied()`` directly rather than
      ``unsatisfied_children()``), and stays falsy otherwise.
    * ``virtual`` -- opt back in to scanning the configured translation layer.
      The default scan target is now the LOWEST (physical/file) layer.

    Pinning the whole map rather than spot-checking one entry is what makes the
    next change a deliberate edit instead of unobserved drift.
    """
    ref, hit, _ = _synth_hit()
    out = emit_plugin_for_hit(hit, ref, "TestKey", tmp_path / "plugin.py")
    reqs = emitted_requirements(out.read_text())

    assert list(reqs) == [
        "primary", "symbols", "kernel", "pid", "full_scan", "virtual",
    ]
    assert reqs == {
        "primary": {
            "kind": "TranslationLayer", "optional": False,
            "has_default": False, "default": None,
        },
        "symbols": {
            "kind": "SymbolTable", "optional": True,
            "has_default": False, "default": None,
        },
        "kernel": {
            "kind": "Module", "optional": True,
            "has_default": False, "default": None,
        },
        "pid": {
            "kind": "Int", "optional": True,
            "has_default": True, "default": None,
        },
        "full_scan": {
            "kind": "Boolean", "optional": True,
            "has_default": True, "default": False,
        },
        "virtual": {
            "kind": "Boolean", "optional": True,
            "has_default": True, "default": False,
        },
    }


def test_emit_output_columns_show_key(tmp_path):
    """Output columns should reference KeyOffset, KeyHex, KeyLength — not pattern length."""
    ref, hit, _ = _synth_hit()
    out = emit_plugin_for_hit(hit, ref, "TestKey", tmp_path / "plugin.py")
    src = out.read_text()
    assert "KeyOffset" in src
    assert "KeyHex" in src
    assert "KeyLength" in src
    assert "KeyEntropy" in src
    assert "PatternOffset" in src


def test_emit_wildcards_the_key_region(tmp_path):
    ref, hit, _ = _synth_hit()
    out = emit_plugin_for_hit(hit, ref, "TestKey", tmp_path / "plugin.py")
    src = out.read_text()
    # The YARA_RULE r'''...''' block should contain ?? wildcards for the
    # volatile middle 32 bytes (pattern_generator represents volatile
    # bytes as `??`).
    assert "??" in src


def test_all_volatile_neighborhood_raises(tmp_path):
    ref = b"\x00" * 1024
    hit = {
        "offset": 256, "length": 32,
        "neighborhood_start": 192,
        "neighborhood_variance": [15000.0] * 160,
    }
    with pytest.raises(RuntimeError, match="insufficient static"):
        emit_plugin_for_hit(hit, ref, "AllVolatile", tmp_path / "bad.py")


def test_empty_neighborhood_raises(tmp_path):
    ref = b"\x00" * 1024
    hit = {
        "offset": 256, "length": 32,
        "neighborhood_start": 192,
        "neighborhood_variance": [],
    }
    with pytest.raises(ValueError, match="no neighborhood"):
        emit_plugin_for_hit(hit, ref, "Empty", tmp_path / "empty.py")


def test_neighborhood_exceeding_dump_raises(tmp_path):
    ref = b"\x00" * 128
    hit = {
        "offset": 100, "length": 32,
        "neighborhood_start": 0,
        "neighborhood_variance": [100.0] * 200,
    }
    with pytest.raises(ValueError, match="exceeds reference"):
        emit_plugin_for_hit(hit, ref, "TooBig", tmp_path / "big.py")


def test_emit_from_hits_file(tmp_path):
    ref, hit, _ = _synth_hit()
    hits_path = tmp_path / "hits.json"
    hits_path.write_text(json.dumps({"hits": [hit]}))
    out = emit_plugin_from_hits_file(hits_path, ref, "FromFile", tmp_path / "plugin.py")
    assert out.exists()
    ast.parse(out.read_text())


def test_emit_from_empty_hits_file_raises(tmp_path):
    hits_path = tmp_path / "empty.json"
    hits_path.write_text(json.dumps({"hits": []}))
    with pytest.raises(ValueError, match="no hits"):
        emit_plugin_from_hits_file(hits_path, b"\x00" * 100, "Empty", tmp_path / "x.py")


def test_hit_index_out_of_range_raises(tmp_path):
    ref, hit, _ = _synth_hit()
    hits_path = tmp_path / "hits.json"
    hits_path.write_text(json.dumps({"hits": [hit]}))
    with pytest.raises(ValueError, match="hit 5"):
        emit_plugin_from_hits_file(
            hits_path, ref, "Idx", tmp_path / "x.py", hit_index=5
        )

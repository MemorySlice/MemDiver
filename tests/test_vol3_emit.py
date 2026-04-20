"""Tests for engine.vol3_emit — vol3 plugin emission from hits."""

import ast
import json

import numpy as np
import pytest

from engine.vol3_emit import emit_plugin_for_hit, emit_plugin_from_hits_file


def _synth_hit(ref_size: int = 1024, key_offset: int = 256, key_length: int = 32):
    np.random.seed(3)
    ref = bytearray(np.random.randint(0, 256, ref_size, dtype=np.uint8).tobytes())
    nb_start = max(0, key_offset - 64)
    nb_len = key_length + 128
    nb_variance = (
        [100.0] * 64           # static struct preamble
        + [15000.0] * key_length  # volatile key region
        + [50.0] * 64          # static struct trailer
    )
    hit = {
        "offset": key_offset,
        "length": key_length,
        "neighborhood_start": nb_start,
        "neighborhood_variance": nb_variance,
    }
    return bytes(ref), hit, nb_len


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


def test_emit_includes_vtypes(tmp_path):
    """Generated plugin must embed a VTYPES dict with at least a key field."""
    ref, hit, _ = _synth_hit()
    out = emit_plugin_for_hit(hit, ref, "TestKey", tmp_path / "plugin.py")
    src = out.read_text()
    assert "VTYPES = " in src
    assert "'key'" in src


def test_emit_pid_required(tmp_path):
    """Generated plugin must require PID by default (optional=False)."""
    ref, hit, _ = _synth_hit()
    out = emit_plugin_for_hit(hit, ref, "TestKey", tmp_path / "plugin.py")
    src = out.read_text()
    # PID requirement should be non-optional
    assert 'name="pid"' in src
    assert "optional=False" in src


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

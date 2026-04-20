"""End-to-end tests for AES-256 consensus + Volatility3 export pipeline."""
import json
import subprocess
import sys
from pathlib import Path

import pytest

# Import the fixture generator
sys.path.insert(0, str(Path(__file__).parent / "fixtures"))
from generate_aes_fixtures import generate_dataset, KEY_OFFSET, KEY_LENGTH, DUMP_SIZE


@pytest.fixture(scope="module")
def aes_dataset(tmp_path_factory):
    """Generate an AES fixture dataset for testing.

    Uses 20 runs to ensure stable variance statistics -- with only 5 runs,
    random byte positions can produce low variance by chance, fragmenting
    the key region classification.
    """
    out = tmp_path_factory.mktemp("aes_dataset")
    result = generate_dataset(out, num_runs=20, seed=42)
    return result, out


@pytest.fixture
def lldb_dump_paths(aes_dataset):
    """Return paths to the lldb dumps."""
    _, base = aes_dataset
    tool_dir = base / "AES256" / "aes_key_in_memory" / "lldb"
    paths = sorted(tool_dir.glob("*/pre_snapshot.dump"))
    # The filename pattern includes timestamp, so glob for any .dump
    if not paths:
        paths = sorted(tool_dir.glob("*/*.dump"))
    return paths


class TestAesProtocol:
    def test_aes_protocol_registered(self):
        from core.protocols import REGISTRY
        desc = REGISTRY.get("AES")
        assert desc is not None
        assert "256" in desc.versions
        assert "AES256_KEY" in desc.secret_types["256"]

    def test_aes_keylog_parses(self, tmp_path):
        from core.keylog import KeylogParser
        keylog = tmp_path / "keylog.csv"
        key_hex = "aa" * 32
        keylog.write_text(f"line\nAES256_KEY {'00' * 32} {key_hex}\n")
        secrets = KeylogParser.parse(keylog)
        assert len(secrets) == 1
        assert secrets[0].secret_type == "AES256_KEY"
        assert secrets[0].secret_value == bytes.fromhex(key_hex)


class TestAesConsensus:
    def test_consensus_identifies_key_region(self, lldb_dump_paths):
        from engine.consensus import ConsensusVector
        assert len(lldb_dump_paths) >= 2

        cm = ConsensusVector()
        cm.build(lldb_dump_paths)
        volatile = cm.get_volatile_regions(min_length=16)

        # Should find at least one volatile region covering most of the key
        # (with few runs, 1-2 key bytes may coincidentally match across runs)
        key_regions = [r for r in volatile
                       if r.start <= KEY_OFFSET + 2 and r.end >= KEY_OFFSET + KEY_LENGTH - 2]
        assert len(key_regions) >= 1, (
            f"Expected KEY_CANDIDATE near offset {KEY_OFFSET}, "
            f"got volatile regions: {[(r.start, r.end) for r in volatile]}"
        )

    def test_consensus_finds_anchors(self, lldb_dump_paths):
        from engine.consensus import ConsensusVector
        cm = ConsensusVector()
        cm.build(lldb_dump_paths)
        static = cm.get_static_regions(min_length=8)

        # Pre-anchor at 112-127 should be invariant
        pre_anchor_regions = [r for r in static
                              if r.start <= 112 and r.end >= 128]
        assert len(pre_anchor_regions) >= 1, (
            f"Expected invariant anchor at offset 112-127, "
            f"got static regions near key: {[(r.start, r.end) for r in static if 100 <= r.start <= 180]}"
        )

    def test_consensus_classification_counts(self, lldb_dump_paths):
        from engine.consensus import ConsensusVector
        cm = ConsensusVector()
        cm.build(lldb_dump_paths)
        counts = cm.classification_counts()
        # With few runs, 1-2 key bytes may coincidentally match
        assert counts["key_candidate"] >= KEY_LENGTH - 2
        assert counts["invariant"] > 0


class TestAesPatternExport:
    def test_static_check_key_region(self, lldb_dump_paths):
        from architect.static_checker import StaticChecker
        # Check the key region: should be volatile (different keys per run)
        static_mask, ref = StaticChecker.check(lldb_dump_paths, KEY_OFFSET, KEY_LENGTH)
        assert len(static_mask) == KEY_LENGTH
        # Most/all bytes should be volatile (different key each run)
        volatile_count = sum(1 for s in static_mask if not s)
        assert volatile_count >= KEY_LENGTH * 0.8, (
            f"Expected mostly volatile key bytes, got {volatile_count}/{KEY_LENGTH} volatile"
        )

    def test_static_check_anchor_region(self, lldb_dump_paths):
        from architect.static_checker import StaticChecker
        # Check the pre-anchor: should be static (identical across runs)
        static_mask, ref = StaticChecker.check(lldb_dump_paths, 112, 16)
        static_count = sum(static_mask)
        assert static_count == 16, f"Expected all 16 anchor bytes static, got {static_count}"

    def test_pattern_generation(self, lldb_dump_paths):
        from architect.static_checker import StaticChecker
        from architect.pattern_generator import PatternGenerator
        # Region spanning anchor + key + anchor (offset 112, length 64)
        static_mask, ref = StaticChecker.check(lldb_dump_paths, 112, 64)
        pattern = PatternGenerator.generate(ref, static_mask, "aes_test", min_static_ratio=0.2)
        assert pattern is not None
        assert pattern["length"] == 64
        # Should have both static and volatile bytes
        assert pattern["static_count"] > 0
        assert pattern["volatile_count"] > 0
        # Wildcard pattern should contain ?? for key bytes
        assert "??" in pattern["wildcard_pattern"]

    def test_yara_export(self, lldb_dump_paths):
        from architect.static_checker import StaticChecker
        from architect.pattern_generator import PatternGenerator
        from architect.yara_exporter import YaraExporter
        static_mask, ref = StaticChecker.check(lldb_dump_paths, 112, 64)
        pattern = PatternGenerator.generate(ref, static_mask, "aes_yara_test", min_static_ratio=0.2)
        rule = YaraExporter.export(pattern)
        assert "rule aes_yara_test" in rule
        assert "$key" in rule

    def test_vol3_export(self, lldb_dump_paths):
        from architect.static_checker import StaticChecker
        from architect.pattern_generator import PatternGenerator
        from architect.volatility3_exporter import Volatility3Exporter
        static_mask, ref = StaticChecker.check(lldb_dump_paths, 112, 64)
        pattern = PatternGenerator.generate(ref, static_mask, "aes_vol3_test", min_static_ratio=0.2)
        source = Volatility3Exporter.export(pattern)
        # Must compile as valid Python
        compile(source, "<vol3_plugin>", "exec")
        assert "PluginInterface" in source
        assert "YARA_RULE" in source

    def test_vol3_export_has_anchors_and_wildcards(self, lldb_dump_paths):
        from architect.static_checker import StaticChecker
        from architect.pattern_generator import PatternGenerator
        from architect.volatility3_exporter import Volatility3Exporter
        static_mask, ref = StaticChecker.check(lldb_dump_paths, 112, 64)
        pattern = PatternGenerator.generate(ref, static_mask, "aes_anchors", min_static_ratio=0.2)
        source = Volatility3Exporter.export(pattern)
        # FALLBACK_NEEDLE should have anchor bytes (non-empty)
        assert 'FALLBACK_NEEDLE = bytes.fromhex("")' not in source


class TestAesHeadlessPipeline:
    def test_consensus_cli(self, lldb_dump_paths, tmp_path):
        """Test memdiver consensus command."""
        out = tmp_path / "consensus.json"
        cmd = [sys.executable, "-m", "cli", "consensus"] + [str(p) for p in lldb_dump_paths] + ["-o", str(out)]
        result = subprocess.run(cmd, capture_output=True, text=True,
                                cwd=str(Path(__file__).parent.parent))
        assert result.returncode == 0, f"stderr: {result.stderr}"
        data = json.loads(out.read_text())
        assert data["num_dumps"] == len(lldb_dump_paths)
        assert len(data["volatile_regions"]) > 0

    def test_export_vol3_with_region(self, lldb_dump_paths, tmp_path):
        """Test memdiver export --format volatility3 with explicit region.

        Uses the anchor+key+anchor region (offset 112, length 64) which
        has both static anchors and volatile key bytes -- ideal for pattern
        generation with wildcards.
        """
        out = tmp_path / "plugin.py"
        cmd = [sys.executable, "-m", "cli", "export"] + [str(p) for p in lldb_dump_paths] + [
            "--offset", "112", "--length", "64",
            "--format", "volatility3", "--name", "aes_vol3",
            "--min-static-ratio", "0.1", "-o", str(out),
        ]
        result = subprocess.run(cmd, capture_output=True, text=True,
                                cwd=str(Path(__file__).parent.parent))
        assert result.returncode == 0, f"stderr: {result.stderr}"
        source = out.read_text()
        compile(source, "<vol3_plugin>", "exec")
        assert "PluginInterface" in source

    def test_export_manual_yara(self, lldb_dump_paths, tmp_path):
        """Test memdiver export with manual offset as YARA."""
        out = tmp_path / "rule.yar"
        cmd = [sys.executable, "-m", "cli", "export"] + [str(p) for p in lldb_dump_paths] + [
            "--offset", str(KEY_OFFSET), "--length", str(KEY_LENGTH),
            "--format", "yara", "--name", "aes_manual",
            "--min-static-ratio", "0.0", "-o", str(out),
        ]
        result = subprocess.run(cmd, capture_output=True, text=True,
                                cwd=str(Path(__file__).parent.parent))
        assert result.returncode == 0, f"stderr: {result.stderr}"
        content = out.read_text()
        assert "rule aes_manual" in content

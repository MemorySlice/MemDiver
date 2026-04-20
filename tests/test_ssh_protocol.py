"""Integration tests for SSH protocol support (Phase 12)."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

import pytest

from core.protocols import REGISTRY
from core.keylog import KeylogParser
from core.keylog_templates import get_template, SSH2_TEMPLATE, AUTO_DETECT_TEMPLATE
from core.discovery import DatasetScanner, RunDiscovery
from tests.fixtures.generate_fixtures import (
    generate_dataset,
    DATASET_ROOT,
    SSH2_SECRET_VALUES_BY_RUN,
)


@pytest.fixture(scope="module")
def dataset_root():
    """Ensure fixture dataset exists (with SSH data)."""
    return generate_dataset()


class TestSSHDescriptor:
    """SSH protocol descriptor registration."""

    def test_ssh_descriptor_registered(self):
        desc = REGISTRY.get("SSH")
        assert desc is not None
        assert desc.name == "SSH"

    def test_ssh_descriptor_versions(self):
        desc = REGISTRY.get("SSH")
        assert desc.versions == ["2"]

    def test_ssh_descriptor_secret_types(self):
        desc = REGISTRY.get("SSH")
        types = desc.secret_types["2"]
        assert len(types) == 4
        assert "SSH2_SESSION_KEY" in types
        assert "SSH2_SESSION_ID" in types
        assert "SSH2_ENCRYPTION_KEY_CS" in types
        assert "SSH2_ENCRYPTION_KEY_SC" in types

    def test_ssh_descriptor_dir_prefix(self):
        desc = REGISTRY.get("SSH")
        assert desc.dir_prefix == "SSH"

    def test_ssh_display_labels(self):
        desc = REGISTRY.get("SSH")
        for st in desc.secret_types["2"]:
            assert desc.get_display_label(st, "2") is not None


class TestSSHKeylog:
    """SSH keylog parsing and templates."""

    def test_ssh_keylog_parse(self, dataset_root):
        keylog_path = dataset_root / "SSH2" / "scenario_a" / "openssh" / "openssh_run_2_1" / "keylog.csv"
        secrets = KeylogParser.parse(keylog_path)
        assert len(secrets) == 4
        types = {s.secret_type for s in secrets}
        assert "SSH2_SESSION_KEY" in types

    def test_ssh_keylog_template_filter(self, dataset_root):
        keylog_path = dataset_root / "SSH2" / "scenario_a" / "openssh" / "openssh_run_2_1" / "keylog.csv"
        secrets = KeylogParser.parse(keylog_path, template=SSH2_TEMPLATE)
        assert len(secrets) == 4
        for s in secrets:
            assert s.secret_type.startswith("SSH2_")

    def test_auto_detect_includes_ssh(self):
        assert "SSH2_SESSION_KEY" in AUTO_DETECT_TEMPLATE.secret_types
        assert "SSH2_SESSION_ID" in AUTO_DETECT_TEMPLATE.secret_types

    def test_get_template_ssh(self):
        tmpl = get_template("SSH 2")
        assert tmpl is not None
        assert tmpl.name == "SSH 2"


class TestSSHDiscovery:
    """SSH dataset discovery."""

    def test_dataset_scan_finds_ssh(self, dataset_root):
        scanner = DatasetScanner(dataset_root)
        info = scanner.fast_scan()
        assert "2" in info.protocol_versions

    def test_protocols_info_populated(self, dataset_root):
        scanner = DatasetScanner(dataset_root)
        info = scanner.fast_scan()
        assert "SSH" in info.protocols_info
        assert "2" in info.protocols_info["SSH"]

    def test_protocols_info_has_tls(self, dataset_root):
        scanner = DatasetScanner(dataset_root)
        info = scanner.fast_scan()
        assert "TLS" in info.protocols_info

    def test_discover_openssh_runs(self, dataset_root):
        openssh_dir = dataset_root / "SSH2" / "scenario_a" / "openssh"
        runs = RunDiscovery.discover_library_runs(openssh_dir)
        assert len(runs) == 2
        assert len(runs[0].dumps) == 4
        assert len(runs[0].secrets) == 4
        types = {s.secret_type for s in runs[0].secrets}
        assert types == {"SSH2_SESSION_KEY", "SSH2_SESSION_ID", "SSH2_ENCRYPTION_KEY_CS", "SSH2_ENCRYPTION_KEY_SC"}
        assert runs[0].secrets[0].secret_value == SSH2_SECRET_VALUES_BY_RUN[1][runs[0].secrets[0].secret_type]


class TestSSHPipeline:
    """SSH through analysis pipeline."""

    def test_pipeline_analyze_ssh(self, dataset_root):
        from engine.pipeline import AnalysisPipeline

        pipeline = AnalysisPipeline()
        lib_dir = dataset_root / "SSH2" / "scenario_a" / "openssh"
        report = pipeline.analyze_library(
            lib_dir,
            phase="pre_handshake",
            protocol_version="2",
            max_runs=1,
        )
        assert report is not None
        assert report.library == "openssh"

    def test_constraint_validator_ssh_dispatch(self):
        from algorithms.base import AnalysisContext, Match

        try:
            from algorithms.unknown_key.constraint_validator import ConstraintValidatorAlgorithm
        except ImportError:
            pytest.skip("constraint_validator not importable (parent dir shadow)")

        validator = ConstraintValidatorAlgorithm()
        ctx = AnalysisContext(
            library="openssh",
            protocol_version="SSH2",
            phase="pre_handshake",
            secrets=[],
            extra={
                "candidates": [
                    Match(offset=0, length=32, confidence=0.5, label="test",
                          data=bytes(range(32)), metadata={}),
                    Match(offset=64, length=32, confidence=0.5, label="test2",
                          data=bytes(range(32, 64)), metadata={}),
                ],
            },
        )
        result = validator.run(bytes(512), ctx)
        assert result.algorithm_name == "constraint_validator"
        assert "protocol_version" in result.metadata

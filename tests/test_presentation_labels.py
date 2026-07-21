"""Tests for the presentation-layer label catalog and its core shim.

Verifies the presentation-separation refactor for display strings:
- the relocated catalog lives in ``memdiver.presentation.labels``,
- the old ``memdiver.core.display_labels`` location is a re-export shim
  preserving object identity,
- label values are unchanged for a representative set of codes, and
- compute packages do not import the presentation label module
  (import-direction guard).
"""
import ast
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from memdiver.core import display_labels as core_shim
from memdiver.presentation import labels as presentation_labels


# --- Shim identity ---

def test_shim_module_is_relocated_module():
    """core.display_labels is aliased to presentation.labels (same module object)."""
    assert core_shim is presentation_labels


def test_shim_get_display_label_identity():
    """get_display_label is the very same function object via both paths."""
    assert core_shim.get_display_label is presentation_labels.get_display_label


def test_shim_get_short_label_identity():
    """get_short_label is the very same function object via both paths."""
    assert core_shim.get_short_label is presentation_labels.get_short_label


def test_legacy_import_path_still_works():
    """Existing `from memdiver.core.display_labels import ...` keeps working."""
    from memdiver.core.display_labels import get_display_label, get_short_label

    assert get_display_label is presentation_labels.get_display_label
    assert get_short_label is presentation_labels.get_short_label


# --- Value equivalence (unchanged behavior) ---

def test_display_label_values_unchanged():
    """Display labels match the pre-refactor expected values."""
    expected = {
        ("CLIENT_RANDOM", "12"): "Master Secret (via CLIENT_RANDOM)",
        ("CLIENT_HANDSHAKE_TRAFFIC_SECRET", "13"): "Client Handshake Traffic Secret",
        ("SERVER_HANDSHAKE_TRAFFIC_SECRET", "13"): "Server Handshake Traffic Secret",
        ("CLIENT_TRAFFIC_SECRET_0", "13"): "Client Traffic Secret 0",
        ("SERVER_TRAFFIC_SECRET_0", "13"): "Server Traffic Secret 0",
        ("EXPORTER_SECRET", "13"): "Exporter Secret",
        ("SSH2_SESSION_KEY", "2"): "Session Key",
        ("AES256_KEY", "256"): "AES-256 Symmetric Key",
    }
    for (secret_type, version), label in expected.items():
        assert presentation_labels.get_display_label(secret_type, version) == label


def test_short_label_values_unchanged():
    """Short labels match the pre-refactor expected values."""
    expected = {
        ("CLIENT_RANDOM", "12"): "Master Secret",
        ("CLIENT_HANDSHAKE_TRAFFIC_SECRET", "13"): "Client HTS",
        ("EXPORTER_SECRET", "13"): "Exporter",
        ("SSH2_ENCRYPTION_KEY_CS", "2"): "Enc C→S",
        ("AES256_KEY", "256"): "AES-256 Key",
    }
    for (secret_type, version), label in expected.items():
        assert presentation_labels.get_short_label(secret_type, version) == label


def test_unknown_code_falls_back_to_raw_string():
    """Unknown (type, version) pairs fall back to the raw secret_type."""
    assert presentation_labels.get_display_label("UNKNOWN_TYPE", "99") == "UNKNOWN_TYPE"
    assert presentation_labels.get_short_label("UNKNOWN_TYPE", "99") == "UNKNOWN_TYPE"


# --- Import-direction guard ---

_COMPUTE_PACKAGES = ("core", "engine", "algorithms", "harvester", "architect")


def _iter_compute_py_files():
    root = Path(__file__).parent.parent
    for pkg in _COMPUTE_PACKAGES:
        pkg_dir = root / pkg
        if not pkg_dir.is_dir():
            continue
        for path in pkg_dir.rglob("*.py"):
            if "__pycache__" in path.parts:
                continue
            # The relocation shim is the one sanctioned re-export back to the
            # presentation module; it is not a compute dependency on display
            # strings, so it is exempt from the import-direction guard.
            if path.name == "display_labels.py" and path.parent.name == "core":
                continue
            yield path


def test_no_compute_module_imports_presentation_labels():
    """Compute packages must never import the presentation display-string catalog."""
    offenders = []
    for path in _iter_compute_py_files():
        source = path.read_text(encoding="utf-8")
        if "presentation.labels" not in source and "presentation import labels" not in source:
            continue
        tree = ast.parse(source, filename=str(path))
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom) and node.module:
                if node.module.endswith("presentation.labels"):
                    offenders.append(str(path))
                elif node.module.endswith("presentation") and any(
                    alias.name == "labels" for alias in node.names
                ):
                    offenders.append(str(path))
            elif isinstance(node, ast.Import):
                if any(alias.name.endswith("presentation.labels") for alias in node.names):
                    offenders.append(str(path))
    assert not offenders, (
        "Compute modules must not import presentation display strings: "
        + ", ".join(sorted(set(offenders)))
    )

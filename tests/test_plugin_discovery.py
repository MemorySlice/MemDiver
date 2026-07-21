"""Tests for the shared plugin-discovery helper and the two registries.

Covers:
  (a) the shared helper isolates a deliberately-broken subclass and still
      returns the good ones;
  (b) the algorithm + KDF registries still discover their built-ins;
  (c) a broken KDF no longer aborts KDF discovery (regression test for the
      failure-isolation fix on the KDF path).
"""

import importlib
from pathlib import Path
from types import ModuleType
from typing import List, Optional

import pytest

from memdiver.algorithms.registry import AlgorithmRegistry, get_registry
from memdiver.core import kdf_registry
from memdiver.core.kdf_base import BaseKDF, KDFParams
from memdiver.core.kdf_registry import KDFRegistry, get_kdf_registry
from memdiver.core.models import CryptoSecret
from memdiver.core.plugin_discovery import discover_subclasses


# --------------------------------------------------------------------------- #
# Fixtures: a tiny plugin hierarchy in a synthetic module.
# --------------------------------------------------------------------------- #
class _FakePluginBase:
    name = ""


class _GoodPlugin(_FakePluginBase):
    name = "good_plugin"


class _BrokenPlugin(_FakePluginBase):
    name = "broken_plugin"

    def __init__(self):
        raise RuntimeError("deliberately broken plugin")


class _UnnamedPlugin(_FakePluginBase):
    name = ""  # falsy name -> should be ignored


def _module_with(*objects) -> ModuleType:
    mod = ModuleType("memdiver._synthetic_test_module")
    for obj in objects:
        setattr(mod, obj.__name__, obj)
    return mod


# --------------------------------------------------------------------------- #
# (a) shared helper isolates a broken subclass.
# --------------------------------------------------------------------------- #
def test_discover_subclasses_isolates_broken_plugin():
    mod = _module_with(_GoodPlugin, _BrokenPlugin, _UnnamedPlugin)

    instances = discover_subclasses([mod], _FakePluginBase)

    names = {type(i).name for i in instances}
    assert names == {"good_plugin"}  # good kept, broken + unnamed dropped


def test_discover_subclasses_can_propagate_when_isolation_disabled():
    mod = _module_with(_GoodPlugin, _BrokenPlugin)

    with pytest.raises(RuntimeError):
        discover_subclasses([mod], _FakePluginBase, isolate_failures=False)


def test_discover_subclasses_last_write_wins_by_name():
    """Two plugins sharing a ``name`` -> the later module wins when keyed.

    ``discover_subclasses`` returns instances in module/attribute-scan order;
    both registries build a ``{name: instance}`` dict from that list, so the
    last-scanned plugin overrides an earlier one with the same name. This
    mirrors how an entry-point plugin can override a built-in.
    """
    class _First(_FakePluginBase):
        name = "dup"

    class _Second(_FakePluginBase):
        name = "dup"

    mod_a = _module_with(_First)
    mod_b = _module_with(_Second)

    instances = discover_subclasses([mod_a, mod_b], _FakePluginBase)
    by_name = {type(i).name: type(i) for i in instances}
    assert by_name["dup"] is _Second  # later module wins


# --------------------------------------------------------------------------- #
# (b) built-ins are still discovered.
# --------------------------------------------------------------------------- #
# The full built-in sets. Locked exactly (not just a subset) so an
# accidentally-dropped or renamed built-in plugin is caught.
_EXPECTED_ALGORITHMS = {
    "change_point",
    "constraint_validator",
    "differential",
    "entropy_scan",
    "exact_match",
    "pattern_match",
    "structure_scan",
    "user_regex",
}
_EXPECTED_KDFS = {"ssh2", "tls12_prf", "tls13_hkdf"}


def test_algorithm_registry_discovers_builtins():
    reg = AlgorithmRegistry()
    reg.discover()
    names = set(reg.names)
    assert "entropy_scan" in names
    assert "exact_match" in names


def test_algorithm_registry_discovers_all_builtins():
    reg = AlgorithmRegistry()
    reg.discover()
    assert set(reg.names) == _EXPECTED_ALGORITHMS


def test_kdf_registry_discovers_all_builtins():
    reg = KDFRegistry()
    reg.discover()
    assert {k.name for k in reg.list_all()} == _EXPECTED_KDFS


def test_algorithm_registry_singleton_has_builtins():
    names = set(get_registry().names)
    assert "entropy_scan" in names
    assert "exact_match" in names


def test_kdf_registry_discovers_builtins():
    reg = KDFRegistry()
    reg.discover()
    names = {k.name for k in reg.list_all()}
    assert "tls12_prf" in names  # a TLS KDF
    assert "ssh2" in names


def test_kdf_registry_get_for_protocol_still_works():
    reg = get_kdf_registry()
    kdf = reg.get_for_protocol("TLS", "12")
    assert kdf is not None
    assert kdf.protocol == "TLS"


# --------------------------------------------------------------------------- #
# (c) a broken KDF no longer aborts KDF discovery (regression test).
# --------------------------------------------------------------------------- #
class _BrokenKDF(BaseKDF):
    name = "broken_kdf"
    protocol = "BROKEN"
    versions = {"1"}

    def __init__(self):
        raise RuntimeError("this KDF is broken on purpose")

    def derive(self, secret: bytes, params: KDFParams) -> bytes:  # pragma: no cover
        return b""

    def expand_traffic_secret(
        self,
        secret: CryptoSecret,
        key_lengths: Optional[List[int]] = None,
        hash_algo: str = "sha256",
    ) -> List[CryptoSecret]:  # pragma: no cover
        return []

    def validate_pair(
        self,
        candidate_a: bytes,
        candidate_b: bytes,
        dump_data: bytes,
        hash_algo: str = "sha256",
        hash_candidates: Optional[List[bytes]] = None,
    ) -> float:  # pragma: no cover
        return 0.0


def test_broken_kdf_does_not_abort_discovery(monkeypatch):
    """A KDF whose __init__ raises must be skipped, not abort discovery.

    Injects a broken KDF into the registry's flat ``core/kdf_*.py`` glob (the
    real discovery path). Before the failure-isolation fix, the unguarded
    ``attr()`` call would raise and abort discovery of every KDF.
    """
    fake_stem = "kdf_zzz_broken_fake"
    fake_mod_name = f"memdiver.core.{fake_stem}"
    fake_path = Path(kdf_registry.__file__).parent / f"{fake_stem}.py"

    real_glob = Path.glob

    def fake_glob(self, pattern):
        results = list(real_glob(self, pattern))
        if pattern == "kdf_*.py":
            results.append(fake_path)
        return results

    real_import = importlib.import_module

    def fake_import(name, *args, **kwargs):
        if name == fake_mod_name:
            return _module_with(_BrokenKDF)
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(kdf_registry.Path, "glob", fake_glob)
    monkeypatch.setattr(kdf_registry.importlib, "import_module", fake_import)

    reg = KDFRegistry()
    reg.discover()  # must not raise

    names = {k.name for k in reg.list_all()}
    assert "broken_kdf" not in names  # broken one skipped
    assert "tls12_prf" in names  # good built-ins still registered

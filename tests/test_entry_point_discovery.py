"""Tests for entry-point-based plugin discovery (out-of-tree / AI-installable).

These exercise ``core.plugin_discovery.discover_entry_point_subclasses`` and its
wiring into the algorithm and KDF registries. An installed package advertises a
plugin under the ``memdiver.algorithms`` / ``memdiver.kdfs`` entry-point group;
we fake that advertisement by monkeypatching ``importlib.metadata.entry_points``
(the exact API ``plugin_discovery._select_entry_points`` calls) so no real
package install is required.

Covered:
  (a) a fake EntryPoint resolving to a BaseAlgorithm/BaseKDF subclass is
      discovered by ``discover_entry_point_subclasses``;
  (b) a fake EntryPoint resolving to a *module* exposing such a subclass is
      discovered too;
  (c) the discovered plugin surfaces through ``get_registry()`` /
      ``get_kdf_registry()``;
  (d) a genuine no-op when no entry points are advertised.
"""

from __future__ import annotations

import importlib.metadata
from types import ModuleType
from typing import List, Optional

from memdiver.algorithms import registry as alg_registry
from memdiver.algorithms.base import AlgorithmResult, AnalysisContext, BaseAlgorithm
from memdiver.algorithms.registry import (
    ALGORITHM_ENTRY_POINT_GROUP,
    AlgorithmRegistry,
    get_registry,
)
from memdiver.core import kdf_registry as kdf_registry_mod
from memdiver.core.kdf_base import BaseKDF, KDFParams
from memdiver.core.kdf_registry import (
    KDF_ENTRY_POINT_GROUP,
    KDFRegistry,
    get_kdf_registry,
)
from memdiver.core.models import CryptoSecret
from memdiver.core.plugin_discovery import discover_entry_point_subclasses


# --------------------------------------------------------------------------- #
# Dummy out-of-tree plugins.
# --------------------------------------------------------------------------- #
class _DummyEPAlgorithm(BaseAlgorithm):
    name = "dummy_ep_algo"
    description = "advertised via entry point"
    mode = ""

    def run(self, dump_data: bytes, context: AnalysisContext) -> AlgorithmResult:
        return AlgorithmResult(algorithm_name=self.name, confidence=0.0)


class _DummyEPKDF(BaseKDF):
    name = "dummy_ep_kdf"
    protocol = "DUMMY"
    versions = {"1"}

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


# --------------------------------------------------------------------------- #
# Fakes mimicking the importlib.metadata entry-point API.
# --------------------------------------------------------------------------- #
class _FakeEntryPoint:
    """Mimics ``importlib.metadata.EntryPoint``: has ``.name`` and ``.load()``."""

    def __init__(self, name: str, obj) -> None:
        self.name = name
        self._obj = obj

    def load(self):
        return self._obj


class _FakeEntryPoints:
    """Mimics the modern ``entry_points()`` result: ``.select(group=...)``."""

    def __init__(self, mapping: dict) -> None:
        self._mapping = mapping

    def select(self, group: str):
        return list(self._mapping.get(group, []))


def _install_entry_points(monkeypatch, mapping: dict) -> None:
    """Route ``importlib.metadata.entry_points()`` through a fake mapping."""
    monkeypatch.setattr(
        importlib.metadata, "entry_points", lambda: _FakeEntryPoints(mapping)
    )


def _module_exposing(*objects) -> ModuleType:
    mod = ModuleType("memdiver._synthetic_ep_module")
    for obj in objects:
        setattr(mod, obj.__name__, obj)
    return mod


# --------------------------------------------------------------------------- #
# (a)/(b) discover_entry_point_subclasses resolves classes and modules.
# --------------------------------------------------------------------------- #
def test_entry_point_resolving_to_class_is_discovered(monkeypatch):
    ep = _FakeEntryPoint("dummy_ep_algo", _DummyEPAlgorithm)
    _install_entry_points(monkeypatch, {ALGORITHM_ENTRY_POINT_GROUP: [ep]})

    instances = discover_entry_point_subclasses(
        ALGORITHM_ENTRY_POINT_GROUP, BaseAlgorithm
    )
    assert [type(i) for i in instances] == [_DummyEPAlgorithm]


def test_entry_point_resolving_to_module_is_discovered(monkeypatch):
    ep = _FakeEntryPoint("dummy_pkg", _module_exposing(_DummyEPAlgorithm))
    _install_entry_points(monkeypatch, {ALGORITHM_ENTRY_POINT_GROUP: [ep]})

    instances = discover_entry_point_subclasses(
        ALGORITHM_ENTRY_POINT_GROUP, BaseAlgorithm
    )
    assert {type(i).name for i in instances} == {"dummy_ep_algo"}


def test_kdf_entry_point_resolving_to_class_is_discovered(monkeypatch):
    ep = _FakeEntryPoint("dummy_ep_kdf", _DummyEPKDF)
    _install_entry_points(monkeypatch, {KDF_ENTRY_POINT_GROUP: [ep]})

    instances = discover_entry_point_subclasses(KDF_ENTRY_POINT_GROUP, BaseKDF)
    assert [type(i) for i in instances] == [_DummyEPKDF]


# --------------------------------------------------------------------------- #
# (c) discovered plugin surfaces through the public registry accessors.
# --------------------------------------------------------------------------- #
def test_get_registry_includes_entry_point_algorithm(monkeypatch):
    # Reset the cached singleton so discover() re-runs under our fake EPs.
    monkeypatch.setattr(alg_registry, "_registry", None, raising=True)
    ep = _FakeEntryPoint("dummy_ep_algo", _DummyEPAlgorithm)
    _install_entry_points(monkeypatch, {ALGORITHM_ENTRY_POINT_GROUP: [ep]})

    reg = get_registry()
    assert "dummy_ep_algo" in reg.names
    # Built-ins are still present alongside the entry-point plugin.
    assert "entropy_scan" in reg.names


def test_get_kdf_registry_includes_entry_point_kdf(monkeypatch):
    monkeypatch.setattr(kdf_registry_mod, "_registry", None, raising=True)
    ep = _FakeEntryPoint("dummy_ep_kdf", _DummyEPKDF)
    _install_entry_points(monkeypatch, {KDF_ENTRY_POINT_GROUP: [ep]})

    reg = get_kdf_registry()
    names = {k.name for k in reg.list_all()}
    assert "dummy_ep_kdf" in names
    assert "tls12_prf" in names


# --------------------------------------------------------------------------- #
# (d) genuine no-op when nothing is advertised.
# --------------------------------------------------------------------------- #
def test_no_entry_points_is_a_noop(monkeypatch):
    _install_entry_points(monkeypatch, {})  # nothing advertised in any group

    assert discover_entry_point_subclasses(ALGORITHM_ENTRY_POINT_GROUP, BaseAlgorithm) == []
    assert discover_entry_point_subclasses(KDF_ENTRY_POINT_GROUP, BaseKDF) == []


def test_registry_without_entry_points_has_only_builtins(monkeypatch):
    monkeypatch.setattr(alg_registry, "_registry", None, raising=True)
    _install_entry_points(monkeypatch, {})

    reg = AlgorithmRegistry()
    reg.discover()
    assert "dummy_ep_algo" not in reg.names
    assert "entropy_scan" in reg.names


def test_kdf_registry_without_entry_points_has_only_builtins(monkeypatch):
    _install_entry_points(monkeypatch, {})

    reg = KDFRegistry()
    reg.discover()
    names = {k.name for k in reg.list_all()}
    assert "dummy_ep_kdf" not in names
    assert "ssh2" in names

"""Regression tests: a plugin module that fails AT IMPORT TIME with a
non-ImportError must not abort discovery of the other plugins.

The existing "broken plugin" tests (test_plugin_discovery/test_algorithms) only
exercise *instantiation* failure — they monkeypatch import_module to return a
prebuilt fake module, so the import itself never raises. A critical audit found
that both registries' import loops originally caught only ``ImportError``, so a
module raising e.g. ``NameError``/``SyntaxError`` at import propagated out of
``discover()`` and crashed the whole registry. These tests lock the broadened
``except Exception`` isolation in place.
"""
from __future__ import annotations

import memdiver.algorithms.registry as algo_reg
import memdiver.core.kdf_registry as kdf_reg


def test_algorithm_import_failure_is_isolated(monkeypatch):
    """A non-ImportError at import of one algorithm module still leaves the rest."""
    real_import = algo_reg.importlib.import_module
    state = {"poisoned": False}

    def flaky_import(name, *args, **kwargs):
        # Poison the first LEAF module import (>= 3 dots, e.g.
        # memdiver.algorithms.unknown_key.entropy_scan), not the subpackage
        # imports — this targets the per-module discovery loop specifically.
        if not state["poisoned"] and name.count(".") >= 3:
            state["poisoned"] = True
            raise NameError("simulated broken algorithm module")
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(algo_reg.importlib, "import_module", flaky_import)

    registry = algo_reg.AlgorithmRegistry()
    registry.discover()  # must NOT raise NameError

    # The poison actually fired, and the remaining built-ins still register.
    assert state["poisoned"]
    assert len(registry._algorithms) > 0


def test_kdf_import_failure_is_isolated(monkeypatch):
    """A non-ImportError at import of one KDF module still leaves the rest."""
    real_import = kdf_reg.importlib.import_module
    state = {"n": 0}

    def flaky_import(name, *args, **kwargs):
        state["n"] += 1
        if state["n"] == 1:
            raise NameError("simulated broken KDF module")
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(kdf_reg.importlib, "import_module", flaky_import)

    registry = kdf_reg.KDFRegistry()
    registry.discover()  # must NOT raise NameError

    assert len(registry._kdfs) > 0

"""Out-of-tree verification resources: the ``memdiver.oracles`` entry-point group.

``engine/resources/builtin_oracle.py`` keeps a registry of resource-type
factories (``resource_type = "tls-pcap"`` today) that the brute-force / N-sweep
pipelines select through an oracle config. An installed third-party package can
now add its own by advertising an entry point under ``memdiver.oracles``, the
register-call shape already used by ``memdiver.dump_sources`` — the entry point
resolves to a module (imported for its ``register_resource_type`` side effect)
or to a callable (invoked to self-register).

We fake the advertisement by monkeypatching ``importlib.metadata.entry_points``
— the exact API ``plugin_discovery._select_entry_points`` calls — so no real
package install is required; this mirrors ``tests/test_entry_point_discovery.py``
for the subclass-based groups. A module-shaped fake performs its registration
inside ``.load()``, because that is precisely when a real plugin module's
import-time side effect fires.

What this module pins, in order:

* a callable- and a module-shaped entry point both register a usable type,
* one broken plugin never aborts discovery of the rest,
* an empty group is a genuine no-op (byte-identical behaviour with nothing
  installed), and discovery is lazy + at-most-once,
* **the sandboxing provenance rule** — an entry-point-registered resource type
  is NOT first-party, so it never inherits the ``oracle_trusted=True`` /
  ``sandbox=False`` exemption that the in-tree pcap resource enjoys. Without
  that rule, ``pip install some-package`` would be enough to get a plugin's
  import and ``build_oracle`` executed outside the untrusted-code sandbox, in
  this process and in every brute-force worker.
"""

from __future__ import annotations

import importlib.metadata
import logging
from pathlib import Path
from types import ModuleType
from unittest.mock import patch

import pytest

from memdiver.app import tools_pipeline as tp
from memdiver.engine.resources import builtin_oracle


# --------------------------------------------------------------------------- #
# A dummy out-of-tree resource + the fakes mimicking importlib.metadata.
# --------------------------------------------------------------------------- #
class _DummyResource:
    """Stands in for a VerificationResource; only construction is exercised."""

    def __init__(self, config: dict) -> None:
        self.config = config


def _dummy_factory(config: dict) -> _DummyResource:
    return _DummyResource(config)


def _register_dummy(name: str = "dummy-ep-resource"):
    """Return a zero-arg registration callable for *name*."""

    def _register() -> None:
        builtin_oracle.register_resource_type(name, _dummy_factory)

    return _register


class _FakeEntryPoint:
    """Mimics ``importlib.metadata.EntryPoint``: has ``.name`` and ``.load()``.

    ``obj`` is what ``.load()`` returns — a callable for the callable shape, or
    anything else to exercise the "did not resolve" branch.
    """

    def __init__(self, name: str, obj) -> None:
        self.name = name
        self._obj = obj

    def load(self):
        return self._obj


class _FakeModuleEntryPoint:
    """A module-shaped entry point.

    ``.load()`` runs *register* and then returns a module object, because a real
    plugin module registers at import time and ``.load()`` IS the import.
    """

    def __init__(self, name: str, register) -> None:
        self.name = name
        self._register = register

    def load(self) -> ModuleType:
        self._register()
        return ModuleType("memdiver._synthetic_oracle_plugin")


class _ExplodingEntryPoint:
    """An entry point whose module fails to import."""

    name = "broken_plugin"

    def load(self):
        raise ImportError("no module named 'definitely_not_installed'")


class _FakeEntryPoints:
    """Mimics the modern ``entry_points()`` result: ``.select(group=...)``."""

    def __init__(self, mapping: dict) -> None:
        self._mapping = mapping
        self.select_calls = 0

    def select(self, group: str):
        self.select_calls += 1
        return list(self._mapping.get(group, []))


@pytest.fixture
def advertise(monkeypatch):
    """Advertise entry points and isolate the resource registry.

    Returns a callable taking the ``memdiver.oracles`` entry-point list. The
    registry dicts and both module flags are restored afterwards, and
    ``_ENTRY_POINTS_LOADED`` is cleared up front so discovery actually re-runs
    under the fake — the flag is a process-lifetime latch by design.
    """
    factories = dict(builtin_oracle.RESOURCE_FACTORIES)
    provenance = dict(builtin_oracle.RESOURCE_TYPE_PROVENANCE)
    monkeypatch.setattr(builtin_oracle, "_ENTRY_POINTS_LOADED", False)
    monkeypatch.setattr(builtin_oracle, "_LOADING_ENTRY_POINTS", False)

    def _advertise(entry_points: list) -> _FakeEntryPoints:
        fake = _FakeEntryPoints({builtin_oracle.ORACLE_ENTRY_POINT_GROUP: entry_points})
        monkeypatch.setattr(importlib.metadata, "entry_points", lambda: fake)
        return fake

    try:
        yield _advertise
    finally:
        builtin_oracle.RESOURCE_FACTORIES.clear()
        builtin_oracle.RESOURCE_FACTORIES.update(factories)
        builtin_oracle.RESOURCE_TYPE_PROVENANCE.clear()
        builtin_oracle.RESOURCE_TYPE_PROVENANCE.update(provenance)


# --------------------------------------------------------------------------- #
# (a) both entry-point shapes register a constructible resource type.
# --------------------------------------------------------------------------- #
def test_callable_entry_point_registers_a_usable_resource_type(advertise):
    advertise([_FakeEntryPoint("dummy_plugin", _register_dummy())])

    resource = builtin_oracle.build_resource(
        {"resource_type": "dummy-ep-resource", "answer": 42}
    )

    assert isinstance(resource, _DummyResource)
    assert resource.config["answer"] == 42


def test_module_entry_point_registers_a_usable_resource_type(advertise):
    advertise([_FakeModuleEntryPoint("dummy_pkg", _register_dummy())])

    resource = builtin_oracle.build_resource({"resource_type": "dummy-ep-resource"})

    assert isinstance(resource, _DummyResource)


def test_entry_point_types_coexist_with_the_builtin(advertise):
    """Additive: the built-in ``tls-pcap`` survives out-of-tree discovery."""
    advertise([_FakeEntryPoint("dummy_plugin", _register_dummy())])

    builtin_oracle.build_resource({"resource_type": "dummy-ep-resource"})

    assert "tls-pcap" in builtin_oracle.RESOURCE_FACTORIES
    assert "dummy-ep-resource" in builtin_oracle.RESOURCE_FACTORIES


# --------------------------------------------------------------------------- #
# (b) per-plugin failure isolation: one bad plugin cannot break the others.
# --------------------------------------------------------------------------- #
def test_broken_entry_point_is_logged_and_skipped(advertise, caplog):
    """A plugin that fails to import is skipped; the healthy one still loads."""
    advertise([
        _ExplodingEntryPoint(),
        _FakeEntryPoint("dummy_plugin", _register_dummy()),
    ])

    with caplog.at_level(logging.WARNING):
        resource = builtin_oracle.build_resource({"resource_type": "dummy-ep-resource"})

    assert isinstance(resource, _DummyResource)
    assert "broken_plugin" in caplog.text


def test_entry_point_raising_on_invocation_is_logged_and_skipped(advertise, caplog):
    """Same isolation for a callable that raises *while* self-registering."""

    def _boom() -> None:
        raise RuntimeError("plugin registration exploded")

    advertise([
        _FakeEntryPoint("angry_plugin", _boom),
        _FakeEntryPoint("dummy_plugin", _register_dummy()),
    ])

    with caplog.at_level(logging.WARNING):
        resource = builtin_oracle.build_resource({"resource_type": "dummy-ep-resource"})

    assert isinstance(resource, _DummyResource)
    assert "angry_plugin" in caplog.text
    # The failing plugin registered nothing, and did not leave the loading flag
    # stuck (which would demote the next first-party registration).
    assert builtin_oracle._LOADING_ENTRY_POINTS is False


# --------------------------------------------------------------------------- #
# (c) nothing installed => nothing changes; discovery is lazy and runs once.
# --------------------------------------------------------------------------- #
def test_empty_group_is_a_noop(advertise):
    """No entry points advertised => byte-identical registry and provenance."""
    advertise([])
    before = dict(builtin_oracle.RESOURCE_FACTORIES)

    builtin_oracle.build_resource({"resource_type": "tls-pcap", "pcap": "/c/x.pcap"})

    assert builtin_oracle.RESOURCE_FACTORIES == before
    assert (
        builtin_oracle.RESOURCE_TYPE_PROVENANCE["tls-pcap"]
        == builtin_oracle.PROVENANCE_FIRST_PARTY
    )


def test_discovery_runs_at_most_once(advertise):
    """The latch holds: repeated builds do not re-scan the entry points."""
    fake = advertise([_FakeEntryPoint("dummy_plugin", _register_dummy())])

    builtin_oracle.build_resource({"resource_type": "dummy-ep-resource"})
    builtin_oracle.build_resource({"resource_type": "dummy-ep-resource"})

    assert fake.select_calls == 1


def test_importing_the_module_does_not_load_entry_points():
    """Discovery is lazy: importing ``builtin_oracle`` must not scan anything.

    Import-time discovery would drag every installed plugin into every process
    that merely wants ``BUILTIN_ORACLE_PATH``, so the module ships with the
    latch clear and only the built-in registered. Asked in a FRESH interpreter
    rather than by reloading in-process: this test's whole subject is what a
    bare import does, and a reload would answer for a module the rest of the
    suite has already touched.
    """
    import subprocess
    import sys

    probe = (
        "import memdiver.engine.resources.builtin_oracle as m; "
        "print(m._ENTRY_POINTS_LOADED, m._LOADING_ENTRY_POINTS, "
        "sorted(m.RESOURCE_TYPE_PROVENANCE.items()))"
    )
    out = subprocess.run(
        [sys.executable, "-c", probe],
        capture_output=True, text=True, check=True,
    ).stdout.strip()

    assert out == "False False [('tls-pcap', 'first-party')]"


def test_unknown_resource_type_still_raises_after_discovery(advertise):
    """The unknown-type error is unchanged, and now lists plugin types too."""
    advertise([_FakeEntryPoint("dummy_plugin", _register_dummy())])

    with pytest.raises(ValueError) as excinfo:
        builtin_oracle.build_resource({"resource_type": "nope"})

    assert "unknown resource_type 'nope'" in str(excinfo.value)
    assert "dummy-ep-resource" in str(excinfo.value)


# --------------------------------------------------------------------------- #
# (d) THE SANDBOXING PROVENANCE RULE.
# --------------------------------------------------------------------------- #
def test_entry_point_resource_type_is_not_first_party(advertise):
    """The load-bearing assertion: an installed plugin is never first-party."""
    advertise([_FakeEntryPoint("dummy_plugin", _register_dummy())])

    assert builtin_oracle.is_first_party_resource_type("dummy-ep-resource") is False
    assert builtin_oracle.is_first_party_resource_type("tls-pcap") is True
    assert (
        builtin_oracle.RESOURCE_TYPE_PROVENANCE["dummy-ep-resource"]
        == builtin_oracle.PROVENANCE_ENTRY_POINT
    )


def test_plugin_cannot_claim_first_party_provenance(advertise):
    """Provenance is derived from HOW registration happened, not from the caller.

    ``register_resource_type`` takes no provenance argument, so a plugin cannot
    spell its own trust level: registering from inside the discovery window is
    entry-point provenance, full stop.
    """
    advertise([_FakeEntryPoint("sneaky_plugin", _register_dummy("sneaky"))])

    assert builtin_oracle.is_first_party_resource_type("sneaky") is False


def test_unknown_resource_type_is_not_first_party(advertise):
    """Fails closed: an unregistered name is never granted the exemption."""
    advertise([])

    assert builtin_oracle.is_first_party_resource_type("never-registered") is False
    assert builtin_oracle.is_first_party_resource_type("") is False


def test_entry_point_shadowing_the_builtin_loses_the_exemption(advertise, caplog):
    """A plugin registering ``tls-pcap`` demotes it, loudly, rather than
    inheriting the built-in's trusted-load privilege."""
    advertise([_FakeEntryPoint("shadow_plugin", _register_dummy("tls-pcap"))])

    with caplog.at_level(logging.WARNING):
        assert builtin_oracle.is_first_party_resource_type("tls-pcap") is False

    assert "shadows the first-party factory" in caplog.text


def test_producer_trust_predicate_follows_provenance(advertise):
    """``tools_pipeline._pcap_oracle_trusted`` is the one trust decision, and it
    answers from provenance rather than from "is there a pcap in the config"."""
    advertise([_FakeEntryPoint("dummy_plugin", _register_dummy())])

    first_party = tp._pcap_oracle_config("/c/session.pcap", None, None, None)
    out_of_tree = tp._pcap_oracle_config(
        "/c/session.pcap", None, None, None, resource_type="dummy-ep-resource"
    )

    assert tp._pcap_oracle_trusted(first_party) is True
    assert tp._pcap_oracle_trusted(out_of_tree) is False


def test_brute_force_withholds_oracle_trusted_from_an_entry_point_resource(advertise):
    """END TO END on the hazard: ``run_brute_force`` must not be handed
    ``oracle_trusted=True`` for an out-of-tree resource type.

    The producer builds its own config with the default ``tls-pcap``, so the
    realistic way a plugin reaches this path is by shadowing that name — which
    is exactly the arbitrary-code-execution route the provenance rule closes.
    ``oracle_trusted=False`` sends the load back through
    ``validate_oracle_sandboxed``.
    """
    advertise([_FakeEntryPoint("shadow_plugin", _register_dummy("tls-pcap"))])
    captured: dict = {}

    def _capture(*_args, **kwargs):
        captured.update(kwargs)
        raise RuntimeError("stop once the oracle kwargs are captured")

    with patch("memdiver.engine.brute_force.run_brute_force", _capture), \
            patch.object(tp, "_read_reference_bytes", return_value=b""):
        with pytest.raises(RuntimeError):
            tp.brute_force(
                candidates_path="/c/candidates.json",
                reference_path="/c/ref.bin",
                output_dir="/c/out",
                pcap_path="/c/session.pcap",
            )

    assert captured["oracle_trusted"] is False


def test_brute_force_keeps_oracle_trusted_for_the_builtin_resource(advertise):
    """REGRESSION guard on the same wiring: with nothing installed, the
    first-party pcap resource keeps today's trusted load (sandboxing a large
    capture's parse would misread a slow parse as a hang)."""
    advertise([])
    captured: dict = {}

    def _capture(*_args, **kwargs):
        captured.update(kwargs)
        raise RuntimeError("stop once the oracle kwargs are captured")

    with patch("memdiver.engine.brute_force.run_brute_force", _capture), \
            patch.object(tp, "_read_reference_bytes", return_value=b""):
        with pytest.raises(RuntimeError):
            tp.brute_force(
                candidates_path="/c/candidates.json",
                reference_path="/c/ref.bin",
                output_dir="/c/out",
                pcap_path="/c/session.pcap",
            )

    assert captured["oracle_trusted"] is True
    assert captured["oracle_config"]["resource_type"] == "tls-pcap"


def _capture_nsweep_load_oracle(tmp_path) -> dict:
    """Run ``n_sweep`` far enough to record how it loaded its oracle."""
    source = tmp_path / "dump.bin"
    source.write_bytes(bytes(1024))
    captured: dict = {}

    def _fake_load(path, config=None, **kw):
        captured["path"] = Path(path)
        captured["kwargs"] = dict(kw)
        raise RuntimeError("stop once the load arguments are captured")

    with patch("memdiver.engine.oracle.load_oracle", _fake_load):
        with pytest.raises(RuntimeError):
            tp.n_sweep(
                source_paths=[str(source)],
                output_dir=str(tmp_path / "out"),
                n_values=[1],
                pcap_path="/c/session.pcap",
            )
    return captured


def test_nsweep_sandboxes_an_entry_point_resource(advertise, tmp_path):
    """The N-sweep surface applies the SAME rule as ``brute_force``: an
    out-of-tree resource type is loaded with the sandbox on."""
    advertise([_FakeEntryPoint("shadow_plugin", _register_dummy("tls-pcap"))])

    captured = _capture_nsweep_load_oracle(tmp_path)

    assert captured["kwargs"]["sandbox"] is True


def test_nsweep_keeps_the_trusted_load_for_the_builtin_resource(advertise, tmp_path):
    """REGRESSION: nothing installed => the pcap oracle still loads unsandboxed."""
    advertise([])

    captured = _capture_nsweep_load_oracle(tmp_path)

    assert captured["kwargs"]["sandbox"] is False


# --------------------------------------------------------------------------- #
# (e) the de-hardcoded resource type.
# --------------------------------------------------------------------------- #
def test_pcap_oracle_config_resource_type_defaults_to_tls_pcap():
    """Zero behaviour change: the default is the literal it replaced."""
    config = tp._pcap_oracle_config("/c/session.pcap", None, None, None)

    assert config == {"resource_type": "tls-pcap", "pcap": "/c/session.pcap"}


def test_pcap_oracle_config_honours_an_explicit_resource_type():
    config = tp._pcap_oracle_config(
        "/c/session.pcap", "aa" * 32, 4, 32, resource_type="other-resource"
    )

    assert config["resource_type"] == "other-resource"
    # The rest of the spec is assembled exactly as before.
    assert config["client_random"] == "aa" * 32
    assert config["max_records_per_direction"] == 4
    assert config["max_challenges"] == 32

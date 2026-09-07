"""First-party builtin oracle: build a ResourceOracle from a resource spec.

Exposes the Shape-2 ``build_oracle(config) -> Oracle`` entry point the existing
oracle loader (:mod:`memdiver.engine.oracle`) already understands, so a pcap
(and, later, other) verification resource plugs into the brute-force pipeline
with **no engine changes** and without the user writing Python. This is
first-party/trusted code — the pcap it reads is data, not code — so callers may
load it with the untrusted-code sandbox disabled.

Config keys (from the oracle TOML file or an in-process dict):

    resource_type = "tls-pcap"   # the only built-in type; extensible below
                                 # (in-tree, or out-of-tree via the
                                 # "memdiver.oracles" entry-point group)
    pcap = "/path/to/capture.pcap"
    client_random = "<hex>"      # optional: restrict to one TLS session
    max_records_per_direction = 16   # optional; must be >= 1 when present
    max_challenges = 64              # optional cap on total challenges tried; >= 1
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any, Callable, Dict, Optional, Tuple

from memdiver.engine.resources.oracle import ResourceOracle

logger = logging.getLogger(__name__)

# Absolute path to this module — the "oracle_path" a surface points at to select
# the builtin resource oracle instead of a user script.
BUILTIN_ORACLE_PATH = str(Path(__file__).resolve())

# Registry of resource-type factories: name -> (config -> VerificationResource).
# New resource kinds (e.g. an encrypted-file resource) register here.
RESOURCE_FACTORIES: Dict[str, Callable[[dict], Any]] = {}

#: Provenance labels for a registered resource type. First-party means the
#: factory ships in this repository (reviewed code, loaded from our own
#: package); entry-point means it arrived from an out-of-tree package
#: advertising :data:`ORACLE_ENTRY_POINT_GROUP`.
PROVENANCE_FIRST_PARTY = "first-party"
PROVENANCE_ENTRY_POINT = "entry-point"

#: Provenance of every registered resource type: name -> provenance label.
#: Parallel to :data:`RESOURCE_FACTORIES` and written by the same function, so a
#: factory can never be registered without its provenance being recorded.
RESOURCE_TYPE_PROVENANCE: Dict[str, str] = {}

#: True only while :func:`_load_entry_point_oracles_once` is running. Every
#: registration that happens inside that window is out-of-tree BY CONSTRUCTION,
#: so provenance is derived from this flag rather than from an argument the
#: registering package controls — a third-party factory must not be able to
#: label itself first-party (see :func:`is_first_party_resource_type` for why
#: that label is security-relevant).
_LOADING_ENTRY_POINTS = False


def register_resource_type(name: str, factory: Callable[[dict], Any]) -> None:
    """Register a resource-type factory under *name*.

    Provenance is recorded alongside the factory (first-party for an in-tree
    registration, entry-point for one made while out-of-tree discovery is
    running) and is NOT a parameter: the caller does not get to declare its own
    trust level. See :func:`is_first_party_resource_type`.
    """
    provenance = (
        PROVENANCE_ENTRY_POINT if _LOADING_ENTRY_POINTS else PROVENANCE_FIRST_PARTY
    )
    if (
        _LOADING_ENTRY_POINTS
        and RESOURCE_TYPE_PROVENANCE.get(name) == PROVENANCE_FIRST_PARTY
    ):
        # An out-of-tree package replacing a built-in type is allowed (the dict
        # has always been last-write-wins) but never silently: the replacement
        # is also demoted to entry-point provenance below, so the shadowed name
        # loses its trusted-load privilege. Say so, or a sandboxed-and-slower
        # pcap oracle would look like an unexplained regression.
        logger.warning(
            "Entry-point resource type %r shadows the first-party factory of "
            "the same name; it will be loaded sandboxed as out-of-tree code.",
            name,
        )
    RESOURCE_FACTORIES[name] = factory
    RESOURCE_TYPE_PROVENANCE[name] = provenance


def is_first_party_resource_type(name: str) -> bool:
    """True only when *name*'s factory is first-party (in-tree) code.

    THE trust predicate for the resource registry, and the reason provenance is
    tracked at all. A caller that builds one of these resources may skip the
    untrusted-code load sandbox (``oracle_trusted=True`` /
    ``load_oracle(sandbox=False)``) — justified for our own module reading a
    pcap, which is data rather than executable, and necessary because
    sandboxing a large-capture parse under the tight wall-clock/memory caps
    would misclassify a slow parse as a hang.

    An entry-point factory gets NO such exemption. Inheriting it would turn
    "pip install some-package" into arbitrary code execution outside the
    sandbox, purely because a resource spec named that package's type.

    Unknown names answer ``False`` — fail closed; :func:`build_resource` then
    raises the unknown-type ``ValueError`` on its own.
    """
    _load_entry_point_oracles_once()
    return RESOURCE_TYPE_PROVENANCE.get(name) == PROVENANCE_FIRST_PARTY


def registered_resource_types() -> Tuple[str, ...]:
    """Every resource type this process can build, sorted, out-of-tree included.

    Triggers the same one-time entry-point discovery :func:`build_resource`
    does, so the answer is the LIVE registry rather than the built-ins alone.
    That matters for the caller this exists for: protocol detection reports
    whether anything installed can decrypt what a capture holds, and reading a
    hardcoded list would tell a user with a third-party oracle installed that
    their protocol is undecryptable.
    """
    _load_entry_point_oracles_once()
    return tuple(sorted(RESOURCE_FACTORIES))


def is_registered_resource_type(name: str) -> bool:
    """True when *name* names a resource type this process can build.

    Deliberately NOT the trust predicate -- see
    :func:`is_first_party_resource_type` for that. This one answers "could a
    resource of this type be constructed at all", which is what "decryptable"
    means in a protocol-detection report; an out-of-tree factory answers True
    here and False there, and both answers are correct.
    """
    _load_entry_point_oracles_once()
    return name in RESOURCE_FACTORIES


def _require_positive_cap(
    name: str, value: Any, *, allow_none: bool = True
) -> Optional[int]:
    """Return *value* as an int cap, refusing anything below 1.

    THE ONE PLACE the bound and the wording live for this layer, so the record
    cap and the challenge cap cannot drift apart -- they are the same mistake
    with two spellings. Both are ``is not None`` checks, NOT truthiness tests:
    under a truthiness test a cap of ``0`` is falsy and silently becomes
    "uncapped" -- the exact opposite of what the caller asked -- while a
    negative cap sails through into a ``[:cap]`` slice, dropping the tail of the
    list and logging the nonsense "truncated 37 challenges to -1".

    Neither is reinterpreted here, because a cap below 1 verifies nothing and
    can therefore only ever turn a real key into an unexplained "0 confirmed"
    from a run that looks successful. ``None`` keeps its meaning -- "no cap
    supplied", leave the default alone -- and passes straight through.

    ``allow_none=False`` is for a caller whose parameter is annotated ``int``
    with a real default rather than ``Optional[int]``: there "no cap supplied"
    is spelled by omitting the argument, so an explicit ``None`` is a caller
    bug, and passing it through would only defer the failure to the
    ``emitted < cap`` comparison as an unrelated ``TypeError`` deep inside
    record emission.

    ``ValueError`` matches the unknown-``resource_type`` raise below. The shared
    producer layer (``app.tools_pipeline._validate_pcap_caps``) rejects the same
    two caps as a typed ``CapabilityError`` so every surface reports it the same
    way, and this message is worded identically to that one; but a
    config-file-driven oracle (an ``oracle.toml`` handed to the oracle loader)
    never passes through a producer, so this layer must not depend on that
    guard.
    """
    if value is None:
        if not allow_none:
            raise ValueError(
                f"{name} must be an int >= 1; None is not a cap here -- omit "
                f"the argument to keep the default."
            )
        return None
    cap = int(value)
    if cap < 1:
        raise ValueError(
            f"{name} must be >= 1 (got {value}); omit it to keep "
            f"the default. A cap below 1 verifies nothing, so a real key "
            f"would be reported as unconfirmed."
        )
    return cap


def _tls_pcap_factory(config: dict) -> Any:
    # Imported lazily so the (optional) dpkt dependency is only required when a
    # pcap resource is actually requested.
    from memdiver.engine.resources.tls_pcap import TlsPcapResource

    pcap = config.get("pcap")
    if not pcap:
        raise ValueError("tls-pcap resource requires a 'pcap' path in config")
    cr_hex = config.get("client_random")
    client_random = bytes.fromhex(cr_hex) if cr_hex else None
    kwargs: Dict[str, Any] = {}
    # Validated on the way in, not merely converted: a bare ``int(...)`` here
    # let ``max_records_per_direction = 0`` reach the resource, which then
    # emitted zero records, which reports a real key as "0 confirmed".
    if config.get("max_records_per_direction") is not None:
        kwargs["max_records_per_direction"] = _require_positive_cap(
            "max_records_per_direction", config["max_records_per_direction"]
        )
    # ``max_challenges`` is ENFORCED by ``ResourceOracle`` (it caps the flat
    # challenge list, across sessions) but handed to the resource too, so
    # ``describe_capture`` reports the cap actually in force for this config
    # rather than only the record cap. Passing it here cannot double-cap: the
    # resource stores it for reporting and never applies it when emitting.
    if config.get("max_challenges") is not None:
        kwargs["max_challenges"] = int(config["max_challenges"])
    return TlsPcapResource(pcap, client_random=client_random, **kwargs)


register_resource_type("tls-pcap", _tls_pcap_factory)


#: Entry-point group under which out-of-tree packages advertise verification
#: resources. Each advertised entry point is a module (imported for its
#: ``register_resource_type`` side effects) or a callable (invoked to
#: self-register) — the same register-call shape as ``memdiver.dump_sources``.
ORACLE_ENTRY_POINT_GROUP = "memdiver.oracles"

#: Guards one-time out-of-tree discovery so it runs at most once, adding zero
#: overhead to normal :func:`build_resource` calls.
_ENTRY_POINTS_LOADED = False


def _load_entry_point_oracles_once() -> None:
    """Load out-of-tree verification resources exactly once, after the built-ins.

    Additive and failure-isolated: a silent no-op when nothing is installed.
    Deliberately NOT called at import time (unlike ``core.dump_source``, which
    has to answer format detection from a cold registry): this module is
    imported by every brute-force run that merely needs
    :data:`BUILTIN_ORACLE_PATH`, so discovery is deferred to the first actual
    :func:`build_resource` call.

    :data:`_LOADING_ENTRY_POINTS` is held for the whole pass so every
    registration it triggers is recorded as out-of-tree, and released in a
    ``finally`` so a plugin that raises cannot leave the flag set and demote a
    later first-party registration.
    """
    global _ENTRY_POINTS_LOADED, _LOADING_ENTRY_POINTS  # noqa: PLW0603
    if _ENTRY_POINTS_LOADED:
        return
    _ENTRY_POINTS_LOADED = True
    from memdiver.core.plugin_discovery import load_entry_point_registrations
    _LOADING_ENTRY_POINTS = True
    try:
        load_entry_point_registrations(ORACLE_ENTRY_POINT_GROUP)
    finally:
        _LOADING_ENTRY_POINTS = False


def build_resource(config: Optional[dict]) -> Any:
    """Construct the VerificationResource named by ``config['resource_type']``.

    Out-of-tree resource types (:data:`ORACLE_ENTRY_POINT_GROUP`) are discovered
    here, lazily and once, so an installed plugin's type resolves without the
    caller doing anything — and a type resolved this way is reported as
    non-first-party by :func:`is_first_party_resource_type`.
    """
    _load_entry_point_oracles_once()
    config = config or {}
    rtype = config.get("resource_type", "tls-pcap")
    factory = RESOURCE_FACTORIES.get(rtype)
    if factory is None:
        raise ValueError(
            f"unknown resource_type {rtype!r}; known: {sorted(RESOURCE_FACTORIES)}"
        )
    return factory(config)


def build_oracle(config: Optional[dict]) -> ResourceOracle:
    """Oracle-loader Shape-2 entry point: config -> ResourceOracle."""
    config = config or {}
    resource = build_resource(config)
    # Both caps are rejected below 1, by the same helper, for the same reason --
    # see :func:`_require_positive_cap`. The record cap is checked inside the
    # tls-pcap factory (it is a resource parameter); this one is checked here
    # because ``max_challenges`` is the oracle's own, enforced by
    # :class:`ResourceOracle` for every resource type.
    max_challenges = _require_positive_cap("max_challenges", config.get("max_challenges"))
    return ResourceOracle(resource, max_challenges=max_challenges)

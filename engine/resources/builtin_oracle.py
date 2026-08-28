"""First-party builtin oracle: build a ResourceOracle from a resource spec.

Exposes the Shape-2 ``build_oracle(config) -> Oracle`` entry point the existing
oracle loader (:mod:`memdiver.engine.oracle`) already understands, so a pcap
(and, later, other) verification resource plugs into the brute-force pipeline
with **no engine changes** and without the user writing Python. This is
first-party/trusted code — the pcap it reads is data, not code — so callers may
load it with the untrusted-code sandbox disabled.

Config keys (from the oracle TOML file or an in-process dict):

    resource_type = "tls-pcap"   # the only type today; extensible below
    pcap = "/path/to/capture.pcap"
    client_random = "<hex>"      # optional: restrict to one TLS session
    max_records_per_direction = 16   # optional; must be >= 1 when present
    max_challenges = 64              # optional cap on total challenges tried; >= 1
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Callable, Dict, Optional

from memdiver.engine.resources.oracle import ResourceOracle

# Absolute path to this module — the "oracle_path" a surface points at to select
# the builtin resource oracle instead of a user script.
BUILTIN_ORACLE_PATH = str(Path(__file__).resolve())

# Registry of resource-type factories: name -> (config -> VerificationResource).
# New resource kinds (e.g. an encrypted-file resource) register here.
RESOURCE_FACTORIES: Dict[str, Callable[[dict], Any]] = {}


def register_resource_type(name: str, factory: Callable[[dict], Any]) -> None:
    """Register a resource-type factory under *name*."""
    RESOURCE_FACTORIES[name] = factory


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


def build_resource(config: Optional[dict]) -> Any:
    """Construct the VerificationResource named by ``config['resource_type']``."""
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

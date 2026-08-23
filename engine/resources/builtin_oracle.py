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
    max_records_per_direction = 16   # optional
    max_challenges = 64              # optional cap on total challenges tried
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
    if config.get("max_records_per_direction") is not None:
        kwargs["max_records_per_direction"] = int(config["max_records_per_direction"])
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
    raw_cap = config.get("max_challenges")
    max_challenges = int(raw_cap) if raw_cap else None
    return ResourceOracle(resource, max_challenges=max_challenges)

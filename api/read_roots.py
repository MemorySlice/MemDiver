"""Re-export shim: the sandbox read/write roots now live in :mod:`memdiver.core.sandbox_roots`.

Kept so ``memdiver.api.read_roots.{configured_roots, dynamic_roots,
sandbox_roots, write_roots}`` keep working for REST code and tests; the MCP
guard imports the core module directly (no MCP -> REST dependency).
"""

from __future__ import annotations

from memdiver.core.sandbox_roots import (
    configured_roots,
    dynamic_roots,
    sandbox_roots,
    write_roots,
)

__all__ = ["configured_roots", "dynamic_roots", "sandbox_roots", "write_roots"]

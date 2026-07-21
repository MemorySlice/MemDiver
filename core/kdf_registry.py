"""Auto-discovery registry for KDF (Key Derivation Function) plugins.

Mirrors the algorithm plugin pattern in algorithms/registry.py.  Discovers
BaseKDF subclasses from all ``core/kdf_*.py`` modules via importlib.
"""

import importlib
import logging
from pathlib import Path
from typing import Dict, List, Optional

from memdiver.core.kdf_base import BaseKDF
from memdiver.core.plugin_discovery import (
    discover_entry_point_subclasses,
    discover_subclasses,
)

logger = logging.getLogger("memdiver.kdf_registry")

#: Entry-point group under which out-of-tree packages advertise KDFs.
KDF_ENTRY_POINT_GROUP = "memdiver.kdfs"


class KDFRegistry:
    """Discover and manage KDF plugins from ``core/kdf_*.py`` modules."""

    def __init__(self):
        self._kdfs: Dict[str, BaseKDF] = {}

    def discover(self) -> None:
        """Walk ``core/kdf_*.py`` modules and register BaseKDF subclasses.

        Per-plugin instantiation failures are isolated (a broken KDF no longer
        aborts discovery of the rest). Also loads any KDFs advertised by
        installed packages under the ``memdiver.kdfs`` entry-point group.
        """
        core_dir = Path(__file__).parent

        modules = []
        for py_file in sorted(core_dir.glob("kdf_*.py")):
            mod_name = f"memdiver.core.{py_file.stem}"
            if mod_name == "memdiver.core.kdf_base" or mod_name == "memdiver.core.kdf_registry":
                continue
            try:
                modules.append(importlib.import_module(mod_name))
            except ImportError as exc:
                if "No module named" in str(exc):
                    logger.debug("Optional KDF module not found: %s", mod_name)
                else:
                    logger.warning("Failed to import KDF module %s: %s", mod_name, exc)
                continue
            except Exception:  # noqa: BLE001 - a broken KDF module must not abort
                # discovery of every other KDF. Isolate it (log + skip), matching
                # plugin_discovery's stated per-plugin failure guarantee.
                logger.warning(
                    "Failed to import KDF module %s; skipping", mod_name, exc_info=True,
                )
                continue

        for instance in discover_subclasses(modules, BaseKDF):
            self._kdfs[instance.name] = instance
            logger.debug("Registered KDF: %s", instance.name)

        for instance in discover_entry_point_subclasses(
            KDF_ENTRY_POINT_GROUP, BaseKDF
        ):
            self._kdfs[instance.name] = instance
            logger.debug("Registered KDF: %s", instance.name)

    def get(self, name: str) -> Optional[BaseKDF]:
        """Return KDF plugin by name, or None."""
        return self._kdfs.get(name)

    def get_for_protocol(
        self, protocol: str, version: str
    ) -> Optional[BaseKDF]:
        """Return the first KDF matching *protocol* and *version*."""
        for kdf in self._kdfs.values():
            if kdf.protocol == protocol and version in kdf.versions:
                return kdf
        return None

    def list_all(self) -> List[BaseKDF]:
        """Return all registered KDF plugins."""
        return list(self._kdfs.values())


_registry: Optional[KDFRegistry] = None


def get_kdf_registry() -> KDFRegistry:
    """Return the lazily-initialised global KDF registry."""
    global _registry
    if _registry is None:
        _registry = KDFRegistry()
        _registry.discover()
    return _registry

"""Auto-discovery registry for KDF (Key Derivation Function) plugins.

Mirrors the algorithm plugin pattern in algorithms/registry.py.  Discovers
BaseKDF subclasses from all ``core/kdf_*.py`` modules via importlib.
"""

import importlib
import logging
import pkgutil
from pathlib import Path
from typing import Dict, List, Optional

from core.kdf_base import BaseKDF

logger = logging.getLogger("memdiver.kdf_registry")


class KDFRegistry:
    """Discover and manage KDF plugins from ``core/kdf_*.py`` modules."""

    def __init__(self):
        self._kdfs: Dict[str, BaseKDF] = {}

    def discover(self) -> None:
        """Walk ``core/kdf_*.py`` modules and register BaseKDF subclasses."""
        core_dir = Path(__file__).parent

        for py_file in sorted(core_dir.glob("kdf_*.py")):
            mod_name = f"core.{py_file.stem}"
            if mod_name == "core.kdf_base" or mod_name == "core.kdf_registry":
                continue
            try:
                mod = importlib.import_module(mod_name)
            except ImportError as exc:
                if "No module named" in str(exc):
                    logger.debug("Optional KDF module not found: %s", mod_name)
                else:
                    logger.warning("Failed to import KDF module %s: %s", mod_name, exc)
                continue

            for attr_name in dir(mod):
                attr = getattr(mod, attr_name)
                if (
                    isinstance(attr, type)
                    and issubclass(attr, BaseKDF)
                    and attr is not BaseKDF
                    and getattr(attr, "name", "")
                ):
                    instance = attr()
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

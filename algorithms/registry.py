"""Auto-discovery registry for algorithm plugins."""

import importlib
import logging
import pkgutil
from pathlib import Path
from typing import Dict, List

from memdiver.core.constants import AlgorithmMode
from memdiver.core.plugin_discovery import (
    discover_entry_point_subclasses,
    discover_subclasses,
)

from .base import BaseAlgorithm

logger = logging.getLogger("memdiver.algorithms.registry")

#: Entry-point group under which out-of-tree packages advertise algorithms.
ALGORITHM_ENTRY_POINT_GROUP = "memdiver.algorithms"


class AlgorithmRegistry:
    """Discover and manage algorithm plugins."""

    def __init__(self):
        self._algorithms: Dict[str, BaseAlgorithm] = {}

    def discover(self) -> None:
        """Walk known_key/ and unknown_key/ subdirectories to find algorithms.

        Also loads any algorithms advertised by installed packages under the
        ``memdiver.algorithms`` entry-point group (additive; a no-op when none
        are installed).
        """
        base_dir = Path(__file__).parent

        modules = []
        for subdir in ["known_key", "unknown_key", "patterns"]:
            pkg_path = base_dir / subdir
            if not pkg_path.is_dir():
                continue

            pkg_name = f"memdiver.algorithms.{subdir}"
            try:
                importlib.import_module(pkg_name)
            except Exception:  # noqa: BLE001 - a broken subpackage __init__ must
                # not abort discovery of the other subpackages' algorithms.
                logger.warning(
                    "Failed to import algorithm subpackage %s; skipping",
                    pkg_name, exc_info=True,
                )
                continue

            for importer, modname, ispkg in pkgutil.walk_packages(
                path=[str(pkg_path)], prefix=f"{pkg_name}."
            ):
                try:
                    modules.append(importlib.import_module(modname))
                except Exception:  # noqa: BLE001 - a broken plugin module must
                    # not abort discovery of every other algorithm. Isolate it
                    # (log + skip), matching plugin_discovery's stated guarantee.
                    logger.warning(
                        "Failed to import algorithm module %s; skipping",
                        modname, exc_info=True,
                    )
                    continue

        for instance in discover_subclasses(modules, BaseAlgorithm):
            self._algorithms[instance.name] = instance

        for instance in discover_entry_point_subclasses(
            ALGORITHM_ENTRY_POINT_GROUP, BaseAlgorithm
        ):
            self._algorithms[instance.name] = instance

    def get(self, name: str) -> BaseAlgorithm:
        return self._algorithms[name]

    def list_all(self) -> List[BaseAlgorithm]:
        return list(self._algorithms.values())

    def list_by_mode(self, mode: AlgorithmMode) -> List[BaseAlgorithm]:
        return [a for a in self._algorithms.values() if a.mode == mode]

    @property
    def names(self) -> List[str]:
        return sorted(self._algorithms.keys())


_registry = None


def get_registry() -> AlgorithmRegistry:
    global _registry
    if _registry is None:
        _registry = AlgorithmRegistry()
        _registry.discover()
    return _registry

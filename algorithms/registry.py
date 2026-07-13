"""Auto-discovery registry for algorithm plugins."""

import importlib
import logging
import pkgutil
from pathlib import Path
from typing import Dict, List

from core.constants import AlgorithmMode

from .base import BaseAlgorithm

logger = logging.getLogger("memdiver.algorithms.registry")


class AlgorithmRegistry:
    """Discover and manage algorithm plugins."""

    def __init__(self):
        self._algorithms: Dict[str, BaseAlgorithm] = {}

    def discover(self) -> None:
        """Walk known_key/ and unknown_key/ subdirectories to find algorithms."""
        base_dir = Path(__file__).parent

        for subdir in ["known_key", "unknown_key", "patterns"]:
            pkg_path = base_dir / subdir
            if not pkg_path.is_dir():
                continue

            pkg_name = f"algorithms.{subdir}"
            try:
                pkg = importlib.import_module(pkg_name)
            except ImportError:
                continue

            for importer, modname, ispkg in pkgutil.walk_packages(
                path=[str(pkg_path)], prefix=f"{pkg_name}."
            ):
                try:
                    mod = importlib.import_module(modname)
                except ImportError:
                    continue

                for attr_name in dir(mod):
                    attr = getattr(mod, attr_name)
                    if (isinstance(attr, type)
                            and issubclass(attr, BaseAlgorithm)
                            and attr is not BaseAlgorithm
                            and hasattr(attr, 'name')
                            and attr.name):
                        try:
                            instance = attr()
                        except Exception:
                            # A single algorithm whose __init__ raises must not
                            # abort discovery of all the others; log and skip it.
                            logger.warning(
                                "Skipping algorithm %s.%s: instantiation failed",
                                modname, attr_name, exc_info=True,
                            )
                            continue
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

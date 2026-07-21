"""Shared plugin auto-discovery helpers.

Factors out the near-duplicate class-scanning / instantiation logic shared by
the algorithm registry (``algorithms/registry.py``) and the KDF registry
(``core/kdf_registry.py``), and adds optional entry-point-based discovery so
out-of-tree (installed) packages can advertise plugins.

The two registries differ only in *how* they gather candidate modules
(``pkgutil.walk_packages`` over subpackages vs. globbing ``core/kdf_*.py``) and
keep that step inline. The identical part — scan a module for concrete
subclasses of a base class and instantiate them — lives here in
:func:`discover_subclasses`, with per-plugin failure isolation so one broken
plugin can never abort discovery of the rest.
"""

import importlib.metadata
import logging
from types import ModuleType
from typing import Iterable, List, Type, TypeVar

logger = logging.getLogger("memdiver.core.plugin_discovery")

T = TypeVar("T")


def _instantiate(cls: Type[T], label: str, isolate_failures: bool):
    """Instantiate *cls*, isolating failures when *isolate_failures* is set."""
    try:
        return cls()
    except Exception:
        if not isolate_failures:
            raise
        # A single plugin whose __init__ raises must not abort discovery of
        # all the others; log and skip it.
        logger.warning(
            "Skipping plugin %s: instantiation failed", label, exc_info=True
        )
        return None


def discover_subclasses(
    modules: Iterable[ModuleType],
    base_class: Type[T],
    *,
    name_attr: str = "name",
    isolate_failures: bool = True,
) -> List[T]:
    """Return instantiated concrete subclasses of *base_class* found in *modules*.

    A class is a candidate when it is a real subclass of *base_class* (but not
    *base_class* itself) and its *name_attr* attribute is truthy. Instances are
    returned in module/attribute-scan order; callers that key by name get the
    usual last-write-wins semantics. With *isolate_failures* (the default) a
    plugin whose constructor raises is logged and skipped instead of aborting
    the whole scan.
    """
    instances: List[T] = []
    for mod in modules:
        for attr_name in dir(mod):
            attr = getattr(mod, attr_name)
            if not (
                isinstance(attr, type)
                and issubclass(attr, base_class)
                and attr is not base_class
                and getattr(attr, name_attr, None)
            ):
                continue
            label = f"{getattr(mod, '__name__', mod)}.{attr_name}"
            instance = _instantiate(attr, label, isolate_failures)
            if instance is not None:
                instances.append(instance)
    return instances


def _select_entry_points(group: str):
    """Return entry points for *group* across importlib.metadata API versions."""
    try:
        eps = importlib.metadata.entry_points()
    except Exception:  # pragma: no cover - metadata backend failure
        return []

    select = getattr(eps, "select", None)
    if callable(select):  # importlib.metadata >= 3.10 (Python 3.10+)
        return list(select(group=group))
    try:  # older mapping-style API
        return list(eps.get(group, []))  # type: ignore[attr-defined]
    except AttributeError:  # pragma: no cover - unexpected backend
        return []


def discover_entry_point_subclasses(
    group: str,
    base_class: Type[T],
    *,
    name_attr: str = "name",
    isolate_failures: bool = True,
) -> List[T]:
    """Discover plugins advertised under entry-point *group* by installed packages.

    Each entry point may resolve to either a module (which is scanned for
    subclasses of *base_class*) or a subclass directly (which is instantiated).
    Degrades silently to an empty list when nothing is installed, and isolates
    per-entry-point load / instantiation failures.
    """
    instances: List[T] = []
    for ep in _select_entry_points(group):
        try:
            obj = ep.load()
        except Exception:
            logger.warning(
                "Failed to load entry point %r in group %s",
                getattr(ep, "name", ep), group, exc_info=True,
            )
            continue

        if isinstance(obj, ModuleType):
            instances.extend(
                discover_subclasses(
                    [obj], base_class,
                    name_attr=name_attr, isolate_failures=isolate_failures,
                )
            )
        elif (
            isinstance(obj, type)
            and issubclass(obj, base_class)
            and obj is not base_class
            and getattr(obj, name_attr, None)
        ):
            instance = _instantiate(obj, getattr(ep, "name", str(obj)), isolate_failures)
            if instance is not None:
                instances.append(instance)
        else:
            logger.warning(
                "Entry point %r in group %s did not resolve to a %s subclass",
                getattr(ep, "name", ep), group, base_class.__name__,
            )
    return instances


def load_entry_point_registrations(group: str) -> int:
    """Load register-call-based plugins advertised under entry-point *group*.

    This is the register-call counterpart to
    :func:`discover_entry_point_subclasses`, for the extension points that
    self-register via a module-level call (``register_dump_source`` /
    ``register_format`` / ``register_stage``) rather than by exposing a
    subclass. Each entry point in *group* is ``.load()``-ed and then:

    * if it resolves to a **module**, it is simply imported (already done by
      ``.load()``) so its module-level ``register_*`` side effects fire;
    * if it resolves to a **callable**, it is invoked with no arguments so it
      can self-register.

    Anything else is logged and skipped. Per-entry-point load / invocation
    failures are isolated (logged and skipped) so one broken plugin can never
    abort discovery of the rest, and the whole call is a silent no-op when the
    group is empty (nothing installed). Returns the number of entry points
    loaded successfully.
    """
    loaded = 0
    for ep in _select_entry_points(group):
        try:
            obj = ep.load()
        except Exception:
            logger.warning(
                "Failed to load entry point %r in group %s",
                getattr(ep, "name", ep), group, exc_info=True,
            )
            continue

        if isinstance(obj, ModuleType):
            # Importing the module (done by .load()) already ran its
            # register-call side effects; nothing more to do.
            loaded += 1
        elif callable(obj):
            try:
                obj()
            except Exception:
                logger.warning(
                    "Entry point %r in group %s raised on invocation",
                    getattr(ep, "name", ep), group, exc_info=True,
                )
                continue
            loaded += 1
        else:
            logger.warning(
                "Entry point %r in group %s resolved to neither a module "
                "nor a callable; skipping",
                getattr(ep, "name", ep), group,
            )
    return loaded

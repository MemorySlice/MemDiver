"""Every product package must be listed in ``[tool.setuptools] packages``.

The list is explicit (``package-dir = {"memdiver" = "."}``), so a new
sub-package that is not added is silently MISSING from an installed wheel while
every in-repo test still passes — this happened to ``memdiver.core.image``,
``memdiver.analysis`` and ``memdiver.analysis.queries``.
"""

import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
#: Top-level directories that are not shipped (tests, tooling, frontend, envs).
NOT_SHIPPED = {"tests", "docs", "frontend", "node_modules", "env", "scripts", "tools",
               "misc", "memdiver.egg-info", "build", "dist"}


def _listed_packages():
    data = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    return set(data["tool"]["setuptools"]["packages"])


def _package_dirs():
    for init in ROOT.rglob("__init__.py"):
        rel = init.parent.relative_to(ROOT)
        if rel.parts and (rel.parts[0] in NOT_SHIPPED or rel.parts[0].startswith(".")):
            continue
        if any(part == "__pycache__" for part in rel.parts):
            continue
        yield ".".join(("memdiver",) + rel.parts)


def test_every_package_with_an_init_is_listed_for_the_wheel():
    missing = sorted(set(_package_dirs()) - _listed_packages())
    assert not missing, f"add to pyproject [tool.setuptools] packages: {missing}"

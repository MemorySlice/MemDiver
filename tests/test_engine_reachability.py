"""Reachability guard for ``engine/``: no analysis module may be an orphan.

Why this module exists
======================
Five ``engine/`` modules — ~2,850 lines — were built, tested and shipped as one
Phase-2 wave and then wired to NO surface at all:

===============================  =====  ==================================
module                           lines  status
===============================  =====  ==================================
``engine/yara_scan.py``            892  wired later (``analysis.yara_scan``)
``engine/detector_metrics.py``     472  wired later (``analysis.score_detector``)
``engine/vol3_verify.py``          484  wired later (``analysis.verify_plugin``)
``engine/vol3_subproc.py``         389  wired later (same, subprocess mode)
``engine/survival_scan.py``        792  still unwired — DELIBERATELY (below)
===============================  =====  ==================================

Nothing noticed for months. The reason is structural, not human: the sibling
guard ``tests/test_capability_completeness.py`` scans only the modules named by
its ``PRODUCER_MODULE_PATTERNS`` (``app/tools*.py`` and
``app/experiment_orchestration.py``), so an ``engine/`` module can sit
unreachable forever without tripping anything. There was no ratchet whose field
of view included it.

This module is that ratchet. It is deliberately SEPARATE from the
capability-completeness guard rather than an extension of it: that guard is
about *producers*, and an engine module is not a producer — it is the compute an
app-layer producer calls. Widening ``PRODUCER_MODULE_PATTERNS`` to ``engine/``
would ask the wrong question (``is every public engine function a capability?``
— no, and it must not be). The complementary question this module asks is
narrow and answerable: **can the app layer get here at all?**

What "reachable" means here — and why
=====================================
Reachability is **transitive from the app layer**, not "has an app-layer
import". That distinction is the whole design.

Most ``engine/`` modules are legitimately internal: ``engine/candidate_grid.py``
is called by ``engine/candidate_pipeline.py``, which ``app/tools_pipeline.py``
calls. A naive "is this module referenced from ``app/``?" check would flag
dozens of perfectly correct helpers, every one of them would be exempted within
a day, and the guard would be meaningless by the end of the week. So:

1. build the module import graph over the whole in-tree package (pure AST);
2. seed it with the app-layer entry points (:data:`SEED_PACKAGES` /
   :data:`SEED_MODULES`);
3. walk transitively;
4. report the ``engine/`` modules the walk never reaches.

Three properties of the walk are load-bearing:

**Imports are collected at ANY nesting depth.** The repo idiom for engine
imports inside producers is *function-local* — ``app/tools_pipeline.py`` has
~40 ``from memdiver.engine... import ...`` statements inside producer bodies
(deferred so that importing the app layer does not drag in numpy/yara/
volatility3). A module-level-only scan would report 15 correctly-wired engine
modules as orphans, so :func:`_import_targets` walks the whole tree, not
``tree.body``. :func:`test_walk_catches_function_local_imports` pins that.

**Importing ``a.b.c`` reaches ``a`` and ``a.b``.** Python executes every
ancestor package's ``__init__.py`` on the way down, so ``engine/resources/
__init__.py`` is reached by any import of ``engine/resources/tls_pcap.py`` even
though nothing names the package itself. Without this, two ``__init__``-shaped
false positives appear immediately.

**The whole app layer is a seed, not just its producers.** An engine module
imported by any ``app/`` module counts as reached. That is intentional
division of labour: whether the *app* module itself is reachable from a surface
is exactly what ``test_capability_completeness.py`` already ratchets (every
public app-layer producer is registered in ``CAPABILITIES`` or exempted). This
guard is not a second opinion on that; it closes the layer below it.

Limits, stated plainly
======================
Only ``import``/``from ... import`` are edges. A module reached ONLY through a
dotted string handed to a runner (the ``runner_dotted`` indirection
``test_capability_completeness.py`` exempts routes for) or through
``importlib.import_module`` would read as unreached and would need an
exemption saying so. No such engine module exists today — there is not one
``"memdiver.engine..."`` string literal in ``app/``, ``api/``, ``cli/`` or
``mcp_server/`` — and if one appears, an honest exemption is the right answer,
because a string hand-off IS harder to see than an import.

``run.py`` is NOT a seed: it is a generated Marimo notebook whose cross-cell
name resolution defeats static analysis (which is why ``[tool.ruff]``
``extend-exclude`` and the coverage ``omit`` list drop it too). Neither are
``ui/``, ``harvester/`` or ``architect/`` — ``architect/`` is reached through
``api/routers/architect.py`` like any other layer, and none of the modules this
guard currently reports is imported by any of the three (checked).

The exemption list
==================
:data:`EXEMPT_ENGINE_MODULES` follows exactly the idiom of
``EXEMPT_PRODUCERS`` / ``EXEMPT_ROUTES`` / ``EXEMPT_ROUTERS``: an
``(identifier, reason)`` pair, a 30-character minimum on the reason so nothing
can be annotated "wip", and — critically — it is **shrink-only in both
directions**. An exemption for a module that later becomes reachable FAILS
(:func:`test_no_exempt_engine_module_is_reachable`), and an exemption naming a
module that no longer exists FAILS (:func:`test_exempt_engine_modules_exist`).
The list cannot rot into a permanent amnesty.

The point of the whole file is to convert "we forgot" into "we decided".
"""

from __future__ import annotations

import ast
from collections import deque
from pathlib import Path
from typing import Dict, FrozenSet, List, Set, Tuple

ROOT = Path(__file__).resolve().parent.parent

#: The import name the repo root is mapped to (``[tool.setuptools]``
#: ``package-dir = {"memdiver" = "."}``), so a repo-relative path is also a
#: dotted module path: ``engine/yara_scan.py`` → ``memdiver.engine.yara_scan``.
PACKAGE = "memdiver"

#: Directories that are not part of the importable package. Mirrors the
#: ``[tool.ruff] extend-exclude`` / ``[tool.bandit] exclude_dirs`` / coverage
#: ``omit`` split: tests and dev tooling are not production import edges, and
#: counting ``tests/`` as a seed would make every module trivially "reachable"
#: (every one of the four modules below IS imported by its own test file).
NON_PACKAGE_DIRS: FrozenSet[str] = frozenset({
    ".git",
    ".venv",
    "__pycache__",
    "build",
    "dist",
    "docs",
    "env",
    "frontend",
    "misc",
    "node_modules",
    "scripts",
    "tests",
    "tools",
})

#: App-layer entry-point PACKAGES (every module under them is a seed) — the
#: five surfaces' own code plus the shared app layer they all route through.
SEED_PACKAGES: Tuple[str, ...] = (
    "memdiver.app",
    "memdiver.api",
    "memdiver.cli",
    "memdiver.mcp_server",
)

#: App-layer entry-point MODULES: the library surface's public re-export
#: facade, and the package root that is ``import memdiver``.
SEED_MODULES: FrozenSet[str] = frozenset({
    "memdiver.services",
    "memdiver",
})

#: The subtree this guard is responsible for. Deliberately just ``engine/``:
#: that is where the five orphans happened, and ``core/`` is a genuinely
#: layered utility package whose reachability question is a different one.
GUARDED_PREFIX = "memdiver.engine"

#: Minimum characters a reason must have, so no entry can be annotated "wip".
#: Same value and same purpose as in ``tests/test_capability_completeness.py``.
_MIN_REASON_CHARS = 30


# ---------------------------------------------------------------------------
# Exemptions — every entry is ``(dotted module, reason)``. Shrink-only, both
# directions: see the module docstring.
# ---------------------------------------------------------------------------

EXEMPT_ENGINE_MODULES: FrozenSet[Tuple[str, str]] = frozenset({
    (
        "memdiver.engine.survival_scan",
        "DECIDED AGAINST WIRING — not an oversight. This is the per-dump "
        "worker of the corpus-survival sweep (does this dump still contain "
        "its own run's keylog secrets?), and the corpus-survival direction is "
        "the one the user's own scope correction of 2026-08-28 CUT: the "
        "product is the interactive N-dump differential workflow, not a batch "
        "survival-measurement instrument built to feed a thesis chapter. The "
        "module works and is fully tested (tests/test_survival_scan.py), it "
        "costs nothing to leave parked, and wiring it to a surface would "
        "re-open a closed scope decision rather than serve a user need. "
        "Recording that here is the entire point of this entry: the next "
        "session must read 'decided against', not rediscover it as a forgotten "
        "module and wire it. If the corpus-survival direction is ever "
        "deliberately reopened, delete this entry — do not quietly widen it.",
    ),
    (
        "memdiver.engine.sweep_plan",
        "FOUND BY THIS GUARD'S FIRST RUN — NOT YET TRIAGED, and no rationale "
        "is invented here. Observable facts only: its own docstring describes "
        "it as the work-unit enumeration and idempotency digests of the same "
        "resumable corpus sweep that survival_scan is the worker for "
        "(enumerate_units / count_units / unit_key / inputs_digest / "
        "config_digest), and tests/test_survival_scan.py imports "
        "SWEEP_SCHEMA_VERSION from it — so the differential-refocus decision "
        "recorded above may well cover it too. But the user named only "
        "survival_scan, so this entry does NOT claim to be that decision. "
        "Triage owed: confirm it belongs to the cut direction (then merge this "
        "reason into the one above), or wire it.",
    ),
    (
        "memdiver.engine.coordinate_refine",
        "FOUND BY THIS GUARD'S FIRST RUN — NOT YET TRIAGED, and no rationale "
        "is invented here. Observable facts only: it computes a "
        "ground-truth-free per-region correspondence score in [0,1] via "
        "bounded-lag normalized cross-correlation, and its docstring states "
        "the intended caller behaviour (gate a no-hit verdict to INCONCLUSIVE "
        "when offsets are not reliably comparable) — a consumer that does not "
        "exist on any surface. tests/test_coordinate_refine.py is its only "
        "importer. Triage owed: wire the INCONCLUSIVE gate it was written for, "
        "or record a decision not to.",
    ),
    (
        "memdiver.engine.envelope_serializer",
        "FOUND BY THIS GUARD'S FIRST RUN — NOT YET TRIAGED, and no rationale "
        "is invented here. Observable facts only: it is a ServiceResult -> "
        "JSON-ready dict bridge that delegates every field mapping to "
        "engine.serializer and attaches status under a reserved '_status' key; "
        "the per-surface presenters under presentation/ are what the four "
        "surfaces actually render envelopes with. Its importers are "
        "tests/test_envelope_serializer.py and tests/test_pickle_boundary.py. "
        "Triage owed: decide whether it is a superseded seam to retire or a "
        "bridge some surface should be using.",
    ),
})


# ---------------------------------------------------------------------------
# AST discovery — pure static analysis, nothing imported, nothing introspected
# at runtime. Matches the style of tests/test_capability_completeness.py and
# tests/test_architecture_invariants.py, and keeps this cheap enough to run in
# every `pytest` (one ast.parse per in-tree module, no product imports).
# ---------------------------------------------------------------------------


def _ids(exemptions: FrozenSet[Tuple[str, str]]) -> FrozenSet[str]:
    return frozenset(identifier for identifier, _reason in exemptions)


def _dotted(path: Path) -> str:
    """Repo-relative path → dotted module name (``__init__.py`` → its package)."""
    parts = list(path.relative_to(ROOT).with_suffix("").parts)
    if parts[-1] == "__init__":
        parts = parts[:-1]
    return ".".join([PACKAGE, *parts])


def discover_modules() -> Dict[str, Path]:
    """Return ``{dotted module: file}`` for every in-tree package module."""
    found: Dict[str, Path] = {}
    for path in ROOT.rglob("*.py"):
        relative = path.relative_to(ROOT)
        if any(part in NON_PACKAGE_DIRS for part in relative.parts):
            continue
        found[_dotted(path)] = path
    return found


def _resolve_relative(node: ast.ImportFrom, dotted: str, is_package: bool) -> str:
    """Resolve ``from .x import y`` / ``from ..x import y`` to an absolute name.

    ``level`` counts dots: 1 means "this module's own package". For a package
    ``__init__`` that package IS the module's dotted name; for a plain module
    it is the parent, hence ``is_package``.
    """
    package = dotted if is_package else dotted.rsplit(".", 1)[0]
    parts = package.split(".")
    base = ".".join(parts[: len(parts) - (node.level - 1)])
    return base + ("." + node.module if node.module else "")


def _candidate_names(path: Path, dotted: str) -> Set[str]:
    """Every dotted name any import in ``path`` could refer to, at ANY depth.

    ``ast.walk`` rather than ``tree.body`` is deliberate and load-bearing —
    see the module docstring: the repo's engine imports inside producers are
    function-local. Both halves of ``from pkg import name`` are emitted
    (``pkg`` and ``pkg.name``), because ``from memdiver.engine import
    floor_policy`` names a MODULE through the ``names`` list, not the
    ``module`` field.
    """
    tree = ast.parse(path.read_text(), filename=str(path))
    is_package = path.name == "__init__.py"
    names: Set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            names.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            if node.level:
                module = _resolve_relative(node, dotted, is_package)
            else:
                module = node.module or ""
            if not module:
                continue
            names.add(module)
            names.update(f"{module}.{alias.name}" for alias in node.names)
    return names


def _import_targets(
    path: Path, dotted: str, modules: Dict[str, Path]
) -> FrozenSet[str]:
    """In-tree modules ``path`` imports, plus every ancestor package of each.

    The ancestor expansion models real Python: importing ``a.b.c`` executes
    ``a/__init__.py`` and ``a/b/__init__.py`` too, so a package whose name
    nothing ever spells is still genuinely reached.
    """
    targets: Set[str] = set()
    for name in _candidate_names(path, dotted):
        if name not in modules:
            continue
        targets.add(name)
        parts = name.split(".")
        for depth in range(1, len(parts)):
            ancestor = ".".join(parts[:depth])
            if ancestor in modules:
                targets.add(ancestor)
    return frozenset(targets)


def build_import_graph(modules: Dict[str, Path]) -> Dict[str, FrozenSet[str]]:
    """Return ``{dotted module: in-tree modules it imports}``."""
    return {
        dotted: _import_targets(path, dotted, modules)
        for dotted, path in modules.items()
    }


def seed_modules(modules: Dict[str, Path]) -> List[str]:
    """The app-layer entry points the transitive walk starts from."""
    return sorted(
        dotted
        for dotted in modules
        if dotted in SEED_MODULES
        or any(
            dotted == package or dotted.startswith(package + ".")
            for package in SEED_PACKAGES
        )
    )


def walk_reachable(
    graph: Dict[str, FrozenSet[str]], seeds: List[str]
) -> FrozenSet[str]:
    """Breadth-first transitive closure of ``seeds`` over ``graph``."""
    reached: Set[str] = set()
    queue = deque(seeds)
    while queue:
        current = queue.popleft()
        if current in reached:
            continue
        reached.add(current)
        queue.extend(graph.get(current, frozenset()) - reached)
    return frozenset(reached)


def reachable_modules() -> FrozenSet[str]:
    """Every in-tree module the app layer can transitively reach."""
    modules = discover_modules()
    return walk_reachable(build_import_graph(modules), seed_modules(modules))


def guarded_modules() -> Dict[str, Path]:
    """The ``engine/`` modules this guard is responsible for."""
    return {
        dotted: path
        for dotted, path in discover_modules().items()
        if dotted == GUARDED_PREFIX or dotted.startswith(GUARDED_PREFIX + ".")
    }


def unreached_engine_modules() -> List[str]:
    """``engine/`` modules no app-layer import path leads to."""
    reached = reachable_modules()
    return sorted(dotted for dotted in guarded_modules() if dotted not in reached)


# ---------------------------------------------------------------------------
# Sanity of the discovery itself (a vacuous graph would make everything pass)
# ---------------------------------------------------------------------------


def test_discovery_is_not_vacuous():
    """The graph must actually find things, and find the known landmarks.

    Modelled on ``test_capability_completeness.py::test_discovery_is_not_
    vacuous``: a scan that silently found nothing would turn this whole file
    green forever. The landmark pair is the sharpest available — one module
    wired this week that MUST be reached, one deliberately-parked module that
    MUST NOT be.
    """
    modules = discover_modules()
    graph = build_import_graph(modules)
    seeds = seed_modules(modules)

    assert len(modules) >= 200, f"module scan looks broken: {len(modules)}"
    assert len(seeds) >= 50, f"seed scan looks broken: {len(seeds)}"
    assert len(guarded_modules()) >= 40, "engine/ scan looks broken"

    # The graph has edges at all, and the app layer really does reach engine/.
    assert sum(len(t) for t in graph.values()) >= 500, "import graph has no edges"

    reached = walk_reachable(graph, seeds)
    assert len(reached) >= 150, f"walk looks broken: {len(reached)} reached"

    # POSITIVE landmark: wired this week as the `analysis.yara_scan` capability.
    assert "memdiver.engine.yara_scan" in reached
    # NEGATIVE landmark: deliberately parked, exempted below. If this ever
    # becomes reachable the exemption is stale and the staleness test fires.
    assert "memdiver.engine.survival_scan" not in reached

    # And the two extremes of the layering are both classified correctly: a
    # deep internal helper is reached transitively (never imported by app/),
    # while the seed set itself is obviously in.
    assert "memdiver.engine.candidate_grid" in reached
    assert "memdiver.app.tools_pipeline" in reached


def test_walk_catches_function_local_imports():
    """The AST walk must see imports at ANY nesting depth, not just module level.

    This is the trap that would have made the guard useless: the repo's engine
    imports inside app-layer producers are deliberately function-local (lazy,
    so importing the app layer does not pull in numpy/yara/volatility3). A
    ``tree.body``-only scan reports every one of those engine modules as an
    orphan.

    The proof is a differential: walk the same seeds over a graph built from
    MODULE-LEVEL imports only, and assert a large set of engine modules —
    including a named landmark that is only ever imported inside a function
    body — flips from reached to unreached. If someone "simplifies"
    :func:`_candidate_names` to ``tree.body``, this fails loudly instead of
    the guard quietly reporting a dozen false orphans.
    """
    modules = discover_modules()
    seeds = seed_modules(modules)

    def module_level_only(path: Path, dotted: str) -> FrozenSet[str]:
        tree = ast.parse(path.read_text(), filename=str(path))
        is_package = path.name == "__init__.py"
        names: Set[str] = set()
        for node in tree.body:  # NOT ast.walk — that is the whole point
            if isinstance(node, ast.Import):
                names.update(alias.name for alias in node.names)
            elif isinstance(node, ast.ImportFrom):
                module = (
                    _resolve_relative(node, dotted, is_package)
                    if node.level
                    else (node.module or "")
                )
                if not module:
                    continue
                names.add(module)
                names.update(f"{module}.{alias.name}" for alias in node.names)
        resolved: Set[str] = set()
        for name in names:
            if name not in modules:
                continue
            resolved.add(name)
            parts = name.split(".")
            for depth in range(1, len(parts)):
                ancestor = ".".join(parts[:depth])
                if ancestor in modules:
                    resolved.add(ancestor)
        return frozenset(resolved)

    shallow = walk_reachable(
        {d: module_level_only(p, d) for d, p in modules.items()}, seeds
    )
    full = walk_reachable(build_import_graph(modules), seeds)

    nested_only = sorted(
        dotted
        for dotted in guarded_modules()
        if dotted in full and dotted not in shallow
    )
    assert len(nested_only) >= 8, (
        "the nested-import walk no longer changes the answer — either the repo "
        "stopped using function-local engine imports (then this test can go) "
        f"or _candidate_names regressed to module level: {nested_only}"
    )
    # Named landmark: app/experiment_orchestration.py imports it inside
    # producer bodies only (twice), so a module-level scan loses it entirely.
    assert "memdiver.engine.verification" in nested_only


def test_every_exemption_carries_a_reason():
    """No entry may be added without a real justification.

    Same 30-character floor as ``test_capability_completeness.py``: it is what
    stops the list degrading into ``("...", "wip")``.
    """
    bad = [
        f"engine module {identifier}: reason too short"
        for identifier, reason in EXEMPT_ENGINE_MODULES
        if len(reason.strip()) < _MIN_REASON_CHARS
    ]
    assert bad == [], "exemption(s) without a real reason:\n" + "\n".join(bad)


def test_exemption_identifiers_are_unique():
    """A frozenset of pairs cannot dedupe by identifier — check it here."""
    identifiers = [identifier for identifier, _ in EXEMPT_ENGINE_MODULES]
    dupes = sorted({i for i in identifiers if identifiers.count(i) > 1})
    assert dupes == [], (
        f"duplicate engine-module exemption identifier(s) — merge the reasons: "
        f"{dupes}"
    )


# ---------------------------------------------------------------------------
# The reachability ratchet
# ---------------------------------------------------------------------------


def test_every_engine_module_is_reachable_or_exempt():
    """RATCHET: no ``engine/`` module may be an invisible orphan.

    Forward check. An engine module the app layer cannot transitively reach,
    and which is not on :data:`EXEMPT_ENGINE_MODULES`, fails. That is the
    blind spot this file exists to close — five modules and ~2,850 lines sat
    fully built, fully tested and reachable from nothing, for months, because
    no guard's field of view included ``engine/``.

    Two honest ways to fix a failure. Wire the module to a surface (an
    app-layer producer registered in ``CAPABILITIES``, which then also brings
    it under the parity ratchet), or exempt it with the reason it stays
    parked. Both are decisions; neither is silence.
    """
    unaccounted = sorted(
        set(unreached_engine_modules()) - _ids(EXEMPT_ENGINE_MODULES)
    )
    assert unaccounted == [], (
        "engine module(s) unreachable from every app-layer entry point — wire "
        "them to a surface, or add them to EXEMPT_ENGINE_MODULES with the "
        "reason they stay parked:\n" + "\n".join(f"  {m}" for m in unaccounted)
    )


def test_no_exempt_engine_module_is_reachable():
    """STALENESS: an exempted module that got wired must be un-exempted.

    The shrink-only direction, mirroring
    ``test_capability_completeness.py::test_no_exempt_producer_is_registered``.
    Without it the list rots: a module could be wired to all four surfaces
    while an entry here still claimed it was deliberately parked, and the next
    reader would believe the stale note. A ratchet that only tightens one way
    is not a ratchet.
    """
    stale = sorted(_ids(EXEMPT_ENGINE_MODULES) & reachable_modules())
    assert stale == [], (
        "EXEMPT_ENGINE_MODULES entr(ies) are now reachable from the app layer "
        "— the exemption is stale, delete it (and if the wiring was "
        "intentional, register the capability):\n"
        + "\n".join(f"  {m}" for m in stale)
    )


def test_exempt_engine_modules_exist():
    """Typo guard: every exemption names a module the scan actually found.

    Catches both a misspelled dotted path and an exemption left behind after
    the module was renamed or deleted.
    """
    unknown = sorted(_ids(EXEMPT_ENGINE_MODULES) - set(guarded_modules()))
    assert unknown == [], (
        "EXEMPT_ENGINE_MODULES names engine module(s) that do not exist "
        "(renamed or deleted) — delete the entr(ies):\n"
        + "\n".join(f"  {m}" for m in unknown)
    )


def test_guard_would_have_caught_the_five_orphans():
    """REGRESSION PROOF: the guard really does detect this week's failure mode.

    Counterfactual over the live graph. Cut every edge into the four modules
    that were wired this week — i.e. rebuild the world as it was while they
    were orphans — and assert all five (the four plus the still-parked
    ``survival_scan``) come out unreachable. If they did not, this whole file
    would be theatre: green today only because the modules happen to be wired
    now, with no evidence it would have fired back then.
    """
    orphaned_this_week = frozenset({
        "memdiver.engine.yara_scan",
        "memdiver.engine.detector_metrics",
        "memdiver.engine.vol3_verify",
        "memdiver.engine.vol3_subproc",
    })
    modules = discover_modules()
    for dotted in orphaned_this_week | {"memdiver.engine.survival_scan"}:
        assert dotted in modules, f"landmark module vanished: {dotted}"

    graph = build_import_graph(modules)
    without_this_weeks_wiring = {
        dotted: targets - orphaned_this_week for dotted, targets in graph.items()
    }
    reached = walk_reachable(without_this_weeks_wiring, seed_modules(modules))

    still_reached = sorted(orphaned_this_week & reached)
    assert still_reached == [], (
        "cutting the direct edges did not orphan these — the counterfactual no "
        f"longer reconstructs the pre-wiring world: {still_reached}"
    )

"""Completeness guard for the capability registry (B4c).

``memdiver.app.capabilities`` is the machine-checkable map of "one capability →
one app-layer producer → the surfaces routed to it", and
``tests/test_architecture_invariants.py::test_cross_surface_capability_parity``
is the ratchet that holds every entry to every in-scope surface.

That ratchet iterates :data:`CAPABILITIES` and nothing else, so it is blind BY
CONSTRUCTION to a producer or a route that was never registered. The registry's
own ``pcap.inspect`` comment records exactly that failure mode: the capability
was wired on all four surfaces from Phase 1 and the ratchet still had a hole
over it, because nothing ever asked "is every producer in the registry?".

This module asks that question. It is a second, orthogonal ratchet:

* every public producer in the app-layer producer modules, and
* every HTTP route in ``api/routers/*.py``

must EITHER be reachable from :data:`CAPABILITIES` or appear on an explicit,
annotated exemption list below. Both exemption lists are shrink-only in the same
sense ``KNOWN_PARITY_GAPS`` is: an entry that becomes registered/covered makes
this module FAIL, so the exemption must be deleted rather than left to rot.

Discovery rules (all pure AST — nothing here imports a heavy module, and
nothing is introspected at runtime, matching the style of
``tests/test_architecture_invariants.py``):

**Producers.** A producer is a module-level ``def``/``async def`` whose name does
not start with ``_``, in one of the modules named by
:data:`PRODUCER_MODULE_PATTERNS`. Nested functions, classes, methods and
assignments are not producers. A producer is *registered* when its dotted path
``memdiver.<module path>.<name>`` is some capability's ``producer``.

**Legacy shims.** A public function whose docstring contains the reST marker
``.. deprecated::`` is a back-compat shim over a real producer, not a producer,
and is excluded from the producer set. This is what handles
``app/tools_inspect_legacy.py``: no filename special-case is needed, because all
nine of its public functions carry that marker (as do the two pre-ServiceResult
shims left in ``app/tools_xref.py``). The rule is checked for staleness by
:func:`test_no_deprecated_shim_is_registered`, and a NEW non-deprecated function
in the legacy module is discovered like any other producer.

**Routes.** A route is a function decorated with ``@<name>.<method>("<path>")``
where ``<method>`` is an HTTP verb (or ``websocket``), in ``api/routers/*.py``.
Its stable identifier is ``"<router module stem>:<METHOD> <path>"``. A route is
*covered* when its handler body references, by bare name or attribute, the leaf
name of some registered capability's producer — i.e. the AST can see the route
handing off to the shared producer. Indirection the AST cannot follow (a
``runner_dotted`` string handed to the TaskManager, most notably) reads as
uncovered and is exempted explicitly rather than papered over.

Whole ROUTERS may be exempted, but only while they expose no registered
capability at all (:func:`test_exempt_routers_are_not_capability_bearing`); the
moment a capability lands in one, the coarse exemption becomes illegal and the
router's routes must be accounted for individually.
"""

from __future__ import annotations

import ast
import sys
from pathlib import Path
from typing import Dict, FrozenSet, List, Tuple

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from memdiver.app.capabilities import CAPABILITIES  # noqa: E402

ROOT = Path(__file__).resolve().parent.parent

#: Globs (repo-relative) of the app-layer modules that HOST capability
#: producers. Deliberately narrow: the rest of ``app/`` is composition,
#: caching and session plumbing, not producer families.
#: :func:`test_producer_scan_covers_every_registered_producer_module` keeps this
#: honest — registering a producer in a module outside these patterns fails
#: until the pattern set grows to include it, so the scan cannot be dodged by
#: putting the next producer somewhere new.
PRODUCER_MODULE_PATTERNS: Tuple[str, ...] = (
    "app/tools*.py",
    "app/experiment_orchestration.py",
)

_HTTP_METHODS: FrozenSet[str] = frozenset(
    {"get", "post", "put", "patch", "delete", "head", "options", "websocket"}
)

#: The reST marker that identifies a back-compat shim (see module docstring).
_DEPRECATED_MARKER = ".. deprecated::"


# ---------------------------------------------------------------------------
# Exemptions — every entry is ``(identifier, one-line reason)``. Shrink-only.
# ---------------------------------------------------------------------------

#: Public app-layer functions that are deliberately NOT capabilities.
#:
#: Registering any of these with the surfaces it actually has would require
#: GROWING ``KNOWN_PARITY_GAPS``, which is documented shrink-only; registering
#: it with surfaces it does NOT have would break the parity ratchet outright.
#: So they stay out of the registry and stay visible here instead.
EXEMPT_PRODUCERS: FrozenSet[Tuple[str, str]] = frozenset({
    (
        "memdiver.app.tools.import_dump",
        "Library + web only (memdiver.services re-export, POST "
        "/api/dumps/upload). The CLI `import` command calls msl.importer."
        "import_dump directly rather than this producer, so registering it "
        "would add a new KNOWN_PARITY_GAPS entry to a shrink-only baseline.",
    ),
    (
        "memdiver.app.tools_consensus.aligned_window_from_vector",
        "The SAME compute as the registered consensus.aligned_window, entered "
        "with a vector the caller already holds instead of building one. Web "
        "(the consensus_id branch of POST /consensus/aligned-window) and "
        "library reach it; CLI and MCP have no vector to hand it, so "
        "registering it would GROW KNOWN_PARITY_GAPS by two entries on a "
        "shrink-only baseline for a function that is not a separate "
        "capability.",
    ),
    (
        "memdiver.app.tools_consensus.class_regions_from_vector",
        "The SAME compute as the registered consensus.class_regions, entered "
        "with a vector the caller already holds instead of building one. Web "
        "(the consensus_id branch of POST /consensus/regions) and library "
        "reach it; CLI and MCP have no vector to hand it, so registering it "
        "would GROW KNOWN_PARITY_GAPS by two entries on a shrink-only baseline "
        "for a function that is not a separate capability.",
    ),
    (
        "memdiver.app.tools_consensus.dump_index_for",
        "NOT A PRODUCER: a one-line selector resolver (an int index or a dump "
        "path -> the dump's position in the build order). It is PUBLIC for the "
        "reason app.composition.raise_if_locked is — "
        "api.routers.analysis._reject_dumps_outside_consensus has to resolve a "
        "selector EXACTLY the way _select_dumps does, or a request passes the "
        "router's 409 gate and is then rejected by the producer over a "
        "difference in path spelling, and a router reaching for another "
        "module's PRIVATE name is worse than the duplication it replaces. It "
        "computes nothing, opens nothing and has no surface of its own, so "
        "registering it would invent a capability that does not exist.",
    ),
    (
        "memdiver.app.tools.import_raw_dump",
        "Back-compat alias that just calls import_dump — same compute, not a "
        "distinct capability. The MCP import_raw_dump tool routes here.",
    ),
})

#: Whole routers with no registered capability behind any of their routes.
#: Legal ONLY while that stays true — see
#: :func:`test_exempt_routers_are_not_capability_bearing`.
EXEMPT_ROUTERS: FrozenSet[Tuple[str, str]] = frozenset({
    (
        "architect",
        "NO APP-LAYER PRODUCER: /check-static, /generate-pattern and /export "
        "bypass the app layer entirely (they import architect/ StaticChecker / "
        "PatternGenerator / *Exporter directly), so there is nothing to "
        "register as a capability. The router's ERROR contract is no longer "
        "part of this gap -- every failure path now raises a transport-agnostic "
        "CapabilityError and is rendered by the global funnel in api/main.py "
        "(see tests/test_api_architect.py) -- but the missing producer is real, "
        "and this entry is what keeps it VISIBLE instead of invisible.",
    ),
    (
        "consensus",
        "Stateful upload/session CRUD for the multi-dump consensus builder "
        "(begin / add-path / add-upload / get / finalize / delete) — session "
        "lifecycle, not compute. The origination producer is "
        "pipeline.consensus.",
    ),
    (
        "docs",
        "GET /{doc_path} reads one bundled markdown file off disk for the "
        "in-app documentation panel. Static prose delivery, not analysis "
        "compute -- there is no app-layer producer and never will be.",
    ),
    (
        "dumps",
        "POST /upload is multipart transport + temp-file handling; the "
        "conversion it performs is app.tools.import_dump, itself exempted "
        "above.",
    ),
    (
        "experiment",
        "POST /run is pure async dispatch: it validates the body and submits "
        "runner_dotted='memdiver.app.pipeline.experiment_task_runner."
        "run_experiment' to the TaskManager. The `experiment` capability IS "
        "wired on web through that runner, but the hand-off is a STRING the "
        "AST cannot follow, so the route reads as uncovered.",
    ),
    (
        "oracles",
        "Oracle file CRUD + arm/dry-run lifecycle (upload, list, arm, delete) "
        "— artifact management that feeds the pipeline capabilities, not a "
        "capability itself.",
    ),
    (
        "path",
        "Filesystem browse/info helpers for the file-picker UI; no compute, no "
        "producer.",
    ),
    (
        "sessions",
        "Named-session CRUD (list/load/save/delete) — UI state persistence.",
    ),
    (
        "settings",
        "Upload-directory get/set — server configuration, not analysis.",
    ),
    (
        "structures",
        "Kaitai structure-definition CRUD + .ksy import/export; the analysis "
        "capabilities over structures are structure.identify / structure.apply "
        "on the inspect router.",
    ),
    (
        "tasks",
        "TaskManager introspection (list/get/result/cancel) — the async "
        "transport every task-dispatching capability shares.",
    ),
})

#: Individual routes in CAPABILITY-BEARING routers that are not covered.
EXEMPT_ROUTES: FrozenSet[Tuple[str, str]] = frozenset({
    # -- analysis router ---------------------------------------------------
    (
        "analysis:POST /run",
        "Async dispatch: submits runner_dotted='...analysis_task_runner."
        "run_analysis' to the TaskManager. dataset/analysis.analyze_library is "
        "the producer behind it; the string hand-off is invisible to AST.",
    ),
    (
        "analysis:POST /run-file",
        "Async dispatch to app.pipeline.analysis_task_runner.run_file (moved "
        "off the request thread after a 102 s inline benchmark); same "
        "runner_dotted indirection.",
    ),
    (
        "analysis:POST /batch",
        "Async dispatch to app.pipeline.batch_task_runner.run_batch; "
        "engine.batch has no app-layer producer (see the dataset/analysis note "
        "in capabilities.py).",
    ),
    (
        "analysis:POST /consensus",
        "A DISTINCT stateful feature from pipeline.consensus: it builds a "
        "vector via engine.consensus_service.build_consensus and REGISTERS it "
        "under a consensus_id for the range queries below. capabilities.py "
        "already records that this route is not the origination producer.",
    ),
    (
        "analysis:GET /consensus/range",
        "Range query against an existing consensus_id registered by POST "
        "/consensus — reads session state, runs no producer.",
    ),
    (
        "analysis:GET /consensus/va-range",
        "VA-coordinate range query over a registered consensus build; session "
        "state read, no producer.",
    ),
    (
        "analysis:GET /consensus/va-overview",
        "VA-coordinate overview/minimap query over a registered consensus "
        "build; session state read, no producer.",
    ),
    (
        "analysis:POST /convergence",
        "Convergence sweep straight over engine.convergence."
        "run_convergence_sweep; no app-layer producer exists for it (unlike "
        "pipeline.n_sweep, which is the artifact-writing sweep).",
    ),
    (
        "analysis:GET /patterns",
        "Lists the bundled algorithms/patterns/*.json definitions off disk — "
        "static asset enumeration, no dump and no compute.",
    ),
    # -- dataset router ----------------------------------------------------
    (
        "dataset:GET /runs",
        "Paginated dataset-run directory listing for the browsing UI "
        "(cheap-enumerate then slice); dataset.scan is the scanning "
        "capability, this is its UI-facing pagination view.",
    ),
    # -- inspect router ----------------------------------------------------
    (
        "inspect:GET /tag-status",
        "AEAD tag-verification diagnostic (spec §10) read straight off the "
        "MSL reader. It exists BECAUSE the inspect presenters drop the status "
        "block — it is the web surface's view of ServiceResult.status, not a "
        "capability of its own.",
    ),
    (
        "inspect:POST /tag-status",
        "Keyed variant of the same diagnostic (distinguishes valid from "
        "corrupted for an encrypted container).",
    ),
    (
        "inspect:GET /thread-contexts",
        "SPEC-RESERVED block reader (THREAD_CONTEXT 0x0011): speculative "
        "layout, answers spec_reserved=true. No producer until the spec fixes "
        "the layout.",
    ),
    (
        "inspect:GET /file-descriptors",
        "Spec-reserved extended-block reader; speculative layout, "
        "spec_reserved=true.",
    ),
    (
        "inspect:GET /network-connections",
        "Spec-reserved extended-block reader; speculative layout, "
        "spec_reserved=true. (inspect.connections is the real capability.)",
    ),
    (
        "inspect:GET /env-blocks",
        "Spec-reserved extended-block reader; speculative layout, "
        "spec_reserved=true.",
    ),
    (
        "inspect:GET /security-tokens",
        "Spec-reserved extended-block reader; speculative layout, "
        "spec_reserved=true.",
    ),
    (
        "inspect:GET /system-context",
        "Spec-reserved extended-block reader; speculative layout, "
        "spec_reserved=true.",
    ),
    # -- pcaps router ------------------------------------------------------
    (
        "pcaps:POST /upload",
        "Chunked multipart transport with a 512 MiB cap that persists the "
        "capture for later re-reads; pcap.inspect (POST /validate) is the "
        "capability.",
    ),
    # -- pipeline router ---------------------------------------------------
    (
        "pipeline:POST /run",
        "Async dispatch: submits runner_dotted='...pipeline_runner...' to the "
        "TaskManager, and it is THAT runner which delegates each stage to the "
        "app producers (which is why pipeline.* is recorded as web-wired). The "
        "string hand-off is invisible to AST.",
    ),
    (
        "pipeline:POST /auto-floor",
        "Calls app.pipeline.pipeline_runner.run_auto_floor_stage rather than "
        "app.tools_pipeline.auto_floor directly; pipeline.auto_floor's web "
        "wiring is that runner.",
    ),
    (
        "pipeline:GET /runs/{task_id}",
        "Task-record read-through for a pipeline run — async transport, not "
        "compute.",
    ),
    (
        "pipeline:DELETE /runs/{task_id}",
        "Cancels a running pipeline task — async transport, not compute.",
    ),
    (
        "pipeline:GET /runs/{task_id}/artifacts/{name}",
        "Serves a finished run's artifact file from the artifact store — "
        "download transport for output the producers already wrote.",
    ),
    (
        "pipeline:GET /runs/{task_id}/neighborhood",
        "Slices the memory-mapped m2 variance array from a run's consensus "
        "state for the hex-overlay minimap; a numpy view over stored task "
        "state, not a producer call.",
    ),
})

#: Minimum characters a reason must have, so no entry can be annotated "wip".
_MIN_REASON_CHARS = 30


# ---------------------------------------------------------------------------
# AST discovery
# ---------------------------------------------------------------------------


def _ids(exemptions: FrozenSet[Tuple[str, str]]) -> FrozenSet[str]:
    return frozenset(identifier for identifier, _reason in exemptions)


def _parse(path: Path) -> ast.Module:
    return ast.parse(path.read_text(), filename=str(path))


def _producer_module_paths() -> List[Path]:
    paths = set()
    for pattern in PRODUCER_MODULE_PATTERNS:
        paths.update(ROOT.glob(pattern))
    return sorted(p for p in paths if p.name != "__init__.py")


def _dotted(path: Path, name: str) -> str:
    rel = path.relative_to(ROOT).with_suffix("")
    return "memdiver." + ".".join(rel.parts) + "." + name


def discover_producers() -> Dict[str, Path]:
    """Return ``{dotted producer path: defining file}`` for the app layer.

    Public module-level functions only; ``.. deprecated::`` shims excluded (see
    the module docstring).
    """
    found: Dict[str, Path] = {}
    for path in _producer_module_paths():
        for node in _parse(path).body:
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            if node.name.startswith("_"):
                continue
            if _DEPRECATED_MARKER in (ast.get_docstring(node) or ""):
                continue
            found[_dotted(path, node.name)] = path
    return found


def discover_deprecated_shims() -> FrozenSet[str]:
    """Dotted paths of the public ``.. deprecated::`` back-compat shims."""
    shims = set()
    for path in _producer_module_paths():
        for node in _parse(path).body:
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            if node.name.startswith("_"):
                continue
            if _DEPRECATED_MARKER in (ast.get_docstring(node) or ""):
                shims.add(_dotted(path, node.name))
    return frozenset(shims)


def _route_decorators(node: ast.AST):
    """Yield ``(method, path)`` for every HTTP-route decorator on ``node``."""
    for dec in getattr(node, "decorator_list", []):
        if not isinstance(dec, ast.Call):
            continue
        func = dec.func
        if not isinstance(func, ast.Attribute) or func.attr not in _HTTP_METHODS:
            continue
        if not isinstance(func.value, ast.Name):
            continue
        route = ""
        if dec.args and isinstance(dec.args[0], ast.Constant):
            if isinstance(dec.args[0].value, str):
                route = dec.args[0].value
        yield func.attr.upper(), route or "/"


def _referenced_names(node: ast.AST) -> FrozenSet[str]:
    names = set()
    for child in ast.walk(node):
        if isinstance(child, ast.Name):
            names.add(child.id)
        elif isinstance(child, ast.Attribute):
            names.add(child.attr)
    return frozenset(names)


def discover_routes() -> Dict[str, FrozenSet[str]]:
    """Return ``{route identifier: names referenced by its handler}``."""
    routes: Dict[str, FrozenSet[str]] = {}
    for path in sorted((ROOT / "api" / "routers").glob("*.py")):
        if path.name == "__init__.py":
            continue
        for node in ast.walk(_parse(path)):
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            for method, route in _route_decorators(node):
                routes[f"{path.stem}:{method} {route}"] = _referenced_names(node)
    return routes


def _registered_producers() -> FrozenSet[str]:
    return frozenset(cap.producer for cap in CAPABILITIES)


def _registered_leaf_names() -> FrozenSet[str]:
    return frozenset(cap.producer.rsplit(".", 1)[1] for cap in CAPABILITIES)


def _covered_routes() -> FrozenSet[str]:
    leaves = _registered_leaf_names()
    return frozenset(
        identifier
        for identifier, names in discover_routes().items()
        if names & leaves
    )


# ---------------------------------------------------------------------------
# Sanity of the discovery itself (a vacuous scan would make everything pass)
# ---------------------------------------------------------------------------


def test_discovery_is_not_vacuous():
    """The scans must actually find things, and find the known landmarks."""
    producers = discover_producers()
    routes = discover_routes()

    assert len(producers) >= 30, f"producer scan looks broken: {len(producers)}"
    assert len(routes) >= 60, f"route scan looks broken: {len(routes)}"

    # Landmarks: one registered producer, one exempt producer, one covered
    # route, one exempt route.
    assert "memdiver.app.tools_inspect.read_hex_result" in producers
    assert "memdiver.app.tools_pipeline.manual_export_pattern" in producers
    assert "inspect:GET /hex" in routes
    assert "architect:POST /check-static" in routes

    assert "inspect:GET /hex" in _covered_routes()


def test_producer_scan_covers_every_registered_producer_module():
    """Every registered capability's producer lives in a SCANNED module.

    Without this, the guard could be dodged by putting the next producer in an
    app module the patterns do not cover.
    """
    scanned = {
        "memdiver." + ".".join(p.relative_to(ROOT).with_suffix("").parts)
        for p in _producer_module_paths()
    }
    outside = sorted(
        cap.producer
        for cap in CAPABILITIES
        if cap.producer.rsplit(".", 1)[0] not in scanned
    )
    assert outside == [], (
        "capability producer(s) live outside PRODUCER_MODULE_PATTERNS — widen "
        "the patterns so the completeness scan can see their module:\n"
        + "\n".join(f"  {p}" for p in outside)
    )


def test_every_exemption_carries_a_reason():
    """No entry may be added without a one-line justification."""
    bad = []
    for label, group in (
        ("producer", EXEMPT_PRODUCERS),
        ("router", EXEMPT_ROUTERS),
        ("route", EXEMPT_ROUTES),
    ):
        for identifier, reason in group:
            if len(reason.strip()) < _MIN_REASON_CHARS:
                bad.append(f"{label} {identifier}: reason too short")
    assert bad == [], "exemption(s) without a real reason:\n" + "\n".join(bad)


def test_exemption_identifiers_are_unique():
    """A frozenset of pairs cannot dedupe by identifier — check it here."""
    for label, group in (
        ("producer", EXEMPT_PRODUCERS),
        ("router", EXEMPT_ROUTERS),
        ("route", EXEMPT_ROUTES),
    ):
        identifiers = [identifier for identifier, _ in group]
        dupes = sorted({i for i in identifiers if identifiers.count(i) > 1})
        assert dupes == [], (
            f"duplicate {label} exemption identifier(s) — merge the reasons: "
            f"{dupes}"
        )


# ---------------------------------------------------------------------------
# The producer ratchet
# ---------------------------------------------------------------------------


def test_every_app_producer_is_registered_or_exempt():
    """RATCHET: no producer may be invisible to the parity ratchet.

    Forward check: a public app-layer producer that is neither registered in
    CAPABILITIES nor exempted below fails. That is the blind spot this module
    exists to close — ``pcap.inspect`` sat wired-on-four-surfaces and
    unregistered, and nothing noticed.
    """
    unaccounted = sorted(
        set(discover_producers())
        - _registered_producers()
        - _ids(EXEMPT_PRODUCERS)
    )
    assert unaccounted == [], (
        "app-layer producer(s) invisible to the capability registry — register "
        "them in CAPABILITIES with the surfaces they GENUINELY have, or add "
        "them to EXEMPT_PRODUCERS with a reason:\n"
        + "\n".join(f"  {p}" for p in unaccounted)
    )


def test_no_exempt_producer_is_registered():
    """STALENESS: an exempted producer that got registered must be un-exempted.

    Mirrors the STALE half of ``KNOWN_PARITY_GAPS``: a ratchet that only
    tightens in one direction rots.
    """
    stale = sorted(_ids(EXEMPT_PRODUCERS) & _registered_producers())
    assert stale == [], (
        "EXEMPT_PRODUCERS entr(ies) are now registered capabilities — delete "
        "them from the exemption list:\n" + "\n".join(f"  {p}" for p in stale)
    )


def test_exempt_producers_exist():
    """Typo guard: every exemption names a producer the scan actually found."""
    producers = set(discover_producers())
    unknown = sorted(_ids(EXEMPT_PRODUCERS) - producers)
    assert unknown == [], (
        "EXEMPT_PRODUCERS names function(s) that no longer exist (renamed, "
        "deleted, or now a `.. deprecated::` shim) — delete the entr(ies):\n"
        + "\n".join(f"  {p}" for p in unknown)
    )


def test_no_deprecated_shim_is_registered():
    """STALENESS for the legacy-shim exclusion rule.

    Public ``.. deprecated::`` functions are excluded from the producer set
    (this is how ``app/tools_inspect_legacy.py`` is handled). If one is ever
    registered as a capability's producer, the exclusion is wrong and the
    registry would be pointing at a shim instead of the real producer.
    """
    shims = discover_deprecated_shims()
    assert shims, "the `.. deprecated::` shim rule found nothing — rule is dead"
    registered_shims = sorted(shims & _registered_producers())
    assert registered_shims == [], (
        "capability producer(s) point at a deprecated back-compat shim rather "
        "than the real producer:\n" + "\n".join(f"  {p}" for p in registered_shims)
    )


# ---------------------------------------------------------------------------
# The route ratchet
# ---------------------------------------------------------------------------


def test_every_api_route_is_covered_or_exempt():
    """RATCHET: no HTTP route may be invisible to the capability registry.

    A route is accounted for when its handler visibly hands off to a
    registered producer, or when it (or its whole router) is exempted with a
    reason. The architect routes are the motivating case: they bypass the app
    layer entirely and would otherwise be nowhere in the registry's field of
    view.
    """
    exempt_routers = _ids(EXEMPT_ROUTERS)
    unaccounted = sorted(
        identifier
        for identifier in discover_routes()
        if identifier.split(":", 1)[0] not in exempt_routers
        and identifier not in _ids(EXEMPT_ROUTES)
        and identifier not in _covered_routes()
    )
    assert unaccounted == [], (
        "API route(s) invisible to the capability registry — route them "
        "through an app-layer producer registered in CAPABILITIES, or add them "
        "to EXEMPT_ROUTES with a reason:\n"
        + "\n".join(f"  {r}" for r in unaccounted)
    )


def test_no_exempt_route_is_covered():
    """STALENESS: an exempted route that now routes through a registered
    producer must lose its exemption."""
    stale = sorted(_ids(EXEMPT_ROUTES) & _covered_routes())
    assert stale == [], (
        "EXEMPT_ROUTES entr(ies) now hand off to a registered producer — "
        "delete them from the exemption list:\n" + "\n".join(f"  {r}" for r in stale)
    )


def test_exempt_routes_exist_and_are_not_double_covered():
    """Typo guard + no overlap with the coarser router-level exemptions."""
    routes = set(discover_routes())
    unknown = sorted(_ids(EXEMPT_ROUTES) - routes)
    assert unknown == [], (
        "EXEMPT_ROUTES names route(s) that no longer exist — delete the "
        "entr(ies):\n" + "\n".join(f"  {r}" for r in unknown)
    )

    exempt_routers = _ids(EXEMPT_ROUTERS)
    redundant = sorted(
        r for r in _ids(EXEMPT_ROUTES) if r.split(":", 1)[0] in exempt_routers
    )
    assert redundant == [], (
        "route exemption(s) inside an already-exempt router — keep ONE level "
        "of exemption per route:\n" + "\n".join(f"  {r}" for r in redundant)
    )


def test_exempt_routers_exist():
    """Typo guard: every exempt router is a real ``api/routers/*.py``."""
    stems = {
        p.stem
        for p in (ROOT / "api" / "routers").glob("*.py")
        if p.name != "__init__.py"
    }
    unknown = sorted(_ids(EXEMPT_ROUTERS) - stems)
    assert unknown == [], (
        "EXEMPT_ROUTERS names router module(s) that do not exist: "
        + ", ".join(unknown)
    )


def test_exempt_routers_are_not_capability_bearing():
    """STALENESS for the coarse exemption: a whole-router exemption is legal
    only while NO route in it hands off to a registered producer.

    The moment a capability lands in an exempted router, the blanket
    exemption stops being honest and must be replaced by per-route entries —
    so the coarse level can only ever cover genuinely capability-free routers.
    """
    covered = _covered_routes()
    offenders = sorted(
        identifier
        for identifier in covered
        if identifier.split(":", 1)[0] in _ids(EXEMPT_ROUTERS)
    )
    assert offenders == [], (
        "route(s) in an EXEMPT_ROUTERS router now hand off to a registered "
        "producer — remove the router-level exemption and account for its "
        "routes individually:\n" + "\n".join(f"  {r}" for r in offenders)
    )

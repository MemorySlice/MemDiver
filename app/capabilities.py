"""Declarative registry of MemDiver capabilities and the surfaces that expose them.

Every user-facing capability is backed by ONE surface-agnostic producer in the
``memdiver.app`` layer. Each surface (the Python library, the CLI, the FastAPI
web app, the MCP server, and — eventually — the marimo UI) is meant to be a thin
presenter that routes to that same producer, so the compute cannot fork.

This module makes that mapping explicit and machine-checkable. It pairs each
capability with its producer's dotted path and the set of surfaces *currently*
routed to that producer. ``tests/test_architecture_invariants.py`` consumes it
as a RATCHET: it asserts every capability is wired on every in-scope surface
except a documented, non-stale set of gaps (:data:`KNOWN_PARITY_GAPS`), and that
every producer path imports and is callable.

That ratchet iterates :data:`CAPABILITIES` and nothing else, so it is blind BY
CONSTRUCTION to a producer that was never registered here — exactly the hole
``pcap.inspect`` sat in (see its comment below). The complementary guard is
``tests/test_capability_completeness.py``: it discovers every public producer in
the app-layer producer modules and every route in ``api/routers/*.py`` by AST
and requires each to be either reachable from :data:`CAPABILITIES` or on an
annotated, shrink-only exemption list. Add a producer without registering it and
that test fails.

Scope note: the registry currently enumerates the presentation-separation
producer families — inspect, xref/structure, the Phase-25 pipeline stages, and
the Phase-5 ``verify`` / ``experiment`` capabilities — plus the dataset/analysis
producers in ``app.tools``. Surfaces are recorded from the ACTUAL wiring
(``cli.py`` subcommands, ``mcp_server/server.py`` tools, ``api/routers/*``, and
re-export of the ``app`` producer through the public ``memdiver.services``
facade for the library). ``marimo`` is a known-incomplete surface
and is deliberately OUT of :data:`IN_SCOPE_SURFACES` for now, so the parity
ratchet does not hold capabilities to it.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import FrozenSet, Tuple

#: Every surface MemDiver can expose a capability on.
ALL_SURFACES: FrozenSet[str] = frozenset(
    {"library", "cli", "web", "mcp", "marimo"}
)

#: Surfaces the cross-surface parity ratchet holds every capability to. ``marimo``
#: is intentionally excluded until its surface is built out.
IN_SCOPE_SURFACES: FrozenSet[str] = frozenset({"library", "cli", "web", "mcp"})


@dataclass(frozen=True)
class Capability:
    """One MemDiver capability, its backing ``app`` producer, and its wiring.

    :param name: Stable dotted capability id (e.g. ``"inspect.processes"``).
    :param producer: Dotted path to the ``app`` producer that owns the compute
        (e.g. ``"memdiver.app.tools_inspect.processes_result"``).
    :param surfaces: The surfaces currently routed to ``producer``.
    """

    name: str
    producer: str
    surfaces: FrozenSet[str]


def _cap(name: str, producer: str, surfaces: Tuple[str, ...]) -> Capability:
    return Capability(name=name, producer=producer, surfaces=frozenset(surfaces))


# The "library" surface means REACHABLE VIA THE SUPPORTED PUBLIC API — i.e.
# re-exported through ``memdiver.services`` (and lifted onto the ``memdiver``
# top level), NOT merely importable from a deep ``memdiver.app.*`` module. As of
# the Phase-6 library-parity work every producer below is re-exported by
# ``memdiver/services.py``, so every capability is genuinely wired on "library".
# The per-capability tuples additionally record cli / web / mcp presence exactly
# as wired today.
CAPABILITIES: Tuple[Capability, ...] = (
    # -- inspect: hex / entropy / strings / byte-search / structured MSL -----
    _cap("inspect.hex", "memdiver.app.tools_inspect.read_hex_result",
         ("library", "cli", "web", "mcp")),
    _cap("inspect.hex_raw", "memdiver.app.tools_inspect.read_hex_raw_result",
         ("library", "web", "mcp")),
    _cap("inspect.resolve_va", "memdiver.app.tools_inspect.resolve_va_result",
         ("library", "web", "mcp")),
    _cap("inspect.byte_search", "memdiver.app.tools_inspect.search_bytes_result",
         ("library", "cli", "web", "mcp")),
    _cap("inspect.entropy", "memdiver.app.tools_inspect.entropy_result",
         ("library", "cli", "web", "mcp")),
    _cap("inspect.strings", "memdiver.app.tools_inspect.strings_result",
         ("library", "cli", "web", "mcp")),
    _cap("inspect.detect_format", "memdiver.app.tools_inspect.detect_format_result",
         ("library", "web", "mcp")),
    _cap("inspect.session_info", "memdiver.app.tools_inspect.session_info_result",
         ("library", "cli", "web", "mcp")),
    _cap("inspect.vas", "memdiver.app.tools_inspect.vas_regions_result",
         ("library", "cli", "web", "mcp")),
    _cap("inspect.page_states", "memdiver.app.tools_inspect.page_states_result",
         ("library", "cli", "web", "mcp")),
    _cap("inspect.processes", "memdiver.app.tools_inspect.processes_result",
         ("library", "cli", "web", "mcp")),
    _cap("inspect.modules", "memdiver.app.tools_inspect.modules_result",
         ("library", "cli", "web", "mcp")),
    _cap("inspect.handles", "memdiver.app.tools_inspect.handles_result",
         ("library", "cli", "web", "mcp")),
    _cap("inspect.connections", "memdiver.app.tools_inspect.connections_result",
         ("library", "web", "mcp")),
    _cap("inspect.module_index", "memdiver.app.tools_inspect.module_index_result",
         ("library", "web", "mcp")),
    _cap("inspect.blocks", "memdiver.app.tools_inspect.blocks_result",
         ("library", "web", "mcp")),
    # "What is at this offset?" — the per-offset investigation view (byte
    # value, local entropy band, printable strings in the neighbourhood). It
    # was a complete, tested producer reachable from NOWHERE, parked in the
    # completeness suite's EXEMPT_PRODUCERS; P2.4 wired the missing web route
    # (GET /api/inspect/region), MCP tool (``analyze_region``), CLI subcommand
    # (``inspect region``) and library re-export in one atomic change, so it is
    # registered truthfully on all four surfaces and needs no KNOWN_PARITY_GAPS
    # entry. The marimo investigation panel still calls
    # core.region_analysis.analyze_region directly, because it holds in-memory
    # variance/hits this path-based producer cannot accept — and marimo is out
    # of IN_SCOPE_SURFACES anyway.
    _cap("inspect.analyze_region", "memdiver.app.tools_inspect.analyze_region_result",
         ("library", "cli", "web", "mcp")),
    # -- xref / structure ----------------------------------------------------
    _cap("xref.cross_references",
         "memdiver.app.tools_xref.get_cross_references_result",
         ("library", "cli", "web", "mcp")),
    _cap("structure.identify",
         "memdiver.app.tools_xref.identify_structure_result",
         ("library", "cli", "web", "mcp")),
    _cap("structure.apply", "memdiver.app.tools_xref.apply_structure_result",
         ("library", "web")),
    # -- pipeline stages (Phase 25) -----------------------------------------
    # The web pipeline (app.pipeline.pipeline_runner, streamed via the task manager)
    # now delegates each stage's compute to these app producers, so web is wired
    # for all of them. ``pipeline.consensus`` on CLI is still a gap — the CLI
    # `consensus` command is a separate region-report implementation, not the
    # origination producer.
    _cap("pipeline.consensus", "memdiver.app.tools_pipeline.consensus",
         ("library", "web", "mcp")),
    _cap("pipeline.search_reduce", "memdiver.app.tools_pipeline.search_reduce",
         ("library", "cli", "web", "mcp")),
    _cap("pipeline.brute_force", "memdiver.app.tools_pipeline.brute_force",
         ("library", "cli", "web", "mcp")),
    _cap("pipeline.n_sweep", "memdiver.app.tools_pipeline.n_sweep",
         ("library", "cli", "web", "mcp")),
    _cap("pipeline.auto_floor", "memdiver.app.tools_pipeline.auto_floor",
         ("library", "cli", "web", "mcp")),
    _cap("pipeline.emit_plugin", "memdiver.app.tools_pipeline.emit_plugin",
         ("library", "cli", "web", "mcp")),
    _cap("pipeline.export_pattern", "memdiver.app.tools_pipeline.export_pattern",
         ("library", "cli", "web", "mcp")),
    # The exact COMPLEMENT of ``export.key_pattern``: "I know the offset, I do
    # not have the key bytes" -- the path out of ``analyze_candidates`` or a
    # reverse-engineering session. It was CLI-only for a long time (and so sat
    # outside the parity ratchet entirely, parked in the completeness suite's
    # EXEMPT_PRODUCERS); P2.3 wired the missing web route
    # (POST /api/analysis/manual-export), MCP tool (``manual_export_pattern``)
    # and library re-export in one atomic change, so it is registered truthfully
    # on all four surfaces and needs no KNOWN_PARITY_GAPS entry.
    _cap("pipeline.manual_export_pattern",
         "memdiver.app.tools_pipeline.manual_export_pattern",
         ("library", "cli", "web", "mcp")),
    # -- consensus: the aligned window (the N-dump differential viewer) -----
    # The ONE place N dumps are read in correspondence. Registered on all four
    # surfaces in the change that introduced it, precisely so it never joins
    # KNOWN_PARITY_GAPS: a capability that ships web-only is how the CLI and
    # MCP surfaces end up re-deriving slab->VA arithmetic of their own, which
    # is the class of bug this producer exists to delete.
    _cap("consensus.aligned_window",
         "memdiver.app.tools_consensus.aligned_window_result",
         ("library", "cli", "web", "mcp")),
    # -- pcap arm/validate (the pcap verification oracle's first step) -------
    # Wired on all four surfaces since Phase 1 (services.py, CLI `inspect-pcap`,
    # POST /api/pcaps/validate, MCP `inspect_pcap`) but never registered here, so
    # the parity ratchet had a blind spot over it. Registering it is a pure
    # tightening: no KNOWN_PARITY_GAPS entry is needed.
    _cap("pcap.inspect", "memdiver.app.tools_pipeline.inspect_pcap",
         ("library", "cli", "web", "mcp")),
    # -- export: Wireshark NSS key log (the mission's headline artifact) -----
    _cap("export.keylog", "memdiver.app.tools_pipeline.keylog_result",
         ("library", "cli", "web", "mcp")),
    # -- verify + experiment (Phase 5, G4) ----------------------------------
    _cap("verify", "memdiver.app.tools_pipeline.verify_key_result",
         ("library", "cli", "web", "mcp")),
    _cap("experiment", "memdiver.app.experiment_orchestration.experiment_result",
         ("library", "cli", "web", "mcp")),
    # -- dataset / analysis (app.tools) -------------------------------------
    # CLI scan/analyze are separate (non-producer) implementations
    # (core.discovery.DatasetScanner / engine.batch), so cli is a gap here.
    _cap("dataset.scan", "memdiver.app.tools.scan_dataset",
         ("library", "web", "mcp")),
    _cap("dataset.list_protocols", "memdiver.app.tools.list_protocols",
         ("library", "web", "mcp")),
    _cap("dataset.list_phases", "memdiver.app.tools.list_phases",
         ("library", "web", "mcp")),
    _cap("analysis.analyze_library", "memdiver.app.tools.analyze_library",
         ("library", "web", "mcp")),
    # -- the exploratory differential path (A4) -----------------------------
    # N dumps in, ranked candidates out, with NO oracle and no capture. Wired
    # on all four surfaces from the start: the whole point of the capability is
    # that the analyst who cannot yet confirm a key still reaches a candidate
    # list, and a headless/agent-driven analyst is exactly that analyst.
    _cap("analysis.candidates", "memdiver.app.tools_pipeline.analyze_candidates",
         ("library", "cli", "web", "mcp")),
    # -- the key-location spine (B1/B3) -------------------------------------
    # "I already hold the secret — which of my dumps still contain it, and
    # where?" and "turn that location into a scanning signature". Both claim all
    # four surfaces from the start for the same reason ``analysis.candidates``
    # does: the headless/agent-driven analyst is the one who most needs the
    # honest three-valued verdict, and the exported rule is a file an agent must
    # be able to ask for.
    _cap("analysis.locate_key", "memdiver.app.tools_pipeline.locate_key",
         ("library", "cli", "web", "mcp")),
    _cap("export.key_pattern", "memdiver.app.tools_pipeline.export_key_pattern",
         ("library", "cli", "web", "mcp")),
    # -- the paired field search (C3) ---------------------------------------
    # ``analysis.locate_key`` above is N dumps and ONE needle. This is N
    # (dump, capture) PAIRS, each dump taking its needle from the capture of
    # the run it belongs to -- the question a corpus of independent handshakes
    # can actually answer, and one no key log is read for. Wired on all four
    # surfaces in the change that introduced it (services.py re-export, CLI
    # ``locate-field-pairs``, POST /api/pcaps/locate-field, MCP
    # ``locate_field_across_pairs``), so it needs no KNOWN_PARITY_GAPS entry --
    # and could not have one, since that baseline is shrink-only.
    _cap("analysis.locate_field_pairs",
         "memdiver.app.tools_pipeline.locate_field_across_pairs",
         ("library", "cli", "web", "mcp")),
    # -- running the rules we EMIT (D1) -------------------------------------
    # ``export.key_pattern`` / ``export_pattern`` above write a signature;
    # until this capability landed nothing could RUN one, so every emitted
    # detector was unevaluated BY CONSTRUCTION. ``engine/yara_scan.py`` was
    # fully built and tested and reachable from no surface at all -- the same
    # hole ``pcap.inspect`` sat in, and the reason
    # ``tests/test_capability_completeness.py`` exists. Named
    # ``analysis.yara_scan`` and NOT ``scan.yara``: ``dataset.scan`` above is a
    # dataset WALK, and a ``scan.*`` family beside it would read as a sibling of
    # that rather than of the analysis producers it actually belongs with.
    # Wired on all four surfaces in the change that introduced it (services.py
    # re-export, CLI ``scan-yara``, POST /api/scan/yara, MCP ``scan_yara_rule``),
    # so it needs no KNOWN_PARITY_GAPS entry -- and could not have one, since
    # that baseline is shrink-only.
    _cap("analysis.yara_scan",
         "memdiver.app.tools_pipeline.scan_yara_rule",
         ("library", "cli", "web", "mcp")),
    # -- and scoring what those rules found (D2) ---------------------------
    # The second half of ``analysis.yara_scan``, and the half that makes it
    # mean anything: a scan says the rule FIRED, and a census of firings with
    # no ground truth beside it measures nothing (a rule matching every page
    # scores a perfect dumps_matched). ``engine/detector_metrics.py`` was the
    # same shape of hole as ``engine/yara_scan.py`` before it -- 472 lines,
    # fully tested, reachable from NO surface. Named ``analysis.score_detector``
    # rather than ``analysis.detector_metrics``: the capability is the act of
    # scoring, and the module name is an implementation detail. Wired on all
    # four surfaces in the change that introduced it (services.py re-export,
    # CLI ``score-detector``, POST /api/scan/score, MCP
    # ``score_detector_matches``), so it needs no KNOWN_PARITY_GAPS entry --
    # and could not have one, since that baseline is shrink-only.
    _cap("analysis.score_detector",
         "memdiver.app.tools_pipeline.score_detector_matches",
         ("library", "cli", "web", "mcp")),
    # -- and RUNNING the Volatility3 plugin we emit (D3) --------------------
    # The vol3 half of ``analysis.yara_scan``. Emitting a plugin was never
    # evidence that it works: for most of this repo's life an emitted plugin
    # was checked only by ``ast.parse`` and substring assertions over its
    # generated text, so one that could not even be IMPORTED passed the whole
    # suite -- and Phase B's four real bugs were all found by RUNNING things,
    # one of them a vol3 export that disagreed with the YARA rule it embedded.
    # ``engine/vol3_verify.py`` (in-process) and ``engine/vol3_subproc.py`` (a
    # real ``vol`` launcher) were written to close that loop and were reachable
    # from NO surface at all -- the same hole ``engine/yara_scan.py`` sat in.
    #
    # Named ``analysis.verify_plugin`` and not ``analysis.vol3_verify``: the
    # capability is the act of verifying an emitted detector, and which of the
    # two engine modules answers is a MODE of the request rather than a
    # different capability. Wired on all four surfaces in the change that
    # introduced it (services.py re-export, CLI ``verify-plugin``,
    # POST /api/scan/verify-plugin, MCP ``verify_vol3_plugin``), so it needs no
    # KNOWN_PARITY_GAPS entry -- and could not have one, since that baseline is
    # shrink-only.
    _cap("analysis.verify_plugin",
         "memdiver.app.tools_pipeline.verify_vol3_plugin",
         ("library", "cli", "web", "mcp")),
    # -- frontend-serving producers (Phase 9) -------------------------------
    # Field inference + algorithm-availability gating were duplicated in the
    # React frontend; they now originate here. Both are wired on the library
    # (re-exported via ``memdiver.services``) and web (FastAPI) surfaces. They
    # carry no CLI subcommand or MCP tool — they exist to feed the web UI — so
    # cli / mcp are documented gaps below.
    _cap("analysis.infer_fields", "memdiver.app.tools_fields.infer_fields_result",
         ("library", "web")),
    _cap("analysis.algorithm_availability",
         "memdiver.app.tools_algorithms.algorithm_availability",
         ("library", "web")),
)


#: (capability, surface) pairs that are IN scope but NOT YET wired — the current,
#: known per-surface parity gaps. This baseline may only SHRINK: the ratchet
#: flags a NEW gap (undocumented) and a STALE gap (documented but now wired).
#:
#: The gaps cluster into a few genuine divergences still to unify:
#:   * inspect read_hex_raw / resolve_va / detect_format / connections /
#:     module_index / blocks and structure.apply lack CLI subcommands.
#:   * structure.apply is web-only (no MCP tool).
#:   * the web pipeline now routes every stage through the app producers
#:     (app.pipeline.pipeline_runner delegates consensus / search_reduce / brute_force /
#:     n_sweep / auto_floor / emit_plugin to ``app.tools_pipeline``), so those are
#:     wired on web. ``pipeline.consensus`` still differs on CLI: the CLI
#:     `consensus` command is a separate region-report implementation, not the
#:     origination producer. (The synchronous ``POST /consensus`` analysis route
#:     is a distinct stateful region/range feature over
#:     ``consensus_session`` — not the origination producer — so it is unaffected.)
#:     ``export_pattern`` is likewise wired everywhere: its CLI `export` command
#:     and the `/auto-export` route both route through the producer.
#:   * dataset scan / list_* / analyze have CLI implementations that do not
#:     route through the app producer.
KNOWN_PARITY_GAPS: FrozenSet[Tuple[str, str]] = frozenset({
    ("inspect.hex_raw", "cli"),
    ("inspect.resolve_va", "cli"),
    ("inspect.detect_format", "cli"),
    ("inspect.connections", "cli"),
    ("inspect.module_index", "cli"),
    ("inspect.blocks", "cli"),
    ("structure.apply", "cli"),
    ("structure.apply", "mcp"),
    ("pipeline.consensus", "cli"),
    ("dataset.scan", "cli"),
    ("dataset.list_protocols", "cli"),
    ("dataset.list_phases", "cli"),
    ("analysis.analyze_library", "cli"),
    # Phase-9 frontend-serving producers: web + library only. No CLI subcommand
    # or MCP tool — they feed the React UI (hex neighborhood overlay / wizard
    # availability), not the terminal/agent surfaces.
    ("analysis.infer_fields", "cli"),
    ("analysis.infer_fields", "mcp"),
    ("analysis.algorithm_availability", "cli"),
    ("analysis.algorithm_availability", "mcp"),
})


def missing_wirings() -> FrozenSet[Tuple[str, str]]:
    """Return every (capability, surface) that is in scope but not yet wired.

    A pair is missing when ``surface`` is in :data:`IN_SCOPE_SURFACES` but not in
    the capability's recorded ``surfaces``. This is the raw gap set the parity
    ratchet compares against :data:`KNOWN_PARITY_GAPS`.
    """
    gaps = set()
    for cap in CAPABILITIES:
        for surface in IN_SCOPE_SURFACES - cap.surfaces:
            gaps.add((cap.name, surface))
    return frozenset(gaps)

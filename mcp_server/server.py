"""MCP server for MemDiver — thin wrappers over tools.py."""

import json
import logging
import sys
from typing import Any, Dict, List, Optional

logger = logging.getLogger("memdiver.mcp_server")


def _resolve_key_material_by_path(
    raw: Optional[Dict[str, Any]],
) -> Optional[Dict[str, Any]]:
    """``{path: {key_file|passphrase|kem_key_file}}`` -> ``{path: open_dump kw}``.

    Per-dump on purpose: an aligned window routinely spans a corpus that mixes
    plaintext captures with containers encrypted under DIFFERENT keys, and one
    flat key triple for the whole call would silently try dump A's key on dump
    B. Entries naming no material at all are dropped so the producer sees a
    mapping with only real keys in it.
    """
    if not raw:
        return None
    from memdiver.app.key_material import has_key_material, key_material_kwargs

    resolved = {}
    for path, spec in raw.items():
        spec = spec or {}
        km = key_material_kwargs(
            spec.get("key_file"), spec.get("passphrase"), spec.get("kem_key_file"),
        )
        if has_key_material(km):
            resolved[str(path)] = km
    return resolved or None


def create_server():
    """Create and configure the MemDiver MCP server."""
    from mcp.server.mcpserver import MCPServer

    from memdiver import __version__

    from memdiver.app import experiment_orchestration
    from memdiver.app.composition import build_tool_session
    # The pinned per-side neighborhood width, imported (never re-literalled) so
    # the MCP surface's default cannot drift from the engine's.
    from memdiver.engine.brute_force import DEFAULT_NEIGHBORHOOD_PAD
    # Same reason again: the pcap verification resource default is the app
    # layer's constant, so the MCP spelling cannot drift from the producer's.
    # ``DEFAULT_INCLUDE_MATCHES`` is ``scan_yara_rule``'s payload verbosity and
    # lives in the app layer rather than the engine because the engine's
    # ``scan_source`` has no such notion — the shape of the ANSWER is the
    # producer's concern.
    # ``DEFAULT_INCLUDE_HITS`` / ``VOL3_*`` are ``verify_vol3_plugin``'s
    # equivalents, and live in the app layer for the same reason: the shape of
    # the ANSWER and the mode vocabulary are the producer's concern, and an
    # agent must see the defaults the library actually applies.
    from memdiver.app.tools_pipeline import (
        DEFAULT_INCLUDE_HITS,
        DEFAULT_INCLUDE_MATCHES,
        DEFAULT_RESOURCE_TYPE,
        VOL3_MAX_HITS,
        VOL3_MODE_AUTO,
        VOL3_SUBPROC_TIMEOUT_S,
    )
    # Same reason: the key-location tool defaults must be the engine's numbers.
    from memdiver.engine.key_location import (
        DEFAULT_KEY_CONTEXT,
        DEFAULT_MAX_KEY_OFFSETS,
    )
    # Same reason once more: ``scan_yara_rule``'s match cap and libyara budget
    # must be the engine's numbers, so the MCP surface cannot advertise a
    # different ceiling from the one the library applies.
    from memdiver.engine.yara_scan import DEFAULT_MAX_MATCHES, DEFAULT_TIMEOUT_S
    # And the same for ``score_detector_matches``'s alignment slack: the
    # tolerance an agent sees advertised must be the one the scorer applies.
    from memdiver.engine.detector_metrics import DEFAULT_TOLERANCE_BYTES

    # Same reason: the region page size an agent sees advertised must be the
    # one the producer actually serves.
    from memdiver.app.tools_consensus import DEFAULT_REGIONS_PER_PAGE

    from mcp.server.mcpserver import ResourceSecurity

    from memdiver.app import tools_consensus

    # Agents get a smaller default row cap than the 1000 of CLI/REST: a SQL
    # result lands in the model's context window.
    MCP_CASE_QUERY_LIMIT = 200
    from memdiver.app import (
        tools_annotations, tools_case, tools_detector_fixtures, tools_disasm, tools_heap, tools_image,
        tools_isf, tools_keyfinders, tools_strings,
        tools_yara, tools_yara_rules, tools_vol3, tools_vol3_dev, tools_vol3_fixtures, tools_vol3_sources,
    )
    # Rows land in the model's context window: a smaller default than REST/CLI.
    MCP_KEYFINDER_LIMIT = 200
    MCP_YARA_LIMIT = 200
    MCP_STRINGS_LIMIT = 200
    # An agent's vol3_run echoes few rows (they land in its context) and has a
    # bounded budget: there is no TaskManager in this stdio process.
    MCP_VOL3_MAX_ROWS = 200
    MCP_VOL3_ROW_LIMIT = 10_000
    MCP_VOL3_TIMEOUT_S = 120.0
    # Same reason: the heap walk cap and chunk page size an agent sees
    # advertised must be the producer's numbers.
    from memdiver.app.tools_heap import (
        DEFAULT_CHUNK_PAGE_SIZE as HEAP_DEFAULT_CHUNK_PAGE_SIZE,
    )
    from memdiver.app.tools_heap import (
        DEFAULT_ROLES_LENGTH as HEAP_DEFAULT_ROLES_LENGTH,
    )
    from memdiver.heap.analyze import DEFAULT_MAX_CHUNKS as HEAP_DEFAULT_MAX_CHUNKS

    from . import tools, tools_inspect, tools_pipeline, tools_xref
    from .presenters import mcp_error_funnel, present_inspect_mcp_call

    mcp = MCPServer(
        "memdiver",
        instructions="Memory dump forensic analysis platform for cryptographic key identification",
        version=__version__,
    )
    _session = build_tool_session()

    def _session_region_filter(region_filter: Optional[str]) -> Optional[str]:
        """Explicit ``region_filter`` wins (``"all"`` = none); else the session's."""
        return _session.region_filter if region_filter is None else region_filter

    @mcp.tool()
    @mcp_error_funnel
    def scan_dataset(
        dataset_root: str,
        keylog_filename: str = "keylog.csv",
        protocols: Optional[List[str]] = None,
    ) -> str:
        """Scan a dataset directory for available protocols, libraries, and phases."""
        return json.dumps(tools.scan_dataset(_session, dataset_root, keylog_filename, protocols))

    @mcp.tool()
    @mcp_error_funnel
    def list_phases(library_dir: str) -> str:
        """List available lifecycle phases for a library directory."""
        return json.dumps(tools.list_phases(_session, library_dir))

    @mcp.tool()
    @mcp_error_funnel
    def list_protocols() -> str:
        """List all registered protocol descriptors with versions and secret types."""
        return json.dumps(tools.list_protocols(_session))

    @mcp.tool()
    @mcp_error_funnel
    def set_region_filter(region_filter: Optional[str] = None) -> str:
        """Set the session's analysis-time region view filter.

        ``region_filter`` is a comma list of region categories (``"heap,stack"``;
        categories as for ``import_raw_dump``'s ``region_types``) or a
        ``"regions=..."`` note; ``"all"`` or omitting it clears the filter.
        Tools that take ``region_filter`` use this value when their own is
        omitted (``.msl`` inputs only). Returns the normalised
        ``region_filter`` (``null`` = every region) and ``active``.
        """
        return json.dumps(tools.set_region_filter(_session, region_filter))

    @mcp.tool()
    @mcp_error_funnel
    def get_region_filter() -> str:
        """Return the session's region view filter (``null`` = every region)."""
        return json.dumps(tools.get_region_filter(_session))

    @mcp.tool()
    @mcp_error_funnel
    def analyze_library(
        library_dirs: List[str],
        phase: str,
        protocol_version: str,
        keylog_filename: str = "keylog.csv",
        template_name: str = "Auto-detect",
        max_runs: int = 10,
        normalize: bool = False,
        expand_keys: bool = True,
        algorithms: Optional[List[str]] = None,
        force_memory: bool = False,
    ) -> str:
        """Run the full analysis pipeline on library directories at a specific phase.

        ``force_memory`` overrides the memory-budget guard: an over-budget
        consensus build is refused with code ``memory_budget_exceeded``
        (``estimate_bytes`` / ``budget_bytes`` in the error) unless
        ``force_memory=true``.
        """
        return json.dumps(tools.analyze_library(
            _session, library_dirs, phase, protocol_version,
            keylog_filename, template_name, max_runs, normalize, expand_keys,
            algorithms, force=force_memory,
        ))

    @mcp.tool()
    def read_hex(
        dump_path: str, offset: int = 0, length: int = 256, view: str = "raw",
        key_file: Optional[str] = None, passphrase: Optional[str] = None,
        kem_key_file: Optional[str] = None,
        region_filter: Optional[str] = None,
    ) -> str:
        """Read raw bytes from a dump file. Returns hex + ASCII representation.

        For ``.msl`` files, ``view="raw"`` (default) reads the container
        bytes; ``view="vas"`` reads the flattened captured-memory projection.
        Encrypted ``.msl`` inputs are decrypted when key material is supplied.

        ``region_filter`` (``.msl`` only; e.g. ``"heap,stack"``) reads through
        the region VIEW filter, so ``offset`` is a filtered-view offset;
        omitted, the session's filter applies and ``"all"`` disables it.
        """
        return json.dumps(present_inspect_mcp_call(lambda: tools_inspect.read_hex_result(
            _session, dump_path, offset, length, view,
            key_file, passphrase, kem_key_file,
            region_filter=_session_region_filter(region_filter),
        )))

    @mcp.tool()
    @mcp_error_funnel
    def get_entropy(
        dump_path: str, offset: int = 0, length: int = 0,
        window: int = 32, step: int = 16, threshold: Optional[float] = None,
        key_file: Optional[str] = None, passphrase: Optional[str] = None,
        kem_key_file: Optional[str] = None, view: Optional[str] = None,
        resolution: str = "auto", buckets: Optional[int] = None,
    ) -> str:
        """Compute sliding-window entropy profile for a dump file region.

        ``view`` ("raw" / "vas" / "va") profiles that byte view; omitted = the
        dump's flat view. The response's ``view`` names the view used.
        ``threshold`` omitted = window-aware default (4.5 at window 32).
        ``resolution``: "full" (every window, exact regions + min/max envelope),
        "sampled" (bounded step), "auto" (full for inputs up to 8 MiB).
        """
        return json.dumps(present_inspect_mcp_call(lambda: tools_inspect.entropy_result(
            _session, dump_path, offset, length, window, step, threshold,
            key_file=key_file, passphrase=passphrase, kem_key_file=kem_key_file,
            view=view, buckets=buckets, resolution=resolution,
        )))

    @mcp.tool()
    @mcp_error_funnel
    def analyze_region(
        dump_path: str, offset: int, window: int = 64, view: str = "raw",
        key_file: Optional[str] = None, passphrase: Optional[str] = None,
        kem_key_file: Optional[str] = None,
    ) -> str:
        """Investigate one offset: byte value, local entropy band, strings.

        The agent-facing "what is at this offset?" probe — the natural
        follow-up to a byte-search or entropy hit. Only the ``window``-sized
        neighbourhood is read, so it is cheap on multi-GB dumps.
        """
        return json.dumps(present_inspect_mcp_call(lambda: tools_inspect.analyze_region_result(
            _session, dump_path, offset, window, view,
            key_file, passphrase, kem_key_file,
        )))

    @mcp.tool()
    @mcp_error_funnel
    def extract_strings(
        dump_path: str, offset: int = 0, length: int = 0,
        min_length: int = 4, encoding: str = "ascii", max_results: int = 500,
        cursor: int = 0, chunk_size: int = 8 * 1024 * 1024,
        key_file: Optional[str] = None, passphrase: Optional[str] = None,
        kem_key_file: Optional[str] = None,
    ) -> str:
        """Extract printable strings from a dump file."""
        return json.dumps(present_inspect_mcp_call(lambda: tools_inspect.strings_result(
            _session, dump_path, offset, length, min_length, encoding, max_results,
            cursor, chunk_size, key_file, passphrase, kem_key_file,
        )))

    @mcp.tool()
    def get_session_info(
        msl_path: str, key_file: Optional[str] = None,
        passphrase: Optional[str] = None, kem_key_file: Optional[str] = None,
    ) -> str:
        """Extract session metadata from an MSL file (process, modules, VAS)."""
        return json.dumps(present_inspect_mcp_call(lambda: tools_inspect.session_info_result(
            _session, msl_path, key_file, passphrase, kem_key_file,
        )))

    @mcp.tool()
    def vas_regions(
        msl_path: str, key_file: Optional[str] = None,
        passphrase: Optional[str] = None, kem_key_file: Optional[str] = None,
    ) -> str:
        """List the per-dump VAS region layout from an MSL file.

        Emits the full five-field entries (base_addr/region_size/region_type/
        protection/mapped_path) the VasChart frontend consumes.
        """
        return json.dumps(present_inspect_mcp_call(lambda: tools_inspect.vas_regions_result(
            _session, msl_path, key_file=key_file, passphrase=passphrase,
            kem_key_file=kem_key_file,
        )))

    @mcp.tool()
    def get_processes(
        msl_path: str, key_file: Optional[str] = None,
        passphrase: Optional[str] = None, kem_key_file: Optional[str] = None,
    ) -> str:
        """List processes captured in an MSL file (pid/ppid/uid/exe/cmdline)."""
        return json.dumps(present_inspect_mcp_call(lambda: tools_inspect.processes_result(
            _session, msl_path, key_file, passphrase, kem_key_file,
        )))

    @mcp.tool()
    def get_modules(
        msl_path: str, key_file: Optional[str] = None,
        passphrase: Optional[str] = None, kem_key_file: Optional[str] = None,
    ) -> str:
        """List loaded modules in an MSL file (path/base_addr/size/version)."""
        return json.dumps(present_inspect_mcp_call(lambda: tools_inspect.modules_result(
            _session, msl_path, key_file, passphrase, kem_key_file,
        )))

    @mcp.tool()
    def get_handles(
        msl_path: str, key_file: Optional[str] = None,
        passphrase: Optional[str] = None, kem_key_file: Optional[str] = None,
    ) -> str:
        """List open handles/fds in an MSL file (pid/fd/type/path)."""
        return json.dumps(present_inspect_mcp_call(lambda: tools_inspect.handles_result(
            _session, msl_path, key_file, passphrase, kem_key_file,
        )))

    # -- heap.* : allocator-aware heap analysis -----------------------------
    # Shared vocabulary for the six heap tools (repeated in each docstring
    # because the docstring IS the tool description an agent reads):
    # ``allocator`` is ``auto`` (detect) or one of ptmalloc2 (glibc), dlmalloc,
    # scudo (Android), mallocng (musl), jemalloc (partial: slab level only) or
    # generic (heuristic fallback when nothing else fits).

    @mcp.tool()
    @mcp_error_funnel
    def heap_detect(
        dump_path: str, allocator: str = "auto", base_va: Optional[int] = None,
        key_file: Optional[str] = None, passphrase: Optional[str] = None,
        kem_key_file: Optional[str] = None,
    ) -> str:
        """Identify which heap allocator produced a dump. START HERE for heap work.

        Returns ranked ``candidates`` (each with a confidence and the
        ``evidence`` behind it), the ``best`` verdict and the detected
        ``platform`` (os/arch/pointer_size). Supported allocators: ptmalloc2
        (glibc), dlmalloc, scudo (Android), mallocng (musl), jemalloc (partial,
        slab level) and a ``generic`` heuristic fallback. ``allocator`` other
        than ``auto`` is echoed back as the verdict (``hinted: true``).
        ``base_va`` sets the VA of a flat raw dump without a ``.maps`` sidecar.
        Works on ``.msl`` (pass key material if encrypted) and raw dumps.
        """
        return json.dumps(present_inspect_mcp_call(lambda: tools_heap.heap_detect_result(
            _session, dump_path, allocator, base_va=base_va,
            key_file=key_file, passphrase=passphrase, kem_key_file=kem_key_file,
        )))

    @mcp.tool()
    @mcp_error_funnel
    def heap_summary(
        dump_path: str, allocator: str = "auto", base_va: Optional[int] = None,
        max_chunks: int = HEAP_DEFAULT_MAX_CHUNKS, regions: Optional[List[str]] = None,
        key_file: Optional[str] = None, passphrase: Optional[str] = None,
        kem_key_file: Optional[str] = None,
    ) -> str:
        """Whole-heap overview: the cheap first look before paging chunks.

        Parses the heap with ``allocator`` (``auto`` detects; ptmalloc2,
        dlmalloc, scudo, mallocng, jemalloc [partial], generic [heuristic])
        and returns the heap ``regions``, chunk counts and bytes per state
        (in_use/free/cached/quarantined), a power-of-two ``size_histogram``,
        ``role_bytes`` (bytes per role: chunk_header, user_data, free_link,
        free_data, allocator_meta, top, slack), ``metadata_bytes``, ``free_list_count``, ``coverage``
        and parser ``diagnostics``. ``partial``/``heuristic`` flag an
        allocator whose parse is incomplete or guessed. ``regions`` limits
        parsing to the named mappings; ``max_chunks`` caps the walk.
        """
        return json.dumps(present_inspect_mcp_call(lambda: tools_heap.heap_summary_result(
            _session, dump_path, allocator, base_va=base_va,
            max_chunks=max_chunks, regions=regions,
            key_file=key_file, passphrase=passphrase, kem_key_file=kem_key_file,
        )))

    @mcp.tool()
    @mcp_error_funnel
    def heap_chunks(
        dump_path: str, allocator: str = "auto", state: Optional[str] = None,
        min_size: Optional[int] = None, max_size: Optional[int] = None,
        va_start: Optional[int] = None, va_end: Optional[int] = None,
        offset: Optional[int] = None, length: Optional[int] = None,
        view: str = "vas", page: int = 0,
        page_size: int = HEAP_DEFAULT_CHUNK_PAGE_SIZE,
        base_va: Optional[int] = None, max_chunks: int = HEAP_DEFAULT_MAX_CHUNKS,
        regions: Optional[List[str]] = None, key_file: Optional[str] = None,
        passphrase: Optional[str] = None, kem_key_file: Optional[str] = None,
    ) -> str:
        """One page of the parsed chunk table (va, size, state, user_va, ...).

        Use to enumerate allocations, e.g. every free chunk of a key-sized
        class. Filters: ``state`` (in_use/free/cached/quarantined; cached =
        parked in tcache/fastbin, so freed though still marked in use), ``min_size``/``max_size``
        and ONE window -- ``va_start``/``va_end`` (half-open VAs) OR
        ``offset``/``length`` in ``view`` (``vas`` dense captured memory,
        ``raw`` file bytes, ``va`` sparse .msl VA view); never both. Each row
        carries ``view_offset`` so it can be opened with ``read_hex``.
        ``page`` is 0-based; ``page_size`` max 2000. Allocators as for
        ``heap_summary`` (``auto`` detects).
        """
        return json.dumps(present_inspect_mcp_call(lambda: tools_heap.heap_chunks_result(
            _session, dump_path, allocator, state=state, min_size=min_size,
            max_size=max_size, va_start=va_start, va_end=va_end, offset=offset,
            length=length, view=view, page=page, page_size=page_size,
            base_va=base_va, max_chunks=max_chunks, regions=regions,
            key_file=key_file, passphrase=passphrase, kem_key_file=kem_key_file,
        )))

    @mcp.tool()
    @mcp_error_funnel
    def heap_chunk_at(
        dump_path: str, allocator: str = "auto", va: Optional[int] = None,
        offset: Optional[int] = None, view: str = "vas",
        base_va: Optional[int] = None, max_chunks: int = HEAP_DEFAULT_MAX_CHUNKS,
        regions: Optional[List[str]] = None, key_file: Optional[str] = None,
        passphrase: Optional[str] = None, kem_key_file: Optional[str] = None,
    ) -> str:
        """Which heap chunk owns an address, and what role does that byte play?

        Give exactly ONE of ``va`` or ``offset`` (in ``view``: vas/raw/va).
        Use it on a candidate key hit (e.g. from ``search_bytes`` or
        ``locate_key``) to tell user data from allocator metadata. Returns
        ``found``, the containing ``chunk``, the byte's ``role``
        (chunk_header, user_data, free_link, free_data [stale payload in a
        freed chunk], allocator_meta, top, slack, none), ``offset_in_chunk``/``offset_in_user`` and the ``prev``/``next``
        neighbour chunks (nearest below/above when ``found`` is false).
        Allocators as for ``heap_summary`` (``auto`` detects).
        """
        return json.dumps(present_inspect_mcp_call(lambda: tools_heap.heap_chunk_at_result(
            _session, dump_path, allocator, va=va, offset=offset, view=view,
            base_va=base_va, max_chunks=max_chunks, regions=regions,
            key_file=key_file, passphrase=passphrase, kem_key_file=kem_key_file,
        )))

    @mcp.tool()
    @mcp_error_funnel
    def heap_free_lists(
        dump_path: str, allocator: str = "auto", kind: Optional[str] = None,
        base_va: Optional[int] = None, max_chunks: int = HEAP_DEFAULT_MAX_CHUNKS,
        regions: Optional[List[str]] = None, key_file: Optional[str] = None,
        passphrase: Optional[str] = None, kem_key_file: Optional[str] = None,
    ) -> str:
        """Walk the allocator's free lists (tcache bins, fastbins, ...).

        Use to find freed-but-not-wiped allocations (residual secrets) and to
        spot heap corruption. Returns every list (or only those of ``kind``;
        ``kinds`` lists what exists) with ``head_va``, the ``chunk_vas`` in
        link order, ``decoded`` (safe-linking undone), a ``cycle`` flag and a
        ``corrupt`` flag when an entry is not a parsed chunk start
        (``unresolved_vas``). Allocators as for ``heap_summary`` (``auto``
        detects); lists exist only where the allocator keeps them.
        """
        return json.dumps(present_inspect_mcp_call(lambda: tools_heap.heap_free_lists_result(
            _session, dump_path, allocator, kind=kind, base_va=base_va,
            max_chunks=max_chunks, regions=regions,
            key_file=key_file, passphrase=passphrase, kem_key_file=kem_key_file,
        )))

    @mcp.tool()
    @mcp_error_funnel
    def heap_roles(
        dump_path: str, allocator: str = "auto", view: str = "vas",
        offset: int = 0, length: int = HEAP_DEFAULT_ROLES_LENGTH,
        base_va: Optional[int] = None, max_chunks: int = HEAP_DEFAULT_MAX_CHUNKS,
        regions: Optional[List[str]] = None, key_file: Optional[str] = None,
        passphrase: Optional[str] = None, kem_key_file: Optional[str] = None,
    ) -> str:
        """Role of every heap byte in a window, as coalesced runs.

        Use to colour a hex window or to see at a glance which bytes of a
        region are allocator metadata vs. user data. The window is
        ``offset``/``length`` in ``view`` (``vas`` dense captured memory,
        ``raw`` file bytes, ``va`` sparse .msl VA view); ``length`` max
        1 MiB. Returns ``runs`` (``{offset, length, role}`` in view offsets,
        sorted, non-overlapping; role is chunk_header, user_data, free_link,
        free_data, allocator_meta, top or slack -- bytes in no chunk are
        omitted), ``chunk_starts`` (view offsets of chunk starts in the
        window) and the allocator's ``partial``/``heuristic`` flags.
        Allocators as for ``heap_summary`` (``auto`` detects).
        """
        return json.dumps(present_inspect_mcp_call(lambda: tools_heap.heap_roles_result(
            _session, dump_path, allocator, view=view, offset=offset,
            length=length, base_va=base_va, max_chunks=max_chunks,
            regions=regions,
            key_file=key_file, passphrase=passphrase, kem_key_file=kem_key_file,
        )))

    # -- annotations.* : the versioned analysis record of a capture ----------
    # ``case_dir`` is required until the Case abstraction (default
    # ~/.memdiver/cases/<name>) lands. Locations are dicts as in
    # ``Location.to_dict()``: {"space": "physical", "value": 4096, ...}.
    @mcp.tool()
    def annotations_list(
        case_dir: str, capture_id: str, kind: Optional[str] = None,
        include_superseded: bool = False,
    ) -> str:
        """List what has been concluded about a capture (its analysis record).

        Returns the CURRENT entries of ``capture_id`` in ``case_dir`` (an
        entry replaced by a newer one, and retractions, are hidden unless
        ``include_superseded``). Each entry has id, kind, author
        (human/agent/tool:<name>), locations, length, label, payload, support
        and a ``superseded`` flag. ``case_dir`` is required.
        """
        return json.dumps(present_inspect_mcp_call(
            lambda: tools_annotations.annotations_list_result(
                case_dir, capture_id, kind, include_superseded)))

    @mcp.tool()
    def annotations_add(
        case_dir: str, capture_id: str, kind: str = "annotation",
        author: str = "agent", locations: Optional[List[dict]] = None,
        label: str = "", payload: Optional[dict] = None,
        support: Optional[List[dict]] = None, length: Optional[int] = None,
    ) -> str:
        """Record a conclusion about a capture (append-only, never edits history).

        ``locations`` are dicts like ``{"space": "physical", "value": 4096}``
        (spaces: physical, kernel_va, process_va [needs pid], msl_va, msl_vas,
        module_rel [needs module], object_field [needs object_id],
        file_offset). ``support`` is a list of ``{"kind", "ref"}`` evidence
        items. ``author`` is human, agent or tool:<name>. Returns the stored
        entry including its id.
        """
        return json.dumps(present_inspect_mcp_call(
            lambda: tools_annotations.annotations_add_result(
                case_dir, capture_id, kind, author, locations, label, payload,
                support, length)))

    @mcp.tool()
    def annotations_supersede(
        case_dir: str, capture_id: str, entry_id: str, author: str = "agent",
        kind: Optional[str] = None, locations: Optional[List[dict]] = None,
        label: Optional[str] = None, payload: Optional[dict] = None,
        support: Optional[List[dict]] = None, length: Optional[int] = None,
    ) -> str:
        """Correct an entry: append a replacement that supersedes ``entry_id``.

        Fields you omit are inherited from the old entry; the old one stays in
        the log, flagged superseded. Use ``annotations_list`` for entry ids.
        """
        changes = {"kind": kind, "locations": locations, "label": label,
                   "payload": payload, "support": support, "length": length}
        return json.dumps(present_inspect_mcp_call(
            lambda: tools_annotations.annotations_supersede_result(
                case_dir, capture_id, entry_id, author,
                **{k: v for k, v in changes.items() if v is not None})))

    @mcp.tool()
    def annotations_retract(
        case_dir: str, capture_id: str, entry_id: str, author: str = "agent",
        reason: str = "",
    ) -> str:
        """Withdraw an entry (a retraction is appended; nothing is deleted)."""
        return json.dumps(present_inspect_mcp_call(
            lambda: tools_annotations.annotations_retract_result(
                case_dir, capture_id, entry_id, author, reason)))

    # -- case.* : the case data lake (Parquet tables + read-only SQL) ---------
    @mcp.tool()
    def case_init(case: str) -> str:
        """Create (or re-open) a case. A bare name means ~/.memdiver/cases/<name>."""
        return json.dumps(present_inspect_mcp_call(
            lambda: tools_case.case_init_result(case)))

    @mcp.tool()
    def case_status(case_dir: str) -> str:
        """Manifest, tables (runs, row counts) and annotation captures of a case."""
        return json.dumps(present_inspect_mcp_call(
            lambda: tools_case.case_status_result(case_dir)))

    @mcp.tool()
    def case_schema(case_dir: str) -> str:
        """Columns, types, location mappings, runs and rows per table.

        Every table carries capture_id, image_sha256, pid, space, addr, size,
        run_id; analysis-record entries are queryable as ``annotations``.
        """
        return json.dumps(present_inspect_mcp_call(
            lambda: tools_case.case_schema_result(case_dir)))

    @mcp.tool()
    def case_query(
        case_dir: str, sql: str, limit: int = MCP_CASE_QUERY_LIMIT,
        params: Optional[List[Any]] = None,
    ) -> str:
        """Run ONE read-only SELECT over the case tables (DuckDB SQL).

        Anything but a single SELECT is refused. Bind values with positional
        ``?`` placeholders via ``params`` rather than formatting them into the
        SQL. Rows are capped at ``limit``; ``truncated`` says whether more
        existed. Call ``case_schema`` first for table and column names.
        """
        return json.dumps(present_inspect_mcp_call(
            lambda: tools_case.case_query_result(case_dir, sql, limit, params)))

    @mcp.tool()
    def context_at(
        case_dir: str, location: dict, length: int = 1,
        dump_path: Optional[str] = None, tables: Optional[List[str]] = None,
    ) -> str:
        """What contains this address? Table rows and annotations, outermost first.

        ``location`` is a dict like ``{"space": "kernel_va", "value": 4096,
        "capture_id": "<id>", "pid": 1}``; ``capture_id`` is required. One
        range-containment query over every case table (VMAs, modules, heap
        chunks, ...) plus the current annotations. With ``dump_path`` the
        result also reports how much of ``[value, value+length)`` the capture
        holds, when the dump supports it.
        """
        return json.dumps(present_inspect_mcp_call(
            lambda: tools_case.context_at_result(
                case_dir, location, length, dump_path, tables)))

    @mcp.tool()
    def case_export(case_dir: str, dump_path: str, what: Optional[List[str]] = None,
                    run_id: Optional[str] = None) -> str:
        """Export a dump's tables into a case (so ``case_query``/``context_at`` see them).

        ``dump_path`` is an ``.mdview`` image view or an ``.msl``. ``what`` is
        ``["auto"]`` (default: view regions for a view; regions, page states and
        heap chunks for an ``.msl``, heap skipped when no allocator is found) or any
        of ``view_regions``, ``msl_regions``, ``page_states``, ``heap_chunks``.
        Runs inline and blocks on a large image. Returns the registered tables
        (``table``, ``run_id``, ``rows``, ``path``) and a ``skipped`` list.
        """
        return json.dumps(present_inspect_mcp_call(
            lambda: tools_case.case_export_result(
                case_dir, dump_path, tuple(what or ("auto",)), run_id)))

    @mcp.tool()
    def keyfinders_list() -> str:
        """List the key finders (structure-based key recognisers) and the ``params`` each reads."""
        return json.dumps(present_inspect_mcp_call(
            lambda: tools_keyfinders.keyfinders_list_result()))

    @mcp.tool()
    def keyfinders_scan(
        dump_path: str, finders: Optional[List[str]] = None, view: Optional[str] = None,
        offset: Optional[int] = None, length: Optional[int] = None,
        heap_policy: str = "annotate", params: Optional[Dict[str, Any]] = None,
        case_dir: Optional[str] = None, limit: int = MCP_KEYFINDER_LIMIT,
        candidates_out: Optional[str] = None, annotate: bool = True,
    ) -> str:
        """Scan the CAPTURED bytes of a dump (.msl, .mdview, raw) for key material.

        ``finders`` default ``["aes_schedule"]`` (``keyfinders_list`` names them).
        ``view``/``offset``/``length`` pick the window in the view's coordinates
        (``va`` default for .msl/.mdview, ``vas`` for .msl, ``raw`` for a flat file).
        A structure straddling a capture gap is never found in invented zeros.
        ``heap_policy``: ``off`` | ``annotate`` (chunk context) | ``mask`` (keep only
        hits inside one chunk's user data). Every row has ``addr`` + ``space`` +
        ``location``; ``coverage`` says what was scanned and ``truncated`` whether
        ``limit`` cut the rows. ``candidates`` feeds verify/brute_force. With
        ``case_dir`` the hits become the ``key_hits`` case table (joinable to
        ``heap_chunks``/``msl_regions`` by ``case_query``) and ``key_hit`` annotations.
        Runs inline and blocks on a large capture.
        """
        return json.dumps(present_inspect_mcp_call(
            lambda: tools_keyfinders.keyfinders_scan_result(
                dump_path, tuple(finders or tools_keyfinders.DEFAULT_FINDERS), view,
                offset, length, heap_policy, params, case_dir, limit, candidates_out,
                annotate)))

    @mcp.tool()
    def yara_check(rule_source: Optional[str] = None, rule_name: Optional[str] = None,
                   case_dir: Optional[str] = None) -> str:
        """Compile a YARA rule WITHOUT scanning: ``valid`` plus ``rule_names``.

        Give ``rule_source`` or a stored ``rule_name`` (+ ``case_dir``), not both.

        A rule that does not compile is an answer, not an error: ``valid: false`` and
        ``errors: [{line, message}]`` (1-based line). ``warnings`` flags a wildcard hex
        string wider than the installed libyara will verify (it matches nothing).
        """
        return json.dumps(present_inspect_mcp_call(
            lambda: tools_yara.yara_check_result(rule_source, rule_name, case_dir)))

    @mcp.tool()
    def yara_scan_dump(
        dump_path: str, rule_source: Optional[str] = None, view: Optional[str] = None,
        offset: Optional[int] = None, length: Optional[int] = None,
        limit: int = MCP_YARA_LIMIT, timeout_s: int = tools_yara.DEFAULT_TIMEOUT_S,
        rule_name: Optional[str] = None, case_dir: Optional[str] = None,
    ) -> str:
        """Scan the CAPTURED bytes of ONE dump (.msl, .mdview, raw) with a YARA rule.

        ``view``/``offset``/``length`` pick the window in the view's coordinates (``va``
        default for .msl/.mdview, ``vas`` for .msl, ``raw`` for a flat file). Only captured
        runs are read: a pattern straddling a capture gap is never found in invented
        zeros. Rows carry rule, string_id, ``addr`` + ``space`` + ``location``, length,
        ``matched_hex`` preview, ``va``, ``vas_offset``, ``region``; ``coverage`` says what
        was scanned and ``truncated`` / ``complete`` / ``incomplete_reason`` whether the
        rows are the whole truth. A non-compiling rule is INVALID_INPUT (use ``yara_check``
        for the line). For a many-dump census use ``scan_yara_rule``. Give ``rule_source`` or
        a stored ``rule_name`` (+ ``case_dir``), not both.
        """
        return json.dumps(present_inspect_mcp_call(
            lambda: tools_yara.yara_scan_dump_result(
                dump_path, rule_source, view, offset, length, limit, timeout_s,
                rule_name, case_dir)))

    @mcp.tool()
    def yara_rule_list(case_dir: Optional[str] = None) -> str:
        """List stored YARA rules: the per-user library and, with ``case_dir``, the case's.

        Rows (no source): name, ``scope`` (library | case), sha256, size, version, updated,
        ``compiles``, ``errors``, ``rule_names``, ``modified_externally``; ``shadows`` marks a
        case rule that hides a library one of the same name. An unreadable rule is a row with
        ``error``; a missing ``case_dir`` leaves the library rows and sets ``case_error``.
        """
        return json.dumps(present_inspect_mcp_call(
            lambda: tools_yara_rules.yara_rule_list_result(case_dir)))

    @mcp.tool()
    def yara_rule_get(name: str, case_dir: Optional[str] = None,
                      scope: Optional[str] = None) -> str:
        """One stored YARA rule with its source.

        ``scope``: ``library`` | ``case`` (exactly that scope) | ``auto`` (default: the case,
        when ``case_dir`` is given, wins over the library).
        """
        return json.dumps(present_inspect_mcp_call(
            lambda: tools_yara_rules.yara_rule_get_result(name, case_dir, scope)))

    @mcp.tool()
    def yara_rule_put(name: str, rule_source: str, scope: Optional[str] = None,
                      case_dir: Optional[str] = None) -> str:
        """Store a YARA rule as ``name`` in ``scope`` (``library`` or ``case`` + ``case_dir``).

        An omitted ``scope`` is ``case`` when ``case_dir`` is given, else ``library``.

        The rule is compile-checked; a draft that does not compile is SAVED and flagged
        (``stored.compiles: false``, ``check.errors`` with lines). The previous version is kept
        in the scope's history. Scan or check it later by ``rule_name``.
        """
        return json.dumps(present_inspect_mcp_call(
            lambda: tools_yara_rules.yara_rule_put_result(name, rule_source, scope, case_dir)))

    @mcp.tool()
    def yara_rule_delete(name: str, scope: Optional[str] = None,
                         case_dir: Optional[str] = None) -> str:
        """Remove a stored YARA rule from exactly ``scope`` (not found if only in the other one).

        An omitted ``scope`` is ``case`` when ``case_dir`` is given, else ``library``. The last
        source is archived to history.
        """
        return json.dumps(present_inspect_mcp_call(
            lambda: tools_yara_rules.yara_rule_delete_result(name, scope, case_dir)))

    # -- ISF workbench: pakunoda probes, versioned ISF drafts in a case, the try-loop.
    @mcp.tool()
    def isf_probe(image_path: str, probe: str, arch: str = "auto",
                  params: Optional[Dict[str, Any]] = None, case_dir: Optional[str] = None,
                  draft: Optional[str] = None) -> str:
        """Run one pakunoda probe on a full image: ``viability``, ``banner``, ``vmcoreinfo``,
        ``kallsyms``, ``btf``, ``init_task``, ``page_table_root``, ``utsname``, ``ksymtab`` or
        ``layout_legs``.

        Rows carry ``Location`` dicts; ``counts``, ``truncated`` and ``timings`` qualify them.
        ``params``: ``limit``, ``va_bits``, ``page_size``, ``type_hints_isf``. ``case_dir`` +
        ``draft`` feed kallsyms/vmcoreinfo/btf/layout_legs findings into that draft. Runs
        inline: kallsyms on a multi-GB image can take over a minute.
        """
        return json.dumps(present_inspect_mcp_call(
            lambda: tools_isf.isf_probe_result(
                image_path, probe, arch=arch, params=params, case_dir=case_dir, draft=draft)))

    @mcp.tool()
    def isf_draft_create(case_dir: str, capture_id: str, name: str, arch: str,
                         banner: Optional[str] = None,
                         base_metadata: Optional[Dict[str, Any]] = None) -> str:
        """Create an empty ISF draft ``name`` for a capture (the image sha256) in a case."""
        return json.dumps(present_inspect_mcp_call(
            lambda: tools_isf.isf_draft_create_result(
                case_dir, capture_id, name, arch, author="agent", banner=banner,
                base_metadata=base_metadata)))

    @mcp.tool()
    def isf_draft_list(case_dir: str, capture_id: str) -> str:
        """List the ISF drafts of a capture."""
        return json.dumps(present_inspect_mcp_call(
            lambda: tools_isf.isf_draft_list_result(case_dir, capture_id)))

    @mcp.tool()
    def isf_draft_get(case_dir: str, capture_id: str, name: str,
                      only: Optional[Dict[str, List[str]]] = None,
                      version: Optional[str] = None, include_origins: bool = False,
                      limit: int = tools_isf.DEFAULT_LIMIT, search: Optional[str] = None,
                      offset: int = 0) -> str:
        """Materialized summary of a draft; item rows only for ``only`` (``{section: [names]}``;
        an empty list selects the whole section). ``search`` filters names by case-insensitive
        substring; ``offset``/``limit`` page each section (``total``/``truncated`` reported).
        ``version`` reads an older state; ``include_origins`` adds item and field provenance."""
        return json.dumps(present_inspect_mcp_call(
            lambda: tools_isf.isf_draft_get_result(
                case_dir, capture_id, name, only=only, version=version,
                include_origins=include_origins, limit=limit, search=search,
                offset=offset)))

    @mcp.tool()
    def isf_draft_set(case_dir: str, capture_id: str, name: str, op: str,
                      args: Dict[str, Any], source: str = "manual", tier: str = "manual",
                      evidence: Optional[List[str]] = None, witnesses: int = 1) -> str:
        """One draft operation: ``op`` is symbol | struct | field | base_type | enum | remove.

        ``args`` are the op's arguments (e.g. struct: ``{"struct": "task_struct", "size": 9792}``);
        a missing one is INVALID_INPUT naming it. Appends an entry with its provenance.
        """
        return json.dumps(present_inspect_mcp_call(
            lambda: tools_isf.isf_draft_set_result(
                case_dir, capture_id, name, op, args, source=source, tier=tier,
                evidence=evidence or (), author="agent", witnesses=witnesses)))

    @mcp.tool()
    def isf_draft_import(case_dir: str, capture_id: str, name: str, isf_path: str,
                         only: Optional[Dict[str, List[str]]] = None,
                         source: str = "isf_import", tier: str = "imported",
                         evidence: Optional[List[str]] = None) -> str:
        """Import (a subset, ``only``) of an ISF JSON file into the draft; records its sha256."""
        return json.dumps(present_inspect_mcp_call(
            lambda: tools_isf.isf_draft_import_result(
                case_dir, capture_id, name, isf_path, only=only, source=source, tier=tier,
                evidence=evidence or (), author="agent")))

    @mcp.tool()
    def isf_draft_retract(case_dir: str, capture_id: str, name: str, entry_id: str,
                          reason: str = "") -> str:
        """Retract one draft entry by id; the history keeps it and the retraction."""
        return json.dumps(present_inspect_mcp_call(
            lambda: tools_isf.isf_draft_retract_result(
                case_dir, capture_id, name, entry_id, author="agent", reason=reason)))

    @mcp.tool()
    def isf_draft_versions(case_dir: str, capture_id: str, name: str,
                           limit: int = tools_isf.DEFAULT_LIMIT) -> str:
        """The version history of a draft."""
        return json.dumps(present_inspect_mcp_call(
            lambda: tools_isf.isf_draft_versions_result(
                case_dir, capture_id, name, limit=limit)))

    @mcp.tool()
    def isf_draft_diff(case_dir: str, capture_id: str, name: str,
                       against_version: Optional[str] = None,
                       against_isf: Optional[str] = None,
                       only: Optional[Dict[str, List[str]]] = None,
                       limit: int = tools_isf.DEFAULT_LIMIT) -> str:
        """Diff the draft against an older version OR an ISF file (exactly one); the direction
        is ``against -> draft`` (``added`` = only in the draft)."""
        return json.dumps(present_inspect_mcp_call(
            lambda: tools_isf.isf_draft_diff_result(
                case_dir, capture_id, name, against_version=against_version,
                against_isf=against_isf, only=only, limit=limit)))

    @mcp.tool()
    def isf_draft_validate(case_dir: str, capture_id: str, name: str,
                           check_schema: bool = False,
                           limit: int = tools_isf.DEFAULT_LIMIT) -> str:
        """Validate the draft as an ISF document and report per-Volatility-plugin readiness."""
        return json.dumps(present_inspect_mcp_call(
            lambda: tools_isf.isf_draft_validate_result(
                case_dir, capture_id, name, check_schema=check_schema, limit=limit)))

    @mcp.tool()
    def isf_draft_export(case_dir: str, capture_id: str, name: str,
                         version: Optional[str] = None, out_path: Optional[str] = None) -> str:
        """Write the draft (at ``version``) as an ISF file; returns path, size and sha256."""
        return json.dumps(present_inspect_mcp_call(
            lambda: tools_isf.isf_draft_export_result(
                case_dir, capture_id, name, version=version, out_path=out_path)))

    @mcp.tool()
    def isf_try(image_path: str, case_dir: Optional[str] = None, draft: Optional[str] = None,
                version: Optional[str] = None, isf_path: Optional[str] = None,
                plugin: str = "linux.pslist", ground_truth: Optional[str] = None,
                timeout_s: float = 120.0, min_recall: float = 0.95,
                min_precision: float = 0.95) -> str:
        """Try a draft (``case_dir`` + ``draft`` [+ ``version``]) OR an ISF file on the image with
        a Volatility plugin; returns the verdict, comparison and implicated entries. A draft
        try is appended to the case's analysis record as an ``isf_try`` entry."""
        return json.dumps(present_inspect_mcp_call(
            lambda: tools_isf.isf_try_result(
                image_path, case_dir=case_dir, draft=draft, version=version,
                isf_path=isf_path, plugin=plugin, ground_truth=ground_truth,
                timeout_s=timeout_s, min_recall=min_recall, min_precision=min_precision,
                author="agent")))

    @mcp.tool()
    def disasm(dump_path: str, address: int, length: int, arch: str = "auto",
               view: Optional[str] = None, mode: Optional[str] = None,
               max_insns: int = tools_disasm.DEFAULT_MAX_INSNS,
               case_dir: Optional[str] = None) -> str:
        """Disassemble ``length`` bytes at ``address`` of a dump; captured stretches only.

        ``address`` is in the view's own space (kernel/process VA for ``.mdview``, MSL VA for
        ``.msl``, file offset for a flat file). ``arch``: auto, x86_64, x86, aarch64, arm,
        mips, mipsel (``mode="thumb"`` for Thumb). Rows: ``addr``, ``location``, ``bytes``,
        ``mnemonic``, ``op_str``; ``stops`` lists undecodable bytes, ``coverage`` the capture
        gaps (never decoded across). With ``case_dir`` the rows become the ``disasm`` table.
        """
        return json.dumps(present_inspect_mcp_call(
            lambda: tools_disasm.disasm_result(
                dump_path, address, length, arch=arch, view=view, mode=mode,
                max_insns=max_insns, case_dir=case_dir)))

    @mcp.tool()
    def detector_fixtures_run(
        artifact_kind: str, artifact: str, fixtures: Optional[List[dict]] = None,
        params: Optional[Dict[str, Any]] = None, case_dir: Optional[str] = None,
    ) -> str:
        """Run a detector's fixtures (positive controls + decoys): ``pass`` / ``fail`` / ``indeterminate``.

        ``artifact_kind`` is ``keyfinder`` (``artifact`` = finder name, e.g. ``aes_schedule``,
        which ships synthetic AES-schedule fixtures) or ``yara`` (``artifact`` = the rule SOURCE).
        With no fixtures the verdict is ``indeterminate`` (reason_code ``no_fixtures``), never a
        pass. ``fixtures`` replaces the default selection with inline ones:
        ``{"name", "sample": {"hex"}, "expect": {"matches": [{"offset", "length"?, "label"?,
        "key_hex"?}]} | {"no_match": true}, "artifact"?: rule name, "params"?}``. ``case_dir`` adds
        the stored fixtures and stores the verdicts (``last_verdict``).
        """
        return json.dumps(present_inspect_mcp_call(
            lambda: tools_detector_fixtures.detector_fixtures_run_result(
                artifact_kind, artifact, fixtures, params, case_dir)))

    @mcp.tool()
    def detector_fixtures_add(
        case_dir: str, name: str, artifact_kind: str, artifact: str, sample: Dict[str, Any],
        expect: Dict[str, Any], params: Optional[Dict[str, Any]] = None,
    ) -> str:
        """Store a detector fixture in a case. ``artifact`` is a finder name or a YARA RULE name.

        ``sample``: ``{"hex"}`` | ``{"base64"}`` | ``{"dump_path", "offset", "length"}`` (a wholly
        captured range). ``expect``: ``{"matches": [{"offset": N, ...}]}`` (sample-relative) or
        ``{"no_match": true}`` for a decoy. An overwrite keeps the old version in ``history/``.
        """
        return json.dumps(present_inspect_mcp_call(
            lambda: tools_detector_fixtures.detector_fixtures_add_result(
                case_dir, name, artifact_kind, artifact, sample, expect, params)))

    @mcp.tool()
    def detector_fixtures_list(
        case_dir: Optional[str] = None, artifact_kind: Optional[str] = None,
        artifact: Optional[str] = None,
    ) -> str:
        """List bundled and (with ``case_dir``) stored detector fixtures with their ``last_verdict``."""
        return json.dumps(present_inspect_mcp_call(
            lambda: tools_detector_fixtures.detector_fixtures_list_result(
                case_dir, artifact_kind, artifact)))

    @mcp.tool()
    def detector_fixtures_remove(case_dir: str, name: str) -> str:
        """Retire a stored detector fixture (its definition is archived under ``history/``)."""
        return json.dumps(present_inspect_mcp_call(
            lambda: tools_detector_fixtures.detector_fixtures_remove_result(case_dir, name)))

    @mcp.tool()
    def strings_table(
        dump_path: str, view: Optional[str] = None, offset: Optional[int] = None,
        length: Optional[int] = None, min_len: int = 4,
        encodings: Optional[List[str]] = None, case_dir: Optional[str] = None,
        limit: int = MCP_STRINGS_LIMIT,
    ) -> str:
        """List the printable strings of the CAPTURED bytes of a dump, one row each.

        ``encodings``: ``ascii`` / ``utf-8`` / ``utf16le`` (default ascii + utf16le).
        ``view``/``offset``/``length`` pick the window in the view's coordinates
        (``va`` default for .msl/.mdview, ``vas`` for .msl, ``raw`` for a flat file).
        A string never crosses a capture gap. Every row has ``addr`` + ``space`` +
        ``location``, ``encoding``, ``length``, ``value``, ``iocs`` (urls, emails,
        ipv4, paths, ...) and its ``region``; ``truncated`` says whether ``limit``
        cut the rows, ``coverage`` what was read. With ``case_dir`` the rows become
        the ``strings`` case table; ``vol3_query`` with ``saved="strings_iocs"`` then
        returns IOC columns. Runs inline and blocks on a large capture.
        """
        region = tools_strings._region_of(offset, length)
        return json.dumps(present_inspect_mcp_call(
            lambda: tools_strings.strings_table_result(
                dump_path, view, region, min_len,
                tuple(encodings or tools_strings.DEFAULT_ENCODINGS), limit, case_dir)))

    # -- image.* : memory-image views. The MCP server has no TaskManager (it is
    # a stdio process), so the slow steps run inline and the call blocks: the
    # first ``image_open_view``/``image_profile`` on a multi-GB image hashes it
    # and pakunoda may take ~15 s.
    @mcp.tool()
    def image_probe(image_path: str, banners: bool = False,
                    isf: Optional[str] = None) -> str:
        """Cheap facts about a memory image: size, physical layer chain, profile status.

        Never hashes the image and never runs pakunoda; ``profile.status`` is
        ``unknown`` until ``image_profile``/``image_open_view`` has hashed it.
        ``banners=true`` also scans the raw image for Linux banners (may read
        all of it).
        """
        return json.dumps(present_inspect_mcp_call(
            lambda: tools_image.image_probe_result(image_path, banners, isf)))

    @mcp.tool()
    def image_profile(image_path: str, isf: Optional[str] = None,
                      allow_pakunoda: bool = True) -> str:
        """Resolve the kernel profile (ISF): explicit -> cache -> pakunoda -> vol3 dirs.

        Slow on a first run (pakunoda ~15 s, maps the whole image); the result
        is cached so ``image_open_view`` finds it.
        """
        return json.dumps(present_inspect_mcp_call(
            lambda: tools_image.image_profile_result(image_path, isf, allow_pakunoda)))

    @mcp.tool()
    def image_open_view(image_path: str, view: str, pid: Optional[int] = None,
                        isf: Optional[str] = None, case_dir: Optional[str] = None,
                        out_path: Optional[str] = None, no_profile: bool = False,
                        paging: Optional[Dict[str, Any]] = None, draft: Optional[str] = None,
                        draft_version: Optional[str] = None) -> str:
        """Write a ``.mdview`` descriptor for a view of the image; returns its path.

        ``view`` is ``physical``, ``kernel`` or ``process`` (needs ``pid``). The
        descriptor opens like any dump (hex/search/regions tools accept it). A
        kernel/process view needs a profile: run ``image_profile`` first, or pass
        ``draft`` (+ ``draft_version``, with ``case_dir``) to use an ISF draft, or
        ``no_profile`` for a kernel view without any ISF (``paging``:
        ``{pgd_phys, arch, va_bits, ...}``; without ``pgd_phys`` a verified root is found).
        Default location: ``<case_dir>/views/``.
        """
        return json.dumps(present_inspect_mcp_call(
            lambda: tools_image.image_open_view_result(
                image_path, view, pid, isf, case_dir, out_path, no_profile=no_profile,
                paging=paging, draft=draft, draft_version=draft_version)))

    @mcp.tool()
    def image_processes(view_path: str) -> str:
        """List the tasks (pid, ppid, comm, uid, has_mm, kernel_va Location) of a view.

        Zero tasks is reported as an error (wrong profile or paging depth).
        """
        return json.dumps(present_inspect_mcp_call(
            lambda: tools_image.image_processes_result(view_path)))

    @mcp.tool()
    def image_extract_process(view_path: str, out_path: str) -> str:
        """Extract the process of a process ``.mdview`` into an ``.msl`` file."""
        return json.dumps(present_inspect_mcp_call(
            lambda: tools_image.image_extract_process_result(view_path, out_path)))

    # -- vol3.* : Volatility 3 plugins over a .mdview. Runs inline and blocks
    # (no TaskManager in this stdio process). A ``source`` plugin runs
    # UNSANDBOXED in this process (D7); its sha256 is logged.
    @mcp.tool()
    def vol3_plugins(os_family: str = "linux") -> str:
        """List the bundled Volatility 3 plugins of an OS family (name, description, version)."""
        return json.dumps(present_inspect_mcp_call(
            lambda: tools_vol3.vol3_plugins_result(os_family)))

    @mcp.tool()
    def vol3_describe(plugin: str = "", source: Optional[str] = None,
                      source_name: Optional[str] = None,
                      case_dir: Optional[str] = None) -> str:
        """A plugin's user requirements (``args`` for ``vol3_run``).

        ``plugin`` names a bundled plugin (``linux.pslist``); ``source`` is the
        text of a user plugin, which is EXECUTED unsandboxed in this process;
        ``source_name`` (with ``case_dir``) names one stored by ``vol3_source_put``.
        """
        return json.dumps(present_inspect_mcp_call(
            lambda: tools_vol3.vol3_describe_result(
                plugin, source, source_name=source_name, case_dir=case_dir)))

    @mcp.tool()
    def vol3_run(
        view_path: str, plugin: str = "", args: Optional[dict] = None,
        case_dir: Optional[str] = None, limit: int = MCP_VOL3_ROW_LIMIT,
        timeout_s: float = MCP_VOL3_TIMEOUT_S, max_rows: int = MCP_VOL3_MAX_ROWS,
        column_map: Optional[dict] = None, source: Optional[str] = None,
        out_dir: Optional[str] = None, source_name: Optional[str] = None,
    ) -> str:
        """Run a Volatility 3 plugin over a ``.mdview`` view; blocks until done.

        ``args`` maps plugin argument names to values (see ``vol3_describe``); a
        process view scopes ``pid`` automatically. With ``case_dir`` the rows
        are registered as the case table ``vol3__<os>_<plugin>`` (standard
        columns ``addr``/``size``/``space``), queryable with ``vol3_query`` /
        ``case_query``. ``limit`` caps rows collected, ``max_rows`` the rows
        echoed; ``timeout_s`` stops the run (``truncated``/``stop_reason``).
        ``source`` is a user plugin (EXECUTED unsandboxed in-process);
        ``source_name`` runs one stored in ``case_dir`` (``vol3_source_put``).
        """
        return json.dumps(present_inspect_mcp_call(
            lambda: tools_vol3.vol3_run_result(
                view_path, plugin, args, case_dir=case_dir, limit=limit,
                timeout_s=timeout_s, max_rows=max_rows, column_map=column_map,
                source=source, out_dir=out_dir, source_name=source_name)))

    @mcp.tool()
    def vol3_query(
        case_dir: str, sql: Optional[str] = None, saved: Optional[str] = None,
        params: Optional[List[Any]] = None, limit: int = MCP_CASE_QUERY_LIMIT,
    ) -> str:
        """Run read-only ``sql`` or a built-in ``saved`` query over a case.

        With neither, returns the list of saved queries (name, description, SQL,
        and the plugin tables each needs). A saved query whose tables are missing
        fails naming the plugin to run.
        """
        return json.dumps(present_inspect_mcp_call(
            lambda: tools_vol3.vol3_query_result(case_dir, sql, saved, params, limit)))

    @mcp.tool()
    def vol3_annotate(
        case_dir: str, table: str, run_id: str, column: str,
        rows: Optional[List[int]] = None, label_column: Optional[str] = None,
        author: str = "agent",
    ) -> str:
        """File one ``plugin_row`` annotation per row of a registered run.

        ``column`` must be a location column of ``table`` (see ``case_schema``);
        ``rows`` are row indexes (default: all). Rows with no address are skipped.
        """
        return json.dumps(present_inspect_mcp_call(
            lambda: tools_vol3.vol3_annotate_result(
                case_dir, table, run_id, column, rows=rows,
                label_column=label_column, author=author)))

    @mcp.tool()
    def vol3_scaffold(name: str, os_family: str = "linux", description: str = "",
                      per_process: bool = True) -> str:
        """Source text of a new Volatility 3 plugin (kernel module, optional ``pid`` filter)."""
        return json.dumps(present_inspect_mcp_call(
            lambda: tools_vol3_dev.vol3_scaffold_result(
                name, os_family=os_family, description=description,
                per_process=per_process)))

    @mcp.tool()
    def vol3_check(source: Optional[str] = None, view_path: Optional[str] = None,
                   source_name: Optional[str] = None,
                   case_dir: Optional[str] = None) -> str:
        """Load plugin ``source`` or a stored ``source_name`` (EXECUTED unsandboxed) and report it.

        Returns ``ok`` with the plugin description, or a structured failure
        (error type, line). With ``view_path`` also lists the requirements the
        view leaves unsatisfied.
        """
        return json.dumps(present_inspect_mcp_call(
            lambda: tools_vol3_dev.vol3_check_result(
                source, view_path, source_name=source_name, case_dir=case_dir)))

    @mcp.tool()
    def vol3_import(
        case_dir: str, path: str, table: str, capture_id: str,
        image_sha256: Optional[str] = None, locations: Optional[dict] = None,
        format: str = "auto",  # noqa: A002
    ) -> str:
        """Register an external vol3 output (Parquet/CSV/JSON) as a run of ``table``.

        ``table`` must start with ``vol3__``. ``locations`` maps address columns
        to spaces; omitted, they are guessed (``locations_guessed``).
        """
        return json.dumps(present_inspect_mcp_call(
            lambda: tools_vol3_dev.vol3_import_parquet_result(
                case_dir, path, table=table, capture_id=capture_id,
                image_sha256=image_sha256, locations=locations, format=format)))

    @mcp.tool()
    def vol3_write_config(view_path: str, out_path: str,
                          plugin: str = "linux.pslist.PsList",
                          source: Optional[str] = None,
                          source_name: Optional[str] = None,
                          case_dir: Optional[str] = None) -> str:
        """Write a ``vol`` ``config.json`` reproducing the view's layer stack for ``plugin``.

        ``source`` (plugin text) or ``source_name`` (stored in ``case_dir``) writes it for a
        user plugin instead — UNSANDBOXED, sha256 logged — so stock ``vol -c`` can run it.
        """
        return json.dumps(present_inspect_mcp_call(
            lambda: tools_vol3_dev.vol3_write_config_result(
                view_path, out_path, plugin, source=source, source_name=source_name,
                case_dir=case_dir)))

    @mcp.tool()
    def vol3_source_list(case_dir: str) -> str:
        """List the user plugin sources stored in a case (name, sha256, size, updated, version)."""
        return json.dumps(present_inspect_mcp_call(
            lambda: tools_vol3_sources.vol3_source_list_result(case_dir)))

    @mcp.tool()
    def vol3_source_get(case_dir: str, name: str) -> str:
        """One stored plugin source with its metadata; ``modified_externally`` flags a hand edit."""
        return json.dumps(present_inspect_mcp_call(
            lambda: tools_vol3_sources.vol3_source_get_result(case_dir, name)))

    @mcp.tool()
    def vol3_source_put(case_dir: str, name: str, source: str,
                        view_path: Optional[str] = None) -> str:
        """Store plugin ``source`` as ``name`` in the case, then check it (EXECUTED unsandboxed).

        An overwrite keeps the previous version under ``plugins/history``. The
        reply carries the ``vol3_check`` outcome; a plugin that fails to load is
        still saved. Run it later with ``vol3_run(source_name=name, case_dir=...)``.
        """
        return json.dumps(present_inspect_mcp_call(
            lambda: tools_vol3_sources.vol3_source_put_result(
                case_dir, name, source, view_path)))

    @mcp.tool()
    def vol3_fixture_put(
        case_dir: str, name: str, view_path: str, expect: List[dict],
        plugin: str = "", source_name: Optional[str] = None, args: Optional[dict] = None,
    ) -> str:
        """Store a plugin fixture: a plugin (bundled ``plugin`` or stored ``source_name``),
        a view and row predicates in ``expect``.

        Predicates: ``{"min_rows": N}``, ``{"max_rows": N}``,
        ``{"row_where": {"COMM": "sshd", "PID": 22176}, "count_at_least": 1}``,
        ``{"column_all": {"column": "PID", "op": ">=", "value": 0}}`` (also ``column_any``).
        """
        return json.dumps(present_inspect_mcp_call(
            lambda: tools_vol3_fixtures.vol3_fixture_put_result(
                case_dir, name, view_path=view_path, expect=expect, plugin=plugin,
                source_name=source_name, args=args)))

    @mcp.tool()
    def vol3_fixture_list(case_dir: str) -> str:
        """List the plugin fixtures stored in a case."""
        return json.dumps(present_inspect_mcp_call(
            lambda: tools_vol3_fixtures.vol3_fixture_list_result(case_dir)))

    @mcp.tool()
    def vol3_fixture_run(
        case_dir: str, name: str, view_path: Optional[str] = None,
        limit: int = MCP_VOL3_ROW_LIMIT, timeout_s: float = MCP_VOL3_TIMEOUT_S,
        register_run: bool = False,
    ) -> str:
        """Run a fixture: verdict ``pass`` / ``fail`` / ``indeterminate`` with per-predicate results.

        ``indeterminate`` means nothing was proven (truncated or timed-out run, view
        unreadable). The verdict is filed as a ``fixture_verdict`` annotation of the
        view's capture; ``register_run`` also files the plugin table and links it.
        """
        return json.dumps(present_inspect_mcp_call(
            lambda: tools_vol3_fixtures.vol3_fixture_run_result(
                case_dir, name, view_path=view_path, limit=limit, timeout_s=timeout_s,
                register_run=register_run)))

    @mcp.resource("memdiver://case/{case_dir}/schema",
                  name="case_schema", mime_type="application/json",
                  description="Schema of a case; URL-encode the case directory.",
                  # A case directory is legitimately an absolute path; ".." and
                  # NUL stay rejected.
                  security=ResourceSecurity(reject_absolute_paths=False))
    def case_schema_resource(case_dir: str) -> str:
        return json.dumps(tools_case.case_schema_result(case_dir).payload)

    @mcp.tool()
    def get_connections(
        msl_path: str, key_file: Optional[str] = None,
        passphrase: Optional[str] = None, kem_key_file: Optional[str] = None,
    ) -> str:
        """List network connections in an MSL file (pid/family/protocol/addrs)."""
        return json.dumps(present_inspect_mcp_call(lambda: tools_inspect.connections_result(
            _session, msl_path, key_file, passphrase, kem_key_file,
        )))

    @mcp.tool()
    def get_module_index(
        msl_path: str, key_file: Optional[str] = None,
        passphrase: Optional[str] = None, kem_key_file: Optional[str] = None,
    ) -> str:
        """List MODULE_LIST_INDEX entries in an MSL file (uuid/base/size/path)."""
        return json.dumps(present_inspect_mcp_call(lambda: tools_inspect.module_index_result(
            _session, msl_path, key_file, passphrase, kem_key_file,
        )))

    @mcp.tool()
    def get_import_provenance(
        msl_path: str, key_file: Optional[str] = None,
        passphrase: Optional[str] = None, kem_key_file: Optional[str] = None,
    ) -> str:
        """List IMPORT_PROVENANCE records of an MSL file with the note parsed.

        Each record has source format/tool/size/hash, the raw note, the kept
        region categories, excluded region/byte totals and, for a materialized
        copy, materialized=true plus the original EoC hash. Empty for non-.msl.
        """
        return json.dumps(present_inspect_mcp_call(lambda: tools_inspect.import_provenance_result(
            _session, msl_path, key_file, passphrase, kem_key_file,
        )))

    @mcp.tool()
    def get_blocks(
        msl_path: str, key_file: Optional[str] = None,
        passphrase: Optional[str] = None, kem_key_file: Optional[str] = None,
    ) -> str:
        """List all blocks in an MSL file grouped by category."""
        return json.dumps(present_inspect_mcp_call(lambda: tools_inspect.blocks_result(
            _session, msl_path, key_file, passphrase, kem_key_file,
        )))

    @mcp.tool()
    @mcp_error_funnel
    def detect_format(
        dump_path: str, offset: int = 0,
        key_file: Optional[str] = None, passphrase: Optional[str] = None,
        kem_key_file: Optional[str] = None,
    ) -> str:
        """Detect the binary format at an offset in a dump's raw container."""
        return json.dumps(present_inspect_mcp_call(lambda: tools_inspect.detect_format_result(
            _session, dump_path, offset, key_file, passphrase, kem_key_file,
        )))

    @mcp.tool()
    def get_cross_references(msl_path: str) -> str:
        """Resolve cross-references for an MSL file in its directory."""
        return json.dumps(present_inspect_mcp_call(
            lambda: tools_xref.get_cross_references_result(_session, msl_path)))

    @mcp.tool()
    def identify_structure(
        dump_path: str, offset: int = 0, protocol: str = "",
    ) -> str:
        """Identify data structure at offset in a dump file."""
        return json.dumps(present_inspect_mcp_call(
            lambda: tools_xref.identify_structure_result(_session, dump_path, offset, protocol)))

    @mcp.tool()
    @mcp_error_funnel
    def import_raw_dump(
        raw_path: str, output_path: str, pid: int = 0,
        region_types: Optional[str] = None,
        exclude_region_types: Optional[str] = None,
        materialize: bool = False,
        key_file: Optional[str] = None, passphrase: Optional[str] = None,
        kem_key_file: Optional[str] = None, decrypt_output: bool = False,
        maps_path: Optional[str] = None,
    ) -> str:
        """Import a dump (raw .dump, ELF core, minidump, or .msl) to .msl.

        Without ``region_types`` / ``exclude_region_types`` EVERY region is
        imported (unchanged behaviour). ``region_types`` is a comma list of
        categories or ``"all"``: heap, stack, image_code, image_data,
        mapped_file, shared, unclassified, runtime (alias ``image``).
        ``runtime`` holds maps classified by mapping name (Android
        zygote/boot-image/ART metadata, JIT caches, kernel/device maps such
        as ``[vdso]``/``[vvar]``); it is NOT in the interactive default
        (heap, stack, unclassified), so name it or use ``"all"`` to keep it.
        Call ``preview_import`` first to see per-category counts/bytes. For
        ``.msl`` input the file is copied verbatim (selection applies at
        analysis time) unless ``materialize`` is true, which writes a filtered
        copy. When a selection is given the result adds ``selection``,
        ``excluded_region_count``, ``excluded_bytes``,
        ``secrets_only_in_excluded`` and ``warnings``.

        Encrypted ``.msl`` (spec §10): supply ``key_file`` (32-byte raw key
        file), ``passphrase`` (Argon2id) or ``kem_key_file`` (X25519/ML-KEM
        private key file) to materialize it. The filtered copy is
        RE-ENCRYPTED with the same key wrapping and a fresh nonce (the same
        material opens it; result ``reencrypted: true``). ``decrypt_output``
        writes a PLAINTEXT copy instead (``decrypted_output: true`` plus a
        warning). Missing/wrong key on materialize -> error, nothing written.
        Key material is never cached or logged.

        Raw dumps have no memory layout (one unclassified region) unless a
        ``/proc/<pid>/maps``-style memory map describes them: ``maps_path``
        names it, else a ``.maps`` sidecar with the same name is used
        (``foo.gdb_raw.bin`` -> ``foo.gdb_raw.maps``, else ``foo.maps``).
        Then every maps entry becomes a region at its real address with a
        real category. A map that does not match the dump size is ignored
        with a warning.
        """
        return json.dumps(tools.import_raw_dump(
            _session, raw_path, output_path, pid,
            selection=region_types, materialize=materialize,
            exclude=exclude_region_types, key_file=key_file,
            passphrase=passphrase, kem_key_file=kem_key_file,
            decrypt_output=decrypt_output, maps_path=maps_path))

    @mcp.tool()
    @mcp_error_funnel
    def preview_import(
        path: str, region_types: Optional[str] = None,
        exclude_region_types: Optional[str] = None,
        key_file: Optional[str] = None, passphrase: Optional[str] = None,
        kem_key_file: Optional[str] = None, maps_path: Optional[str] = None,
    ) -> str:
        """Preview the regions an import of ``path`` would emit (writes nothing).

        Returns ``format``, ``is_msl``, every region with its ``category``,
        per-category ``totals`` (count, bytes) and a ``summary`` of what
        ``region_types`` / ``exclude_region_types`` would keep and exclude.
        Use it to choose ``import_raw_dump``'s region selection.

        ``encrypted`` / ``decrypted`` flag an AEAD-encrypted ``.msl``; pass
        ``key_file`` / ``passphrase`` / ``kem_key_file`` to list its regions.

        ``layout`` is ``native`` (format records it), ``maps`` (raw dump +
        memory map; ``maps_path`` or an auto-detected ``.maps`` sidecar) or
        ``none`` (raw dump: one unclassified region, categories cannot be
        separated).

        ``platform`` is the target platform (``android``, ``linux``,
        ``windows``, ...; null when unknown) and ``platform_source`` how it
        was determined (``mapping_names``, ``header`` or ``format``). Each
        region carries its mapping ``name`` (null when the source has none).
        ``runtime_count`` / ``runtime_bytes`` total the ``runtime`` regions
        (Android zygote/boot-image/ART metadata, JIT, kernel/device maps);
        they are dropped by the default selection, and a ``notes`` entry
        says so when any exist.
        """
        return json.dumps(tools.preview_import(
            _session, path, selection=region_types,
            exclude=exclude_region_types, key_file=key_file,
            passphrase=passphrase, kem_key_file=kem_key_file,
            maps_path=maps_path))

    # ------------------------------------------------------------------
    # Phase 25 pipeline stage tools
    # ------------------------------------------------------------------

    @mcp.tool()
    @mcp_error_funnel
    def analyze_candidates(
        dump_paths: List[str],
        classes: Optional[List[str]] = None,
        min_variance: Optional[float] = None,
        min_region: int = 16, max_region: int = 0,
        alignment: int = 8, block_size: int = 32,
        density_threshold: float = 0.5,
        entropy_window: int = 32, entropy_threshold: float = 4.5,
        order: str = "rank",
        max_returned: int = tools_pipeline.DEFAULT_MAX_RETURNED_REGIONS,
        normalize: bool = False,
        project_id: str = "",
        region_filter: Optional[str] = None,
        key_file: Optional[str] = None, passphrase: Optional[str] = None,
        kem_key_file: Optional[str] = None,
        force_memory: bool = False,
        heap_policy: str = "annotate",
        allocator: str = "auto",
    ) -> str:
        """Rank candidate regions across N dumps — NO oracle, NO capture needed.

        The one call for the exploratory question "I have N dumps of one
        process, I do not know whether there is a key or where": consensus →
        class / length / entropy / density filters → ranked candidates. Use it
        BEFORE ``brute_force`` — that tool needs an oracle or a pcap to confirm
        a hit, this one confirms nothing and is reachable without either.

        The regions come back INLINE under ``regions``, each with ``rank``,
        ``score`` and the ``score_components`` the score is the weighted sum of.
        The list is capped at ``max_returned`` best-ranked rows (0 = uncapped);
        ``num_regions`` is always the true total.

        ``classes`` names ByteClass bands ("invariant", "structural",
        "pointer", "key_candidate"). Prefer ALL THREE non-invariant bands: real
        key material is class-MIXED (a measured 48-byte TLS 1.2 secret is 22
        KEY_CANDIDATE + 18 POINTER + 8 STRUCTURAL), so a KEY_CANDIDATE-only
        query returns fragments from inside the key instead of the key. Leave
        ``min_variance`` unset — it resolves against ``classes`` so a class
        query is not silently re-narrowed by the historical 3000 floor.

        Read ``alignment`` for how the dumps were put into correspondence and
        ``warnings`` / ``diagnostics`` before trusting the numbers: an empty
        ``regions`` list is a legitimate answer and always says which gate
        emptied it. Supply ``key_file`` / ``passphrase`` / ``kem_key_file`` for
        encrypted ``.msl`` inputs.

        ``region_filter`` (``.msl`` only; a comma list of region categories
        such as ``"heap,stack"``, or a ``"regions=..."`` note) analyses through the region VIEW filter, so offsets are
        filtered-view offsets; omitted, the session's filter applies and
        ``"all"`` explicitly disables it.

        ``force_memory`` overrides the memory-budget guard: an over-budget
        consensus build is refused with code ``memory_budget_exceeded``
        (``estimate_bytes`` / ``budget_bytes`` in the error) unless
        ``force_memory=true``.

        ``heap_policy`` controls allocator-metadata handling: "annotate" (the
        default, non-destructive) tags each candidate with the heap chunk it
        sits in (``chunk`` / ``residual`` fields) without changing the ranking;
        "mask" removes allocator metadata (chunk headers, free-list links)
        from the candidates before reduction and reports the cost under
        ``stages.heap_masked``; "off" disables heap analysis entirely.
        ``allocator`` ("auto", "ptmalloc2", "dlmalloc", "scudo", "mallocng",
        "jemalloc", "generic" or "off") picks the heap parser; "auto" detects.
        """
        return json.dumps(tools_pipeline.analyze_candidates(
            dump_paths=dump_paths,
            classes=classes,
            min_variance=min_variance,
            min_region=min_region,
            max_region=max_region,
            alignment=alignment,
            block_size=block_size,
            density_threshold=density_threshold,
            entropy_window=entropy_window,
            entropy_threshold=entropy_threshold,
            order=order,
            max_returned=max_returned,
            normalize=normalize,
            project_id=project_id,
            region_filter=_session_region_filter(region_filter),
            key_file=key_file,
            passphrase=passphrase,
            kem_key_file=kem_key_file,
            force=force_memory,
            heap_policy=heap_policy,
            allocator=allocator,
        ))

    @mcp.tool()
    @mcp_error_funnel
    def search_reduce(
        variance_path: str, reference_path: str, num_dumps: int,
        output_dir: str,
        alignment: int = 8, block_size: int = 32,
        density_threshold: float = 0.5, min_variance: float = 3000.0,
        entropy_window: int = 32, entropy_threshold: float = 4.5,
        min_region: int = 16, max_region: int = 0,
        classes: Optional[List[str]] = None,
        order: str = "offset",
        max_returned: int = tools_pipeline.DEFAULT_MAX_RETURNED_REGIONS,
        region_filter: Optional[str] = None,
        key_file: Optional[str] = None, passphrase: Optional[str] = None,
        kem_key_file: Optional[str] = None,
        heap_policy: str = "annotate",
    ) -> str:
        """Reduce consensus variance to a RANKED candidate region list.

        The regions come back inline under ``regions`` — each with ``rank``,
        ``score`` and the ``score_components`` the score is the weighted sum of
        — so this tool is usable without reading ``candidates_path`` back off
        disk. The inline list is capped at ``max_returned`` best-ranked rows (0
        = uncapped); ``regions_truncated`` says whether the cap bit and
        ``num_regions`` is always the true total.

        ``classes`` narrows to named variance bands ("key_candidate",
        "pointer", "structural", "invariant") ON TOP OF ``min_variance``, whose
        3000.0 default already excludes everything below KEY_CANDIDATE — pass
        ``min_variance=0.0`` alongside a multi-class query. ``order`` is
        "offset" or "rank". ``max_region`` mirrors ``min_region``.

        Supply ``key_file`` / ``passphrase`` / ``kem_key_file`` when the
        reference is an encrypted ``.msl``.

        ``region_filter`` (``.msl`` only) overrides the view filter the
        upstream stage recorded in its artifact; omitted, the recorded filter
        is reused so offsets stay consistent, and ``"all"`` disables it.

        ``heap_policy`` uses the heap layout persisted beside the variance
        artifact: "annotate" (default, non-destructive) tags candidates with
        their heap chunk; "mask" removes allocator metadata from the
        candidates (count under ``stages.heap_masked``); "off" disables it.
        """
        return json.dumps(tools_pipeline.search_reduce(
            variance_path=variance_path,
            reference_path=reference_path,
            num_dumps=num_dumps,
            output_dir=output_dir,
            alignment=alignment,
            block_size=block_size,
            density_threshold=density_threshold,
            min_variance=min_variance,
            entropy_window=entropy_window,
            entropy_threshold=entropy_threshold,
            min_region=min_region,
            max_region=max_region,
            classes=classes,
            order=order,
            max_returned=max_returned,
            region_filter=region_filter,
            key_file=key_file,
            passphrase=passphrase,
            kem_key_file=kem_key_file,
            heap_policy=heap_policy,
        ))

    @mcp.tool()
    @mcp_error_funnel
    def brute_force(
        candidates_path: str, reference_path: str,
        output_dir: str, oracle_path: Optional[str] = None,
        oracle_config_path: Optional[str] = None,
        oracle_config: Optional[Dict[str, Any]] = None,
        pcap_path: Optional[str] = None,
        tls_client_random: Optional[str] = None,
        pcap_max_records: Optional[int] = None,
        pcap_max_challenges: Optional[int] = None,
        resource_type: str = DEFAULT_RESOURCE_TYPE,
        persist_ground_truth: bool = False,
        key_sizes: Optional[List[int]] = None, stride: int = 1,
        jobs: int = 0, exhaustive: bool = True,
        state_path: Optional[str] = None, top_k: int = 10,
        neighborhood_pad: int = DEFAULT_NEIGHBORHOOD_PAD,
        variance_threshold: Optional[float] = None,
        region_filter: Optional[str] = None,
        key_file: Optional[str] = None, passphrase: Optional[str] = None,
        kem_key_file: Optional[str] = None,
    ) -> str:
        """Iterate surviving candidates through an oracle.

        Supply exactly one oracle source: ``oracle_path`` (a BYO decryption
        oracle script) or ``pcap_path`` (a pcap/pcapng of the same TLS session,
        routed through MemDiver's first-party trusted pcap oracle to prove a
        recovered key decrypts real captured records). ``tls_client_random``
        (hex) optionally restricts pcap matching to one session.
        ``pcap_max_records`` / ``pcap_max_challenges`` size the pcap oracle's
        verification work (records per direction / total challenges); leave both
        unset to keep the defaults, and read ``inspect_pcap``'s ``caps`` +
        ``records_truncated`` to see what a capture actually loses to them.

        ``resource_type`` picks the registered verification resource (default
        ``"tls-pcap"``). Change it only when a capture holds a protocol another
        installed resource handles — the error you get on a multi-protocol
        capture names the choices, and ``inspect_pcap(detect_protocols=True)``
        lists them before you run.

        A BYO oracle's configuration comes either from ``oracle_config_path``
        (a TOML file) or inline as ``oracle_config`` (the already-parsed
        mapping), which saves writing a file for a one-shot run. The inline
        mapping wins when both are given; neither confers trust — a BYO oracle
        stays sandboxed.

        Supply ``key_file`` / ``passphrase`` / ``kem_key_file`` to brute-force
        against an *encrypted* ``.msl`` reference; ``variance_threshold`` sets
        the static-byte cutoff surfaced in the stage's preview.
        ``neighborhood_pad`` (default 64 bytes per side) is the context width
        attached to each hit and therefore baked into every emitted vol3/YARA
        artifact — leave it at the default unless you mean to change what the
        tool emits.

        ``region_filter`` (``.msl`` only) overrides the view filter the
        upstream stage recorded in its artifact; omitted, the recorded filter
        is reused so offsets stay consistent, and ``"all"`` disables it.
        """
        return json.dumps(tools_pipeline.brute_force(
            candidates_path=candidates_path,
            reference_path=reference_path,
            oracle_path=oracle_path,
            output_dir=output_dir,
            oracle_config_path=oracle_config_path,
            oracle_config=oracle_config,
            pcap_path=pcap_path,
            tls_client_random=tls_client_random,
            pcap_max_records=pcap_max_records,
            pcap_max_challenges=pcap_max_challenges,
            resource_type=resource_type,
            persist_ground_truth=persist_ground_truth,
            key_sizes=tuple(key_sizes or [32]),
            stride=stride,
            jobs=jobs,
            exhaustive=exhaustive,
            state_path=state_path,
            top_k=top_k,
            neighborhood_pad=neighborhood_pad,
            variance_threshold=variance_threshold,
            region_filter=region_filter,
            key_file=key_file,
            passphrase=passphrase,
            kem_key_file=kem_key_file,
        ))

    @mcp.tool()
    @mcp_error_funnel
    def n_sweep(
        source_paths: List[str], output_dir: str,
        n_values: List[int],
        oracle_path: Optional[str] = None,
        pcap_path: Optional[str] = None,
        tls_client_random: Optional[str] = None,
        pcap_max_records: Optional[int] = None,
        pcap_max_challenges: Optional[int] = None,
        resource_type: str = DEFAULT_RESOURCE_TYPE,
        reduce_kwargs: Optional[dict] = None,
        key_sizes: Optional[List[int]] = None,
        stride: int = 1, exhaustive: bool = True,
        oracle_config_path: Optional[str] = None,
        oracle_config: Optional[Dict[str, Any]] = None,
        escalate: bool = False,
        escalate_oracle_budget: Optional[int] = None,
        region_filter: Optional[str] = None,
        key_file: Optional[str] = None, passphrase: Optional[str] = None,
        kem_key_file: Optional[str] = None,
    ) -> str:
        """Run the N-scaling harness and emit the Plotly survivor report.

        Supply exactly one oracle source, the same pair ``brute_force`` takes:
        ``oracle_path`` (a BYO decryption oracle script) or ``pcap_path`` (a
        pcap/pcapng of the same TLS session, routed through MemDiver's
        first-party trusted pcap oracle). The sweep re-runs whichever one it was
        given at every N. ``tls_client_random`` (hex) optionally restricts pcap
        matching to one session, and ``pcap_max_records`` /
        ``pcap_max_challenges`` size the pcap oracle's verification work.
        ``resource_type`` picks the registered verification resource (default
        ``"tls-pcap"``), the same knob ``brute_force`` takes.

        A BYO oracle's configuration comes from ``oracle_config_path`` (a TOML
        file) or inline as ``oracle_config``, exactly as for ``brute_force``;
        the inline mapping wins when both are given.

        Set ``escalate`` to run a floor-free sweep at the terminal N when no
        checkpoint found a hit; its verdict surfaces under ``escalation``.
        Supply ``key_file`` / ``passphrase`` / ``kem_key_file`` for encrypted
        ``.msl`` sources.

        ``region_filter`` (``.msl`` only; a comma list of region categories
        such as ``"heap,stack"``, or a ``"regions=..."`` note) analyses through the region VIEW filter, so offsets are
        filtered-view offsets; omitted, the session's filter applies and
        ``"all"`` explicitly disables it.
        """
        return json.dumps(tools_pipeline.n_sweep(
            source_paths=source_paths,
            oracle_path=oracle_path,
            pcap_path=pcap_path,
            tls_client_random=tls_client_random,
            pcap_max_records=pcap_max_records,
            pcap_max_challenges=pcap_max_challenges,
            resource_type=resource_type,
            output_dir=output_dir,
            n_values=n_values,
            reduce_kwargs=reduce_kwargs,
            key_sizes=tuple(key_sizes or [32]),
            stride=stride,
            exhaustive=exhaustive,
            oracle_config_path=oracle_config_path,
            oracle_config=oracle_config,
            escalate=escalate,
            escalate_oracle_budget=escalate_oracle_budget,
            region_filter=_session_region_filter(region_filter),
            key_file=key_file,
            passphrase=passphrase,
            kem_key_file=kem_key_file,
        ))

    @mcp.tool()
    @mcp_error_funnel
    def emit_plugin(
        hits_path: str, reference_path: str, name: str, output_dir: str,
        description: Optional[str] = None, hit_index: int = 0,
        variance_threshold: Optional[float] = None,
        region_filter: Optional[str] = None,
        key_file: Optional[str] = None, passphrase: Optional[str] = None,
        kem_key_file: Optional[str] = None,
    ) -> str:
        """Emit a Volatility 3 plugin from a brute-force hit's neighborhood.

        Supply ``key_file`` / ``passphrase`` / ``kem_key_file`` when the
        reference is an encrypted ``.msl``.

        ``region_filter`` (``.msl`` only) overrides the view filter the
        upstream stage recorded in its artifact; omitted, the recorded filter
        is reused so offsets stay consistent, and ``"all"`` disables it.
        """
        return json.dumps(tools_pipeline.emit_plugin(
            hits_path=hits_path,
            reference_path=reference_path,
            name=name,
            output_dir=output_dir,
            description=description,
            hit_index=hit_index,
            variance_threshold=variance_threshold,
            region_filter=region_filter,
            key_file=key_file,
            passphrase=passphrase,
            kem_key_file=kem_key_file,
        ))

    # ------------------------------------------------------------------
    # Additional inspect tools
    # ------------------------------------------------------------------

    @mcp.tool()
    def read_hex_raw(
        dump_path: str, offset: int = 0, length: int = 8192, view: str = "raw",
        key_file: Optional[str] = None, passphrase: Optional[str] = None,
        kem_key_file: Optional[str] = None,
        region_filter: Optional[str] = None,
    ) -> str:
        """Read raw bytes from a dump file, returned base64-encoded.

        ``region_filter`` (``.msl`` only; e.g. ``"heap,stack"``) reads through
        the region VIEW filter, so ``offset`` is a filtered-view offset;
        omitted, the session's filter applies and ``"all"`` disables it.
        """
        return json.dumps(present_inspect_mcp_call(lambda: tools_inspect.read_hex_raw_result(
            _session, dump_path, offset, length, view,
            key_file, passphrase, kem_key_file,
            region_filter=_session_region_filter(region_filter),
        )))

    @mcp.tool()
    def resolve_va(
        dump_path: str, va: int, key_file: Optional[str] = None,
        passphrase: Optional[str] = None, kem_key_file: Optional[str] = None,
    ) -> str:
        """Translate a virtual address to file and VAS offsets for an MSL dump."""
        return json.dumps(present_inspect_mcp_call(lambda: tools_inspect.resolve_va_result(
            _session, dump_path, va, key_file, passphrase, kem_key_file,
        )))

    @mcp.tool()
    def search_bytes(
        dump_path: str, pattern_hex: str, view: str = "raw",
        max_results: int = 500, cursor: int = 0,
        key_file: Optional[str] = None, passphrase: Optional[str] = None,
        kem_key_file: Optional[str] = None, pattern_format: str = "hex",
    ) -> str:
        """Search a dump for every occurrence of a byte pattern.

        ``pattern_hex`` is the raw pattern TEXT (the name is historical) and
        ``pattern_format`` says how to read it: ``hex`` (default), ``text``
        (UTF-8), ``utf16le`` for wide strings, ``base64``, or ``u32le`` /
        ``u32be`` / ``u64le`` / ``u64be`` for a numeric value or pointer.
        ``auto`` resolves to hex for unambiguous whole-byte hex and to text
        otherwise. The result echoes the resolved bytes as ``pattern_hex``.

        ``view`` selects the MSL byte source: ``raw``, ``vas``, or ``va``
        (the sparse full VA span, captured bytes only).
        """
        return json.dumps(present_inspect_mcp_call(lambda: tools_inspect.search_bytes_result(
            _session, dump_path, pattern_hex, view, max_results, cursor,
            key_file, passphrase, kem_key_file, pattern_format,
        )))

    @mcp.tool()
    def get_page_states(
        msl_path: str, key_file: Optional[str] = None,
        passphrase: Optional[str] = None, kem_key_file: Optional[str] = None,
        view: str = "va",
    ) -> str:
        """Surface the MSL three-state page model (CAPTURED/FAILED/UNMAPPED).

        ``view`` is ``"va"`` (default) or ``"vas"`` (only the VA -> packed-offset
        map; what a kernel ``.mdview`` offers for navigation).
        """
        return json.dumps(present_inspect_mcp_call(lambda: tools_inspect.page_states_result(
            _session, msl_path, key_file, passphrase, kem_key_file, view=view,
        )))

    # ------------------------------------------------------------------
    # Pipeline origination + export breadth tools
    # ------------------------------------------------------------------

    @mcp.tool()
    @mcp_error_funnel
    def consensus(
        dump_paths: List[str], output_dir: str, normalize: bool = False,
        region_filter: Optional[str] = None,
        key_file: Optional[str] = None, passphrase: Optional[str] = None,
        kem_key_file: Optional[str] = None,
        force_memory: bool = False,
        allocator: str = "auto",
    ) -> str:
        """Build a per-byte consensus variance vector; writes variance.npy.

        Originates the MCP pipeline: the returned ``variance_path`` +
        ``num_dumps`` + ``reference_path`` feed straight into ``search_reduce``.

        ``region_filter`` (``.msl`` only; a comma list of region categories
        such as ``"heap,stack"``, or a ``"regions=..."`` note) analyses through the region VIEW filter, so offsets are
        filtered-view offsets; omitted, the session's filter applies and
        ``"all"`` explicitly disables it.

        ``force_memory`` overrides the memory-budget guard: an over-budget
        consensus build is refused with code ``memory_budget_exceeded``
        (``estimate_bytes`` / ``budget_bytes`` in the error) unless
        ``force_memory=true``.

        ``allocator`` ("auto", "ptmalloc2", "dlmalloc", "scudo", "mallocng",
        "jemalloc", "generic" or "off") drives the non-destructive heap-role
        annotation (reported under ``heap``); "auto" detects the allocator and
        "off" disables heap analysis.
        """
        return json.dumps(tools_pipeline.consensus(
            dump_paths=dump_paths, output_dir=output_dir, normalize=normalize,
            region_filter=_session_region_filter(region_filter),
            key_file=key_file, passphrase=passphrase, kem_key_file=kem_key_file,
            force=force_memory, allocator=allocator,
        ))

    @mcp.tool()
    @mcp_error_funnel
    def aligned_window(
        dump_paths: List[str],
        anchor_path: Optional[str] = None,
        anchor_view: str = "va",
        offset: int = 0,
        slab_offset: Optional[int] = None,
        length: int = 1024,
        normalize: bool = False,
        classify: bool = True,
        include_bytes: bool = True,
        region_filter: Optional[str] = None,
        key_material_by_path: Optional[dict] = None,
        force_memory: bool = False,
        allocator: str = "auto",
    ) -> str:
        """Read ONE window in EVERY dump at the address the consensus aligned.

        The agent-facing form of the N-dump differential view. Every returned
        ``dumps[d].bytes`` is already in WINDOW coordinates — byte ``i`` of
        each dump is the byte that dump holds at the address put in
        correspondence with the anchor's byte at ``offset + i``, and
        ``classes[i]`` is that correspondence's ByteClass (``-1`` where there
        is none). Do NOT apply ``segments[].dumps[].va``/``offset``: those are
        provenance, and under module-offset alignment two adjacent pages can
        carry different relocation deltas.

        ``key_material_by_path`` is ``{dump_path: {key_file|passphrase|
        kem_key_file}}`` — per dump, because a corpus routinely mixes plaintext
        captures with containers encrypted under different keys.

        ``region_filter`` (``.msl`` only; a comma list of region categories
        such as ``"heap,stack"``, or a ``"regions=..."`` note) analyses through the region VIEW filter, so offsets are
        filtered-view offsets; omitted, the session's filter applies and
        ``"all"`` explicitly disables it.

        ``force_memory`` overrides the memory-budget guard: an over-budget
        consensus build is refused with code ``memory_budget_exceeded``
        (``estimate_bytes`` / ``budget_bytes`` in the error) unless
        ``force_memory=true``.

        ``allocator`` ("auto", "ptmalloc2", "dlmalloc", "scudo", "mallocng",
        "jemalloc", "generic" or "off") drives the non-destructive heap-role
        annotation the window's ``heap_roles`` are read from; "off" omits them.
        """
        return json.dumps(tools_consensus.aligned_window_result(
            _session, dump_paths=dump_paths, anchor_path=anchor_path,
            anchor_view=anchor_view, offset=offset, slab_offset=slab_offset,
            length=length, normalize=normalize, classify=classify,
            include_bytes=include_bytes,
            region_filter=_session_region_filter(region_filter),
            key_material_by_path=_resolve_key_material_by_path(key_material_by_path),
            force=force_memory, allocator=allocator,
        ).payload)

    @mcp.tool()
    @mcp_error_funnel
    def consensus_regions(
        dump_paths: List[str],
        classes: Optional[List[str]] = None,
        min_length: int = 8,
        max_length: int = 0,
        sort: str = "offset",
        after: int = -1,
        limit: int = DEFAULT_REGIONS_PER_PAGE,
        anchor_path: Optional[str] = None,
        anchor_view: str = "va",
        include_anchor_offsets: bool = True,
        normalize: bool = False,
        region_filter: Optional[str] = None,
        key_material_by_path: Optional[dict] = None,
        force_memory: bool = False,
        allocator: str = "auto",
    ) -> str:
        """List EVERY occurrence of a consensus class, paginated and jumpable.

        The complement of ``aligned_window``: that tool answers "what is at
        this offset in all N dumps", this one answers "where are all the
        offsets worth looking at". Each row carries its slab coordinates, its
        label, its per-class byte mix, and — when ``anchor_path`` is given —
        the NAVIGABLE OFFSET in that dump's ``anchor_view``, so the next call
        can be ``read_hex`` / ``aligned_window`` at that offset with no
        coordinate arithmetic of your own. ``-1`` means "not addressable in
        that view"; the envelope's ``anchor.jumpable`` says so for the page.

        OMIT ``classes`` unless you know better. The default is the
        NON-INVARIANT UNION (structural + pointer + key_candidate), because
        real key material is class-MIXED: a measured 48-byte TLS 1.2 secret is
        22 KEY_CANDIDATE + 18 POINTER + 8 STRUCTURAL bytes, so
        ``classes=["key_candidate"]`` does not return that secret — it shatters
        it into 3-byte shards that ``min_length`` then discards.
        ``"non_invariant"`` names the union explicitly.

        ``sort`` is ``"offset"`` (address order), ``"length_desc"`` (longest
        first) or ``"length_asc"`` — the length orders answer "show me the
        biggest key candidates first" without walking the whole list.

        Page with the CURSOR, not a page number: pass the previous response's
        ``next_after`` as ``after``. Its unit follows ``sort`` (aligned-space
        offset vs rank), so treat it as opaque and never compute with it. ``total`` sizes the whole result set and
        ``counts`` is the whole-build class histogram.

        ``key_material_by_path`` is ``{dump_path: {key_file|passphrase|
        kem_key_file}}`` — per dump, because a corpus routinely mixes plaintext
        captures with containers encrypted under different keys.

        ``region_filter`` (``.msl`` only; a comma list of region categories
        such as ``"heap,stack"``, or a ``"regions=..."`` note) analyses through the region VIEW filter, so offsets are
        filtered-view offsets; omitted, the session's filter applies and
        ``"all"`` explicitly disables it.

        ``force_memory`` overrides the memory-budget guard: an over-budget
        consensus build is refused with code ``memory_budget_exceeded``
        (``estimate_bytes`` / ``budget_bytes`` in the error) unless
        ``force_memory=true``.

        ``allocator`` ("auto", "ptmalloc2", "dlmalloc", "scudo", "mallocng",
        "jemalloc", "generic" or "off") drives the non-destructive heap-role
        annotation (reported under ``heap``); "auto" detects the allocator and
        "off" disables heap analysis.
        """
        return json.dumps(tools_consensus.class_regions_result(
            _session, dump_paths=dump_paths, classes=classes,
            min_length=min_length, max_length=max_length, sort=sort, after=after,
            limit=limit, anchor_path=anchor_path, anchor_view=anchor_view,
            include_anchor_offsets=include_anchor_offsets, normalize=normalize,
            region_filter=_session_region_filter(region_filter),
            key_material_by_path=_resolve_key_material_by_path(key_material_by_path),
            force=force_memory, allocator=allocator,
        ).payload)

    @mcp.tool()
    @mcp_error_funnel
    def auto_floor(
        variance_path: str, reference_path: str, oracle_path: str,
        output_dir: str, num_dumps: int,
        oracle_config_path: Optional[str] = None,
        oracle_config: Optional[Dict[str, Any]] = None,
        key_sizes: Optional[List[int]] = None, stride: int = 1,
        reduce_kwargs: Optional[dict] = None,
        coverage: Optional[float] = None, correspondence: Optional[float] = None,
        filter_recall: Optional[float] = None, min_coverage: float = 0.80,
        positive_control_hex: Optional[str] = None,
        phi0_method: str = "pmin", p_min: float = 0.35,
        self_test_trials: int = 8, oracle_budget: Optional[int] = None,
        alignment_quality: Optional[float] = None, min_alignment: float = 0.5,
        managed_region: bool = False,
        neighborhood_pad: int = DEFAULT_NEIGHBORHOOD_PAD,
        region_filter: Optional[str] = None,
        key_file: Optional[str] = None, passphrase: Optional[str] = None,
        kem_key_file: Optional[str] = None,
    ) -> str:
        """Automated oracle-arbitrated variance-floor selection → verdict.

        The oracle's configuration comes from ``oracle_config_path`` (a TOML
        file) or inline as ``oracle_config``; the inline mapping wins when both
        are given.

        ``neighborhood_pad`` (default 64 bytes per side) is the context width
        attached to a recovered hit; it reaches every emitted artifact.

        ``region_filter`` (``.msl`` only) overrides the view filter the
        upstream stage recorded in its artifact; omitted, the recorded filter
        is reused so offsets stay consistent, and ``"all"`` disables it.
        """
        return json.dumps(tools_pipeline.auto_floor(
            variance_path=variance_path, reference_path=reference_path,
            oracle_path=oracle_path, output_dir=output_dir, num_dumps=num_dumps,
            oracle_config_path=oracle_config_path,
            oracle_config=oracle_config,
            key_sizes=tuple(key_sizes or [32]), stride=stride,
            reduce_kwargs=reduce_kwargs, coverage=coverage,
            correspondence=correspondence, filter_recall=filter_recall,
            min_coverage=min_coverage, positive_control_hex=positive_control_hex,
            phi0_method=phi0_method, p_min=p_min,
            self_test_trials=self_test_trials, oracle_budget=oracle_budget,
            alignment_quality=alignment_quality, min_alignment=min_alignment,
            managed_region=managed_region, neighborhood_pad=neighborhood_pad,
            region_filter=region_filter,
            key_file=key_file, passphrase=passphrase, kem_key_file=kem_key_file,
        ))

    @mcp.tool()
    @mcp_error_funnel
    def export_pattern(
        dump_paths: List[str], output_dir: Optional[str] = None,
        fmt: str = "volatility3", name: str = "memdiver_pattern",
        align: bool = True, context: int = 32, min_static_ratio: float = 0.3,
        key_file: Optional[str] = None, passphrase: Optional[str] = None,
        kem_key_file: Optional[str] = None,
        force_memory: bool = False,
    ) -> str:
        """Auto-detect a volatile region and export a YARA/JSON/Vol3 pattern.

        ``force_memory`` overrides the memory-budget guard: an over-budget
        consensus build is refused with code ``memory_budget_exceeded``
        (``estimate_bytes`` / ``budget_bytes`` in the error) unless
        ``force_memory=true``.
        """
        return json.dumps(tools_pipeline.export_pattern(
            dump_paths=dump_paths, output_dir=output_dir, fmt=fmt, name=name,
            align=align, context=context, min_static_ratio=min_static_ratio,
            key_file=key_file, passphrase=passphrase, kem_key_file=kem_key_file,
            force=force_memory,
        ))

    @mcp.tool()
    @mcp_error_funnel
    def manual_export_pattern(
        dump_paths: List[str], offset: int, length: int,
        output_dir: Optional[str] = None,
        fmt: str = "volatility3", name: str = "memdiver_pattern",
        min_static_ratio: float = 0.3,
        key_file: Optional[str] = None, passphrase: Optional[str] = None,
        kem_key_file: Optional[str] = None,
    ) -> str:
        """Export a YARA/JSON/Vol3 pattern from a KNOWN offset + length.

        The manual counterpart to ``export_pattern``: use it when the region is
        already known — from ``analyze_candidates``, from a previous run, or
        from a reverse-engineering session — so no consensus/auto-detect pass is
        needed (hence no ``align`` / ``context``). ``offset`` is memory-relative
        for ``.msl`` inputs, the same space every other offset this server
        reports is in.
        """
        return json.dumps(tools_pipeline.manual_export_pattern(
            dump_paths=dump_paths, offset=offset, length=length,
            output_dir=output_dir, fmt=fmt, name=name,
            min_static_ratio=min_static_ratio,
            key_file=key_file, passphrase=passphrase, kem_key_file=kem_key_file,
        ))

    @mcp.tool()
    @mcp_error_funnel
    def export_keylog(
        secrets: List[dict], output_path: Optional[str] = None,
    ) -> str:
        """Emit a Wireshark-loadable NSS key log from recovered TLS secrets.

        Each item in ``secrets`` is a dict with ``secret_type`` (str),
        ``client_random`` (hex) and ``secret`` (hex). Returns the rendered
        key-log text + line ``count``; also writes it to ``output_path`` when
        given. Loadable via ``tshark -o tls.keylog_file=<path>``.
        """
        return json.dumps(tools_pipeline.keylog_result(
            secrets=secrets, output_path=output_path,
        ))

    @mcp.tool()
    @mcp_error_funnel
    def locate_key(
        dump_paths: List[str],
        key_hex: str = "",
        keylog_line: str = "",
        secret: Optional[dict] = None,
        pcap_field: Optional[dict] = None,
        view: Optional[str] = None,
        max_offsets: int = DEFAULT_MAX_KEY_OFFSETS,
        key_file: Optional[str] = None, passphrase: Optional[str] = None,
        kem_key_file: Optional[str] = None,
        allocator: str = "auto",
    ) -> str:
        """Locate a secret you ALREADY HOLD across N dumps — honest three-valued.

        Use this when you have the key bytes (from a key log, a confirmed
        brute-force hit, a paste) and want to know which dumps still contain
        them and where. It is NOT a search for unknown keys — that is
        ``analyze_candidates`` (no oracle) or ``brute_force`` (with one).

        Supply the secret in exactly ONE of four forms; two forms is an error,
        with no precedence, because two forms naming different bytes would
        otherwise return a confident census of the wrong secret:

        * ``key_hex`` — bare hex ("aa bb cc" or "0xaabbcc").
        * ``keylog_line`` — "<LABEL> <client_random_hex> <secret_hex>". This form
          also reports ``secret_type`` and ``client_random``.
        * ``secret`` — {"secret_type", "client_random", "secret"}.
        * ``pcap_field`` — {"pcap_path", "field_id", "client_random"?}: NAME a
          handshake field instead of pasting its bytes, e.g.
          {"pcap_path": "/x/session.pcap", "field_id": "client_random"}. Prefer
          this over transcribing hex out of an ``inspect_pcap`` result — it
          cannot lose a nibble, and it re-resolves against a re-captured
          session. List the ids with ``inspect_pcap(include_fields=True)`` and
          pick one whose ``searchable`` is true; a non-searchable field is
          refused because it matches everywhere. ``client_random`` is required
          only when the capture holds several sessions (guessing is refused).
          The result reports the resolved ``field_id`` in ``secret_type`` and
          the session in ``client_random``.

        ONE dump is enough (unlike every other N-dump tool here).

        READ ``verdict`` FIRST and do not skip to the counts:

        * ``"found"`` — present in at least one searched dump.
        * ``"absent"`` — searched, and provably not there. A real finding.
        * ``"not_searched"`` — NOTHING was read (unreadable/too-small dumps).
          This claims nothing at all and must never be reported as an absence.

        Each per-dump row carries the same discipline: ``present`` is ``null``,
        not ``false``, on any dump whose ``status`` is not ``"searched"``.
        ``hit_count`` is the TRUE occurrence total even when ``offsets`` was
        truncated to ``max_offsets``.

        Partial survival (present in some dumps, absent from others) is the
        NORMAL shape of a real key across a process lifecycle, not a failure —
        on the reference 8-dump OpenSSL run the master secret survives in 2.
        Nothing is persisted. Supply key_file / passphrase / kem_key_file for
        encrypted ``.msl`` inputs.

        ``allocator`` ("auto", "ptmalloc2", "dlmalloc", "scudo", "mallocng",
        "jemalloc", "generic" or "off") adds non-destructive heap context:
        each dump row with hits gains ``heap``, a list parallel to ``offsets``
        of ``{allocator, chunk_va, chunk_size, state, offset_in_chunk, role}``
        (``null`` outside every chunk) — a hit in a FREED chunk is a residual
        copy. "off" disables it.
        """
        return json.dumps(tools_pipeline.locate_key(
            dump_paths=dump_paths,
            key_hex=key_hex,
            keylog_line=keylog_line,
            secret=secret,
            pcap_field=pcap_field,
            view=view,
            max_offsets=max_offsets,
            key_file=key_file,
            passphrase=passphrase,
            kem_key_file=kem_key_file,
            allocator=allocator,
        ))

    @mcp.tool()
    @mcp_error_funnel
    def locate_field_across_pairs(
        pairs: Optional[List[dict]] = None,
        dump_paths: Optional[List[str]] = None,
        field_id: str = "client_random",
        view: Optional[str] = None,
        max_offsets: int = DEFAULT_MAX_KEY_OFFSETS,
        pcap_max_records: Optional[int] = None,
        pcap_max_challenges: Optional[int] = None,
        key_file: Optional[str] = None, passphrase: Optional[str] = None,
        kem_key_file: Optional[str] = None,
    ) -> str:
        """Search N dumps for a handshake field, each from ITS OWN capture.

        ``locate_key`` searches N dumps for ONE needle — right for a single
        session, wrong for a corpus: 40 runs of the same client each negotiated
        their own handshake, so one client random answers about 39 runs it was
        never in. This tool asks the scalable question instead: *for each dump,
        is the ``field_id`` of the capture belonging to THAT dump present in it,
        and where?* The needle varies per pair.

        NO KEY LOG IS READ — the needle comes off the wire — so this works on a
        corpus that ships captures but no ground truth.

        Supply the pairing in exactly ONE of two forms (both is an error, with
        no precedence, because a disagreement would yield a confident census
        read from the wrong capture):

        * ``pairs`` — explicit: [{"dump_path": ..., "pcap_path": ...,
          "client_random": <optional>}, ...]. ``client_random`` picks a session
          when a capture holds several.
        * ``dump_paths`` — discovery: each dump finds the capture of the run it
          lives in (``meta.capture``, then ``run_data/traffic.pcap*``, then a
          capture sitting beside the dumps).

        ``field_id`` defaults to ``client_random`` (32 bytes, unique per
        handshake, present in every TLS version). Browse the alternatives with
        ``inspect_pcap(include_fields=True)`` and pick one whose ``searchable``
        is true; a non-searchable field is refused because it matches
        everywhere.

        READ ``verdict`` FIRST: ``"found"`` / ``"absent"`` (a measured absence)
        / ``"not_searched"`` (NOTHING was read — claims neither).

        Each row in ``pairs`` carries a three-valued ``status`` you must read
        before its numbers:

        * ``"searched"`` — ``location`` holds a ``locate_key``-shaped census
          over that one dump.
        * ``"unpaired"`` — no capture belongs to this dump, so nothing was
          searched. ``location`` is null and ``needle_hex`` is "". This is a ROW,
          not an omission: it keeps the denominator honest.
        * ``"field_unresolved"`` — a capture was found but yields no usable
          ``field_id``; ``detail`` says why. Also not an absence.

        ``counts.captures_distinct`` / ``counts.needles_distinct`` tell you
        whether this was a real pairing or one needle wearing N hats, and
        ``offsets_agree`` / ``common_offset`` whether the field lands at the same
        offset across the dumps that hold it.

        Nothing is persisted. Supply key_file / passphrase / kem_key_file for
        encrypted ``.msl`` inputs.
        """
        return json.dumps(tools_pipeline.locate_field_across_pairs(
            pairs=pairs,
            dump_paths=dump_paths,
            field_id=field_id,
            view=view,
            max_offsets=max_offsets,
            pcap_max_records=pcap_max_records,
            pcap_max_challenges=pcap_max_challenges,
            key_file=key_file,
            passphrase=passphrase,
            kem_key_file=kem_key_file,
        ))

    @mcp.tool()
    @mcp_error_funnel
    def scan_yara_rule(
        dump_paths: List[str],
        rule_source: Optional[str] = None,
        rule_paths: Optional[List[str]] = None,
        view: Optional[str] = None,
        max_matches: Optional[int] = DEFAULT_MAX_MATCHES,
        timeout_s: int = DEFAULT_TIMEOUT_S,
        overlap_bytes: int = 0,
        include_matches: bool = DEFAULT_INCLUDE_MATCHES,
        key_file: Optional[str] = None, passphrase: Optional[str] = None,
        kem_key_file: Optional[str] = None,
    ) -> str:
        """Compile ONE YARA rule set and scan N dumps with it.

        The other half of ``export_key_pattern`` / ``export_pattern``, which
        only ever WROTE a signature. Until this tool existed an emitted
        detector was unevaluated by construction: you could publish a rule and
        never learn whether it fires on the corpus it came from, let alone on a
        held-out one. Point this at the rule and the dumps and you get a census.

        Supply the rules in exactly ONE of two forms (both is an error, with no
        precedence, because silently preferring one would hand you a confident
        census produced by rules you did not intend):

        * ``rule_source`` — inline YARA rule text, e.g. the ``content`` field
          ``export_key_pattern(fmt="yara")`` just handed you.
        * ``rule_paths`` — ``.yar`` files, each compiled into its OWN namespace
          so two files may define the same rule name.

        A precompiled ``.yarc`` is NOT accepted in any form and will not be
        added: a compiled rule file is executable libyara bytecode, so loading
        one has the trust properties of importing a module.

        The rule set is compiled ONCE and reused across every dump, which is
        both what makes a corpus sweep affordable and what makes the rows
        comparable.

        READ ``verdict`` FIRST, because only ONE of its four values is an
        absence:

        * ``"matched"``      — at least one dump matched.
        * ``"clean"``        — at least one dump was scanned end to end with no
          match, and NO scanned dump was degraded. The only value you may
          report as "the rule does not fire here".
        * ``"inconclusive"`` — nothing matched, but every zero came from a scan
          that timed out or hit a read error, so the zeros are UNPROVEN. Raise
          ``timeout_s`` or widen ``overlap_bytes`` and ask again.
        * ``"not_scanned"``  — no dump was readable. Claims nothing.

        Then read each row's ``status`` before its numbers: ``"scanned"`` rows
        carry a ``scan`` block (``match_count``, ``matches`` with absolute
        ``offset``s in ``scan.view`` coordinates, plus ``truncated`` /
        ``timed_out`` / ``errors``), and ``"unreadable"`` rows carry
        ``scan: null`` and a ``detail``. An unreadable dump is a ROW, not an
        omission: it keeps the denominator honest, and every rate in ``counts``
        is over ``dumps_scanned`` rather than ``dumps_total``.

        Each match's ``offset`` is the start of the matched WINDOW, not of the
        key. ``key_offset`` / ``key_length`` (lifted from the rule's meta when
        MemDiver emitted it) say where the key sits inside that window, so the
        key is expected at ``offset + key_offset``.

        ``max_matches`` caps the matches kept per dump and sets that row's
        ``scan.truncated``; it must be positive, and ``null`` (not ``0``) is how
        you ask for no cap at all. Nothing is persisted. Supply key_file /
        passphrase / kem_key_file for encrypted ``.msl`` inputs — a locked
        container is refused rather than reported as a clean scan.

        ``include_matches=False`` is the COUNT-ONLY census, and on this surface
        it is the difference between an answerable question and an unusable one:
        a tool result is a single JSON string you have to hold in context, and
        an unselective rule can fire hundreds of thousands of times per dump,
        each firing carrying up to 512 bytes of ``matched_hex``. Ask for counts
        whenever the question is "how selective is this rule?" rather than
        "where exactly did it fire?". Every count and flag survives —
        ``match_count`` per row, ``counts.matches_total``, ``truncated``,
        ``timed_out``, ``errors``, ``scanned_bytes``, ``chunks``, ``strategy``
        and the ``verdict`` are all identical to the full form's; only each
        row's ``matches`` list is gone, replaced by ``matches_omitted: true``
        (ABSENT rather than empty, so an empty-list check cannot misread a
        count-only row as a proven absence).

        Two things it does NOT do. It does not make the scan faster or smaller
        in memory — libyara still finds every match; only the payload is
        bounded. And it does not touch ``max_matches``: the two are orthogonal,
        so a count-only run still stops at the cap and its ``matches_total`` is
        then a FLOOR. Pass ``max_matches=null`` with it for the honest census;
        the ``analysis.yara_scan.count_only`` diagnostic says which of the two
        you got. A count-only payload cannot be fed to
        ``score_detector_matches``, which reads ``dumps[].scan.matches``.
        """
        return json.dumps(tools_pipeline.scan_yara_rule(
            dump_paths=dump_paths,
            rule_source=rule_source,
            rule_paths=rule_paths,
            view=view,
            max_matches=max_matches,
            timeout_s=timeout_s,
            overlap_bytes=overlap_bytes,
            include_matches=include_matches,
            key_file=key_file,
            passphrase=passphrase,
            kem_key_file=kem_key_file,
        ))

    @mcp.tool()
    @mcp_error_funnel
    def verify_vol3_plugin(
        dump_paths: List[str],
        plugin_source: Optional[str] = None,
        plugin_path: Optional[str] = None,
        mode: str = VOL3_MODE_AUTO,
        view: Optional[str] = None,
        expected_offset: Optional[int] = None,
        key_hex: Optional[str] = None,
        pid: Optional[int] = None,
        vol_bin: Optional[str] = None,
        vol_python: Optional[str] = None,
        timeout_s: int = VOL3_SUBPROC_TIMEOUT_S,
        max_hits: int = VOL3_MAX_HITS,
        include_hits: bool = DEFAULT_INCLUDE_HITS,
        key_file: Optional[str] = None, passphrase: Optional[str] = None,
        kem_key_file: Optional[str] = None,
    ) -> str:
        """RUN a MemDiver-emitted Volatility3 plugin over N dumps.

        The Volatility3 half of what ``scan_yara_rule`` is for YARA, and the
        thing that makes ``emit_plugin`` / ``export_pattern`` claims checkable:
        an emitted plugin that has not been RUN is not evidence. For most of
        this repo's life such a plugin was checked only by parsing its
        generated text, so one that could not even be imported passed every
        test there was.

        Supply the plugin in exactly ONE of two forms (both is an error, with
        no precedence, because silently preferring one would hand you a
        confident verification of a plugin you did not mean to test):

        * ``plugin_source`` — the plugin's Python TEXT, e.g. the ``content``
          field ``export_key_pattern(fmt="vol3")`` just handed you.
        * ``plugin_path`` — a ``.py`` file on disk.

        **Pick the mode deliberately; the two answer different questions.**

        * ``"in_process"`` execs the plugin here, constructs it through
          Volatility3's own requirement gate, and scans bytes MemDiver
          PROJECTED. It is the only mode that can address an ``.msl``.
        * ``"subprocess"`` runs ``vol -p <dir> -f <dump> <module>.<Class>``
          against a real launcher — the way a plugin is actually used, often
          against a different framework version than MemDiver's own.
        * ``"auto"`` (the default) prefers in-process and falls back.

        Point ``vol_bin`` / ``vol_python`` at a specific launcher and the
        interpreter that owns its Volatility3. They beat the
        ``MEMDIVER_VOL3_BIN`` / ``MEMDIVER_VOL3_PYTHON`` env vars, and on this
        surface they are the ONLY way to select a launcher — you cannot set an
        environment variable through a tool call.

        READ ``verdict`` FIRST, because only ONE of its four values is an
        absence:

        * ``"hit"``          — the plugin fired on at least one dump.
        * ``"no_hit"``       — it ran end to end and fired on nothing, and no
          zero was degraded. The only value you may report as "this plugin does
          not fire here".
        * ``"inconclusive"`` — nothing fired, but every zero came off a run
          that covered 0 bytes, so the zeros are UNPROVEN.
        * ``"not_run"``      — nothing ran at all. Claims NOTHING, and it is
          in particular what ``mode="subprocess"`` returns for an ``.msl``:
          ``vol`` takes a bare file path and would scan the CONTAINER, which on
          the ground-truth run puts the key at 371752 where every MemDiver
          coordinate says 370672. That row is REFUSED as ``"unsupported"``
          rather than reported, because a confident wrong offset is worse than
          no answer. Re-run with ``mode="in_process"``.

        Then read ``runtime`` and each row's ``framework_version``. This is not
        bookkeeping: three Volatility3 trees commonly coexist on one machine
        and they disagree, and a hit at 370672 that does not say which
        framework found it cannot be reproduced. ``runtime.versions_agree``
        states whether the two runtimes match (``null`` when either is
        unknown), and ``runtime.subprocess`` carries the launcher's path, cwd
        and interpreter, all three of which affect which framework loads.

        Each row's ``status`` comes before its numbers: ``"verified"`` rows
        carry a ``run`` block, and ``"unreadable"`` / ``"unsupported"`` rows
        carry ``run: null`` plus a ``detail``. Those are ROWS, not omissions —
        every rate in ``counts`` is over ``dumps_verified``.

        Inside ``run``, three claims of increasing strength:
        ``match_count`` (it fired), ``expected_offset_reported`` (it fired at
        the byte you named — EXACT, no tolerance), and ``key_recovered`` (it
        handed the key's own bytes back). That last one is the sharpest
        instrument here and it is ``null``, never ``false``, when you supply no
        ``key_hex``. Expect it to disagree with ``match_count`` on a real
        corpus: an emitted pattern WILDCARDS the key, so its window still
        matches a dump the key was wiped from. Measured on the 8-dump
        ground-truth run, a pad-256 plugin fires on 8 of 8 at offset 370672 and
        ``key_recovered`` is true on exactly the 2 dumps that still hold the
        secret. Reading ``match_count`` alone would have called that 8 of 8.

        ``max_hits`` caps the RETAINED list, never ``match_count``; when
        ``hits_capped`` is true, ``key_recovered`` and
        ``expected_offset_reported`` may be false negatives.
        ``include_hits=False`` is the count-only census — ask for it whenever
        the question is "how selective is this plugin?" rather than "where
        exactly did it fire?"; ``anchor_distinct_bytes`` is the number to read
        for selectivity, and an anchor of 128 zero bytes has 1.

        ``pid`` is passed through to the plugin's ``--pid`` and is EXPLICITLY
        UNPROVEN: narrowing needs a kernel image plus a matching ISF, a flat
        process dump has neither, and the emitted plugin then warns and scans
        the whole layer anyway. Do not report the rows as restricted to that
        process.

        Nothing is persisted. Supply key_file / passphrase / kem_key_file for
        encrypted ``.msl`` inputs — a locked container is refused in BOTH modes
        rather than reported as a clean run.
        """
        return json.dumps(tools_pipeline.verify_vol3_plugin(
            dump_paths=dump_paths,
            plugin_source=plugin_source,
            plugin_path=plugin_path,
            mode=mode,
            view=view,
            expected_offset=expected_offset,
            key_hex=key_hex,
            pid=pid,
            vol_bin=vol_bin,
            vol_python=vol_python,
            timeout_s=timeout_s,
            max_hits=max_hits,
            include_hits=include_hits,
            key_file=key_file,
            passphrase=passphrase,
            kem_key_file=kem_key_file,
        ))

    @mcp.tool()
    @mcp_error_funnel
    def score_detector_matches(
        matches: Optional[List[Dict[str, Any]]] = None,
        truths: Optional[List[Dict[str, Any]]] = None,
        detector: Optional[str] = None,
        dump: Optional[str] = None,
        truth_sources: Optional[List[str]] = None,
        rows: Optional[List[Dict[str, Any]]] = None,
        tolerance_bytes: int = DEFAULT_TOLERANCE_BYTES,
    ) -> str:
        """Score detector firings against the key's known-true intervals.

        The second half of ``scan_yara_rule``. That tool tells you the rule
        FIRED; it cannot tell you the rule was RIGHT, and those are different
        facts — a rule that matches every page gives you a perfect
        ``dumps_matched`` and is worthless. Take a scan's
        ``dumps[].scan.matches``, put them beside the intervals you know the
        key occupies, and this returns interval precision/recall.

        Nothing is opened and nothing is persisted: both sides arrive as data,
        so there are no paths and no key-material parameters here.

        Supply the work in exactly ONE of two intakes (both is an error, with
        no precedence):

        * ``matches`` + ``truths`` — one detector, one dump. ``detector`` /
          ``dump`` / ``truth_sources`` are optional labels on this form.
        * ``rows`` — N objects, each with those same keys. Rows are scored
          INDEPENDENTLY and only the counts are summed, so a firing from one
          dump can never pair with a truth from another whose offsets happen to
          line up.

        Each match needs ``offset`` and ``length`` (absolute, in the same view
        the scan ran in) and MAY carry ``key_offset`` / ``key_length``. A
        firing without ``key_offset`` makes no positional claim, so it is
        excluded from the ``key_offset``/``exact`` precision denominators
        rather than charged as a false positive. Each truth needs ``start``
        (or ``offset``) and ``length``, and should carry ``source``
        (``"keylog"`` / ``"ledger"``) so sparse ledger corroboration is not
        mistaken for complete key-log truth. A match or truth with NO byte
        position is REFUSED rather than defaulted to 0.

        Three CRITERIA come back for every row and for the roll-up, always
        together, because reading them side by side is what distinguishes
        "found the neighbourhood" from "found the key":

        * ``containment`` — the firing's window enclosed the key. This is what
          a wildcarded-window rule actually claims.
        * ``key_offset``  — the firing's PREDICTED key position was right to
          within ``tolerance_bytes`` (default 16, the alignment slack).
        * ``exact``       — right to the byte.

        Precision is match-indexed and recall truth-indexed (they are NOT two
        views of one confusion matrix), so ALSO read
        ``max_truths_per_match``: a recall of 1.0 reached by one enormous
        window that swallowed every key shows up there, and the diagnostics
        say so out loud.

        READ ``verdict`` FIRST — only one of the three is a measurement:

        * ``"scored"``     — rows had both keys and firings; the numbers mean
          something.
        * ``"no_matches"`` — there were keys to find and the detector fired on
          none of them. This zero is REAL.
        * ``"no_truths"``  — no row carried a truth interval, so nothing was
          scorable, ``report`` is null, and the result says nothing at all
          about the firings — least of all that they were wrong.
        """
        return json.dumps(tools_pipeline.score_detector_matches(
            matches=matches,
            truths=truths,
            detector=detector,
            dump=dump,
            truth_sources=truth_sources,
            rows=rows,
            tolerance_bytes=tolerance_bytes,
        ))

    @mcp.tool()
    @mcp_error_funnel
    def export_key_pattern(
        dump_paths: List[str],
        key_hex: str = "",
        keylog_line: str = "",
        secret: Optional[dict] = None,
        context: int = DEFAULT_KEY_CONTEXT,
        fmt: str = "yara",
        name: str = "memdiver_key_pattern",
        min_static_ratio: float = 0.3,
        view: Optional[str] = None,
        output_dir: Optional[str] = None,
        include_window_hex: bool = False,
        max_offsets: int = DEFAULT_MAX_KEY_OFFSETS,
        key_file: Optional[str] = None, passphrase: Optional[str] = None,
        kem_key_file: Optional[str] = None,
    ) -> str:
        """Turn a KNOWN secret's location into a scanning signature.

        The companion to ``locate_key``: same three input forms, same mutual
        exclusion. Where ``export_pattern`` GUESSES which region is the key,
        this one is told, locates it per dump, and describes its NEIGHBOURHOOD —
        wildcarding the key bytes themselves, which is what makes the rule
        reusable on a different session.

        PASS DUMPS IN WHICH THE KEY IS ABSENT. This is the counter-intuitive
        part and it is measured, not stylistic: the static mask is computed over
        every searched dump, and the dumps that DO NOT hold the key are the
        mechanism that turns the key span into "??". On the reference 8-dump
        OpenSSL run, masking over all 8 wildcards exactly the 48 key bytes;
        masking over only the 2 dumps that hold it yields a 100 %-static rule
        that embeds the secret verbatim and matches that one key and nothing
        else. If you pass only the dumps where the key is present you will get
        exactly that, plus a ``key_fully_static`` WARNING telling you so.

        Read ``diagnostics`` before using the rule. Two WARNINGs matter most:
        ``key_fully_static`` (above) and ``degenerate_anchors`` — the static
        anchors carry near-zero entropy, so the rule matches almost anywhere
        (this fires at the default context on the real corpus key, whose
        surroundings are zeros; raise ``context``). Also check the top-level
        ``offsets_agree``: when it is false, ``region.offset`` is the reference
        dump's window start and generalises to nothing.

        ``fmt`` defaults to ``yara`` here. Requires at least 2 dumps (a static
        mask is a comparison). ``include_window_hex`` adds each dump's raw
        window bytes.
        """
        return json.dumps(tools_pipeline.export_key_pattern(
            dump_paths=dump_paths,
            key_hex=key_hex,
            keylog_line=keylog_line,
            secret=secret,
            context=context,
            fmt=fmt,
            name=name,
            min_static_ratio=min_static_ratio,
            view=view,
            output_dir=output_dir,
            include_window_hex=include_window_hex,
            max_offsets=max_offsets,
            key_file=key_file,
            passphrase=passphrase,
            kem_key_file=kem_key_file,
        ))

    @mcp.tool()
    @mcp_error_funnel
    def inspect_pcap(
        pcap_path: str,
        pcap_max_records: Optional[int] = None,
        pcap_max_challenges: Optional[int] = None,
        include_fields: bool = False,
        detect_protocols: bool = False,
    ) -> str:
        """Summarise the TLS sessions in a capture (the pcap arm/validate step).

        Parses ``pcap_path``'s handshakes and returns, per session, the
        client/server random, negotiated cipher suite + version, and the
        per-direction application-data record counts — the facts the pcap
        verification oracle keys off. Reads only parsed state (no key
        derivation, no decryption). Requires the ``pcap`` extra (dpkt).

        Pass the same ``pcap_max_records`` / ``pcap_max_challenges`` the
        ``brute_force`` run will use, so the reported ``caps`` and the
        ``records_truncated`` / ``challenges_truncated`` flags describe the caps
        actually in force rather than the resource defaults. Leave both unset
        for the defaults. A cap below 1 is rejected: it would verify nothing and
        so could only turn a real key into an unexplained "0 confirmed".

        Set ``include_fields`` to also get the byte-addressed view of each
        handshake: per session a ``fields`` list (``field_id``, ``value_hex``,
        ``length``, ``source``, wire ``provenance``, ``searchable``) plus
        ``field_notes``, and a top-level ``field_index`` cataloguing the ids the
        capture offers. That is how you find the ``field_id`` to hand to
        ``locate_key``'s ``pcap_field`` form — the way to search dumps for a
        handshake value without transcribing its hex. Read ``searchable`` first:
        a false one matches everywhere, so a hit on it means nothing, and
        ``locate_key`` refuses it. Off by default because it re-reads the
        capture; leave it off when you only want the session facts.

        Set ``detect_protocols`` when ``session_count`` comes back 0 (or a
        ``brute_force`` run refuses the capture): it adds a top-level
        ``protocols`` list saying what the capture actually holds — per protocol
        the ``resource_type`` that would read it, whether anything installed can
        ``decrypt`` it, the connection count, and sample endpoints as
        ``evidence``. That is how you find the ``resource_type`` to pass to
        ``brute_force`` / ``n_sweep``. Never errors: an unreadable or
        unrecognisable capture yields an empty list. Off by default (it costs
        two extra reads of the capture, one of them a UDP pass for QUIC/DTLS).
        """
        return json.dumps(tools_pipeline.inspect_pcap(
            pcap_path=pcap_path,
            pcap_max_records=pcap_max_records,
            pcap_max_challenges=pcap_max_challenges,
            include_fields=include_fields,
            detect_protocols=detect_protocols,
        ))

    # ------------------------------------------------------------------
    # verify + experiment — the two capabilities lifted into shared
    # producers in Phase 5 (previously CLI/API-only), now reachable here too.
    # ------------------------------------------------------------------

    @mcp.tool()
    @mcp_error_funnel
    def verify(
        dump_path: str, offset: int, ciphertext_hex: str, length: int = 32,
        cipher: str = "AES-256-CBC", iv_hex: Optional[str] = None,
        nonce_hex: Optional[str] = None, aad_hex: Optional[str] = None,
        tag_hex: Optional[str] = None,
        view: Optional[str] = None,
        key_file: Optional[str] = None, passphrase: Optional[str] = None,
        kem_key_file: Optional[str] = None,
    ) -> str:
        """Verify a candidate key read at an offset decrypts a known ciphertext.

        The offset is read through the dump's memory projection (VAS for
        ``.msl``) unless ``view`` ("raw" / "vas" / "va") names the view it
        addresses; encrypted containers are decrypted with the key material.
        AEAD ciphers (GCM, ChaCha20-Poly1305) authenticate a real record via the
        optional ``nonce_hex`` / ``aad_hex`` / ``tag_hex`` parameters.
        """
        from memdiver.app.key_material import key_material_kwargs
        return json.dumps(tools_pipeline.verify_key_result(
            dump_path=dump_path, offset=offset, length=length,
            ciphertext_hex=ciphertext_hex, cipher=cipher, iv_hex=iv_hex,
            nonce_hex=nonce_hex, aad_hex=aad_hex, tag_hex=tag_hex, view=view,
            key_material=key_material_kwargs(key_file, passphrase, kem_key_file),
        ))

    @mcp.tool()
    @mcp_error_funnel
    def experiment(
        target: str, output_dir: str, num_runs: int = 10,
        tools: Optional[List[str]] = None, export_format: str = "volatility3",
        convergence: bool = False, max_fp: int = 0,
        region_filter: Optional[str] = None,
        key_file: Optional[str] = None, passphrase: Optional[str] = None,
        kem_key_file: Optional[str] = None,
        force_memory: bool = False,
    ) -> str:
        """Run the full spawn→dump→consensus→verify→emit experiment.

        Requires a usable local dump tool. frida-tools and memslicer ship in
        the base install; LLDB comes from the OS. Returns a
        ``missing_backend`` CapabilityError, carrying the per-tool remedy,
        when none are available.

        ``region_filter`` (``.msl`` only; a comma list of region categories
        such as ``"heap,stack"``, or a ``"regions=..."`` note) analyses through the region VIEW filter, so offsets are
        filtered-view offsets; omitted, the session's filter applies and
        ``"all"`` explicitly disables it.

        ``force_memory`` overrides the memory-budget guard: an over-budget
        consensus build is refused with code ``memory_budget_exceeded``
        (``estimate_bytes`` / ``budget_bytes`` in the error) unless
        ``force_memory=true``.
        """
        from memdiver.app.key_material import key_material_kwargs
        return json.dumps(experiment_orchestration.experiment_result(
            target=target, output_dir=output_dir, num_runs=num_runs,
            tools=tools, export_format=export_format,
            convergence=convergence, max_fp=max_fp,
            region_filter=_session_region_filter(region_filter),
            key_material=key_material_kwargs(key_file, passphrase, kem_key_file),
            force=force_memory,
        ))

    @mcp.tool()
    @mcp_error_funnel
    def capture_dump(
        target: str, output: str, tool: str = "memslicer",
        device: str = "local", max_region_size: Optional[int] = None,
        include_large_readonly: bool = False, timeout: Optional[float] = None,
    ) -> str:
        """Capture ONE dump of a running process and return the capture report.

        ``target`` is a pid or a process / Android package name. ``device``:
        ``local`` (default), ``usb`` (first USB device), ``usb:<frida-id>``
        (e.g. ``usb:emulator-5554``) or ``remote:<host>[:<port>]``; lldb is
        local-only, fridump supports local and ``usb``. ``tool``: memslicer
        (``.msl``), lldb or fridump (raw bin + ``.maps`` sidecar). Every region
        not captured is listed under ``skipped`` (base/size/reason) and in
        ``summary_warnings``; ``max_region_size`` is an explicit cap (skipped
        regions are reported), ``include_large_readonly`` makes lldb also take
        the >= 100 MiB read-only regions (macOS shared cache).
        """
        return json.dumps(experiment_orchestration.capture_result(
            target=target, output=output, tool=tool, device=device,
            max_region_size=max_region_size,
            include_large_readonly=include_large_readonly, timeout=timeout,
        ))

    return mcp


def main(transport: str = "stdio", port: int = 8080) -> None:
    """Entry point for the MCP server.

    For ``transport == "sse"``, ``port`` selects the SSE listener port
    (bound to 127.0.0.1). Any other transport runs over stdio and the port
    argument is ignored.
    """
    from memdiver.core.log import setup_logging
    setup_logging(level="WARNING")

    server = create_server()
    if transport == "sse":
        # mcp 2.x: MCPServer.run() takes the SSE listener's host/port as
        # keywords (they are no longer constructor settings). Loopback only.
        server.run(transport="sse", host="127.0.0.1", port=port)
    else:
        server.run(transport="stdio")

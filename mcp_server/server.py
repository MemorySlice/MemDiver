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
    from mcp.server.fastmcp import FastMCP

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

    from memdiver.app import tools_consensus

    from . import tools, tools_inspect, tools_pipeline, tools_xref
    from .presenters import mcp_error_funnel, present_inspect_mcp_call

    mcp = FastMCP(
        "memdiver",
        instructions="Memory dump forensic analysis platform for cryptographic key identification",
    )
    _session = build_tool_session()

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
    ) -> str:
        """Run the full analysis pipeline on library directories at a specific phase."""
        return json.dumps(tools.analyze_library(
            _session, library_dirs, phase, protocol_version,
            keylog_filename, template_name, max_runs, normalize, expand_keys,
            algorithms,
        ))

    @mcp.tool()
    def read_hex(
        dump_path: str, offset: int = 0, length: int = 256, view: str = "raw",
        key_file: Optional[str] = None, passphrase: Optional[str] = None,
        kem_key_file: Optional[str] = None,
    ) -> str:
        """Read raw bytes from a dump file. Returns hex + ASCII representation.

        For ``.msl`` files, ``view="raw"`` (default) reads the container
        bytes; ``view="vas"`` reads the flattened captured-memory projection.
        Encrypted ``.msl`` inputs are decrypted when key material is supplied.
        """
        return json.dumps(present_inspect_mcp_call(lambda: tools_inspect.read_hex_result(
            _session, dump_path, offset, length, view,
            key_file, passphrase, kem_key_file,
        )))

    @mcp.tool()
    @mcp_error_funnel
    def get_entropy(
        dump_path: str, offset: int = 0, length: int = 0,
        window: int = 32, step: int = 16, threshold: float = 7.5,
        key_file: Optional[str] = None, passphrase: Optional[str] = None,
        kem_key_file: Optional[str] = None,
    ) -> str:
        """Compute sliding-window entropy profile for a dump file region."""
        return json.dumps(present_inspect_mcp_call(lambda: tools_inspect.entropy_result(
            _session, dump_path, offset, length, window, step, threshold,
            key_file, passphrase, kem_key_file,
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
    ) -> str:
        """Import a raw .dump file to .msl format."""
        return json.dumps(tools.import_raw_dump(_session, raw_path, output_path, pid))

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
        key_file: Optional[str] = None, passphrase: Optional[str] = None,
        kem_key_file: Optional[str] = None,
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
            key_file=key_file,
            passphrase=passphrase,
            kem_key_file=kem_key_file,
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
        key_file: Optional[str] = None, passphrase: Optional[str] = None,
        kem_key_file: Optional[str] = None,
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
            key_file=key_file,
            passphrase=passphrase,
            kem_key_file=kem_key_file,
        ))

    @mcp.tool()
    @mcp_error_funnel
    def brute_force(
        candidates_path: str, reference_path: str,
        output_dir: str, oracle_path: Optional[str] = None,
        oracle_config_path: Optional[str] = None,
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

        Supply ``key_file`` / ``passphrase`` / ``kem_key_file`` to brute-force
        against an *encrypted* ``.msl`` reference; ``variance_threshold`` sets
        the static-byte cutoff surfaced in the stage's preview.
        ``neighborhood_pad`` (default 64 bytes per side) is the context width
        attached to each hit and therefore baked into every emitted vol3/YARA
        artifact — leave it at the default unless you mean to change what the
        tool emits.
        """
        return json.dumps(tools_pipeline.brute_force(
            candidates_path=candidates_path,
            reference_path=reference_path,
            oracle_path=oracle_path,
            output_dir=output_dir,
            oracle_config_path=oracle_config_path,
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
        escalate: bool = False,
        escalate_oracle_budget: Optional[int] = None,
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

        Set ``escalate`` to run a floor-free sweep at the terminal N when no
        checkpoint found a hit; its verdict surfaces under ``escalation``.
        Supply ``key_file`` / ``passphrase`` / ``kem_key_file`` for encrypted
        ``.msl`` sources.
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
            escalate=escalate,
            escalate_oracle_budget=escalate_oracle_budget,
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
        key_file: Optional[str] = None, passphrase: Optional[str] = None,
        kem_key_file: Optional[str] = None,
    ) -> str:
        """Emit a Volatility 3 plugin from a brute-force hit's neighborhood.

        Supply ``key_file`` / ``passphrase`` / ``kem_key_file`` when the
        reference is an encrypted ``.msl``.
        """
        return json.dumps(tools_pipeline.emit_plugin(
            hits_path=hits_path,
            reference_path=reference_path,
            name=name,
            output_dir=output_dir,
            description=description,
            hit_index=hit_index,
            variance_threshold=variance_threshold,
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
    ) -> str:
        """Read raw bytes from a dump file, returned base64-encoded."""
        return json.dumps(present_inspect_mcp_call(lambda: tools_inspect.read_hex_raw_result(
            _session, dump_path, offset, length, view,
            key_file, passphrase, kem_key_file,
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
        kem_key_file: Optional[str] = None,
    ) -> str:
        """Search a dump for every occurrence of a hex byte pattern."""
        return json.dumps(present_inspect_mcp_call(lambda: tools_inspect.search_bytes_result(
            _session, dump_path, pattern_hex, view, max_results, cursor,
            key_file, passphrase, kem_key_file,
        )))

    @mcp.tool()
    def get_page_states(
        msl_path: str, key_file: Optional[str] = None,
        passphrase: Optional[str] = None, kem_key_file: Optional[str] = None,
    ) -> str:
        """Surface the MSL three-state page model (CAPTURED/FAILED/UNMAPPED)."""
        return json.dumps(present_inspect_mcp_call(lambda: tools_inspect.page_states_result(
            _session, msl_path, key_file, passphrase, kem_key_file,
        )))

    # ------------------------------------------------------------------
    # Pipeline origination + export breadth tools
    # ------------------------------------------------------------------

    @mcp.tool()
    @mcp_error_funnel
    def consensus(
        dump_paths: List[str], output_dir: str, normalize: bool = False,
        key_file: Optional[str] = None, passphrase: Optional[str] = None,
        kem_key_file: Optional[str] = None,
    ) -> str:
        """Build a per-byte consensus variance vector; writes variance.npy.

        Originates the MCP pipeline: the returned ``variance_path`` +
        ``num_dumps`` + ``reference_path`` feed straight into ``search_reduce``.
        """
        return json.dumps(tools_pipeline.consensus(
            dump_paths=dump_paths, output_dir=output_dir, normalize=normalize,
            key_file=key_file, passphrase=passphrase, kem_key_file=kem_key_file,
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
        key_material_by_path: Optional[dict] = None,
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
        """
        return json.dumps(tools_consensus.aligned_window_result(
            _session, dump_paths=dump_paths, anchor_path=anchor_path,
            anchor_view=anchor_view, offset=offset, slab_offset=slab_offset,
            length=length, normalize=normalize, classify=classify,
            include_bytes=include_bytes,
            key_material_by_path=_resolve_key_material_by_path(key_material_by_path),
        ).payload)

    @mcp.tool()
    @mcp_error_funnel
    def auto_floor(
        variance_path: str, reference_path: str, oracle_path: str,
        output_dir: str, num_dumps: int,
        oracle_config_path: Optional[str] = None,
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
        key_file: Optional[str] = None, passphrase: Optional[str] = None,
        kem_key_file: Optional[str] = None,
    ) -> str:
        """Automated oracle-arbitrated variance-floor selection → verdict.

        ``neighborhood_pad`` (default 64 bytes per side) is the context width
        attached to a recovered hit; it reaches every emitted artifact.
        """
        return json.dumps(tools_pipeline.auto_floor(
            variance_path=variance_path, reference_path=reference_path,
            oracle_path=oracle_path, output_dir=output_dir, num_dumps=num_dumps,
            oracle_config_path=oracle_config_path,
            key_sizes=tuple(key_sizes or [32]), stride=stride,
            reduce_kwargs=reduce_kwargs, coverage=coverage,
            correspondence=correspondence, filter_recall=filter_recall,
            min_coverage=min_coverage, positive_control_hex=positive_control_hex,
            phi0_method=phi0_method, p_min=p_min,
            self_test_trials=self_test_trials, oracle_budget=oracle_budget,
            alignment_quality=alignment_quality, min_alignment=min_alignment,
            managed_region=managed_region, neighborhood_pad=neighborhood_pad,
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
    ) -> str:
        """Auto-detect a volatile region and export a YARA/JSON/Vol3 pattern."""
        return json.dumps(tools_pipeline.export_pattern(
            dump_paths=dump_paths, output_dir=output_dir, fmt=fmt, name=name,
            align=align, context=context, min_static_ratio=min_static_ratio,
            key_file=key_file, passphrase=passphrase, kem_key_file=kem_key_file,
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
        key_file: Optional[str] = None, passphrase: Optional[str] = None,
        kem_key_file: Optional[str] = None,
    ) -> str:
        """Verify a candidate key read at an offset decrypts a known ciphertext.

        The offset is read through the dump's memory projection (VAS for
        ``.msl``); encrypted containers are decrypted with the key material.
        AEAD ciphers (GCM, ChaCha20-Poly1305) authenticate a real record via the
        optional ``nonce_hex`` / ``aad_hex`` / ``tag_hex`` parameters.
        """
        from memdiver.app.key_material import key_material_kwargs
        return json.dumps(tools_pipeline.verify_key_result(
            dump_path=dump_path, offset=offset, length=length,
            ciphertext_hex=ciphertext_hex, cipher=cipher, iv_hex=iv_hex,
            nonce_hex=nonce_hex, aad_hex=aad_hex, tag_hex=tag_hex,
            key_material=key_material_kwargs(key_file, passphrase, kem_key_file),
        ))

    @mcp.tool()
    @mcp_error_funnel
    def experiment(
        target: str, output_dir: str, num_runs: int = 10,
        tools: Optional[List[str]] = None, export_format: str = "volatility3",
        convergence: bool = False, max_fp: int = 0,
        key_file: Optional[str] = None, passphrase: Optional[str] = None,
        kem_key_file: Optional[str] = None,
    ) -> str:
        """Run the full spawn→dump→consensus→verify→emit experiment.

        Requires a usable local dump tool. frida-tools and memslicer ship in
        the base install; LLDB comes from the OS. Returns a
        ``missing_backend`` CapabilityError, carrying the per-tool remedy,
        when none are available.
        """
        from memdiver.app.key_material import key_material_kwargs
        return json.dumps(experiment_orchestration.experiment_result(
            target=target, output_dir=output_dir, num_runs=num_runs,
            tools=tools, export_format=export_format,
            convergence=convergence, max_fp=max_fp,
            key_material=key_material_kwargs(key_file, passphrase, kem_key_file),
        ))

    return mcp


def main(transport: str = "stdio", port: int = 8080) -> None:
    """Entry point for the MCP server.

    For ``transport == "sse"``, ``port`` selects the SSE listener port.
    For stdio transport the port argument is ignored.
    """
    from memdiver.core.log import setup_logging
    setup_logging(level="WARNING")

    server = create_server()
    if transport == "sse":
        # FastMCP's run() accepts the port via keyword for SSE transport.
        server.run(transport=transport, port=port)
    else:
        server.run(transport=transport)

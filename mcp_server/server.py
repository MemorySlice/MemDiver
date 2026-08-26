"""MCP server for MemDiver — thin wrappers over tools.py."""

import json
import logging
import sys
from typing import List, Optional

logger = logging.getLogger("memdiver.mcp_server")


def create_server():
    """Create and configure the MemDiver MCP server."""
    from mcp.server.fastmcp import FastMCP

    from memdiver.app import experiment_orchestration
    from memdiver.app.composition import build_tool_session

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
    def search_reduce(
        variance_path: str, reference_path: str, num_dumps: int,
        output_dir: str,
        alignment: int = 8, block_size: int = 32,
        density_threshold: float = 0.5, min_variance: float = 3000.0,
        entropy_window: int = 32, entropy_threshold: float = 4.5,
        min_region: int = 16,
        key_file: Optional[str] = None, passphrase: Optional[str] = None,
        kem_key_file: Optional[str] = None,
    ) -> str:
        """Reduce consensus variance to a candidate region list.

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
        persist_ground_truth: bool = False,
        key_sizes: Optional[List[int]] = None, stride: int = 1,
        jobs: int = 0, exhaustive: bool = True,
        state_path: Optional[str] = None, top_k: int = 10,
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

        Supply ``key_file`` / ``passphrase`` / ``kem_key_file`` to brute-force
        against an *encrypted* ``.msl`` reference; ``variance_threshold`` sets
        the static-byte cutoff surfaced in the stage's preview.
        """
        return json.dumps(tools_pipeline.brute_force(
            candidates_path=candidates_path,
            reference_path=reference_path,
            oracle_path=oracle_path,
            output_dir=output_dir,
            oracle_config_path=oracle_config_path,
            pcap_path=pcap_path,
            tls_client_random=tls_client_random,
            persist_ground_truth=persist_ground_truth,
            key_sizes=tuple(key_sizes or [32]),
            stride=stride,
            jobs=jobs,
            exhaustive=exhaustive,
            state_path=state_path,
            top_k=top_k,
            variance_threshold=variance_threshold,
            key_file=key_file,
            passphrase=passphrase,
            kem_key_file=kem_key_file,
        ))

    @mcp.tool()
    @mcp_error_funnel
    def n_sweep(
        source_paths: List[str], oracle_path: str, output_dir: str,
        n_values: List[int],
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

        Set ``escalate`` to run a floor-free sweep at the terminal N when no
        checkpoint found a hit; its verdict surfaces under ``escalation``.
        Supply ``key_file`` / ``passphrase`` / ``kem_key_file`` for encrypted
        ``.msl`` sources.
        """
        return json.dumps(tools_pipeline.n_sweep(
            source_paths=source_paths,
            oracle_path=oracle_path,
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
        key_file: Optional[str] = None, passphrase: Optional[str] = None,
        kem_key_file: Optional[str] = None,
    ) -> str:
        """Automated oracle-arbitrated variance-floor selection → verdict."""
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
            managed_region=managed_region,
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
    def inspect_pcap(pcap_path: str) -> str:
        """Summarise the TLS sessions in a capture (the pcap arm/validate step).

        Parses ``pcap_path``'s handshakes and returns, per session, the
        client/server random, negotiated cipher suite + version, and the
        per-direction application-data record counts — the facts the pcap
        verification oracle keys off. Reads only parsed state (no key
        derivation, no decryption). Requires the ``pcap`` extra (dpkt).
        """
        return json.dumps(tools_pipeline.inspect_pcap(pcap_path=pcap_path))

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

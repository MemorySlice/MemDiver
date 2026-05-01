"""MCP server for MemDiver — thin wrappers over tools.py."""

import json
import logging
import sys
from typing import List, Optional

logger = logging.getLogger("memdiver.mcp_server")


def create_server():
    """Create and configure the MemDiver MCP server."""
    from mcp.server.fastmcp import FastMCP

    from . import tools, tools_inspect, tools_pipeline, tools_xref
    from .session import ToolSession

    mcp = FastMCP(
        "memdiver",
        description="Memory dump forensic analysis platform for cryptographic key identification",
    )
    _session = ToolSession()

    @mcp.tool()
    def scan_dataset(
        dataset_root: str,
        keylog_filename: str = "keylog.csv",
        protocols: Optional[List[str]] = None,
    ) -> str:
        """Scan a dataset directory for available protocols, libraries, and phases."""
        return json.dumps(tools.scan_dataset(_session, dataset_root, keylog_filename, protocols))

    @mcp.tool()
    def list_phases(library_dir: str) -> str:
        """List available lifecycle phases for a library directory."""
        return json.dumps(tools.list_phases(_session, library_dir))

    @mcp.tool()
    def list_protocols() -> str:
        """List all registered protocol descriptors with versions and secret types."""
        return json.dumps(tools.list_protocols(_session))

    @mcp.tool()
    def analyze_library(
        library_dirs: List[str],
        phase: str,
        protocol_version: str,
        keylog_filename: str = "keylog.csv",
        template_name: str = "Auto-detect",
        max_runs: int = 10,
        normalize: bool = False,
        expand_keys: bool = True,
    ) -> str:
        """Run the full analysis pipeline on library directories at a specific phase."""
        return json.dumps(tools.analyze_library(
            _session, library_dirs, phase, protocol_version,
            keylog_filename, template_name, max_runs, normalize, expand_keys,
        ))

    @mcp.tool()
    def read_hex(dump_path: str, offset: int = 0, length: int = 256) -> str:
        """Read raw bytes from a dump file. Returns hex + ASCII representation."""
        return json.dumps(tools_inspect.read_hex(_session, dump_path, offset, length))

    @mcp.tool()
    def get_entropy(
        dump_path: str, offset: int = 0, length: int = 0,
        window: int = 32, step: int = 16, threshold: float = 7.5,
    ) -> str:
        """Compute sliding-window entropy profile for a dump file region."""
        return json.dumps(tools_inspect.get_entropy(
            _session, dump_path, offset, length, window, step, threshold,
        ))

    @mcp.tool()
    def extract_strings(
        dump_path: str, offset: int = 0, length: int = 0,
        min_length: int = 4, encoding: str = "ascii", max_results: int = 500,
    ) -> str:
        """Extract printable strings from a dump file."""
        return json.dumps(tools_inspect._extract_strings(
            _session, dump_path, offset, length, min_length, encoding, max_results,
        ))

    @mcp.tool()
    def get_session_info(msl_path: str) -> str:
        """Extract session metadata from an MSL file (process, modules, VAS)."""
        return json.dumps(tools_inspect.get_session_info(_session, msl_path))

    @mcp.tool()
    def get_cross_references(msl_path: str) -> str:
        """Resolve cross-references for an MSL file in its directory."""
        return json.dumps(tools_xref.get_cross_references(_session, msl_path))

    @mcp.tool()
    def identify_structure(
        dump_path: str, offset: int = 0, protocol: str = "",
    ) -> str:
        """Identify data structure at offset in a dump file."""
        return json.dumps(tools_xref.identify_structure(_session, dump_path, offset, protocol))

    @mcp.tool()
    def import_raw_dump(
        raw_path: str, output_path: str, pid: int = 0,
    ) -> str:
        """Import a raw .dump file to .msl format."""
        return json.dumps(tools.import_raw_dump(_session, raw_path, output_path, pid))

    # ------------------------------------------------------------------
    # Phase 25 pipeline stage tools
    # ------------------------------------------------------------------

    @mcp.tool()
    def search_reduce(
        variance_path: str, reference_path: str, num_dumps: int,
        output_dir: str,
        alignment: int = 8, block_size: int = 32,
        density_threshold: float = 0.5, min_variance: float = 3000.0,
        entropy_window: int = 32, entropy_threshold: float = 4.5,
        min_region: int = 16,
    ) -> str:
        """Reduce consensus variance to a candidate region list."""
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
        ))

    @mcp.tool()
    def brute_force(
        candidates_path: str, reference_path: str, oracle_path: str,
        output_dir: str, oracle_config_path: Optional[str] = None,
        key_sizes: Optional[List[int]] = None, stride: int = 8,
        jobs: int = 1, exhaustive: bool = True,
        state_path: Optional[str] = None, top_k: int = 10,
    ) -> str:
        """Iterate surviving candidates through a BYO oracle."""
        return json.dumps(tools_pipeline.brute_force(
            candidates_path=candidates_path,
            reference_path=reference_path,
            oracle_path=oracle_path,
            output_dir=output_dir,
            oracle_config_path=oracle_config_path,
            key_sizes=tuple(key_sizes or [32]),
            stride=stride,
            jobs=jobs,
            exhaustive=exhaustive,
            state_path=state_path,
            top_k=top_k,
        ))

    @mcp.tool()
    def n_sweep(
        source_paths: List[str], oracle_path: str, output_dir: str,
        n_values: List[int],
        reduce_kwargs: Optional[dict] = None,
        key_sizes: Optional[List[int]] = None,
        stride: int = 8, exhaustive: bool = True,
        oracle_config_path: Optional[str] = None,
    ) -> str:
        """Run the N-scaling harness and emit the Plotly survivor report."""
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
        ))

    @mcp.tool()
    def emit_plugin(
        hits_path: str, reference_path: str, name: str, output_dir: str,
        description: Optional[str] = None, hit_index: int = 0,
        min_static_ratio: float = 0.3,
    ) -> str:
        """Emit a Volatility 3 plugin from a brute-force hit's neighborhood."""
        return json.dumps(tools_pipeline.emit_plugin(
            hits_path=hits_path,
            reference_path=reference_path,
            name=name,
            output_dir=output_dir,
            description=description,
            hit_index=hit_index,
            min_static_ratio=min_static_ratio,
        ))

    return mcp


def main(transport: str = "stdio") -> None:
    """Entry point for the MCP server."""
    from core.log import setup_logging
    setup_logging(level="WARNING")

    server = create_server()
    server.run(transport=transport)

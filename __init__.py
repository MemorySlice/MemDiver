"""MemDiver — interactive platform for identifying and analyzing data structures in memory dumps.

Public library API
==================
The names re-exported here form MemDiver's supported programmatic surface. Everything
else under ``memdiver.*`` is an internal implementation detail and may change without
notice.

Quickstart::

    from pathlib import Path
    import memdiver

    # Open any supported dump (raw / ELF core / gdb-raw / lldb-raw / .msl),
    # transparently decrypting an encrypted .msl when key material is supplied.
    # key / passphrase / kem_private_key are bytes.
    with memdiver.open_dump(Path("capture.msl"), passphrase=b"hunter2") as src:
        data = src.read_range(0x1000, 256)

    # Convert a raw/ELF-core/minidump dump into the .msl container format.
    result = memdiver.import_dump(Path("core.1234"), Path("capture.msl"))

    # Parse an .msl container directly.
    with memdiver.MslReader(Path("capture.msl")) as reader:
        modules = reader.collect_modules()

See ``docs/quickstart/library.md`` for the full guide.
"""

from importlib.metadata import PackageNotFoundError, version as _version

try:
    __version__ = _version("memdiver")
except PackageNotFoundError:  # pragma: no cover - source checkout without install
    __version__ = "0.0.0+unknown"

# --- High-level dump access -------------------------------------------------
from memdiver.core.dump_source import (
    MslDumpSource,
    RawDumpSource,
    open_dump,
)
from memdiver.core.format_detect import detect_format

# --- MSL container read / write / import ------------------------------------
from memdiver.core.binary_formats.minidump_reader import MinidumpReader
from memdiver.msl.importer import (
    ImportResult,
    import_dump,
    import_elf_core,
    import_minidump,
    import_run_directory,
)
from memdiver.msl.reader import MslReader
from memdiver.msl.writer import MslWriter

# --- Analysis engine --------------------------------------------------------
from memdiver.engine.auto_floor import AutoFloorResult, run_auto_floor
from memdiver.engine.consensus import ConsensusVector
from memdiver.engine.consensus_service import build_consensus

# --- Extension registration hooks -------------------------------------------
from memdiver.core.dump_source import register_dump_source
from memdiver.core.binary_formats.format_descriptor import register_format
from memdiver.app.pipeline.pipeline_runner import register_stage
from memdiver.core.structure_library import get_structure_library

# --- Structured error model -------------------------------------------------
from memdiver.core.service_errors import CapabilityError, ErrorCategory

# --- Structured service results ---------------------------------------------
from memdiver.core.service_result import (
    Diagnostic,
    KeyStatus,
    Resolution,
    ServiceResult,
    StatusBlock,
)

# --- Structured services (full feature parity) ------------------------------
# The surface-agnostic ``app`` producers shared by every MemDiver surface (CLI,
# web, MCP). They return ``ServiceResult`` / raise ``CapabilityError``. The
# whole set lives on ``memdiver.services``; the most-used producers are lifted
# to the top level below. See ``docs/quickstart/library.md`` and
# ``docs/architecture/app.md``.
from memdiver import services
from memdiver.services import (
    ToolSession,
    # inspect
    analyze_region_result,
    blocks_result,
    connections_result,
    detect_format_result,
    entropy_result,
    handles_result,
    modules_result,
    module_index_result,
    page_states_result,
    processes_result,
    read_hex_raw_result,
    read_hex_result,
    resolve_va_result,
    search_bytes_result,
    session_info_result,
    strings_result,
    # xref / structure
    apply_structure_result,
    get_cross_references_result,
    identify_structure_result,
    # pipeline
    analyze_candidates,
    auto_floor,
    brute_force,
    consensus,
    emit_plugin,
    export_key_pattern,
    export_pattern,
    locate_field_across_pairs,
    locate_key,
    manual_export_pattern,
    n_sweep,
    search_reduce,
    # verify / experiment
    experiment_result,
    verify_key_result,
    # dataset / analysis
    analyze_library,
    list_phases,
    list_protocols,
    scan_dataset,
)

__all__ = [
    "__version__",
    # dump access
    "open_dump",
    "RawDumpSource",
    "MslDumpSource",
    "detect_format",
    # container read/write/import
    "MslReader",
    "MslWriter",
    "MinidumpReader",
    "import_dump",
    "import_elf_core",
    "import_minidump",
    "import_run_directory",
    "ImportResult",
    # analysis
    "run_auto_floor",
    "AutoFloorResult",
    "ConsensusVector",
    "build_consensus",
    # extension registration hooks
    "register_dump_source",
    "register_format",
    "register_stage",
    "get_structure_library",
    # structured error model
    "CapabilityError",
    "ErrorCategory",
    # structured service results
    "ServiceResult",
    "StatusBlock",
    "KeyStatus",
    "Diagnostic",
    "Resolution",
    # structured services (full feature parity) — see memdiver.services
    "services",
    "ToolSession",
    # inspect producers
    "read_hex_result",
    "read_hex_raw_result",
    "resolve_va_result",
    "analyze_region_result",
    "search_bytes_result",
    "entropy_result",
    "strings_result",
    "detect_format_result",
    "session_info_result",
    "page_states_result",
    "processes_result",
    "modules_result",
    "handles_result",
    "connections_result",
    "module_index_result",
    "blocks_result",
    # xref / structure producers
    "get_cross_references_result",
    "identify_structure_result",
    "apply_structure_result",
    # pipeline producers
    "consensus",
    "analyze_candidates",
    "search_reduce",
    "brute_force",
    "n_sweep",
    "auto_floor",
    "emit_plugin",
    "export_pattern",
    "manual_export_pattern",
    "locate_key",
    "export_key_pattern",
    "locate_field_across_pairs",
    # verify / experiment producers
    "verify_key_result",
    "experiment_result",
    # dataset / analysis producers
    "scan_dataset",
    "list_protocols",
    "list_phases",
    "analyze_library",
]

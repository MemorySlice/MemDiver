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
from memdiver.engine.pipeline_runner import register_stage
from memdiver.core.structure_library import get_structure_library

# --- Structured error model -------------------------------------------------
from memdiver.core.service_errors import CapabilityError, ErrorCategory

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
]

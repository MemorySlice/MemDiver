"""Raw-to-MSL import: convert .dump files to .msl format."""

import logging
from dataclasses import dataclass
from pathlib import Path
from typing import List, Optional

from core.models import CryptoSecret
from .enums import MslKeyType, MslProtocol, OSType, ArchType
from .writer import MslWriter

logger = logging.getLogger("memdiver.msl.importer")


@dataclass
class ImportResult:
    """Result of importing a single raw dump to MSL format."""

    source_path: Path
    output_path: Path
    regions_written: int
    key_hints_written: int
    total_bytes: int


_SECRET_TO_KEY_TYPE = {
    "CLIENT_RANDOM": MslKeyType.PRE_MASTER_SECRET,
    "CLIENT_HANDSHAKE_TRAFFIC_SECRET": MslKeyType.HANDSHAKE_SECRET,
    "SERVER_HANDSHAKE_TRAFFIC_SECRET": MslKeyType.HANDSHAKE_SECRET,
    "CLIENT_TRAFFIC_SECRET_0": MslKeyType.APP_TRAFFIC_SECRET,
    "SERVER_TRAFFIC_SECRET_0": MslKeyType.APP_TRAFFIC_SECRET,
    "EXPORTER_SECRET": MslKeyType.SESSION_KEY,
    "SSH2_SESSION_KEY": MslKeyType.SSH_SESSION_KEY,
}

_SECRET_TO_PROTOCOL = {
    "CLIENT_RANDOM": MslProtocol.TLS_12,
    "SSH2_SESSION_KEY": MslProtocol.SSH,
}


def _map_key_type(secret_type: str) -> int:
    return _SECRET_TO_KEY_TYPE.get(secret_type, MslKeyType.UNKNOWN)


def _map_protocol(secret_type: str) -> int:
    return _SECRET_TO_PROTOCOL.get(secret_type, MslProtocol.TLS_13)


def import_raw_dump(
    raw_path: Path,
    output_path: Path,
    pid: int = 0,
    secrets: Optional[List[CryptoSecret]] = None,
    os_type: int = OSType.UNKNOWN,
    arch_type: int = ArchType.UNKNOWN,
    page_size_log2: int = 12,
) -> ImportResult:
    """Convert a raw .dump file to .msl format."""
    raw_data = raw_path.read_bytes()
    orig_size = len(raw_data)
    writer = MslWriter(
        output_path, pid=pid, os_type=os_type, arch_type=arch_type
    )

    # MSL Specification v1.0.0 §5.1 mandates that RegionSize be a multiple
    # of PageSize. Raw .dump files are an arbitrary number of bytes, so we
    # zero-pad up to the next page boundary. Importer-injected padding is
    # transparent because the original size is recorded in the
    # IMPORT_PROVENANCE block's `orig_file_size` field.
    page_size = 1 << page_size_log2
    pad = (-orig_size) % page_size
    region_data = raw_data + b"\x00" * pad if pad else raw_data

    region_uuid = writer.add_memory_region(
        0, region_data, page_size_log2=page_size_log2
    )

    hints_written = 0
    if secrets:
        for secret in secrets:
            # Search the original bytes (key offsets reference the original
            # file; padding is appended past the end and won't shift hits).
            offset = raw_data.find(secret.secret_value)
            if offset >= 0:
                writer.add_key_hint(
                    region_uuid=region_uuid,
                    offset=offset,
                    key_length=len(secret.secret_value),
                    key_type=_map_key_type(secret.secret_type),
                    protocol=_map_protocol(secret.secret_type),
                )
                hints_written += 1

    writer.add_import_provenance(
        source_format=0x01,
        tool_name="memdiver",
        orig_file_size=orig_size,
        note=f"Imported from {raw_path.name}",
    )
    writer.add_end_of_capture()
    writer.write()

    return ImportResult(
        source_path=raw_path,
        output_path=output_path,
        regions_written=1,
        key_hints_written=hints_written,
        total_bytes=orig_size,
    )


def import_run_directory(
    run_dir: Path,
    output_dir: Path,
    keylog_filename: str = "keylog.csv",
) -> List[ImportResult]:
    """Import all .dump files in a run directory to .msl format."""
    output_dir.mkdir(parents=True, exist_ok=True)
    results = []

    secrets = None
    keylog_path = run_dir / keylog_filename
    if keylog_path.is_file():
        from core.keylog import KeylogParser

        secrets = KeylogParser().parse(keylog_path)

    for dump_file in sorted(run_dir.glob("*.dump")):
        out_path = output_dir / dump_file.with_suffix(".msl").name
        result = import_raw_dump(dump_file, out_path, secrets=secrets)
        results.append(result)

    return results

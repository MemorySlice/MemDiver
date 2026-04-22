"""DumpSource for lldb-produced ``lldb_raw.bin`` + ``lldb_raw.maps`` pairs."""

from ._regioned_base import _RegionedRawSource


class LldbRawDumpSource(_RegionedRawSource):
    """Raw memory dump produced by lldb ``memory read`` over a maps file."""

    format_name = "lldb_raw"

"""DumpSource for gdb-produced ``gdb_raw.bin`` + ``gdb_raw.maps`` pairs."""

from ._regioned_base import _RegionedRawSource


class GdbRawDumpSource(_RegionedRawSource):
    """Raw memory dump produced by gdb's ``dump memory`` over a maps file."""

    format_name = "gdb_raw"

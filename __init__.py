"""MemDiver - Interactive platform for identifying and analyzing data structures in memory dumps."""

from importlib.metadata import PackageNotFoundError, version as _version

try:
    __version__ = _version("memdiver")
except PackageNotFoundError:
    __version__ = "0.0.0+unknown"

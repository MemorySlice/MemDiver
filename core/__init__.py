"""MemDiver core library - stdlib-only data layer."""

try:
    from memdiver import __version__
except ImportError:
    __version__ = "0.0.0+unknown"

__all__ = ["__version__"]

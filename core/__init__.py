"""MemDiver core library - stdlib-only data layer."""

try:
    from memdiver import __version__
except ImportError:
    __version__ = "0.1.0"

__all__ = ["__version__"]

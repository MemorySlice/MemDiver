"""Kernel-profile (ISF) resolution for memory images (plan D3, task T1.4).

A :class:`ProfileChain` asks a fixed sequence of :class:`ProfileProvider`
objects for the symbol profile of one image: explicit ``isf=`` -> MemDiver ISF
cache -> analysis-record draft -> pakunoda extraction -> Volatility 3's own
symbol directories. The first provider that answers wins. A provider answers
``None`` for "not mine / not found" and never raises for that; the reason is
kept on the provider (``last_reason``) and in the chain's ``attempts`` so a
total miss produces one diagnosable error instead of silence.

pakunoda (Apache-2.0) and volatility3 are the optional ``memdiver[image]``
extra and are imported lazily, inside ``resolve``.

Cache layout: ``<cache_dir()>/<image sha256>/<name>.isf.json`` plus a
``provenance.json`` sidecar naming the file and its origin.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Protocol, Sequence, Tuple
from urllib.parse import unquote, urlparse

from memdiver.core.image.context import cache_dir, file_sha256
from memdiver.core.image.view_descriptor import ProfileRef
from memdiver.core.service_errors import CapabilityError, ErrorCategory

PROVENANCE_NAME = "provenance.json"
ISF_SUFFIX = ".isf.json"
_BANNER_MARKER = b"Linux version "
_BANNER_MAX = 1024
_BANNER_CANDIDATES = 16
_SCAN_BLOCK = 16 * 1024 * 1024


@dataclass(frozen=True)
class ProfileResolution:
    """A resolved ISF file and where it came from."""

    isf_path: Path
    sha256: str
    origin: str                      # explicit | cache | draft | pakunoda | vol3
    banner: Optional[str] = None
    details: Dict[str, Any] = field(default_factory=dict)

    def to_profile_ref(self) -> ProfileRef:
        return ProfileRef(str(self.isf_path), self.sha256, self.origin)


class ProfileProvider(Protocol):
    """One source of kernel profiles."""

    name: str

    def resolve(self, image_path: Path, image_sha256: str) -> Optional[ProfileResolution]:
        """The profile for the image, or ``None`` when this source has none."""
        ...


class _ReasonMixin:
    """Remembers why the last ``resolve`` returned ``None``."""

    last_reason: str = ""

    def _miss(self, reason: str) -> Any:
        self.last_reason = reason
        return None


class ExplicitProvider(_ReasonMixin):
    """The caller named the ISF file."""

    name = "explicit"

    def __init__(self, isf_path: Optional[Path]) -> None:
        self._isf_path = Path(isf_path) if isf_path else None

    def resolve(self, image_path: Path, image_sha256: str) -> Optional[ProfileResolution]:
        if self._isf_path is None:
            return self._miss("no explicit ISF given")
        if not self._isf_path.is_file():
            return self._miss(f"explicit ISF not found: {self._isf_path}")
        return ProfileResolution(self._isf_path, file_sha256(self._isf_path), "explicit")


def _image_cache_dir(image_sha256: str) -> Path:
    return cache_dir() / image_sha256


def _read_provenance(directory: Path) -> Dict[str, Any]:
    try:
        return dict(json.loads((directory / PROVENANCE_NAME).read_text(encoding="utf-8")))
    except (OSError, ValueError):
        return {}


def write_cached_isf(image_sha256: str, name: str, isf_json: Dict[str, Any],
                     origin: str, details: Dict[str, Any]) -> Path:
    """Store an ISF document and its provenance sidecar in the image's cache dir."""
    directory = _image_cache_dir(image_sha256)
    directory.mkdir(parents=True, exist_ok=True)
    isf_path = directory / f"{name}{ISF_SUFFIX}"
    isf_path.write_text(json.dumps(isf_json), encoding="utf-8")
    provenance = {"isf": isf_path.name, "origin": origin, **details}
    (directory / PROVENANCE_NAME).write_text(json.dumps(provenance, indent=1), encoding="utf-8")
    return isf_path


class CacheProvider(_ReasonMixin):
    """An ISF a previous resolution stored under the image's sha256."""

    name = "cache"

    def resolve(self, image_path: Path, image_sha256: str) -> Optional[ProfileResolution]:
        directory = _image_cache_dir(image_sha256)
        provenance = _read_provenance(directory)
        isf_path = directory / str(provenance.get("isf", ""))
        if not provenance.get("isf") or not isf_path.is_file():
            return self._miss(f"nothing cached under {directory}")
        details = {k: v for k, v in provenance.items() if k not in ("isf", "origin")}
        details["cached_origin"] = provenance.get("origin", "unknown")
        return ProfileResolution(isf_path, file_sha256(isf_path), "cache",
                                 banner=provenance.get("banner"), details=details)


class DraftProvider(_ReasonMixin):
    """Analysis-record ISF drafts (workbench). Stub: they arrive in P4 / T4.1."""

    name = "draft"

    def resolve(self, image_path: Path, image_sha256: str) -> Optional[ProfileResolution]:
        return self._miss("analysis-record ISF drafts are not implemented yet (P4/T4.1)")


class PakunodaLinuxProvider(_ReasonMixin):
    """Extract an ISF from the Linux image itself with pakunoda."""

    name = "pakunoda"

    def __init__(self, arch: str = "auto") -> None:
        self._arch = arch

    def resolve(self, image_path: Path, image_sha256: str) -> Optional[ProfileResolution]:
        try:
            import pakunoda
        except ImportError:
            return self._miss("pakunoda is not installed (pip install \"memdiver[image]\")")
        try:
            result = pakunoda.extract_isf(Path(image_path), arch=self._arch)
        except Exception as exc:  # noqa: BLE001  (extraction failure == a miss)
            return self._miss(f"pakunoda extraction failed: {exc}")
        return self._store(result, pakunoda.__version__, image_sha256)

    def _store(self, result: Any, version: str,
               image_sha256: str) -> Optional[ProfileResolution]:
        if not getattr(result, "success", False) or not result.isf_json:
            return self._miss("pakunoda produced no ISF: "
                              + "; ".join(getattr(result, "errors", []) or ["no reason given"]))
        loadability = getattr(result, "loadability", None)
        if loadability is not None and not loadability.loadable:
            return self._miss(loadability.reason)
        banner = _decode_banner(getattr(result, "banner_bytes", None))
        details = {"pakunoda_version": version, "banner": banner,
                   "kernel_version": getattr(result, "kernel_version", None),
                   "loadable": None if loadability is None else True}
        path = write_cached_isf(image_sha256, "pakunoda", result.isf_json, "pakunoda", details)
        return ProfileResolution(path, file_sha256(path), "pakunoda", banner, details)


def _decode_banner(raw: Optional[bytes]) -> Optional[str]:
    if not raw:
        return None
    return raw.decode("utf-8", errors="replace").rstrip("\x00\n")


def scan_linux_banners(image_path: Path, limit: int = _BANNER_CANDIDATES) -> List[bytes]:
    """Distinct ``Linux version ...`` banner strings found in the raw image bytes."""
    found: List[bytes] = []
    carry = b""
    with open(image_path, "rb") as fh:
        for block in iter(lambda: fh.read(_SCAN_BLOCK), b""):
            data = carry + block
            _collect_banners(data, found, limit)
            if len(found) >= limit:
                break
            carry = data[-_BANNER_MAX:]
    return found


#: A real kernel banner: ``Linux version <release> (<builder>) ...``. Source-code
#: comments and format strings that merely contain "Linux version " do not match.
_PLAUSIBLE_BANNER = re.compile(rb"^Linux version \d+\.\d+\S* \(")


def plausible_banners_first(banners: Sequence[bytes]) -> List[bytes]:
    """``banners`` with real kernel banners first; scan order kept within each group."""
    return sorted(banners, key=lambda b: _PLAUSIBLE_BANNER.match(b) is None)


def _collect_banners(data: bytes, found: List[bytes], limit: int) -> None:
    pos = data.find(_BANNER_MARKER)
    while pos != -1 and len(found) < limit:
        chunk = data[pos:pos + _BANNER_MAX]
        end = min((i for i in (chunk.find(b"\n"), chunk.find(b"\x00")) if i != -1),
                  default=len(chunk))
        banner = chunk[:end]
        if len(banner) < _BANNER_MAX and banner not in found:
            found.append(banner)
        pos = data.find(_BANNER_MARKER, pos + len(_BANNER_MARKER))


def _location_to_path(location: str) -> Optional[Path]:
    parsed = urlparse(location)
    if parsed.scheme not in ("", "file"):
        return None
    path = Path(unquote(parsed.path) if parsed.scheme else location)
    return path if path.is_file() else None


class Vol3SymbolDirProvider(_ReasonMixin):
    """An ISF in vol3's symbol directories whose ``linux_banner`` matches the image."""

    name = "vol3"

    def resolve(self, image_path: Path, image_sha256: str) -> Optional[ProfileResolution]:
        try:
            from volatility3.framework.automagic import symbol_cache
            known = symbol_cache.load_cache_manager().get_identifier_dictionary(
                operating_system="linux", local_only=True)
        except ImportError:
            return self._miss("volatility3 is not installed (pip install \"memdiver[image]\")")
        except Exception as exc:  # noqa: BLE001  (no/odd identifier cache == a miss)
            return self._miss(f"vol3 identifier cache unavailable: {exc}")
        return self._match(image_path, {k.rstrip(b"\x00\n"): v for k, v in known.items()})

    def _match(self, image_path: Path,
               known: Dict[bytes, str]) -> Optional[ProfileResolution]:
        for banner in scan_linux_banners(image_path):
            isf_path = _location_to_path(known[banner]) if banner in known else None
            if isf_path is not None:
                text = _decode_banner(banner)
                return ProfileResolution(isf_path, file_sha256(isf_path), "vol3", text)
        return self._miss("no vol3 symbol file matches the image's Linux banner")


class ProfileChain:
    """Tries providers in order; the first hit wins."""

    def __init__(self, providers: Sequence[ProfileProvider]) -> None:
        self.providers = list(providers)
        self.attempts: List[Tuple[str, str]] = []

    def resolve(self, image_path: Path, image_sha256: str) -> ProfileResolution:
        self.attempts = []
        for provider in self.providers:
            hit = provider.resolve(Path(image_path), image_sha256)
            if hit is not None:
                self.attempts.append((provider.name, "hit"))
                return hit
            reason = getattr(provider, "last_reason", "") or "no profile"
            self.attempts.append((provider.name, f"miss: {reason}"))
        raise CapabilityError(self._failure_message(image_path),
                              category=ErrorCategory.UNSUPPORTED,
                              details={"attempts": [list(a) for a in self.attempts]})

    def _failure_message(self, image_path: Path) -> str:
        lines = [f"  {name}: {outcome}" for name, outcome in self.attempts]
        return (f"no kernel profile (ISF) found for {image_path}; pass isf= explicitly "
                "or install pakunoda. Tried:\n" + "\n".join(lines))


def default_chain(explicit_isf: Optional[Path] = None) -> ProfileChain:
    """The D3 chain: explicit -> cache -> draft -> pakunoda -> vol3 symbol dirs."""
    return ProfileChain([ExplicitProvider(explicit_isf), CacheProvider(), DraftProvider(),
                         PakunodaLinuxProvider(), Vol3SymbolDirProvider()])

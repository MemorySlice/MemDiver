"""``.mdview`` view descriptors: a full-image view as a small real file (plan D2).

Dump references stay real file paths. Instead of a URI grammar (which ~30
``exists()``/path-policy/cache sites would reject), a view of a memory image is
a small text file whose first line is :data:`MAGIC` and whose remainder is
JSON::

    MEMDIVER-VIEW/1
    {"image": "alma-9.lime", "image_sha256": "...", "view": "process", "pid": 22176,
     "profile": {"isf": "...", "sha256": "...", "origin": "pakunoda"}}

``open_dump`` detects the magic and returns a
:class:`~memdiver.core.image.sources.Vol3LayerSource`. A relative ``image`` (or
profile ``isf``) path is resolved against the descriptor's own directory, so a
case directory can be moved as a whole.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Any, Dict, Optional

MAGIC = "MEMDIVER-VIEW/1"
MAGIC_BYTES = (MAGIC + "\n").encode("ascii")
SUFFIX = ".mdview"


class ViewKind(Enum):
    """Which address space of the image the view exposes."""

    PHYSICAL = "physical"
    KERNEL = "kernel"
    PROCESS = "process"


@dataclass(frozen=True)
class ProfileRef:
    """The symbol profile (ISF) a kernel/process view is interpreted with."""

    isf: str
    sha256: Optional[str] = None
    origin: str = "explicit"   # explicit | cache | draft | pakunoda | vol3

    def to_dict(self) -> Dict[str, Any]:
        return {"isf": self.isf, "sha256": self.sha256, "origin": self.origin}

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "ProfileRef":
        return cls(str(data["isf"]), data.get("sha256"), data.get("origin", "explicit"))


@dataclass(frozen=True)
class PagingSpec:
    """Manual paging parameters (no-ISF kernel view, or overriding detection)."""

    pgd_phys: Optional[int] = None
    arch: Optional[str] = None      # "x86_64", "aarch64", ...
    va_bits: Optional[int] = None   # x86_64: 48 (4-level) or 57 (LA57, 5-level)
    page_size: int = 4096

    def to_dict(self) -> Dict[str, Any]:
        return {"pgd_phys": self.pgd_phys, "arch": self.arch,
                "va_bits": self.va_bits, "page_size": self.page_size}

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "PagingSpec":
        return cls(data.get("pgd_phys"), data.get("arch"), data.get("va_bits"),
                   int(data.get("page_size", 4096)))


@dataclass(frozen=True)
class ViewDescriptor:
    """One view of one memory image. ``capture_id`` is the image's sha256."""

    image: str
    image_sha256: str
    view: ViewKind
    pid: Optional[int] = None
    profile: Optional[ProfileRef] = None
    paging: Optional[PagingSpec] = None

    def __post_init__(self) -> None:
        if not isinstance(self.view, ViewKind):
            raise TypeError(f"view must be a ViewKind, got {self.view!r}")
        if self.view is ViewKind.PROCESS and (self.pid is None or self.profile is None):
            raise ValueError("a process view requires 'pid' and 'profile'")
        if self.view is not ViewKind.PROCESS and self.pid is not None:
            raise ValueError(f"a {self.view.value} view takes no 'pid'")
        if self.view is ViewKind.KERNEL and self.profile is None and self.paging is None:
            raise ValueError("a kernel view requires 'profile' or 'paging'")

    @property
    def capture_id(self) -> str:
        return self.image_sha256

    def image_path(self, descriptor_path: Path) -> Path:
        """The image file, resolving a relative path against the descriptor's dir."""
        return _resolve(self.image, descriptor_path)

    def isf_path(self, descriptor_path: Path) -> Optional[Path]:
        return _resolve(self.profile.isf, descriptor_path) if self.profile else None

    def to_dict(self) -> Dict[str, Any]:
        out: Dict[str, Any] = {"image": self.image, "image_sha256": self.image_sha256,
                               "view": self.view.value}
        if self.pid is not None:
            out["pid"] = self.pid
        if self.profile is not None:
            out["profile"] = self.profile.to_dict()
        if self.paging is not None:
            out["paging"] = self.paging.to_dict()
        return out

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "ViewDescriptor":
        profile = data.get("profile")
        paging = data.get("paging")
        return cls(
            image=str(data["image"]),
            image_sha256=str(data["image_sha256"]),
            view=ViewKind(data["view"]),
            pid=data.get("pid"),
            profile=ProfileRef.from_dict(profile) if profile else None,
            paging=PagingSpec.from_dict(paging) if paging else None,
        )

    def write(self, path: Path) -> Path:
        """Write the descriptor (magic line + JSON) and return ``path``."""
        path = Path(path)
        path.write_text(MAGIC + "\n" + json.dumps(self.to_dict(), indent=2) + "\n",
                        encoding="utf-8")
        return path

    @classmethod
    def read(cls, path: Path) -> "ViewDescriptor":
        text = Path(path).read_text(encoding="utf-8")
        first, _, body = text.partition("\n")
        if first.strip() != MAGIC:
            raise ValueError(f"{path} is not a {MAGIC} descriptor")
        return cls.from_dict(json.loads(body))


def is_view_descriptor(header: bytes) -> bool:
    """Detector for ``open_dump``: the file starts with the magic line."""
    return header.startswith(MAGIC_BYTES)


def _resolve(target: str, descriptor_path: Path) -> Path:
    candidate = Path(target).expanduser()
    if candidate.is_absolute():
        return candidate
    return (Path(descriptor_path).parent / candidate).resolve()

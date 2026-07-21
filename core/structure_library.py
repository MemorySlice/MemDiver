"""Registry of predefined data structure definitions.

Provides a StructureLibrary with built-in definitions for common
cryptographic memory layouts (TLS 1.2/1.3 key schedule secrets, SSH-2
session/exchange hashes, AES key/IV blocks, binary format headers).
"""

import logging
from pathlib import Path
from typing import Dict, List, Optional

from memdiver.core import structure_loader
from memdiver.core.structure_defs import FieldDef, FieldType, StructureDef

logger = logging.getLogger("memdiver.structure_library")


class StructureLibrary:
    """Registry for StructureDef instances."""

    def __init__(self):
        self._structures: Dict[str, StructureDef] = {}

    def register(self, struct_def: StructureDef) -> None:
        self._structures[struct_def.name] = struct_def

    def unregister(self, name: str) -> bool:
        """Remove a structure by name. Returns True if it existed."""
        return self._structures.pop(name, None) is not None

    def get(self, name: str) -> Optional[StructureDef]:
        return self._structures.get(name)

    def list_all(self) -> List[StructureDef]:
        return list(self._structures.values())

    def list_by_protocol(self, protocol: str) -> List[StructureDef]:
        return [s for s in self._structures.values() if s.protocol == protocol]

    def list_by_tag(self, tag: str) -> List[StructureDef]:
        return [s for s in self._structures.values() if tag in s.tags]


# AES key + IV built-ins (generic symmetric crypto)

def _aes_key(name: str, size: int, desc: str) -> StructureDef:
    return StructureDef(
        name=name,
        total_size=size,
        fields=(
            FieldDef("key", FieldType.BYTES, 0, size,
                     description=desc, constraints={"not_zero": True}),
        ),
        protocol="",
        description=desc,
        tags=("crypto", "symmetric", "aes"),
    )


def _aes_iv(name: str, size: int, desc: str) -> StructureDef:
    return StructureDef(
        name=name,
        total_size=size,
        fields=(
            FieldDef("iv", FieldType.BYTES, 0, size, description=desc),
        ),
        protocol="",
        description=desc,
        tags=("crypto", "symmetric", "aes"),
    )


AES_BUILTINS = [
    _aes_key("aes128_key", 16, "AES-128 key (16 bytes)"),
    _aes_key("aes192_key", 24, "AES-192 key (24 bytes)"),
    _aes_key("aes256_key", 32, "AES-256 key (32 bytes)"),
    _aes_iv("aes_gcm_iv", 12, "AES-GCM 96-bit IV/nonce"),
    _aes_iv("aes_cbc_iv", 16, "AES-CBC 128-bit IV"),
]


try:
    from memdiver.core.binary_formats.elf_defs import ELF_DEFS as _ELF_DEFS
except ImportError:
    _ELF_DEFS = []

from memdiver.core.structure_library_tls import TLS_BUILTINS
from memdiver.core.structure_library_ssh import SSH_BUILTINS

_BUILTINS = (
    list(TLS_BUILTINS)
    + list(SSH_BUILTINS)
    + list(AES_BUILTINS)
    + list(_ELF_DEFS)
)

# Names owned by built-ins. User structures may never override these in the
# live singleton, mirroring the collision policy in ``_merge_user_structures``.
_BUILTIN_NAMES = frozenset(s.name for s in _BUILTINS)

_library: Optional[StructureLibrary] = None


def _build_builtin_library() -> StructureLibrary:
    """Return a fresh library populated with only the built-in structures."""
    lib = StructureLibrary()
    for s in _BUILTINS:
        lib.register(s)
    return lib


def _merge_user_structures(library: StructureLibrary) -> None:
    """Merge user-defined structures into ``library`` without clobbering.

    Collision policy: built-ins take precedence. Because built-ins are
    registered first, any user structure whose name matches an already
    registered structure (a built-in, or an earlier user structure) is
    skipped with a warning rather than overriding it. This keeps built-in
    behaviour identical and makes name clashes explicit instead of silent.

    Best-effort and fully contained: a missing/unreadable directory or an
    invalid JSON file is logged and skipped, never raised. The per-file
    validation lives in :func:`structure_loader.load_user_structures`; this
    wrapper additionally guards against the loader itself failing.
    """
    try:
        user_structs = structure_loader.load_user_structures(
            structure_loader.DEFAULT_USER_DIR
        )
    except Exception:  # noqa: BLE001 - user data must never break the library
        logger.warning(
            "Failed to load user structures from %s; "
            "continuing with built-ins only",
            structure_loader.DEFAULT_USER_DIR,
            exc_info=True,
        )
        return

    for s in user_structs:
        if library.get(s.name) is not None:
            logger.warning(
                "User structure '%s' collides with an already-registered "
                "structure; skipping (built-ins take precedence)",
                s.name,
            )
            continue
        library.register(s)


def get_structure_library(include_user: bool = True) -> StructureLibrary:
    """Return the lazily-initialised global structure library.

    Built-ins are always registered first. When ``include_user`` is True
    (the default), user-defined structures from ``~/.memdiver/structures``
    are additionally merged in; a user structure whose name collides with an
    existing one is skipped so built-ins always win. Loading user structures
    is best-effort and never raises (see :func:`_merge_user_structures`).

    Pass ``include_user=False`` to obtain a fresh, uncached built-ins-only
    library, useful for tests and deterministic callers. The zero-argument
    call remains backward-compatible and returns the shared singleton.
    """
    global _library
    if not include_user:
        return _build_builtin_library()
    if _library is None:
        lib = _build_builtin_library()
        _merge_user_structures(lib)
        _library = lib
    return _library


def add_user_structure(struct_def: StructureDef) -> Path:
    """Persist a user structure and register it in the live singleton.

    Co-locates the two steps that must always happen together so no caller has
    to remember the dance: the JSON is written via
    :func:`structure_loader.save_user_structure` and the definition is
    registered into the cached library so it is visible immediately, without
    waiting for a rebuild.

    Built-ins win: a definition whose name matches a built-in is still written
    to disk (preserving prior behaviour) but is *not* registered over the
    built-in — exactly how a fresh rebuild would treat it (see
    :func:`_merge_user_structures`). User-to-user name reuse is allowed and
    overwrites the earlier user entry, matching an in-place edit.

    Returns the path written by :func:`structure_loader.save_user_structure`.
    """
    path = structure_loader.save_user_structure(struct_def)
    if struct_def.name in _BUILTIN_NAMES:
        logger.warning(
            "User structure '%s' collides with a built-in; persisted to disk "
            "but not registered (built-ins take precedence)",
            struct_def.name,
        )
    else:
        get_structure_library().register(struct_def)
    return path


def remove_user_structure(
    name: str, directory: Optional[Path] = None
) -> bool:
    """Delete a user structure file and unregister it from the live singleton.

    The inverse of :func:`add_user_structure`: removes ``<directory>/<name>.json``
    (defaulting to the user-structures directory) and unregisters ``name`` from
    the cached library so callers stop seeing it without a rebuild.

    Built-ins are never removed here: a name owned by a built-in is left
    registered (it could only have reached the singleton as a built-in, since
    :func:`add_user_structure` refuses to register over one). Deletion is
    contained to ``directory`` — a ``name`` that would resolve outside it is a
    no-op — and any unlink error is logged, never raised.

    Returns True if a user file was actually deleted.
    """
    base = structure_loader.DEFAULT_USER_DIR if directory is None else directory
    base = Path(base)
    path = base / f"{name}.json"
    deleted = False
    try:
        if path.parent.resolve() == base.resolve() and path.is_file():
            path.unlink()
            deleted = True
    except OSError:
        logger.warning(
            "Failed to delete user structure file %s", path, exc_info=True
        )
    if name not in _BUILTIN_NAMES:
        get_structure_library().unregister(name)
    return deleted

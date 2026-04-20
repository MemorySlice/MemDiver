"""Registry of predefined data structure definitions.

Provides a StructureLibrary with built-in definitions for common
cryptographic memory layouts (TLS 1.2/1.3 key schedule secrets, SSH-2
session/exchange hashes, AES key/IV blocks, binary format headers).
"""

import logging
from typing import Dict, List, Optional

from core.structure_defs import FieldDef, FieldType, StructureDef

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
    from core.binary_formats.elf_defs import ELF_DEFS as _ELF_DEFS
except ImportError:
    _ELF_DEFS = []

from core.structure_library_tls import TLS_BUILTINS
from core.structure_library_ssh import SSH_BUILTINS

_BUILTINS = (
    list(TLS_BUILTINS)
    + list(SSH_BUILTINS)
    + list(AES_BUILTINS)
    + list(_ELF_DEFS)
)

_library: Optional[StructureLibrary] = None


def get_structure_library() -> StructureLibrary:
    """Return the lazily-initialised global structure library."""
    global _library
    if _library is None:
        _library = StructureLibrary()
        for s in _BUILTINS:
            _library.register(s)
    return _library

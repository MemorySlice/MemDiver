"""Built-in SSH-2 structure definitions.

Polymorphic session_id and exchange_hash structures. Probes hash sizes
(SHA-512, SHA-256, SHA-1) via FieldDef.size_choices.
"""

from typing import List

from core.structure_defs import FieldDef, FieldType, StructureDef


def _ssh2_hash_struct(
    name: str, field_name: str, desc: str, tag: str,
) -> StructureDef:
    return StructureDef(
        name=name,
        total_size=32,  # default/middle size
        fields=(
            FieldDef(
                field_name, FieldType.BYTES, 0, 32,
                description=desc,
                constraints={"not_zero": True},
                size_choices=(64, 32, 20),
            ),
        ),
        protocol="SSH",
        description=desc,
        tags=("crypto", "ssh2", tag),
        auto_offsets=True,
    )


SSH_BUILTINS: List[StructureDef] = [
    _ssh2_hash_struct(
        "ssh2_session_id", "session_id",
        "SSH-2 session_id (hash output; SHA-1/256/512)", "session_id",
    ),
    _ssh2_hash_struct(
        "ssh2_exchange_hash", "exchange_hash",
        "SSH-2 exchange hash H (SHA-1/256/512)", "exchange_hash",
    ),
]

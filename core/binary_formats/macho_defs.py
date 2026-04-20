"""Mach-O binary format structure definitions."""
from core.structure_defs import StructureDef, FieldDef, FieldType

MACH_HEADER_64 = StructureDef(
    name="mach_header_64",
    total_size=32,
    protocol="binary",
    description="Mach-O 64-bit header",
    tags=("macho", "header"),
    fields=(
        FieldDef(name="magic", field_type=FieldType.UINT32_LE, offset=0, size=4,
                 description="Magic: 0xFEEDFACF (LE)"),
        FieldDef(name="cputype", field_type=FieldType.UINT32_LE, offset=4, size=4,
                 description="CPU type"),
        FieldDef(name="cpusubtype", field_type=FieldType.UINT32_LE, offset=8, size=4,
                 description="CPU subtype"),
        FieldDef(name="filetype", field_type=FieldType.UINT32_LE, offset=12, size=4,
                 description="File type"),
        FieldDef(name="ncmds", field_type=FieldType.UINT32_LE, offset=16, size=4,
                 description="Number of load commands"),
        FieldDef(name="sizeofcmds", field_type=FieldType.UINT32_LE, offset=20, size=4,
                 description="Size of load commands"),
        FieldDef(name="flags", field_type=FieldType.UINT32_LE, offset=24, size=4,
                 description="Flags"),
        FieldDef(name="reserved", field_type=FieldType.UINT32_LE, offset=28, size=4,
                 description="Reserved"),
    ),
)

MACHO_DEFS = [MACH_HEADER_64]

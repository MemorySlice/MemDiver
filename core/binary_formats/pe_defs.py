"""PE binary format structure definitions."""
from core.structure_defs import StructureDef, FieldDef, FieldType

DOS_HEADER = StructureDef(
    name="dos_header",
    total_size=64,
    protocol="binary",
    description="DOS MZ header",
    tags=("pe", "header"),
    fields=(
        FieldDef(name="e_magic", field_type=FieldType.BYTES, offset=0, size=2,
                 description="Magic: MZ", constraints={"equals": "4d5a"}),
        FieldDef(name="e_lfanew", field_type=FieldType.UINT32_LE, offset=60, size=4,
                 description="PE header offset"),
    ),
)

COFF_HEADER = StructureDef(
    name="coff_header",
    total_size=20,
    protocol="binary",
    description="COFF file header",
    tags=("pe", "header"),
    fields=(
        FieldDef(name="machine", field_type=FieldType.UINT16_LE, offset=0, size=2,
                 description="Target machine"),
        FieldDef(name="num_sections", field_type=FieldType.UINT16_LE, offset=2, size=2,
                 description="Number of sections"),
        FieldDef(name="timestamp", field_type=FieldType.UINT32_LE, offset=4, size=4,
                 description="Timestamp"),
        FieldDef(name="symbol_table", field_type=FieldType.UINT32_LE, offset=8, size=4,
                 description="Symbol table pointer"),
        FieldDef(name="num_symbols", field_type=FieldType.UINT32_LE, offset=12, size=4,
                 description="Number of symbols"),
        FieldDef(name="opt_header_size", field_type=FieldType.UINT16_LE, offset=16, size=2,
                 description="Optional header size"),
        FieldDef(name="characteristics", field_type=FieldType.UINT16_LE, offset=18, size=2,
                 description="Characteristics flags"),
    ),
)

PE_DEFS = [DOS_HEADER, COFF_HEADER]

"""ELF binary format structure definitions."""
from core.structure_defs import StructureDef, FieldDef, FieldType

ELF64_HEADER = StructureDef(
    name="elf64_header",
    total_size=64,
    protocol="binary",
    description="ELF-64 file header",
    tags=("elf", "header"),
    fields=(
        FieldDef(name="e_ident_magic", field_type=FieldType.BYTES, offset=0, size=4,
                 description="Magic: 0x7f ELF", constraints={"equals": "7f454c46"}),
        FieldDef(name="e_ident_class", field_type=FieldType.UINT8, offset=4, size=1,
                 description="Class: 1=32-bit, 2=64-bit"),
        FieldDef(name="e_ident_data", field_type=FieldType.UINT8, offset=5, size=1,
                 description="Data: 1=LE, 2=BE"),
        FieldDef(name="e_type", field_type=FieldType.UINT16_LE, offset=16, size=2,
                 description="Object type"),
        FieldDef(name="e_machine", field_type=FieldType.UINT16_LE, offset=18, size=2,
                 description="Architecture"),
        FieldDef(name="e_entry", field_type=FieldType.UINT64_LE, offset=24, size=8,
                 description="Entry point"),
        FieldDef(name="e_phoff", field_type=FieldType.UINT64_LE, offset=32, size=8,
                 description="Program header offset"),
        FieldDef(name="e_shoff", field_type=FieldType.UINT64_LE, offset=40, size=8,
                 description="Section header offset"),
        FieldDef(name="e_phnum", field_type=FieldType.UINT16_LE, offset=56, size=2,
                 description="Program header count"),
        FieldDef(name="e_shnum", field_type=FieldType.UINT16_LE, offset=60, size=2,
                 description="Section header count"),
    ),
)

ELF_DEFS = [ELF64_HEADER]

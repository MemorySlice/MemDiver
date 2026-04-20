"""Block tree model for MSL file navigation."""

import logging
import struct
from dataclasses import dataclass, field
from typing import Dict, List

logger = logging.getLogger("memdiver.msl.block_tree")

# Block type categories for grouping
_CATEGORIES = {
    "Process Context": [0x0040, 0x0050, 0x0051],
    "Memory": [0x0001, 0x1001],
    "Code": [0x0002, 0x0010, 0x0011],
    "Crypto": [0x0020],
    "I/O": [0x0012, 0x0014, 0x0015, 0x0053],
    "Network": [0x0013, 0x0052],
    "Forensic": [0x0041, 0x0030, 0x0FFF],
}

# Reverse lookup: block_type -> category
_TYPE_TO_CATEGORY = {}
for _cat, _types in _CATEGORIES.items():
    for _bt in _types:
        _TYPE_TO_CATEGORY[_bt] = _cat


@dataclass
class BlockNode:
    """A single MSL block for navigation."""

    type_code: int
    type_name: str
    payload_size: int
    file_offset: int
    block_uuid: str = ""
    is_capture_time: bool = False

    @property
    def category(self) -> str:
        return _TYPE_TO_CATEGORY.get(self.type_code, "Other")


def list_blocks(reader) -> List[BlockNode]:
    """List all blocks from an MslReader as BlockNode objects."""
    nodes = []
    try:
        for hdr, _payload in reader.iter_blocks():
            name = _block_type_name(hdr.block_type)
            node = BlockNode(
                type_code=hdr.block_type,
                type_name=name,
                payload_size=hdr.payload_length,
                file_offset=hdr.file_offset,
                block_uuid=hdr.block_uuid.hex if hdr.block_uuid else "",
                is_capture_time=(hdr.block_type < 0x1000),
            )
            nodes.append(node)
    except (IOError, ValueError, struct.error):
        logger.exception("Error listing MSL blocks")
    return nodes


def group_blocks(nodes: List[BlockNode]) -> Dict[str, List[BlockNode]]:
    """Group blocks by category, preserving order."""
    groups: Dict[str, List[BlockNode]] = {}
    for node in nodes:
        cat = node.category
        if cat not in groups:
            groups[cat] = []
        groups[cat].append(node)
    return groups


def _block_type_name(type_code: int) -> str:
    """Map block type code to human-readable name via BlockType enum."""
    from msl.enums import BlockType
    try:
        return BlockType(type_code).name
    except ValueError:
        return f"UNKNOWN_0x{type_code:04X}"

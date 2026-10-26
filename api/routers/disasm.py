"""Disassembly router — ``POST /api/disasm`` (the ``disasm`` capability).

The web face of :mod:`memdiver.app.tools_disasm`: decode the CAPTURED bytes at an
address of one dump. ``dump_path`` goes through the opt-in read sandbox; a ``case_dir``
(rows become the ``disasm`` table) is a write target and is contained like the case
router's.
"""

from __future__ import annotations

from typing import Optional

from fastapi import APIRouter
from pydantic import BaseModel, ConfigDict

from memdiver.api.routers.image import _case_target
from memdiver.app import tools_disasm

router = APIRouter()


class DisasmRequest(BaseModel):
    # A misspelled field must be a 422, never a silent default with a 200.
    model_config = ConfigDict(extra="forbid")

    dump_path: str
    address: int
    length: int
    arch: str = "auto"
    view: Optional[str] = None
    mode: Optional[str] = None
    max_insns: int = tools_disasm.DEFAULT_MAX_INSNS
    case_dir: Optional[str] = None


@router.post("")
def disassemble(req: DisasmRequest):
    """Disassemble ``length`` bytes at ``address``, captured stretches only."""
    return tools_disasm.disasm_result(
        req.dump_path, req.address, req.length, arch=req.arch, view=req.view,
        mode=req.mode, max_insns=req.max_insns,
        case_dir=_case_target(req.case_dir)).payload

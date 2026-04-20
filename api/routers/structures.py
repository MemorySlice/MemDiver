"""CRUD endpoints for structure definitions."""

from __future__ import annotations
import json
from pathlib import Path
from fastapi import APIRouter, File, HTTPException, UploadFile
from pydantic import BaseModel

from core.structure_library import get_structure_library
from core.structure_schema import validate_structure_json, json_to_structure_def, structure_def_to_json
from core.structure_loader import load_user_structures, save_user_structure, DEFAULT_USER_DIR

router = APIRouter()


class StructureCreateRequest(BaseModel):
    name: str
    total_size: int
    protocol: str = ""
    description: str = ""
    tags: list[str] = []
    fields: list[dict] = []


@router.get("/list")
def list_structures():
    lib = get_structure_library()
    return [
        {"name": sd.name, "protocol": sd.protocol, "description": sd.description,
         "total_size": sd.total_size, "field_count": len(sd.fields), "tags": list(sd.tags),
         "library": sd.library, "library_version": sd.library_version,
         "stability": sd.stability}
        for sd in lib.list_all()
    ]


@router.get("/{name}")
def get_structure(name: str):
    lib = get_structure_library()
    sd = lib.get(name)
    if sd is None:
        raise HTTPException(status_code=404, detail=f"Structure '{name}' not found")
    return structure_def_to_json(sd)


@router.post("/create")
def create_structure(req: StructureCreateRequest):
    data = req.model_dump()
    valid, errors = validate_structure_json(data)
    if not valid:
        raise HTTPException(status_code=400, detail=errors)
    sd = json_to_structure_def(data)
    path = save_user_structure(sd)
    lib = get_structure_library()
    lib.register(sd)
    return {"name": sd.name, "path": str(path)}


@router.delete("/{name}")
def delete_structure(name: str):
    path = DEFAULT_USER_DIR / f"{name}.json"
    if not path.exists():
        raise HTTPException(status_code=404, detail=f"User structure '{name}' not found")
    path.unlink()
    lib = get_structure_library()
    lib.unregister(name)
    return {"deleted": name}


@router.post("/import-ksy")
async def import_ksy(file: UploadFile = File(...)):
    """Import a Kaitai Struct .ksy format definition file."""
    content = await file.read()
    try:
        text = content.decode("utf-8")
    except UnicodeDecodeError:
        raise HTTPException(status_code=400, detail="File is not valid UTF-8 text")

    try:
        import yaml
    except ImportError:
        raise HTTPException(
            status_code=500,
            detail="PyYAML is not installed; cannot validate .ksy files",
        )

    try:
        doc = yaml.safe_load(text)
    except yaml.YAMLError as exc:
        raise HTTPException(status_code=400, detail=f"Invalid YAML: {exc}")

    if not isinstance(doc, dict):
        raise HTTPException(status_code=400, detail="KSY file must be a YAML mapping")

    meta = doc.get("meta")
    if not isinstance(meta, dict) or "id" not in meta:
        raise HTTPException(status_code=400, detail="KSY file must contain meta.id")

    if "seq" not in doc:
        raise HTTPException(status_code=400, detail="KSY file must contain a top-level 'seq' key")

    meta_id: str = meta["id"]
    formats_dir = Path.home() / ".memdiver" / "formats"
    formats_dir.mkdir(parents=True, exist_ok=True)

    filename = f"{meta_id}.ksy"
    dest = formats_dir / filename
    dest.write_text(text, encoding="utf-8")

    return {"name": meta_id, "filename": filename, "message": "Imported successfully"}


@router.get("/{name}/export")
def export_structure(name: str):
    lib = get_structure_library()
    sd = lib.get(name)
    if sd is None:
        raise HTTPException(status_code=404, detail=f"Structure '{name}' not found")
    return structure_def_to_json(sd)

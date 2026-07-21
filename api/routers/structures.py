"""CRUD endpoints for structure definitions."""

from __future__ import annotations
import asyncio
import json
from pathlib import Path
from fastapi import APIRouter, File, HTTPException, UploadFile
from pydantic import BaseModel

from memdiver.api.path_safety import safe_filename
from memdiver.core.structure_library import (
    add_user_structure,
    get_structure_library,
    remove_user_structure,
)
from memdiver.core.structure_schema import validate_structure_json, json_to_structure_def, structure_def_to_json
from memdiver.core.structure_loader import load_user_structures, save_user_structure, DEFAULT_USER_DIR

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
    # Persist + register in one step so the live singleton stays in sync with
    # disk (built-ins-win collision policy preserved by the helper).
    path = add_user_structure(sd)
    return {"name": sd.name, "path": str(path)}


@router.delete("/{name}")
def delete_structure(name: str):
    # The name comes straight from the URL and is joined onto DEFAULT_USER_DIR
    # to build the file to unlink, so contain it to a bare filename inside that
    # directory — a name with path separators or "../" (e.g. "../../etc/foo")
    # must not be able to unlink a file outside the user-structures dir.
    try:
        path = safe_filename(DEFAULT_USER_DIR, name, ".json")
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    if not path.exists():
        raise HTTPException(status_code=404, detail=f"User structure '{name}' not found")
    # Delete + unregister in one step so the live singleton stays in sync with
    # disk. The name is already contained to DEFAULT_USER_DIR by safe_filename.
    remove_user_structure(name, DEFAULT_USER_DIR)
    return {"deleted": name}


@router.post("/import-ksy")
async def import_ksy(file: UploadFile = File(...)):
    """Import a Kaitai Struct .ksy format definition file."""
    content = await file.read()
    if len(content) > 10 * 1024 * 1024:
        raise HTTPException(status_code=413, detail="ksy exceeds 10 MiB cap")
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
        doc = await asyncio.to_thread(yaml.safe_load, text)
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
    await asyncio.to_thread(dest.write_text, text, encoding="utf-8")

    return {"name": meta_id, "filename": filename, "message": "Imported successfully"}


@router.get("/{name}/export")
def export_structure(name: str):
    lib = get_structure_library()
    sd = lib.get(name)
    if sd is None:
        raise HTTPException(status_code=404, detail=f"Structure '{name}' not found")
    return structure_def_to_json(sd)

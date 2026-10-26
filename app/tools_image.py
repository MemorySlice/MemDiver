"""Memory-image producers: probe, profile, open (``.mdview``), processes, extract.

The ``image.*`` capabilities (plan T1.7). Thin, surface-agnostic wrappers over
:mod:`memdiver.core.image` that return a :class:`ServiceResult` with a plain-JSON
payload and RAISE a :class:`CapabilityError` on bad input. Volatility 3 and
pakunoda are the optional ``memdiver[image]`` extra and load lazily.

Cost model (why REST/MCP run some of these as jobs):

* ``image_probe_result`` never hashes the image and never runs pakunoda; banners
  (a raw scan that may read the whole image) are opt-in.
* ``image_profile_result`` may run pakunoda (~15 s, mmaps the whole image).
* ``image_open_view_result`` hashes the image (cached by path/size/mtime, but the
  first pass over a multi-GB file is slow).
* ``image_extract_process_result`` walks every VMA of a process.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Sequence

from memdiver.analysis.case import case_path
from memdiver.core.image.context import (
    ImageContext,
    cache_dir,
    file_sha256,
    get_image_context,
)
from memdiver.core.image.profiles import (
    CacheProvider,
    DraftProvider,
    ExplicitProvider,
    ProfileChain,
    ProfileResolution,
    default_chain,
    plausible_banners_first,
    scan_linux_banners,
)
from memdiver.core.image.pakunoda_view import require_va_bits
from memdiver.core.image.view_descriptor import (
    SUFFIX,
    PagingSpec,
    ProfileRef,
    ViewDescriptor,
    ViewKind,
)
from memdiver.core.service_errors import CapabilityError, ErrorCategory
from memdiver.core.service_result import ServiceResult

#: Banners a probe reports at most (``banners=True`` only).
PROBE_BANNER_LIMIT = 4

#: Label of the physical-memory-map rows written into an extracted ``.msl``.
PHYSICAL_RANGE_LABEL = "System RAM"

#: Result of ``pslist`` rows beyond this are cut (a Linux box rarely has more).
DEFAULT_PROCESS_LIMIT = 100_000


def _invalid(message: str, code: str) -> CapabilityError:
    return CapabilityError(message, category=ErrorCategory.INVALID_INPUT, code=code)


def _image_file(image_path: str) -> Path:
    if not image_path or not str(image_path).strip():
        raise _invalid("image_path is required", "image_path_required")
    path = Path(image_path).expanduser()
    if not path.is_file():
        raise CapabilityError(f"memory image not found: {path}",
                              category=ErrorCategory.NOT_FOUND, code="image_not_found")
    return path.resolve()


def _isf_file(isf: Optional[str]) -> Optional[Path]:
    if not isf:
        return None
    path = Path(isf).expanduser()
    if not path.is_file():
        raise CapabilityError(f"ISF file not found: {path}",
                              category=ErrorCategory.NOT_FOUND, code="isf_not_found")
    return path.resolve()


def _tool_versions() -> Dict[str, Optional[str]]:
    """Versions of the optional image dependencies (``None`` when not installed)."""
    versions: Dict[str, Optional[str]] = {"volatility3": None, "pakunoda": None}
    try:
        from volatility3.framework import constants
        versions["volatility3"] = str(constants.PACKAGE_VERSION)
    except ImportError:
        pass
    try:
        import pakunoda
        versions["pakunoda"] = str(pakunoda.__version__)
    except ImportError:
        pass
    return versions


def _known_sha256(image: Path) -> Optional[str]:
    """The image's sha256 when ``file_sha256`` already cached it; never hashes."""
    stat = image.stat()
    key = f"{image}|{stat.st_size}|{stat.st_mtime_ns}"   # file_sha256's index key
    try:
        index = json.loads((cache_dir() / "sha256_index.json").read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    value = index.get(key)
    return str(value) if value else None


def _resolution_dict(hit: ProfileResolution, chain: ProfileChain) -> Dict[str, Any]:
    return {"status": "found", "isf": str(hit.isf_path), "sha256": hit.sha256,
            "origin": hit.origin, "banner": hit.banner, "details": hit.details,
            "attempts": [list(a) for a in chain.attempts]}


def _cheap_chain(isf: Optional[Path]) -> ProfileChain:
    """Explicit + cache providers only: never pakunoda, never a raw banner scan."""
    return ProfileChain([ExplicitProvider(isf), CacheProvider()])


def _probe_profile(image: Path, isf: Optional[Path]) -> Dict[str, Any]:
    sha = _known_sha256(image)
    if sha is None and isf is not None:
        sha = ""   # the explicit provider never looks at the hash
    if sha is None:
        return {"status": "unknown",
                "reason": "image not hashed yet; run `image profile` or `image open`"}
    chain = _cheap_chain(isf)
    try:
        return _resolution_dict(chain.resolve(image, sha), chain)
    except CapabilityError:
        return {"status": "missing", "attempts": [list(a) for a in chain.attempts]}


def image_probe_result(image_path: str, banners: bool = False,
                       isf: Optional[str] = None) -> "ServiceResult":
    """Size, physical layer chain, optional banners and the cached-profile status."""
    image = _image_file(image_path)
    isf_file = _isf_file(isf)
    image_ctx = ImageContext.build(image, None)
    payload: Dict[str, Any] = {
        "image": str(image), "size": image.stat().st_size,
        "physical_layer_chain": image_ctx.describe()["physical_layer_chain"],
        "image_sha256": _known_sha256(image),
        "profile": _probe_profile(image, isf_file), "versions": _tool_versions()}
    if banners:
        payload["banners"] = [b.decode("utf-8", errors="replace")
                              for b in plausible_banners_first(
                                  scan_linux_banners(image, PROBE_BANNER_LIMIT))]
    return ServiceResult.ok(payload)


def _full_chain(isf: Optional[Path], allow_pakunoda: bool,
                progress: Optional[Callable[[str, float], None]] = None,
                cancel: Optional[Callable[[], bool]] = None) -> ProfileChain:
    chain = default_chain(isf, progress=progress, cancel=cancel)
    if not allow_pakunoda:
        chain.providers = [p for p in chain.providers if p.name != "pakunoda"]
    return chain


def image_profile_result(image_path: str, isf: Optional[str] = None,
                         allow_pakunoda: bool = True,
                         progress: Optional[Callable[[str, float], None]] = None,
                         cancel: Optional[Callable[[], bool]] = None) -> "ServiceResult":
    """Resolve the kernel profile (explicit -> cache -> pakunoda -> vol3 dirs).

    pakunoda extraction takes ~15 s and maps the whole image; surfaces with a
    request/response cycle run this as a job. ``progress(stage, elapsed_s)`` /
    ``cancel()`` are forwarded to pakunoda; a cancel raises ``CapabilityError``
    with ``code="cancelled"``.
    """
    image = _image_file(image_path)
    sha = file_sha256(image)
    chain = _full_chain(_isf_file(isf), allow_pakunoda, progress, cancel)
    hit = chain.resolve(image, sha)
    return ServiceResult.ok({"image": str(image), "image_sha256": sha,
                             **_resolution_dict(hit, chain)})


def _view_kind(view: str, pid: Optional[int]) -> ViewKind:
    try:
        kind = ViewKind(view)
    except ValueError:
        choices = ", ".join(k.value for k in ViewKind)
        raise _invalid(f"unknown view {view!r}; choose one of: {choices}",
                       "invalid_view") from None
    if kind is ViewKind.PROCESS and pid is None:
        raise _invalid("a process view requires pid", "pid_required")
    if kind is not ViewKind.PROCESS and pid is not None:
        raise _invalid(f"a {kind.value} view takes no pid", "pid_not_allowed")
    return kind


def _profile_for_view(image: Path, sha: str, isf: Optional[Path]) -> ProfileRef:
    chain = _cheap_chain(isf)
    try:
        return chain.resolve(image, sha).to_profile_ref()
    except CapabilityError as exc:
        raise CapabilityError(
            "no kernel profile is known for this image; run `memdiver image profile` "
            f"first (or pass isf). {exc.message}",
            category=ErrorCategory.PRECONDITION, code="profile_required",
            details=exc.details) from exc


def _check_profile_loads(descriptor: ViewDescriptor, target: Path) -> None:
    """Build the profiled view's context NOW (through the shared cache, so the work is
    reused by the first read): a profile vol3 cannot load refuses the descriptor with
    ``profile_build_failed`` + the implicated entries instead of failing every later read."""
    if descriptor.profile is None or descriptor.view is ViewKind.PHYSICAL:
        return
    try:
        _context_for(descriptor, target)
    except CapabilityError as exc:
        if exc.code != "profile_build_failed":
            raise
        label = f"{descriptor.profile.origin} {Path(str(descriptor.profile.isf)).name}"
        items = ", ".join(i["item"] for i in (exc.details or {}).get("implicated", [])[:8])
        raise CapabilityError(
            f"profile {label} cannot load yet" + (f": {items}" if items else "")
            + f" ({exc.message})", category=exc.category, code=exc.code,
            details=exc.details) from exc


def _view_target(image: Path, kind: ViewKind, pid: Optional[int],
                 case_dir: Optional[str], out_path: Optional[str]) -> Path:
    if out_path:
        target = Path(out_path).expanduser()
        if not target.name.endswith(SUFFIX) or target.name == SUFFIX:
            raise _invalid(f"out_path must end in {SUFFIX}: {target}", "view_out_target")
        if "annotations" in target.resolve(strict=False).parts:
            raise _invalid("out_path must not lie inside a case's annotations/",
                           "view_out_target")
        if target.exists() or target.is_symlink():
            raise _invalid(f"out_path already exists (views never overwrite): {target}",
                           "view_out_exists")
        target.parent.mkdir(parents=True, exist_ok=True)
        return target
    from memdiver.analysis.case import Case
    case = Case.init(case_dir if case_dir else image.stem)
    views = case.dir / "views"
    views.mkdir(exist_ok=True)
    suffix = f".pid{pid}" if pid is not None else ""
    return views / f"{image.stem}.{kind.value}{suffix}{SUFFIX}"


def _discovered_paging(image: Path, paging: Optional[Dict[str, Any]]) -> PagingSpec:
    """Paging for a no-ISF kernel view: as given, or found by pakunoda (verified only)."""
    given = dict(paging or {})
    if given.get("pgd_phys") is not None:
        if not given.get("arch") and not given.get("format"):
            raise _invalid("paging needs 'arch' (or an explicit 'format') with pgd_phys",
                           "paging_arch_required")
        spec = PagingSpec.from_dict(given)
        require_va_bits(spec)
        return spec
    from memdiver.app.tools_isf import isf_probe_result
    wanted_bits = given.get("va_bits")
    found = isf_probe_result(str(image), "page_table_root",
                             arch=str(given.get("arch") or "auto"),
                             params={"va_bits": wanted_bits} if wanted_bits else None).payload
    rows = found.get("rows") or []
    if not rows or not rows[0].get("verified"):
        raise CapabilityError(
            "pakunoda found no VERIFIED kernel page-table root in this image; pass "
            "paging={'pgd_phys': ..., 'arch': ...} explicitly",
            category=ErrorCategory.PRECONDITION, code="paging_root_not_found",
            details={"probe": {k: found.get(k) for k in ("arch", "rows", "warnings")}})
    root = rows[0]
    if wanted_bits and int(root["va_bits"]) != int(wanted_bits):
        raise CapabilityError(
            f"requested va_bits={wanted_bits} but the verified page-table root uses "
            f"va_bits={root['va_bits']}; pass pgd_phys explicitly to force this layout",
            category=ErrorCategory.PRECONDITION, code="paging_va_bits_mismatch",
            details={"requested": int(wanted_bits), "found": int(root["va_bits"])})
    return PagingSpec(root["pgd_phys"], found["arch"], root["va_bits"], root["page_size"],
                      str(given.get("endian", "little")), given.get("format"),
                      given.get("kernel_va_start"))


def _profile_choice(image: Path, sha: str, kind: ViewKind, isf: Optional[Path],
                    no_profile: bool, draft: Optional[str], draft_version: Optional[str],
                    case_dir: Optional[str]) -> Optional[ProfileRef]:
    if kind is ViewKind.PHYSICAL or no_profile:
        return None
    if draft:
        if isf is not None:
            raise _invalid("pass either isf or draft, not both", "profile_conflict")
        if not case_dir:
            raise _invalid("a draft profile needs case_dir", "draft_case_required")
        provider = DraftProvider(case_path(case_dir), draft, draft_version)
        hit = provider.resolve(image, sha)
        if hit is None:
            raise _invalid(f"draft {draft!r} was not usable: {provider.last_reason}",
                           "draft_unusable")
        return hit.to_profile_ref()
    return _profile_for_view(image, sha, isf)


def image_open_view_result(image_path: str, view: str, pid: Optional[int] = None,
                           isf: Optional[str] = None, case_dir: Optional[str] = None,
                           out_path: Optional[str] = None, *, no_profile: bool = False,
                           paging: Optional[Dict[str, Any]] = None,
                           draft: Optional[str] = None,
                           draft_version: Optional[str] = None) -> "ServiceResult":
    """Write a ``.mdview`` descriptor for one view of the image; return its path.

    ``no_profile`` opens a KERNEL view without any ISF (plan T4.3): ``paging``
    supplies ``pgd_phys``/``arch``/... or, without ``pgd_phys``, pakunoda finds a
    verified root. ``draft`` (+ ``draft_version``, with ``case_dir``) uses an ISF
    draft from the case's analysis record as the profile.
    """
    kind = _view_kind(view, pid)
    if no_profile and kind is not ViewKind.KERNEL:
        raise _invalid("no_profile applies to the kernel view only", "no_profile_view")
    if no_profile and (isf or draft):
        raise _invalid("no_profile excludes isf and draft", "no_profile_conflict")
    image = _image_file(image_path)
    isf_file = _isf_file(isf)
    sha = file_sha256(image)
    profile = _profile_choice(image, sha, kind, isf_file, no_profile, draft, draft_version,
                              case_dir)
    spec = _discovered_paging(image, paging) if no_profile else (
        PagingSpec.from_dict(paging) if paging else None)
    descriptor = ViewDescriptor(str(image), sha, kind, pid=pid, profile=profile, paging=spec)
    target = _view_target(image, kind, pid, case_dir, out_path)
    _check_profile_loads(descriptor, target)
    path = descriptor.write(target)
    return ServiceResult.ok({"view_path": str(path), "capture_id": descriptor.capture_id,
                             "descriptor": descriptor.to_dict()})


def _read_descriptor(view_path: str) -> "tuple[Path, ViewDescriptor]":
    if not view_path or not str(view_path).strip():
        raise _invalid("view_path is required", "view_path_required")
    path = Path(view_path).expanduser()
    if not path.is_file():
        raise CapabilityError(f"view descriptor not found: {path}",
                              category=ErrorCategory.NOT_FOUND, code="view_not_found")
    try:
        return path, ViewDescriptor.read(path)
    except (ValueError, KeyError, TypeError) as exc:
        raise _invalid(f"not a valid .mdview descriptor: {path} ({exc})",
                       "invalid_view_descriptor") from exc


def _context_for(descriptor: ViewDescriptor, path: Path) -> ImageContext:
    """The cached ImageContext of a descriptor (same key as ``Vol3LayerSource``)."""
    isf = descriptor.isf_path(path)
    profile = descriptor.profile
    isf_sha = profile.sha256 if profile and profile.sha256 else (
        file_sha256(isf) if isf else None)
    paging = descriptor.paging
    return get_image_context(descriptor.image_path(path), descriptor.image_sha256, isf,
                             isf_sha, paging.va_bits if paging else None,
                             paging.pgd_phys if paging else None)


def _task_row(task: Any, capture_id: str, image_ctx: ImageContext) -> Dict[str, Any]:
    from volatility3.plugins.linux import pslist
    fields = pslist.PsList.get_task_fields(task)
    uid = fields.uid
    offset = image_ctx.canonical_kernel_va(int(fields.offset))
    return {"pid": int(fields.user_pid), "ppid": int(fields.user_ppid),
            "comm": str(fields.name), "uid": None if uid is None else int(uid),
            "has_mm": int(task.mm) != 0, "task_offset": offset,
            "location": {"space": "kernel_va", "value": offset,
                         "capture_id": capture_id}}


def _list_tasks(image_ctx: ImageContext, capture_id: str, limit: int) -> List[Dict[str, Any]]:
    from volatility3.plugins.linux import pslist
    rows: List[Dict[str, Any]] = []
    with image_ctx.lock:  # vol3 contexts are not thread-safe (see ImageContext.lock)
        for task in pslist.PsList.list_tasks(image_ctx.context, image_ctx.kernel.name):
            rows.append(_task_row(task, capture_id, image_ctx))
            if len(rows) >= limit:
                break
    return rows


def image_processes_result(view_path: str,
                           limit: int = DEFAULT_PROCESS_LIMIT) -> "ServiceResult":
    """The task list of a kernel or process view (``pslist``); never silently empty."""
    path, descriptor = _read_descriptor(view_path)
    if descriptor.view is ViewKind.PHYSICAL or descriptor.profile is None:
        raise _invalid("listing processes needs a kernel or process view with a profile",
                       "kernel_view_required")
    if limit < 1:
        raise _invalid("limit must be >= 1", "invalid_limit")
    rows = _list_tasks(_context_for(descriptor, path), descriptor.capture_id, limit)
    if not rows:
        raise CapabilityError("pslist returned no tasks — wrong profile or paging depth",
                              category=ErrorCategory.PRECONDITION, code="pslist_empty")
    return ServiceResult.ok({"view_path": str(path), "capture_id": descriptor.capture_id,
                             "row_source": "pslist", "count": len(rows), "processes": rows})


def _kernel_banner(image_ctx: ImageContext) -> str:
    """The ``linux_banner`` string read through the kernel layer ('' if unreadable)."""
    try:
        with image_ctx.lock:
            banner = image_ctx.kernel.object_from_symbol("linux_banner")
            return str(banner.cast("string", max_length=1024, errors="replace")).strip()
    except Exception:  # noqa: BLE001 - provenance only; extraction must not fail on it
        return ""


def _note_fields(descriptor: ViewDescriptor, meta: Dict[str, Any],
                 image_ctx: ImageContext) -> Dict[str, str]:
    layer = meta.get("layer", {})
    profile = descriptor.profile
    versions = _tool_versions()
    return {"image_sha256": descriptor.image_sha256,
            "isf_sha256": (profile.sha256 if profile else None) or "",
            "isf_origin": profile.origin if profile else "",
            "vol3": versions["volatility3"] or "", "pakunoda": versions["pakunoda"] or "",
            "pid": str(descriptor.pid), "comm": str(layer.get("comm", "")),
            "dtb": hex(layer["process_dtb"]) if "process_dtb" in layer else "",
            "banner": _kernel_banner(image_ctx)}


def _physical_ranges(image_ctx: ImageContext) -> List[Any]:
    from memdiver.core.image.adapters import physical_runs
    try:
        from memdiver.msl.types import PhysicalRange
    except ImportError as exc:  # pragma: no cover - defensive; the class ships in msl.types
        raise CapabilityError("this MemDiver build cannot write a physical memory map",
                              category=ErrorCategory.UNSUPPORTED) from exc
    with image_ctx.lock:
        layer = image_ctx.context.layers[image_ctx.physical_layer]
        runs = physical_runs(layer)
    return [PhysicalRange(run.start, run.end - 1, PHYSICAL_RANGE_LABEL) for run in runs]


def _extractor() -> Any:
    try:
        from memdiver.msl.image_extract import extract_process_to_msl
    except ImportError as exc:
        raise CapabilityError("image -> .msl extraction is not available in this build "
                              f"(memdiver.msl.image_extract: {exc})",
                              category=ErrorCategory.UNSUPPORTED,
                              code="extractor_unavailable") from exc
    return extract_process_to_msl


def _extract_payload(result: Any, view_path: Path, ranges: Sequence[Any]) -> Dict[str, Any]:
    """``ranges`` are the PhysicalRanges this call wrote (``ExtractResult`` only counts them)."""
    return {"view_path": str(view_path), "output_path": str(result.output_path),
            "pid": result.pid, "regions_written": result.regions_written,
            "modules_written": getattr(result, "modules_written", None),
            "skipped_vmas": getattr(result, "skipped_vmas", None),
            "captured_bytes": result.captured_bytes,
            "state_bytes": dict(result.state_bytes),
            "physical_ranges": [[r.start, r.end_inclusive, r.label] for r in ranges]}


def image_extract_process_result(view_path: str, out_path: str) -> "ServiceResult":
    """Extract the process of a process view into an ``.msl`` at ``out_path``."""
    from memdiver.core.dump_source import open_dump
    path, descriptor = _read_descriptor(view_path)
    if descriptor.view is not ViewKind.PROCESS:
        raise _invalid("extraction needs a process view (use `image open --view process --pid N`)",
                       "process_view_required")
    if not out_path or not str(out_path).strip():
        raise _invalid("out_path is required", "out_path_required")
    extract = _extractor()
    target = Path(out_path).expanduser()
    if not target.name.endswith(".msl") or target.name == ".msl":
        raise _invalid(f"out_path must end in .msl: {target}", "out_path_target")
    if target.exists() or target.is_symlink():
        raise _invalid(f"out_path already exists (extraction never overwrites): {target}",
                       "out_path_exists")
    target.parent.mkdir(parents=True, exist_ok=True)
    image_ctx = _context_for(descriptor, path)
    ranges = list(_physical_ranges(image_ctx) or ())
    with open_dump(path) as source:
        result = extract(source, target,
                         note_fields=_note_fields(descriptor, source.metadata(), image_ctx),
                         physical_ranges=ranges)
    return ServiceResult.ok(_extract_payload(result, path, ranges))


__all__ = ["DEFAULT_PROCESS_LIMIT", "PROBE_BANNER_LIMIT", "image_probe_result",
           "image_profile_result", "image_open_view_result", "image_processes_result",
           "image_extract_process_result"]

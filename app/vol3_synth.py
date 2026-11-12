"""Volatility 3 plugin synthesis: a located key -> a standalone, self-proving vol3 plugin.

Moved verbatim out of :mod:`memdiver.app.tools_pipeline` (move-only refactor,
no behaviour change) so synthesis has its own home as it grows. Every name is
still importable from ``memdiver.app.tools_pipeline``, which re-exports them
lazily (PEP 562 ``__getattr__``): this module imports the helpers it shares
with the rest of the pipeline FROM ``tools_pipeline``, so that module must not
import this one at import time. Patch names used by this code HERE
(``memdiver.app.vol3_synth``); a patch on the facade does not reach it.
"""

from __future__ import annotations

import json
import tempfile
import threading
import time
from contextlib import ExitStack, contextmanager
from pathlib import Path
from typing import (
    Any,
    Callable,
    Dict,
    Iterator,
    List,
    Mapping,
    NamedTuple,
    Optional,
    Sequence,
    Tuple,
    cast,
)

from memdiver.core.service_errors import (
    CapabilityError,
    ErrorCategory,
    FileNotFoundServiceError,
)
from memdiver.core.service_result import Diagnostic, Severity
from memdiver.engine.progress import Cancelled as _SynthCancelled
from memdiver.engine.vol3_subproc import NAMED_STDOUT_CAP as _VOL3_NAMED_STDOUT_CAP
from memdiver.engine.vol3_verify import PROVEN_PREFIX as _VOL3_PROVEN_PREFIX

from .key_material import KeyedSources, probe_dump_key
# Shared with the rest of the pipeline; they stay defined there. ``logger`` is
# the ``memdiver.app.tools_pipeline`` logger, so log records keep their name.
from .tools_pipeline import (
    VOL3_SUBPROC_TIMEOUT_S,
    _needle_from_key_hex,
    _raise_if_locked,
    _resolve_key_material,
    logger,
)


# ---------------------------------------------------------------------------
# synthesize_vol3_plugin: a located key -> a standalone, self-proving vol3 plugin
# ---------------------------------------------------------------------------

#: Verify targets :func:`synthesize_vol3_plugin` knows. ``"msl"`` runs the
#: emitted plugin IN-PROCESS over every supplied dump through the real
#: Volatility 3 framework, on the same ``MslVasLayer``/``MslLayer`` stack stock
#: ``vol -p <vol3plugins>`` builds, so the offsets are the ones a user sees.
#: ``full_image`` is not listed here: it is requested by passing ``full_image=``.
SYNTH_TARGET_MSL = "msl"
SYNTH_TARGET_FULL_IMAGE = "full_image"
SYNTH_VERIFY_TARGETS = (SYNTH_TARGET_MSL,)

SYNTH_PROVEN = "proven"
SYNTH_NOT_PROVEN = "not_proven"
SYNTH_ERROR = "error"

SYNTH_PASSPHRASE_LAYER_CODE = "synth.vol3_plugin.passphrase_not_forwarded"  # nosec B105 -- an error code, not a secret
SYNTH_NOT_PROVEN_CODE = "synth.vol3_plugin.not_proven"
SYNTH_NOT_VERIFIED_CODE = "synth.vol3_plugin.not_verified"
SYNTH_STORED_UNPROVEN_CODE = "synth.vol3_plugin.stored_unproven"
SYNTH_UNSTORED_CODE = "synth.vol3_plugin.plugin_dir_is_temporary"

#: Default context bytes either side of the key (the recipe builder's default).
from memdiver.architect.vol3_recipe import (  # noqa: E402
    DEFAULT_CONTEXT as SYNTH_DEFAULT_CONTEXT,
)

#: Case layout of synthesized plugins. The plugin directory is what the
#: ``vol_command`` hands to ``vol -p``, and vol imports EVERY ``.py`` beneath
#: a ``-p`` directory -- so replaced versions are archived in a SIBLING
#: directory, never under it (``PluginStore``'s ``plugins/history/`` would be
#: imported as ``history.<name>-<sha>`` and listed by ``vol -h``).
#: Defined once in ``tools_vol3_sources`` (it lists the store without importing
#: this module); ``tools_vol3_dev`` refuses the history directory as ``vol -p``.
from .tools_vol3_sources import (  # noqa: E402
    SYNTHESIZED_DIR as SYNTH_STORE_DIR,
    SYNTHESIZED_HISTORY_DIR as SYNTH_HISTORY_DIR,
)

#: Serialises in-process plugin runs: ``engine.vol3_verify`` names each emitted
#: module from an unguarded counter and registers it in ``sys.modules``.
_SYNTH_RUN_LOCK = threading.Lock()


def vol3_plugin_dir() -> Dict[str, Any]:
    """The installed ``memdiver/vol3plugins`` directory, for ``vol -p <dir>``.

    Resolved through the import system's spec, so nothing inside the
    directory is imported (``vol3plugins`` is the ``-p`` directory stock vol
    loads; MemDiver itself is already imported by whoever calls this).
    """
    import importlib.util

    spec = importlib.util.find_spec("memdiver.vol3plugins")
    locations = list(spec.submodule_search_locations or []) if spec else []
    if not locations:
        raise CapabilityError(
            "memdiver.vol3plugins is not installed with this MemDiver",
            category=ErrorCategory.INTERNAL, code="vol3.plugin_dir_missing")
    return {"path": str(Path(locations[0]).resolve())}


#: Minimum seconds between two progress reports from inside one in-process vol3
#: scan (Volatility 3 calls its progress callback once per scanned chunk).
_SYNTH_SCAN_REPORT_S = 0.5


class _SynthSteps(NamedTuple):
    """Cancel checks and progress reports of one synthesis; both are optional.

    ``report(fraction, message)`` receives the OVERALL fraction in ``[0, 1]``. A
    step's own fraction is mapped into ``[lo, hi]``, so :meth:`within` nests a
    sub-step (one dump of N, one vol attempt of M) inside its parent's range.
    A true ``cancel()`` makes :meth:`step` -- and an in-process vol3 scan,
    through :meth:`vol3_callback` -- raise ``engine.progress.Cancelled``.
    Messages carry dump/image NAMES and counts only, never key material.
    """

    cancel: Optional[Callable[[], bool]] = None
    report: Optional[Callable[[float, str], None]] = None
    lo: float = 0.0
    hi: float = 1.0

    def within(self, lo: float, hi: float) -> "_SynthSteps":
        width = self.hi - self.lo
        return self._replace(lo=self.lo + width * lo, hi=self.lo + width * hi)

    def check(self) -> None:
        if self.cancel is not None and self.cancel():
            raise _SynthCancelled()

    def step(self, fraction: float, message: str) -> None:
        """Stop here when cancelled, else report *message* at *fraction* of this range."""
        self.check()
        if self.report is not None:
            self.report(self.lo + (self.hi - self.lo) * fraction, message)

    def vol3_callback(self, message: str) -> Optional[Callable[[float, str], None]]:
        """A vol3 ``progress_callback``: checks cancel per chunk, reports throttled."""
        if self.cancel is None and self.report is None:
            return None
        last = [time.monotonic()]

        def callback(percent: float, _description: str) -> None:
            self.check()
            now = time.monotonic()
            if now - last[0] >= _SYNTH_SCAN_REPORT_S:
                last[0] = now
                done = min(max(float(percent), 0.0), 100.0)
                self.step(done / 100.0, f"{message} ({done:.0f}%)")
        return callback


#: Overall progress fractions of the synthesis phases: the recipe build and the
#: emission come first, then the verify targets share the rest.
_SYNTH_EMIT_AT, _SYNTH_VERIFY_FROM, _SYNTH_MSL_SHARE_WITH_IMAGE = 0.08, 0.15, 0.3


def _synth_spans(msl: bool, image: bool) -> Tuple[Tuple[float, float], Tuple[float, float]]:
    """``(msl range, full-image range)`` of the overall progress (the vol run is the long one)."""
    if not msl:
        split = _SYNTH_VERIFY_FROM
    elif not image:
        split = 1.0
    else:
        split = _SYNTH_VERIFY_FROM + _SYNTH_MSL_SHARE_WITH_IMAGE
    return (_SYNTH_VERIFY_FROM, split), (split, 1.0)


def _synth_dump_label(path: Path) -> str:
    """``run_0001/memslicer.msl``: corpus dumps share a file name, their runs differ."""
    return f"{path.parent.name}/{path.name}" if path.parent.name else path.name


def _synth_invalid(message: str, code: str,
                   category: ErrorCategory = ErrorCategory.INVALID_INPUT) -> CapabilityError:
    return CapabilityError(message, category=category, code=f"synth.vol3_plugin.{code}")


def _synth_per_dump(value: Any, count: int, what: str) -> List[Any]:
    """One value per dump: a scalar is broadcast, a sequence must match ``count``."""
    if value is None or isinstance(value, (str, Path)):
        return [value] * count
    values = list(value)
    if len(values) != count:
        raise _synth_invalid(f"{len(values)} {what} for {count} dumps", "length_mismatch")
    return values


def _synth_redacted(text: str) -> str:
    """A key for an error message: its length only (messages reach task records and the WS)."""
    return f"<{len(str(text))} chars>"


def _synth_parse_key(text: str, index: int) -> str:
    """Normalised key hex; a refusal never echoes the key (``_needle_from_key_hex`` would)."""
    try:
        return _needle_from_key_hex(str(text)).hex()
    except CapabilityError:
        raise _synth_invalid(f"key {index} is not valid hex {_synth_redacted(text)}",
                             "invalid_key") from None


def _synth_error_from_recipe(exc: Exception) -> CapabilityError:
    """Map the recipe builder's refusals onto the capability error categories."""
    from memdiver.architect import vol3_recipe as vr

    message = str(exc)
    if isinstance(exc, vr.UnimplementedLocatorError):
        return _synth_invalid(message, "unimplemented_locator", ErrorCategory.UNSUPPORTED)
    if isinstance(exc, vr.HighEntropyContextError):
        return _synth_invalid(message, "high_entropy_context", ErrorCategory.PRECONDITION)
    if isinstance(exc, vr.DegenerateAnchorError):
        return _synth_invalid(message, "degenerate_anchor", ErrorCategory.PRECONDITION)
    if "none of the supplied dumps" in message:
        return _synth_invalid(message, "key_not_found", ErrorCategory.NOT_FOUND)
    return _synth_invalid(message, "recipe")


def _synth_oracle_module(oracle_kind: str) -> Any:
    from memdiver.oracles import UnknownFormatError, get_format

    if not oracle_kind:
        raise _synth_invalid("oracle_kind is required: the oracle alone decides Proven",
                             "oracle_required")
    try:
        return get_format(oracle_kind)
    except UnknownFormatError as exc:
        raise _synth_invalid(str(exc).strip("'\""), "unknown_oracle") from exc


def _synth_hit_range(hit: Mapping[str, Any]) -> Tuple[int, int]:
    """A hit's ``(offset, length)``, shape-checked WITHOUT touching a dump."""
    try:
        offset, length = int(hit["offset"]), int(hit["length"])
    except (KeyError, TypeError, ValueError) as exc:
        raise _synth_invalid("hit needs key_hex, or offset + length", "bad_hit") from exc
    if length <= 0 or offset < 0:
        raise _synth_invalid("hit offset must be >= 0 and length > 0", "bad_hit")
    return offset, length


def _synth_hit_dump(hit: Optional[Mapping[str, Any]], paths: Sequence[Path]) -> Optional[Path]:
    """A hit's own ``dump_path`` when it is NOT one of *paths* (those are guarded already)."""
    own = (hit or {}).get("dump_path")
    if not own:
        return None
    path = Path(own).expanduser()
    return None if path in paths else path


def _synth_key_from_hit(hit: Mapping[str, Any], dump_paths: Sequence[str],
                        sources: KeyedSources) -> str:
    """The key hex of an ``{"offset", "length"[, "dump_path", "view"]}`` hit, read from its dump.

    The dump comes from *sources* (the run's pool), so an encrypted dump the
    guard already opened is not decrypted again. A range outside the dump is
    ``bad_hit`` -- on a background job's worker too: its preflight checks the
    hit's shape only (:func:`_synth_hit_range`), never reads it.
    """
    offset, length = _synth_hit_range(hit)
    view_kw = {"view": hit["view"]} if hit.get("view") else {}
    with sources.source(hit.get("dump_path") or dump_paths[0]) as source:
        _raise_if_locked(source)
        data = bytes(cast(Any, source).read_range(offset, length, **view_kw))
    if len(data) != length:
        raise _synth_invalid(f"hit [{offset}, +{length}) is outside the dump", "bad_hit")
    return data.hex()


def _synth_guard_dumps(paths: Sequence[Path], km: Dict[str, Any],
                       on_source: Optional[Callable[[Any], None]],
                       steps: Optional["_SynthSteps"] = None, *,
                       sources: Optional[KeyedSources] = None,
                       probe: bool = False) -> List[Optional[str]]:
    """Existence + locked-container guard BEFORE the builder reads anything.

    A locked ``.msl`` reads back empty, which the builder would report as
    "the key is in none of the supplied dumps" -- a confident wrong answer.
    Every dump is opened through *sources* -- the run's pool, so the builder
    reads the same open source; without one, a pool closed on return -- and
    its ``format_name`` returned, so the verify step need not reopen (and,
    for an encrypted ``.msl``, decrypt again) just to read it.

    *probe* (the preflight of a background job) opens nothing and returns
    ``[]``: each dump's key is probed (:func:`probe_dump_key`, block 0 only)
    and a missing or wrong key refused with the same error and hint. A
    ciphertext tampered beyond block 0 then fails the job instead.
    *on_source* is not called (there is no source).
    """
    missing = [str(p) for p in paths if not p.exists()]
    if missing:
        raise FileNotFoundServiceError(f"File not found: {', '.join(missing)}")
    if probe:
        _synth_probe_dumps(paths, km, steps or _SynthSteps())
        return []
    formats: List[Optional[str]] = []
    with ExitStack() as scope:
        pool = sources if sources is not None else scope.enter_context(KeyedSources(km))
        for path in paths:
            if steps is not None:
                steps.check()
            with pool.source(path) as source:
                _raise_if_locked(source)
                if on_source is not None:
                    on_source(source)
                formats.append(getattr(source, "format_name", None))
    return formats


def _synth_probe_dumps(paths: Sequence[Path], km: Dict[str, Any], steps: "_SynthSteps") -> None:
    """The lock guard on a probed key (no dump opened): same error, same hint."""
    for path in paths:
        steps.check()
        _raise_if_locked(probe_dump_key(path, km))


def _synth_display_spec(pkg_dir: str, plugin_dir: Path, target: str, dump: Path,
                        extra: Sequence[str] = (), symbol_dirs: Sequence[str] = ()) -> Any:
    """The stock ``vol`` run one verdict reproduces, as a copy-paste ``VolSpec``.

    No ``-q`` / ``-r json`` (a user reads the table); *symbol_dirs* become
    ``-s <dirs> --offline``. Paths are shown exactly as given. A verdict's
    ``vol_command`` and ``exec`` both come from this one spec.
    """
    from memdiver.engine.vol3_subproc import VolSpec

    return VolSpec(plugin=target, image=str(dump), plugin_dirs=(pkg_dir, str(plugin_dir)),
                   symbol_dirs=tuple(symbol_dirs), plugin_args=tuple(extra),
                   renderer=None, quiet=False)


def _synth_oracle_summary(recipe: Any) -> Dict[str, Any]:
    oracle = recipe.oracle
    sample = oracle.sample if oracle is not None else None
    return {"kind": oracle.kind if oracle else None,
            "sample_sha256": sample.sha256 if sample else None,
            "sample_bytes": len(sample.blob()) if sample else 0}


def _synth_archive(directory: Path, history: Path, name: str) -> None:
    """Copy the stored ``<name>.py`` and its ``.recipe.json`` / ``.yar`` into history, ONE tag for all."""
    from memdiver.analysis.plugin_store import FILE_MODE, safe_file, sha256_text
    from memdiver.core.artifact_util import atomic_write_text

    current = safe_file(directory, f"{name}.py")
    if not current.is_file():
        return
    text = current.read_text(encoding="utf-8")
    tag = sha256_text(text)[:12]
    for suffix, body in ((".py", text), (".recipe.json", None), (".yar", None)):
        source = safe_file(directory, f"{name}{suffix}")
        keep = safe_file(history, f"{name}-{tag}{suffix}")
        if keep.exists() or not source.is_file():
            continue
        atomic_write_text(keep, body if body is not None else source.read_text(
            encoding="utf-8"), mode=FILE_MODE)


def _synth_store(case_dir: str, recipe: Any, source_text: str,
                 yara_text: Optional[str] = None) -> Dict[str, Any]:
    """Store the plugin in ``<case>/vol3/plugins``, its recipe (and ``.yar`` rule) beside it.

    The ``.yar`` sidecar is safe in the ``vol -p`` directory: vol imports only
    ``.py`` / ``.pyc`` files there, and the case source listing globs ``*.py``.
    A version emitted without a rule drops the previous version's (archived) one.

    A replaced version (plugin AND recipe, same tag) goes to
    ``<case>/vol3/history`` -- outside the ``vol -p`` directory, see
    :data:`SYNTH_STORE_DIR`. The recipe carries the key's sha256 only, so
    nothing written here holds the key itself.
    """
    from memdiver.analysis.plugin_store import (
        FILE_MODE, MAX_SOURCE_BYTES, safe_directory, safe_file, sha256_text, store_error,
        validate_name)
    from memdiver.core.artifact_util import atomic_write_text

    name = validate_name(recipe.name)
    size = len(source_text.encode("utf-8"))
    if size > MAX_SOURCE_BYTES:
        raise store_error(f"plugin is {size} bytes; the cap is {MAX_SOURCE_BYTES}",
                          "plugin.too_large")
    case = Path(case_dir).expanduser()
    directory = safe_directory(case, SYNTH_STORE_DIR, create=True)
    history = safe_directory(case, SYNTH_HISTORY_DIR, create=True)
    _synth_archive(directory, history, name)
    plugin_path = safe_file(directory, f"{name}.py")
    recipe_path = safe_file(directory, f"{name}.recipe.json")
    atomic_write_text(plugin_path, source_text, mode=FILE_MODE)
    atomic_write_text(recipe_path, recipe.to_json() + "\n", mode=FILE_MODE)
    yara_path = safe_file(directory, f"{name}.yar")
    if yara_text:
        atomic_write_text(yara_path, yara_text, mode=FILE_MODE)
    elif yara_path.is_file():
        yara_path.unlink()  # a stale rule of the replaced version, kept in history
    return {"path": str(plugin_path), "recipe_path": str(recipe_path),
            "yara_path": str(yara_path) if yara_text else None,
            "history_dir": str(history), "sha256": sha256_text(source_text),
            "versions_archived": len(list(history.glob(f"{name}-*.py")))}


def _synth_msl_context(dump: Path, key_file: Optional[str],
                       kem_key_file: Optional[str]) -> Tuple[Any, str, int]:
    """A vol3 context holding ``FileLayer -> MslVasLayer -> MslLayer`` for ``dump``.

    Built exactly as ``vol3plugins.memdiver_stackers.MslStacker`` stacks it
    under stock ``vol``, plus the layer's own key-file options for an
    encrypted container. Returns ``(context, top layer name, captured bytes)``.
    """
    from volatility3.framework import contexts
    from volatility3.framework.configuration import requirements
    from volatility3.framework.layers import physical

    from memdiver.vol3plugins import msl_layer

    ctx = contexts.Context()
    ctx.config["FileLayer.location"] = requirements.URIRequirement.location_from_file(
        str(dump.resolve()))
    ctx.add_layer(physical.FileLayer(ctx, "FileLayer", "FileLayer"))
    ctx.config["MslVasLayer.base_layer"] = "FileLayer"
    for option, value in (("key_file", key_file), ("kem_key_file", kem_key_file)):
        if value:
            ctx.config[f"MslVasLayer.{option}"] = str(Path(value).expanduser().resolve())
    vas = msl_layer.MslVasLayer(ctx, "MslVasLayer", "MslVasLayer")
    ctx.add_layer(vas)
    ctx.config["MslLayer.base_layer"] = "MslVasLayer"
    ctx.add_layer(msl_layer.MslLayer(ctx, "MslLayer", "MslLayer"))
    return ctx, "MslLayer", int(vas.zero_region_offset)


def _synth_run_locked(source_text: str, dump: Path, *, fmt: Optional[str],
                      extra_config: Optional[Dict[str, Any]],
                      key_file: Optional[str], kem_key_file: Optional[str],
                      progress_callback: Optional[Callable[[float, str], None]] = None) -> Any:
    """One in-process run; *progress_callback* is vol3's (raising from it stops the scan)."""
    from memdiver.engine import vol3_verify

    if fmt != "msl":
        return vol3_verify.run_over_file(source_text, dump, extra_config=extra_config,
                                         progress_callback=progress_callback)
    ctx, layer, layer_bytes = _synth_msl_context(dump, key_file, kem_key_file)
    plugin_cls = vol3_verify.load_plugin_class(
        source_text, vol3_verify._default_module_name(source_text))
    grid = vol3_verify._run_plugin(plugin_cls, ctx, layer, extra_config=extra_config,
                                   progress_callback=progress_callback)
    return vol3_verify._build_report(
        source=source_text, plugin_cls=plugin_cls, grid=grid, layer_name=layer,
        layer_bytes=layer_bytes, expected_offset=None,
        max_hits=vol3_verify.DEFAULT_MAX_HITS)


@contextmanager
def _synth_vol3_isolation() -> Iterator[None]:
    """Serialise an in-process plugin load and drop the emitted module afterwards.

    Used for the emit self-test and every in-process verify run, so repeated
    synthesis neither races ``vol3_verify``'s module counter nor accumulates
    plugin modules in ``sys.modules``.
    """
    import sys

    with _SYNTH_RUN_LOCK:
        before = set(sys.modules)
        try:
            yield
        finally:
            for module in set(sys.modules) - before:
                if module.startswith("memdiver_emitted_vol3_"):
                    sys.modules.pop(module, None)


def _synth_run_in_process(source_text: str, dump: Path, **kwargs: Any) -> Any:
    """Run the plugin in this interpreter (an ``.msl`` on its VA layer stack)."""
    from memdiver.engine import vol3_verify

    vol3_verify._require_volatility3()
    with _synth_vol3_isolation():
        return _synth_run_locked(source_text, dump, **kwargs)


def _synth_proves(proven: Any, key_hex: Any, kind: str, key: Optional[bytes]) -> bool:
    """``Proven`` is ``oracle:<kind>`` and, when *key* is known, the row holds that key."""
    return (proven == f"{_VOL3_PROVEN_PREFIX}{kind}"
            and (key is None or str(key_hex or "").lower() == key.hex()))


def _synth_proven_hits(hits: Sequence[Any], kind: str, key: bytes) -> List[Dict[str, Any]]:
    """In-process hits an oracle proved AND whose key is the located key (no key bytes out)."""
    return [{"key_offset": hit.key_absolute_offset, "pattern_offset": hit.offset,
             "proven": hit.proven}
            for hit in hits if _synth_proves(hit.proven, hit.key_hex, kind, key)]


def _synth_rows_proven(rows: Sequence[Dict[str, Any]], kind: str,
                       key: Optional[bytes]) -> List[Dict[str, Any]]:
    """``vol`` JSON rows the oracle proved; when *key* is known only rows holding that key count.

    Without an expected key the oracle verdict is the proof: the row's key
    authenticated the vault sample taken from that image.
    """
    return [{"key_offset": int(row["KeyOffset"]), "pattern_offset": int(row["PatternOffset"]),
             "proven": row.get("Proven")}
            for row in rows if _synth_proves(row.get("Proven"), row.get("KeyHex"), kind, key)]


def _synth_verdict(target: str, path: Path, *, proven_hits: List[Dict[str, Any]],
                   rows: int, framework: Optional[Sequence[int]], display: Any,
                   sample_override: bool, error: Optional[str] = None,
                   error_code: Optional[str] = None,
                   matched_dump: Optional[int] = None) -> Dict[str, Any]:
    """One verdict; *display* (a ``VolSpec``) gives both ``vol_command`` and ``exec``."""
    status = SYNTH_ERROR if error else (SYNTH_PROVEN if proven_hits else SYNTH_NOT_PROVEN)
    return {"target": target, "dump_path": str(path), "name": path.name, "status": status,
            "proven": status == SYNTH_PROVEN, "proven_hits": proven_hits, "rows": rows,
            "framework_version": list(framework) if framework else None,
            "oracle_sample_override": sample_override,
            "vol_command": display.display_command(), "exec": display.exec_request(),
            "matched_dump_index": matched_dump, "error": error, "error_code": error_code}


def _synth_error_code(exc: BaseException) -> str:
    """A short code for a verify-boundary failure."""
    try:
        from volatility3.framework.exceptions import VolatilityException
    except ImportError:  # pragma: no cover - the extra is checked before any run
        VolatilityException = ()  # type: ignore[assignment,misc]
    if isinstance(exc, VolatilityException):
        return "synth.vol3_plugin.vol3_error"
    if isinstance(exc, CapabilityError):
        return exc.code or "synth.vol3_plugin.capability_error"
    return "synth.vol3_plugin.verify_failed"


def _synth_verify_msl(source_text: str, *, paths: Sequence[Path], keys: Sequence[bytes],
                      samples: Sequence[Optional[str]], kind: str,
                      formats: Sequence[Optional[str]],
                      key_file: Optional[str], kem_key_file: Optional[str],
                      command: Callable[[Path, Sequence[str]], Any],
                      steps: Optional["_SynthSteps"] = None) -> List[Dict[str, Any]]:
    """Target ``"msl"``: every supplied dump, in-process.

    Dump 0 is proven with the INLINED sample (what the plain ``vol_command``
    uses); a later dump with its own sample gets it as ``oracle_sample``.
    A failure of one dump is that dump's ``error`` verdict, never a raise --
    except a cancel (*steps*), which stops the whole synthesis.
    """
    steps = steps or _SynthSteps()
    verdicts = []
    for index, (path, key, sample, fmt) in enumerate(zip(paths, keys, samples, formats)):
        # Absolute, as the full-image attempts pass it: a relative "-x" path would read as a vol option.
        override = _synth_paths(sample)[0] if index and sample else None
        extra = ["--oracle-sample", override] if override else []
        dump_steps = steps.within(index / len(paths), (index + 1) / len(paths))
        label = f"verifying on dump {index + 1}/{len(paths)}: {_synth_dump_label(path)}"
        dump_steps.step(0.0, label)
        try:
            report = _synth_run_in_process(
                source_text, path, fmt=fmt,
                extra_config={"oracle_sample": override} if override else None,
                key_file=key_file, kem_key_file=kem_key_file,
                progress_callback=dump_steps.vol3_callback(label))
        except _SynthCancelled:
            raise
        except Exception as exc:  # the verify boundary: reported per dump, see docstring
            logger.warning("synthesized plugin failed on %s: %s", path.name, type(exc).__name__)
            verdicts.append(_synth_verdict(
                SYNTH_TARGET_MSL, path, proven_hits=[], rows=0, framework=None,
                display=command(path, extra), sample_override=bool(override),
                error=f"{type(exc).__name__}: {exc}"[:2000], error_code=_synth_error_code(exc)))
            continue
        verdicts.append(_synth_verdict(
            SYNTH_TARGET_MSL, path, proven_hits=_synth_proven_hits(report.hits, kind, key),
            rows=report.match_count, framework=report.framework_version,
            display=command(path, extra), sample_override=bool(override),
            matched_dump=index))
    return verdicts


#: The synthesized plugin's WARNING when ``--pid`` fell back to the physical
#: layer (no kernel symbols, or no such process): the rows then come from a
#: whole-image scan, so the ``--pid`` narrowing claim does not hold.
SYNTH_PID_UNHONOURED_MARK = "could NOT be honoured"
#: Its WARNING when a ``.msl`` slice of ANOTHER process was scanned anyway.
SYNTH_PID_MISMATCH_MARK = "this .msl slice holds pid"
SYNTH_PID_UNHONOURED_CODE = "synth.vol3_plugin.pid_not_honoured"
SYNTH_PID_MISMATCH_CODE = "synth.vol3_plugin.pid_mismatch"
SYNTH_IMAGE_ARGS_IGNORED_CODE = "synth.vol3_plugin.full_image_args_ignored"

#: Memory bounds on one full-image ``vol`` run: the JSON rows (a plugin caps
#: its rows, so a larger stdout is refused) and the stderr tail kept for the
#: plugin's warnings and error messages.
SYNTH_VOL_STDOUT_CAP = _VOL3_NAMED_STDOUT_CAP
SYNTH_VOL_STDERR_TAIL = 1024 * 1024

#: ``pid_scope`` states of one full-image attempt (see :func:`_synth_pid_scope`).
_PID_PROCESS, _PID_PHYSICAL, _PID_MSL, _PID_MSL_MISMATCH = (
    "process", "physical", "msl", "msl_mismatch")


def _synth_paths(value: Any) -> List[str]:
    """One path or a sequence of paths -> absolute path strings (``~`` expanded)."""
    if not value:
        return []
    items = [value] if isinstance(value, (str, Path)) else list(value)
    return [str(Path(item).expanduser().resolve()) for item in items]


def _synth_refuse_semicolon(paths: Sequence[Any], what: str) -> None:
    """vol splits ``-p`` / ``-s`` on ``;``: a path holding one would be split apart.

    Checked up front (not left to the run) so a surface refuses with this code inline.
    """
    from memdiver.engine.vol3_subproc import semicolon_paths

    bad = semicolon_paths(paths)
    if bad:
        raise _synth_invalid(f"{what} path(s) contain ';', which vol uses to separate "
                             f"-p / -s directories: {bad}", "semicolon_in_path")


def _synth_image_run(launcher: Any, display: Any, *, plugin_dirs: Sequence[Any], cache: str,
                     cancel: Optional[Callable[[], bool]] = None
                     ) -> Tuple[List[Dict[str, Any]], str]:
    """One full-image ``vol`` run of the verdict's *display* spec -> (rows, stderr tail).

    The run is the display with ``-q -r json``, the run's ``--cache-path``
    and the RESOLVED *plugin_dirs* (vol runs in the launcher's directory).
    The target is the recipe's own class name, not ``run_plugin``'s first
    class in the file (a recipe-v2 plugin declares helper classes first).
    Through ``vol3_subproc.run_vol``: memory bounded (stdout up to
    :data:`SYNTH_VOL_STDOUT_CAP`, the last :data:`SYNTH_VOL_STDERR_TAIL`
    bytes of stderr for the plugin's warnings), no ``__pycache__`` written,
    the whole process group killed on timeout or *cancel* (-> ``Cancelled``).
    Raises ``RuntimeError("vol exited <rc>: <stderr tail>")`` on a failure.
    """
    import dataclasses

    from memdiver.engine import vol3_subproc

    spec = dataclasses.replace(
        display, plugin_dirs=tuple(map(str, plugin_dirs)), cache_path=cache,
        renderer="json", quiet=True)
    run = vol3_subproc.run_vol(
        launcher, spec, timeout=VOL3_SUBPROC_TIMEOUT_S, cancel=cancel,
        stdout_cap=SYNTH_VOL_STDOUT_CAP, stderr_tail=SYNTH_VOL_STDERR_TAIL).raise_for_status()
    return run.rows, run.stderr_tail


def _synth_pid_scope(pid: Optional[int], rows: Sequence[Dict[str, Any]],
                     stderr: str) -> Optional[str]:
    """Where a ``--pid`` run really read its keys, or ``None`` (no pid / unknown).

    The rows' ``Scope`` column decides first (``process:<pid>`` /
    ``physical`` / ``msl:<pid>``); without it -- an older plugin, or no rows
    -- the plugin's own warnings on stderr do.
    """
    if pid is None:
        return None
    scopes = {str(row["Scope"]) for row in rows if row.get("Scope")}
    if scopes:
        if "physical" in scopes:
            return _PID_PHYSICAL
        slices = {s for s in scopes if s.startswith("msl:")}
        if slices:
            return _PID_MSL if slices == {f"msl:{int(pid)}"} else _PID_MSL_MISMATCH
        return _PID_PROCESS if scopes == {f"process:{int(pid)}"} else _PID_PHYSICAL
    if SYNTH_PID_UNHONOURED_MARK in stderr:
        return _PID_PHYSICAL
    if SYNTH_PID_MISMATCH_MARK in stderr:
        return _PID_MSL_MISMATCH
    return None


def _synth_scope_honoured(scope: Optional[str]) -> Optional[bool]:
    """``None`` for an unknown scope; False when the scan was not that process."""
    return None if scope is None else scope in (_PID_PROCESS, _PID_MSL)


def _synth_pid_honoured(pid: Optional[int], stderr: str,
                        rows: Sequence[Dict[str, Any]] = ()) -> Optional[bool]:
    """``None`` without ``--pid`` or when unknown; False when the scan was not that process."""
    return _synth_scope_honoured(_synth_pid_scope(pid, rows, stderr))


def _synth_merge_pid_scopes(scopes: Sequence[Optional[str]]) -> Optional[str]:
    """One verdict's scope over its attempts: any failure wins, else any success, else None."""
    for state in (_PID_MSL_MISMATCH, _PID_PHYSICAL, _PID_PROCESS, _PID_MSL):
        if state in scopes:
            return state
    return None


def _synth_verify_full_image(*, plugin_dir: Path, target: str, image: Path,
                             pid: Optional[int], keys: Sequence[bytes],
                             samples: Sequence[Optional[str]], kind: str, pkg_dir: str,
                             launcher: Any,
                             command: Callable[[Path, Sequence[str]], Any],
                             image_sample: Optional[str] = None,
                             image_key: Optional[bytes] = None,
                             steps: Optional["_SynthSteps"] = None) -> Dict[str, Any]:
    """Target ``"full_image"``: stock ``vol`` in a subprocess.

    The image may belong to any supplied dump's session, so each distinct
    (key, oracle sample) is tried -- the inlined sample first -- until one
    proves its own key. An image from ANOTHER session (a kernel image of a
    live system) brings its own *image_sample*, tried before all of them.
    *image_key* (ground truth), when given, filters EVERY attempt: only rows
    holding that key count; without it a row of the image-sample attempt
    counts when the oracle proves it. ``proven_by_image_sample`` says which
    attempt proved. *command* gives each attempt's display spec (with the
    symbol directories); the run is that spec (see :func:`_synth_image_run`).
    ``--pid`` and ``--oracle-sample`` follow the target. ``pid_honoured`` comes
    from the rows' ``Scope`` column, else the plugin's warnings: False when
    the scan was not that process (physical fallback, or a ``.msl`` slice of
    another pid), None when unknown or vol failed. Each attempt is bounded by
    ``VOL3_SUBPROC_TIMEOUT_S``, so the worst case is (dumps + 1) x timeout.
    vol writes no ``__pycache__`` into the plugin directory (``run_vol``).
    *steps* reports each attempt; its cancel kills the running vol and raises.
    """
    steps = steps or _SynthSteps()
    image, plugin_dir = image.resolve(), plugin_dir.resolve()  # vol runs in launcher.cwd
    pid_args = ["--pid", str(int(pid))] if pid is not None else []
    rows: List[Dict[str, Any]] = []
    args: List[str] = list(pid_args)
    scopes: List[Optional[str]] = []
    verdict: Optional[Dict[str, Any]] = None
    by_image_sample = False
    try:
        with tempfile.TemporaryDirectory(prefix="memdiver_vol3_cache_") as cache:
            attempts = _synth_image_attempts(keys, samples, image_sample, image_key)
            # Attempts that differ only in the expected key share one vol run: the
            # argv is the same, so its rows are re-filtered instead of re-scanned.
            runs: Dict[Tuple[str, ...], Tuple[List[Dict[str, Any]], str]] = {}
            for number, (index, key, oracle_args) in enumerate(attempts):
                args = pid_args + oracle_args
                if tuple(args) not in runs:
                    steps.within(number / len(attempts), (number + 1) / len(attempts)).step(
                        0.0, f"full-image vol run {number + 1}/{len(attempts)} over {image.name}")
                    runs[tuple(args)] = _synth_image_run(
                        launcher, command(image, args), plugin_dirs=(pkg_dir, plugin_dir),
                        cache=cache, cancel=steps.cancel)
                    scopes.append(_synth_pid_scope(pid, *runs[tuple(args)]))
                rows = runs[tuple(args)][0]
                proven = _synth_rows_proven(rows, kind, key)
                if proven:
                    by_image_sample = index is None
                    verdict = _synth_verdict(
                        SYNTH_TARGET_FULL_IMAGE, image, proven_hits=proven, rows=len(rows),
                        framework=None, display=command(image, args),
                        sample_override=bool(oracle_args), matched_dump=index)
                    break
    except _SynthCancelled:
        raise
    except Exception as exc:  # the verify boundary: an ``error`` verdict, never a raise
        scopes = []  # a crashed / timed-out run tells nothing about --pid
        verdict = _synth_verdict(SYNTH_TARGET_FULL_IMAGE, image, proven_hits=[], rows=0,
                                 framework=None, display=command(image, args),
                                 sample_override=False, error=str(exc)[:2000],
                                 error_code=_synth_error_code(exc))
    if verdict is None:
        verdict = _synth_verdict(SYNTH_TARGET_FULL_IMAGE, image, proven_hits=[], rows=len(rows),
                                 framework=None, display=command(image, pid_args),
                                 sample_override=False)
    scope = _synth_merge_pid_scopes(scopes)
    verdict["pid_scope"] = scope
    verdict["pid_honoured"] = _synth_scope_honoured(scope)
    verdict["image_sample"] = bool(image_sample)
    verdict["proven_by_image_sample"] = by_image_sample
    return verdict


def _synth_image_attempts(keys: Sequence[bytes], samples: Sequence[Optional[str]],
                          image_sample: Optional[str], image_key: Optional[bytes]
                          ) -> List[Tuple[Optional[int], Optional[bytes], List[str]]]:
    """The image's own sample (dump index None) first, then the dumps' (key, sample).

    With *image_key* every attempt expects that key (the image's ground
    truth), the dumps' attempts included. Sample paths are made absolute:
    vol runs in the launcher's directory.
    """
    attempts: List[Tuple[Optional[int], Optional[bytes], List[str]]] = []
    if image_sample:
        attempts.append((None, image_key, ["--oracle-sample", _synth_paths(image_sample)[0]]))
    seen = set()
    inlined = samples[0] if samples else None
    for index, (key, sample) in enumerate(zip(keys, samples)):
        # Dump 0's sample is inlined: passing the SAME sample again is no new attempt.
        override = sample if index and sample and sample != inlined else None
        if (key, override) in seen:  # one attempt per distinct (key, sample)
            continue
        seen.add((key, override))
        args = ["--oracle-sample", _synth_paths(override)[0]] if override else []
        attempts.append((index, key if image_key is None else image_key, args))
    return attempts


def _synth_build_recipe(paths: Sequence[Path], key_hexes: List[str], *, name: str,
                        oracle_kind: str, sample: Optional[str],
                        oracle_params: Optional[Mapping[str, Any]], context: int,
                        km: Dict[str, Any], allow_high_entropy_context: bool,
                        is_cancelled: Optional[Callable[[], bool]] = None,
                        opener: Optional[Callable[..., Any]] = None
                        ) -> Tuple[Any, Dict[str, Any]]:
    """The recipe from the located key; *opener* is the run's pool (``KeyedSources.opener``)."""
    from memdiver.architect import vol3_recipe as vr

    try:
        return vr.recipe_from_located_key(
            [str(p) for p in paths], key_hexes if len(set(key_hexes)) > 1 else key_hexes[0],
            oracle_kind=oracle_kind, oracle_sample_path=sample, oracle_params=oracle_params,
            context=context, name=name, key_material=km or None,
            allow_high_entropy_context=allow_high_entropy_context, is_cancelled=is_cancelled,
            opener=opener)
    except (vr.RecipeError, vr.UnimplementedLocatorError) as exc:
        raise _synth_error_from_recipe(exc) from exc


def _synth_emit(recipe: Any, extras: Dict[str, Any], plugin_dir: Path,
                steps: Optional["_SynthSteps"] = None) -> Any:
    """Write the plugin, then -- after a cancel check -- self-test it in-process.

    A self-test failure becomes ``self_test.error`` (``vr.emit``'s contract),
    never a raise; a cancel between write and self-test raises.
    """
    from memdiver.architect import vol3_recipe as vr

    steps = steps or _SynthSteps()
    try:
        with _synth_vol3_isolation():
            return vr.emit(recipe, extras["reference_data"], plugin_dir,
                           expected_offset=extras["expected_offset"],
                           before_self_test=steps.check)
    except (vr.RecipeError, vr.UnimplementedLocatorError) as exc:
        raise _synth_error_from_recipe(exc) from exc


def _synth_emit_and_store(recipe: Any, extras: Dict[str, Any], case_dir: Optional[str],
                          steps: Optional["_SynthSteps"] = None
                          ) -> Tuple[Any, Optional[Dict[str, Any]], Path, List[str]]:
    """Emit (+ self-test); with a case, store it and point everything at the store.

    Without a case the emission directory is a fresh temporary directory that
    is KEPT on success (it is the ``plugin_dir`` of the returned
    ``vol_command``) and removed when emission fails.
    """
    import shutil

    if not case_dir:
        plugin_dir = Path(tempfile.mkdtemp(prefix="memdiver_vol3_synth_"))
        try:
            emitted = _synth_emit(recipe, extras, plugin_dir, steps)
        except BaseException:
            shutil.rmtree(plugin_dir, ignore_errors=True)
            raise
        files = [emitted.path, emitted.path.with_name(f"{emitted.path.stem}.recipe.json"),
                 emitted.yara_path]
        return emitted, None, plugin_dir, [str(p) for p in files if p is not None]
    with tempfile.TemporaryDirectory(prefix="memdiver_vol3_synth_") as scratch:
        emitted = _synth_emit(recipe, extras, Path(scratch), steps)
        # Read before the scratch directory goes: the no-case path keeps this sidecar too.
        yara_text = (emitted.yara_path.read_text(encoding="utf-8")
                     if emitted.yara_path is not None else None)
    stored = _synth_store(case_dir, recipe, emitted.source, yara_text)
    files = [stored["path"], stored["recipe_path"], stored["yara_path"]]
    return (emitted, stored, Path(stored["path"]).parent, [f for f in files if f])


def _synth_diagnostics(*, recipe_diags: Sequence[Dict[str, Any]],
                       verdicts: Sequence[Dict[str, Any]], passphrase_unforwarded: bool,
                       stored: Optional[Dict[str, Any]], plugin_dir: Path
                       ) -> List[Dict[str, Any]]:
    diagnostics = [dict(d) for d in recipe_diags]
    failed = [v["name"] for v in verdicts if not v["proven"]]
    if not verdicts:
        diagnostics.append(Diagnostic(
            SYNTH_NOT_VERIFIED_CODE,
            "no verify target ran (verify_on=() and no full_image), so proven is False: "
            "the plugin was emitted and self-tested but not run on any capture").to_dict())
    if failed:
        diagnostics.append(Diagnostic(
            SYNTH_NOT_PROVEN_CODE,
            f"the emitted plugin did not prove the located key on {len(failed)} "
            f"target(s): {', '.join(failed)}",
            details={"targets": failed}).to_dict())
    if stored is not None and (failed or not verdicts):
        diagnostics.append(Diagnostic(
            SYNTH_STORED_UNPROVEN_CODE,
            f"the plugin was stored in the case at {stored['path']} although it is not "
            f"proven on every target", details={"path": stored["path"]}).to_dict())
    if passphrase_unforwarded:
        diagnostics.append(Diagnostic(
            SYNTH_PASSPHRASE_LAYER_CODE,
            "a passphrase / pre-decoded key material was used to LOCATE the key, but "
            "the in-process vol3 layer takes key files only; set "
            "MEMDIVER_MSL_PASSPHRASE for the layer (stock vol reads it too)").to_dict())
    if stored is None:
        diagnostics.append(Diagnostic(
            SYNTH_UNSTORED_CODE,
            f"no case_dir: the plugin was written to the temporary directory {plugin_dir}, "
            f"which is kept; pass case_dir to keep it in the case",
            Severity.INFO, details={"plugin_dir": str(plugin_dir)}).to_dict())
    return diagnostics


def _synth_key_hexes(key_hex: Any, hit: Optional[Mapping[str, Any]],
                     count: int) -> Optional[List[str]]:
    """One normalised key per dump, checked without touching a dump.

    A hit's key is broadcast to every dump. ``None`` for a hit at an offset:
    its SHAPE is checked here, its bytes are read later from a dump
    (:func:`_synth_key_from_hit`).
    """
    if bool(key_hex) == (hit is not None):
        raise _synth_invalid("pass exactly ONE of key_hex= or hit=", "key_form")
    if hit is not None and not hit.get("key_hex"):
        _synth_hit_range(hit)
        return None
    return _synth_keys_per_dump(str(hit["key_hex"]) if hit is not None else key_hex, count)


def _synth_keys_per_dump(raw: Any, count: int) -> List[str]:
    """*raw* (one key, or one per dump) as one normalised key hex per dump."""
    return [_synth_parse_key(k, i)
            for i, k in enumerate(_synth_per_dump(raw, count, "keys"))]


def _synth_samples(oracle_sample_path: Any, count: int) -> List[Optional[str]]:
    """One oracle sample path per dump (``~`` expanded); a missing one is a 404."""
    samples = [None if s is None else str(Path(s).expanduser())
               for s in _synth_per_dump(oracle_sample_path, count, "oracle samples")]
    missing = [s for s in samples if s and not Path(s).exists()]
    if missing:
        raise FileNotFoundServiceError(f"Oracle sample not found: {', '.join(missing)}")
    return samples


def _synth_launcher(full_image: Optional[str], vol_bin: Optional[str],
                    vol_python: Optional[str]) -> Any:
    if not full_image:
        return None
    from memdiver.app.tools_vol3_dev import require_launcher

    launcher = require_launcher(vol_bin, vol_python, purpose="full_image verification",
                                code="synth.vol3_plugin.no_launcher")
    if not Path(full_image).expanduser().exists():
        raise FileNotFoundServiceError(f"File not found: {full_image}")
    return launcher


def _synth_image_evidence(sample: Any, key_hex: str
                          ) -> Tuple[Optional[str], Optional[bytes]]:
    """The full image's own (absolute sample path, expected key); the key is never echoed."""
    path = None
    if sample:
        resolved = Path(sample).expanduser().resolve()
        if not resolved.exists():
            raise FileNotFoundServiceError(f"File not found: {sample}")
        path = str(resolved)
    if not key_hex:
        return path, None
    try:
        return path, _needle_from_key_hex(str(key_hex))
    except CapabilityError:
        raise _synth_invalid(f"full_image_key_hex is not valid hex {_synth_redacted(key_hex)}",
                             "invalid_key") from None


def _synth_pid_diagnostics(verdicts: Sequence[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """A warning per verdict whose ``--pid`` scan was not that process."""
    diagnostics = []
    for v in verdicts:
        if v.get("pid_honoured") is not False:
            continue
        if v.get("pid_scope") == _PID_MSL_MISMATCH:
            diagnostics.append(Diagnostic(
                SYNTH_PID_MISMATCH_CODE,
                f"--pid does not match {v['name']}: the .msl slice holds another process, "
                f"which was scanned anyway", Severity.WARNING,
                details={"target": v["dump_path"]}).to_dict())
            continue
        diagnostics.append(Diagnostic(
            SYNTH_PID_UNHONOURED_CODE,
            f"--pid was NOT honoured on {v['name']}: the plugin found no kernel (missing "
            f"symbols? pass symbol_dirs) or no such process, and scanned the whole physical "
            f"layer instead", Severity.WARNING, details={"target": v["dump_path"]}).to_dict())
    return diagnostics


def _synth_image_args_diagnostics(full_image: Optional[str], full_image_sample: Any,
                                  full_image_key_hex: str) -> List[Dict[str, Any]]:
    """A warning when image-only arguments are passed without ``full_image``."""
    given = [name for name, value in (("full_image_sample", full_image_sample),
                                      ("full_image_key_hex", full_image_key_hex)) if value]
    if full_image or not given:
        return []
    return [Diagnostic(
        SYNTH_IMAGE_ARGS_IGNORED_CODE,
        f"{' and '.join(given)} given without full_image: ignored", Severity.WARNING,
        details={"arguments": given}).to_dict()]


class _SynthInputs(NamedTuple):
    """The checked, resolved inputs of one synthesis (see :func:`_synth_inputs`)."""

    paths: List[Path]
    km: Dict[str, Any]
    launcher: Any
    image_sample: Optional[str]
    image_key: Optional[bytes]
    image_symbol_dirs: List[str]
    key_hexes: Optional[List[str]]
    samples: List[Optional[str]]
    formats: List[Optional[str]]
    sources: Optional[KeyedSources]


def _synth_inputs(*, dump_paths: Sequence[str], key_hex: Any = "",
                  hit: Optional[Mapping[str, Any]] = None, oracle_kind: str,
                  oracle_sample_path: Any = None, case_dir: Optional[str] = None,
                  verify_on: Sequence[str] = SYNTH_VERIFY_TARGETS,
                  full_image: Optional[str] = None, vol_bin: Optional[str] = None,
                  vol_python: Optional[str] = None, key_file: Optional[str] = None,
                  passphrase: Optional[str] = None, kem_key_file: Optional[str] = None,
                  key_material: Optional[Dict[str, Any]] = None,
                  on_source: Optional[Callable[[Any], None]] = None,
                  full_image_sample: Any = None, full_image_key_hex: str = "",
                  symbol_dirs: Any = (), steps: Optional[_SynthSteps] = None,
                  run: Optional[ExitStack] = None) -> _SynthInputs:
    """Every check of a synthesis before the build, in the producer's order; the resolved inputs.

    The refusals :func:`synthesize_vol3_plugin` raises before it builds a
    recipe -- and, with *run* ``None``, what :func:`preflight_synthesize_vol3_plugin`
    (a surface submitting a background job) refuses up front with the same
    code. The checks that need no dump run FIRST (launcher, image evidence,
    ``;`` in paths, the key form and hex, a hit's shape, the per-dump list
    lengths, the oracle samples), so a typo never costs a dump open.

    Then the dumps. With *run* (the synthesis' scope) each is opened ONCE,
    into a :class:`KeyedSources` entered on *run* (``sources`` of the result:
    the build reads the same open sources), lock-guarded, and a hit at an
    offset is read. Without *run* nothing is opened: an ``.msl``'s key is
    probed on block 0 and the hit is not read (``key_hexes`` stays ``None``).
    *steps* is checked once per dump.
    """
    steps = steps or _SynthSteps()
    paths = [Path(p).expanduser() for p in dump_paths]
    if not paths:
        raise _synth_invalid("need at least one dump", "no_dumps")
    unknown = [t for t in verify_on if t not in SYNTH_VERIFY_TARGETS]
    if unknown:
        raise _synth_invalid(f"unknown verify target(s) {unknown}; known: "
                             f"{list(SYNTH_VERIFY_TARGETS)}", "unknown_target")
    _synth_oracle_module(oracle_kind)
    if case_dir and not Path(case_dir).expanduser().is_dir():
        raise FileNotFoundServiceError(f"Case directory not found: {case_dir}")
    km = _resolve_key_material(key_material, key_file, passphrase, kem_key_file)
    launcher = _synth_launcher(full_image, vol_bin, vol_python)
    image_sample, image_key = _synth_image_evidence(full_image_sample, full_image_key_hex)
    image_symbol_dirs = _synth_paths(symbol_dirs)  # vol's -s; absolute (vol runs elsewhere)
    _synth_refuse_semicolon([case_dir, *image_symbol_dirs], "case_dir / symbol_dirs")
    _synth_refuse_semicolon([vol3_plugin_dir()["path"]], "vol3plugins")
    key_hexes = _synth_key_hexes(key_hex, hit, len(paths))
    samples = _synth_samples(oracle_sample_path, len(paths))
    sources = None if run is None else run.enter_context(KeyedSources(km))
    formats = _synth_guard_dumps(paths, km, on_source, steps, sources=sources,
                                 probe=sources is None)
    hit_dump = _synth_hit_dump(hit, paths) if key_hexes is None else None
    if hit_dump is not None:  # the same 404 / locked guard for a hit's own dump
        _synth_guard_dumps([hit_dump], km, None, steps, sources=sources, probe=sources is None)
    if key_hexes is None and sources is not None and hit is not None:
        key_hexes = _synth_keys_per_dump(_synth_key_from_hit(hit, dump_paths, sources),
                                         len(paths))
    return _SynthInputs(paths, km, launcher, image_sample, image_key, image_symbol_dirs,
                        key_hexes, samples, formats, sources)


def preflight_synthesize_vol3_plugin(**kwargs: Any) -> None:
    """Raise what :func:`synthesize_vol3_plugin` would refuse with up front, else nothing.

    Takes the producer's keyword arguments (those the checks do not use are
    ignored). For a surface that runs the synthesis as a background job: the
    caller gets the same 4xx code inline instead of a queued job failing later.

    Runs on the request thread, so it opens NO dump: every check of
    :func:`_synth_inputs` but the dumps' is the inline one; a dump is
    checked for existence and an encrypted ``.msl``'s key probed on block 0
    (one key derivation, no full AEAD pass). Contract (inline / job):

    ====================  ===============================  ==================================
    fault                 inline                           job (this preflight)
    ====================  ===============================  ==================================
    missing dump          404                              404
    encrypted, no key     400 encrypted_dump_locked        400 encrypted_dump_locked
    wrong key             400 encrypted_dump_locked        400 encrypted_dump_locked
    tampered ciphertext   400 encrypted_dump_locked        202; the job fails with that code
    hit outside its dump  400 synth.vol3_plugin.bad_hit    202; the job fails with that code
    ====================  ===============================  ==================================

    A job's failure carries the refusal's ``code`` / ``category`` on its
    ``error`` event (``app.pipeline.vol3_synth_task_runner``).
    """
    import inspect

    known = inspect.signature(_synth_inputs).parameters
    _synth_inputs(**{k: v for k, v in kwargs.items()
                     if k in known and k not in ("steps", "run")})


def synthesize_vol3_plugin(
    *,
    dump_paths: Sequence[str],
    name: str,
    key_hex: Any = "",
    hit: Optional[Mapping[str, Any]] = None,
    oracle_kind: str,
    oracle_sample_path: Any = None,
    oracle_params: Optional[Mapping[str, Any]] = None,
    context: int = SYNTH_DEFAULT_CONTEXT,
    case_dir: Optional[str] = None,
    verify_on: Sequence[str] = SYNTH_VERIFY_TARGETS,
    full_image: Optional[str] = None,
    pid: Optional[int] = None,
    vol_bin: Optional[str] = None,
    vol_python: Optional[str] = None,
    key_file: Optional[str] = None,
    passphrase: Optional[str] = None,
    kem_key_file: Optional[str] = None,
    key_material: Optional[Dict[str, Any]] = None,
    allow_high_entropy_context: bool = False,
    on_source: Optional[Callable[[Any], None]] = None,
    full_image_sample: Any = None,
    full_image_key_hex: str = "",
    symbol_dirs: Any = (),
    is_cancelled: Optional[Callable[[], bool]] = None,
    on_progress: Optional[Callable[[float, str], None]] = None,
) -> Dict[str, Any]:
    """A key located in N dumps -> a standalone Volatility 3 plugin, verified.

    The single implementation behind "Export as Volatility 3 plugin". Flow:
    locate the key and build a recipe (``architect.vol3_recipe
    .recipe_from_located_key``), emit the plugin with the oracle source
    inlined and self-test it, store it in the case, then RUN it on every
    verify target and read its ``Proven`` column.

    Args:
        dump_paths: The captures holding the key (``.msl`` or raw).
        name: Plugin name (a Python identifier); the file is ``<name>.py``.
        key_hex: One key for every dump, or one key per dump (several runs of
            one program, each with its own key). Exclusive with *hit*.
        hit: A located key, broadcast to every dump: ``{"key_hex"}`` or
            ``{"offset", "length"}`` plus an optional ``"dump_path"`` /
            ``"view"`` (bytes are read from the dump).
        oracle_kind: A ``memdiver.oracles`` format; it alone decides ``Proven``.
        oracle_sample_path: The oracle evidence (e.g. a gocryptfs cipher dir),
            one for every dump or one per dump. The FIRST is inlined in the
            plugin; a later dump's own sample is passed as ``oracle_sample``.
            *oracle_params* are inlined in the recipe and need no override.
        context: Bytes either side of the key the anchor is measured over.
        case_dir: An existing case; the plugin + ``.recipe.json`` go to
            ``<case>/vol3/plugins`` (replaced versions to ``<case>/vol3/history``).
        verify_on: Verify targets (:data:`SYNTH_VERIFY_TARGETS`); ``()`` skips.
        full_image / pid: Also run the plugin under the stock ``vol`` launcher
            (*vol_bin* / *vol_python*) over a full memory image, ``--pid pid``.
            Each supplied dump's (key, sample) is tried until one proves.
        key_file / passphrase / kem_key_file / key_material: Decryption
            material for encrypted ``.msl`` containers.
        allow_high_entropy_context: Accept a high-entropy static run beside the
            key (see ``architect.vol3_recipe``) when only one key is seen.
        on_source: Called with each opened dump source, after the lock guard.
        full_image_sample: The full image's OWN oracle evidence (e.g. the vault
            recovered from that image's page cache), for an image of another
            session than every dump; tried first as ``--oracle-sample``. Its
            rows prove by the oracle alone unless *full_image_key_hex* (ground
            truth, never echoed) is given: that key then filters EVERY attempt
            (image sample and dumps' samples alike). Both are ignored, with a
            warning diagnostic, without *full_image*.
        symbol_dirs: ISF directory or directories for *full_image* (``-s ... --offline``,
            also in the verdict's ``vol_command``); without them vol uses its
            own lookup, and a plugin that cannot find the kernel ignores
            ``--pid`` -- reported as ``pid_honoured: False`` + a warning.
        is_cancelled / on_progress: For a background job. ``is_cancelled()`` is checked
            between steps, per chunk of an in-process scan and every
            ``vol3_subproc.CANCEL_POLL_S`` of a full-image ``vol`` run (whose
            process group is then killed); true raises
            ``engine.progress.Cancelled``, and a plugin emitted without a case
            is removed. ``on_progress(fraction, message)`` gets the overall
            fraction ``[0, 1]`` and a phase message (names, never key material).
            Both default to ``None``: no checks, no reports, behaviour unchanged.

    Returns:
        ``{source, recipe, oracle, self_test, verdicts, proven, proven_hits,
        export_files, stored, vol_command, plugin_dir, diagnostics}``. A
        ``full_image`` verdict also carries ``pid_honoured`` (None without
        *pid* or when unknown), ``pid_scope`` (process | physical | msl |
        msl_mismatch | None), ``image_sample`` (its own sample was supplied)
        and ``proven_by_image_sample`` (that sample's attempt proved).
        ``proven`` is True iff at least one target ran and every target proved
        the located key. The key never reaches disk, the result or an error
        message: the recipe keeps its sha256 only.

    Raises:
        CapabilityError: bad input (no dumps, both / neither key form, invalid
            key hex -- redacted --, unknown oracle or verify target, mismatched
            per-dump lists), the key absent from every dump (NOT_FOUND), an
            anchor refused by the recipe guards (PRECONDITION), no ``vol``
            launcher for *full_image* (UNSUPPORTED).
        FileNotFoundServiceError: a dump, the case or the full image does not exist.
        EncryptedDumpLockedError: an encrypted dump without its key.
        engine.progress.Cancelled: *is_cancelled* turned true.
    """
    steps = _SynthSteps(is_cancelled, on_progress)
    # The run's dump pool: each encrypted dump is decrypted ONCE for the guard,
    # a hit read and the recipe build, and closed before emit / verify (the
    # verify opens its own; a full-image run takes minutes).
    with ExitStack() as run:
        inputs = _synth_inputs(
            dump_paths=dump_paths, key_hex=key_hex, hit=hit, oracle_kind=oracle_kind,
            oracle_sample_path=oracle_sample_path, case_dir=case_dir, verify_on=verify_on,
            full_image=full_image, vol_bin=vol_bin, vol_python=vol_python, key_file=key_file,
            passphrase=passphrase, kem_key_file=kem_key_file, key_material=key_material,
            on_source=on_source, full_image_sample=full_image_sample,
            full_image_key_hex=full_image_key_hex, symbol_dirs=symbol_dirs, steps=steps,
            run=run)
        (paths, km, launcher, image_sample, image_key, image_symbol_dirs, key_hexes, samples,
         formats, sources) = inputs
        # With *run* the inputs always carry the pool and every dump's key (a hit is read).
        if sources is None or key_hexes is None:  # narrows the types; cannot happen on this path
            raise RuntimeError("synthesis inputs lack the keyed sources or key hexes")
        steps.step(0.0, "locating the key and building the recipe")
        recipe, extras = _synth_build_recipe(
            paths, key_hexes, name=name, oracle_kind=oracle_kind, sample=samples[0],
            oracle_params=oracle_params, context=context, km=km,
            allow_high_entropy_context=allow_high_entropy_context, is_cancelled=steps.cancel,
            opener=sources.opener)
    steps.step(_SYNTH_EMIT_AT, "emitting and self-testing the plugin")
    emitted, stored, plugin_dir, export_files = _synth_emit_and_store(
        recipe, extras, case_dir, steps)
    target = f"{recipe.name}.{recipe.class_name}"
    pkg_dir = vol3_plugin_dir()["path"]
    _synth_refuse_semicolon([pkg_dir, plugin_dir], "vol3plugins / plugin directory")

    def command(dump: Path, extra: Sequence[str], symbol_dirs: Sequence[str] = ()) -> Any:
        return _synth_display_spec(pkg_dir, plugin_dir, target, dump, extra, symbol_dirs)

    keys = [bytes.fromhex(k) for k in key_hexes]
    verdicts: List[Dict[str, Any]] = []
    msl_span, image_span = _synth_spans(SYNTH_TARGET_MSL in verify_on, bool(full_image))
    try:
        if SYNTH_TARGET_MSL in verify_on:
            verdicts += _synth_verify_msl(
                emitted.source, paths=paths, keys=keys, samples=samples, kind=oracle_kind,
                formats=formats, key_file=key_file, kem_key_file=kem_key_file, command=command,
                steps=steps.within(*msl_span))
        if full_image:
            verdicts.append(_synth_verify_full_image(
                plugin_dir=plugin_dir, target=target, image=Path(full_image).expanduser(),
                pid=pid, keys=keys, samples=samples, kind=oracle_kind, pkg_dir=pkg_dir,
                launcher=launcher,
                command=lambda dump, extra: command(dump, extra, image_symbol_dirs),
                image_sample=image_sample, image_key=image_key,
                steps=steps.within(*image_span)))
    except _SynthCancelled:
        if stored is None:  # the kept temporary emission dir: nobody will get its path
            import shutil

            shutil.rmtree(plugin_dir, ignore_errors=True)
        raise
    return {
        "source": emitted.source,
        "recipe": recipe.to_dict(),
        "oracle": _synth_oracle_summary(recipe),
        "self_test": emitted.self_test.to_dict() if emitted.self_test else None,
        "verdicts": verdicts,
        "proven": bool(verdicts) and all(v["proven"] for v in verdicts),
        "proven_hits": sum(len(v["proven_hits"]) for v in verdicts),
        "export_files": export_files,
        "stored": stored,
        # The command of the first PROVEN verdict (the one a user should re-run), else the
        # first dump's: with several targets the first .msl is not always the proven one.
        "vol_command": next((v["vol_command"] for v in verdicts if v["proven"]),
                            command(paths[0], ()).display_command()),
        "plugin_dir": str(plugin_dir),
        "diagnostics": _synth_diagnostics(
            recipe_diags=list(extras["diagnostics"]) + list(emitted.diagnostics),
            verdicts=verdicts,
            passphrase_unforwarded=bool((passphrase or key_material) and not key_file
                                        and not kem_key_file),
            stored=stored, plugin_dir=plugin_dir) + _synth_pid_diagnostics(verdicts)
        + _synth_image_args_diagnostics(full_image, full_image_sample, full_image_key_hex),
    }

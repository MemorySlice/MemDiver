"""End-to-end experiment orchestration.

Owns the full experiment once: spawn target -> dump N x per tool -> consensus
-> decryption-verify -> emit plugin. Extracted verbatim from ``tools_pipeline``
(P3.1); the public :func:`experiment_result` is the single implementation
behind the CLI ``experiment`` command, the API experiment task runner, and the
MCP ``experiment`` tool.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Callable, Dict, Optional, Sequence

import numpy as np

from memdiver.core.install_hints import (CAPTURE_BACKEND_HINT,
                                        missing_package_message)
from memdiver.core.service_errors import (
    CapabilityError,
    ErrorCategory,
    FileNotFoundServiceError,
)

from ._progress import _emit, _experiment_check_cancelled


def _experiment_capture(
    orch: Any,
    target_path: Path,
    num_runs: int,
    output_dir: Path,
    on_progress: Optional[Callable[..., None]],
) -> Any:
    """Run the orchestrator, streaming a bracketing ``capture`` stage."""
    _emit(
        on_progress, "stage_start", stage="capture", pct=0.0,
        msg=f"capturing {num_runs} runs across {len(orch.available_tools)} tools",
    )
    exp = orch.run_experiment(target_path, num_runs, output_dir)
    dump_summary: Dict[str, int] = {}
    for tool_name, tool_dir in exp.tool_dirs.items():
        dumps = sorted(list(Path(tool_dir).glob("*/*.dump"))
                       + list(Path(tool_dir).glob("*/*.msl")))
        dump_summary[tool_name] = len(dumps)
        _emit(
            on_progress, "progress", stage="capture", pct=1.0,
            msg=f"{tool_name}: {len(dumps)} dumps",
            extra={"tool": tool_name, "dumps": len(dumps)},
        )
    _emit(
        on_progress, "stage_end", stage="capture", pct=1.0,
        msg=f"captured {sum(dump_summary.values())} dumps total",
        extra={"dumps_per_tool": dump_summary},
    )
    return exp


def _experiment_consensus_phase(
    tool_dirs: Dict[str, Any],
    key_material: Optional[Dict[str, Any]],
    on_source: Optional[Callable[[Any], None]],
    on_progress: Optional[Callable[..., None]],
) -> Dict[str, Dict[str, Any]]:
    """Fold each tool's dumps into a MEMORY-relative consensus vector.

    Uses :func:`engine.consensus_service.build_consensus` (the ``open_dump``
    projection) — NOT the raw-bytes ``ConsensusVector.build`` the API runner
    used to call — so downstream offsets stay in the projection space (A5).
    """
    from memdiver.engine.consensus_service import build_consensus

    tools = list(tool_dirs.items())
    _emit(on_progress, "stage_start", stage="consensus", pct=0.0,
          msg=f"folding consensus for {len(tools)} tools")
    per_tool: Dict[str, Dict[str, Any]] = {}
    for idx, (tool_name, tool_dir) in enumerate(tools):
        pct = (idx + 1) / max(len(tools), 1)
        dumps = sorted(list(Path(tool_dir).glob("*/*.dump"))
                       + list(Path(tool_dir).glob("*/*.msl")))
        if len(dumps) < 2:
            _emit(on_progress, "progress", stage="consensus", pct=pct,
                  msg=f"{tool_name}: not enough dumps ({len(dumps)}); skipping",
                  extra={"tool": tool_name, "skipped": True})
            continue
        cm = build_consensus(
            dumps, key_material=key_material or {}, on_source=on_source
        )
        aligned = cm.get_aligned_candidates()
        volatile = cm.get_volatile_regions()
        per_tool[tool_name] = {
            "consensus": cm, "dump_paths": dumps,
            "aligned": aligned, "volatile": volatile,
        }
        _emit(on_progress, "progress", stage="consensus", pct=pct,
              msg=f"{tool_name}: {len(aligned)} aligned, {len(volatile)} volatile regions",
              extra={"tool": tool_name, "aligned_regions": len(aligned),
                     "volatile_regions": len(volatile), "num_dumps": len(dumps)})
    _emit(on_progress, "stage_end", stage="consensus", pct=1.0,
          msg=f"consensus ready for {len(per_tool)} tools",
          extra={"tools": list(per_tool.keys())})
    return per_tool


def _experiment_scan_for_key(verify: Callable, aligned: Sequence[Any],
                             reference: bytes, ciphertext: bytes) -> bool:
    """Byte-by-byte AES-CBC scan of the aligned regions for a matching key."""
    from memdiver.engine.verification import (
        HAS_CRYPTO,
        VERIFICATION_IV,
        VERIFICATION_PLAINTEXT,
    )

    if not HAS_CRYPTO:
        return False
    for region in aligned:
        for off in range(region.start, region.end - 31):
            if verify(reference[off:off + 32], ciphertext,
                      VERIFICATION_IV, VERIFICATION_PLAINTEXT):
                return True
    return False


def _experiment_render_plugin(pattern: Any, export_format: str) -> Optional[str]:
    if export_format in ("volatility3", "vol3"):
        from memdiver.architect.volatility3_exporter import Volatility3Exporter
        from memdiver.architect.yara_exporter import YaraExporter
        return Volatility3Exporter.export(
            pattern, yara_rule=YaraExporter.export(pattern))
    if export_format == "yara":
        from memdiver.architect.yara_exporter import YaraExporter
        return YaraExporter.export(pattern)
    return None


def _experiment_emit_plugin(cm: Any, volatile: Sequence[Any], tool_name: str,
                            output_dir: Path, export_format: str) -> Optional[Path]:
    """Emit a plugin from the largest volatile region's MEMORY-relative slab.

    The static mask is derived from the consensus variance (a byte is static
    iff its variance is 0) rather than re-reading raw file bytes — the A5 fix
    the CLI already carried, now shared with the API runner.
    """
    if not volatile:
        return None
    from memdiver.architect.pattern_generator import PatternGenerator

    best = max(volatile, key=lambda r: r.end - r.start)
    ctx_pad = 32
    exp_offset = max(0, best.start - ctx_pad)
    exp_end = min(cm.size, best.end + ctx_pad)
    reference = cm.reference_bytes[exp_offset:exp_end]
    var_slice = cm.variance[exp_offset:exp_end]
    if isinstance(var_slice, np.ndarray):
        static_mask = (var_slice == 0.0).tolist()
    else:
        static_mask = [v == 0.0 for v in var_slice]
    if not reference:
        return None
    pattern = PatternGenerator.generate(
        reference, static_mask, f"{tool_name}_aes256_key")
    if not pattern:
        return None
    plugin_content = _experiment_render_plugin(pattern, export_format)
    if not plugin_content:
        return None
    plugins_dir = Path(output_dir) / "plugins"
    plugins_dir.mkdir(parents=True, exist_ok=True)
    ext = ".py" if export_format in ("volatility3", "vol3") else ".yar"
    plugin_path = plugins_dir / f"{tool_name}_aes256_key{ext}"
    plugin_path.write_text(plugin_content)
    return plugin_path


def _experiment_verify_phase(
    per_tool: Dict[str, Dict[str, Any]],
    metadata: Dict[str, Any],
    output_dir: Path,
    export_format: str,
    convergence: bool,
    max_fp: int,
    on_progress: Optional[Callable[..., None]],
) -> Dict[str, Dict[str, Any]]:
    """Run decryption verification + plugin emission per tool."""
    from memdiver.engine.verification import (
        AesCbcVerifier,
        VERIFICATION_IV,
        VERIFICATION_PLAINTEXT,
    )

    verifier = AesCbcVerifier()
    verify = verifier.verify
    tools = list(per_tool.items())
    _emit(on_progress, "stage_start", stage="verify", pct=0.0,
          msg=f"verifying {len(tools)} tools")
    first_key = bytes.fromhex(metadata["runs"][0]["key_hex"])
    ciphertext = verifier.create_ciphertext(
        first_key, VERIFICATION_PLAINTEXT, VERIFICATION_IV)

    results: Dict[str, Dict[str, Any]] = {}
    for idx, (tool_name, info) in enumerate(tools):
        cm, dumps = info["consensus"], info["dump_paths"]
        aligned, volatile = info["aligned"], info["volatile"]
        dec_verified = _experiment_scan_for_key(
            verify, aligned, cm.reference_bytes, ciphertext)
        plugin_path = _experiment_emit_plugin(
            cm, volatile, tool_name, output_dir, export_format)
        tool_result: Dict[str, Any] = {
            "tool": tool_name,
            "format": "MSL (.msl)" if tool_name == "memslicer" else "Raw (.dump)",
            "num_dumps": len(dumps),
            "volatile_regions": len(volatile),
            "aligned_regions": len(aligned),
            "decryption_verified": dec_verified,
            "plugin_saved": str(plugin_path) if plugin_path else None,
        }
        if convergence:
            from memdiver.engine.convergence import run_convergence_sweep
            from memdiver.engine.serializer import serialize_convergence_result
            sweep = run_convergence_sweep(dumps, max_fp=max_fp)
            tool_result["convergence"] = serialize_convergence_result(sweep)
        results[tool_name] = tool_result
        _emit(on_progress, "progress", stage="verify",
              pct=(idx + 1) / max(len(tools), 1),
              msg=f"{tool_name}: decryption "
                  f"{'verified' if dec_verified else 'not verified'}",
              extra=tool_result)
    _emit(on_progress, "stage_end", stage="verify", pct=1.0,
          msg=f"verified {len(results)} tools",
          extra={"tool_results": results})
    return results


def experiment_result(
    *,
    target: str,
    output_dir: str,
    num_runs: int = 10,
    tools: Optional[Sequence[str]] = None,
    export_format: str = "volatility3",
    convergence: bool = False,
    max_fp: int = 0,
    key_material: Optional[Dict[str, Any]] = None,
    on_source: Optional[Callable[[Any], None]] = None,
    on_progress: Optional[Callable[..., None]] = None,
    is_cancelled: Optional[Callable[[], bool]] = None,
) -> Dict[str, Any]:
    """Own the full experiment once: spawn -> dump N x per tool -> consensus ->
    decryption-verify -> emit plugin.

    The single implementation behind the CLI ``experiment`` command, the API
    experiment task runner, and the MCP ``experiment`` tool — replacing the two
    forked copies (the CLI's memory-relative analysis and the API runner's
    raw-bytes analysis). The MEMORY-relative consensus is used uniformly, so
    the API surface inherits the A5 offset fix.

    Progress streams through the optional ``on_progress(event, **fields)`` sink
    (the API passes ``ctx.emit``); ``is_cancelled`` is polled between stages.
    A missing/unusable backend raises ``CapabilityError`` with
    ``code="missing_backend"`` so a surface can degrade gracefully; a missing
    target raises ``FileNotFoundServiceError``.
    """
    try:
        from memdiver.core.dump_driver import DumpOrchestrator
    except ImportError as exc:  # pragma: no cover - environmental
        raise CapabilityError(
            f"experiment backend unavailable: {exc}. "
            + missing_package_message("The dump-driver backend"),
            category=ErrorCategory.UNSUPPORTED, code="missing_backend",
        ) from exc

    target_path = Path(target).expanduser()
    if not target_path.is_file():
        _emit(on_progress, "error", error=f"target not found: {target_path}")
        raise FileNotFoundServiceError(f"target not found: {target_path}")

    tools_list = list(tools) if tools else None
    try:
        orch = DumpOrchestrator(tools=tools_list)
    except Exception as exc:  # pragma: no cover - defensive
        raise CapabilityError(
            f"DumpOrchestrator unavailable: {exc}",
            category=ErrorCategory.PRECONDITION, code="missing_backend",
        ) from exc
    if not orch.available_tools:
        raise CapabilityError(
            CAPTURE_BACKEND_HINT,
            category=ErrorCategory.PRECONDITION, code="missing_backend",
        )

    _experiment_check_cancelled(is_cancelled, on_progress)
    exp = _experiment_capture(
        orch, target_path, num_runs, Path(output_dir), on_progress)
    _experiment_check_cancelled(is_cancelled, on_progress)
    per_tool = _experiment_consensus_phase(
        exp.tool_dirs, key_material, on_source, on_progress)
    tool_results = _experiment_verify_phase(
        per_tool, exp.metadata, Path(output_dir),
        export_format, convergence, max_fp, on_progress)
    return {
        "tool_results": tool_results,
        "tools_used": list(per_tool.keys()),
        "target": str(target_path),
        "num_runs": num_runs,
    }

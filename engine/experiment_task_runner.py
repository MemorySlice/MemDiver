"""Worker entry point for the SPA-driven experiment surface.

This is the streaming counterpart to :func:`cli._cmd_experiment`. It
lifts the orchestration of *spawn target -> dump -> consensus -> verify
-> emit plugin* into a top-level function so the
:class:`api.services.task_manager.TaskManager` can dispatch it on its
spawn ``ProcessPoolExecutor``. ``run_experiment`` MUST stay top-level
(no closures, no instance methods) so the function pickles cleanly
under spawn semantics.

Progress is forwarded via ``ctx.emit`` (the WorkerContext API). The
three stage names match the router's ``stage_names`` argument:

* ``capture``   -- one progress event per dump captured per tool.
* ``consensus`` -- one stage_start + per-tool progress + stage_end as
  the consensus vector finalizes.
* ``verify``    -- one progress event per oracle / decryption check.

Optional engine modules (memslicer, frida, lldb, architect exporters)
are imported inside the runner so the task fails *gracefully* with a
``missing_backend`` summary instead of crashing the worker before the
first event.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any, Dict, List

logger = logging.getLogger("memdiver.engine.experiment_task_runner")


def _missing_backend(ctx, message: str) -> Dict[str, Any]:
    """Emit a non-fatal terminal summary when optional deps are unavailable.

    The TaskManager treats a returned dict as success so the SPA can
    render a friendly notice instead of a stack trace.
    """
    ctx.emit(
        "progress",
        stage="capture",
        pct=None,
        msg=message,
        extra={"missing_backend": True},
    )
    return {
        "artifacts": [],
        "summary": {
            "status": "missing_backend",
            "message": message,
            "tool_results": {},
        },
    }


def _resolve_artifact_dir(params: Dict[str, Any], ctx) -> Path:
    """Pick the per-task artifact directory the same way pipeline_runner does."""
    if "artifact_dir" in params:
        artifact_dir = Path(params["artifact_dir"]).expanduser()
    elif "task_root" in params:
        artifact_dir = Path(params["task_root"]).expanduser() / ctx.task_id
    else:
        # Fallback for ad-hoc invocations (tests). The TaskManager
        # always provides one of the above in production.
        artifact_dir = Path("./experiment_output").expanduser() / ctx.task_id
    artifact_dir.mkdir(parents=True, exist_ok=True)
    return artifact_dir


def _capture_dumps(
    orch,
    target_path: Path,
    num_runs: int,
    output_dir: Path,
    *,
    ctx,
) -> Any:
    """Run the orchestrator and stream a ``capture`` event per finished run.

    DumpOrchestrator.run_experiment is synchronous and does not expose a
    progress callback, so we can only emit a single bracketing event
    here. To preserve responsive UI feedback the SPA still gets a
    stage_start before the call and a stage_end with the per-tool dump
    counts after.
    """
    ctx.emit(
        "stage_start",
        stage="capture",
        pct=0.0,
        msg=f"capturing {num_runs} runs across {len(orch.available_tools)} tools",
    )
    exp = orch.run_experiment(target_path, num_runs, output_dir)

    dump_summary: Dict[str, int] = {}
    for tool_name, tool_dir in exp.tool_dirs.items():
        dump_paths = sorted(
            list(tool_dir.glob("*/*.dump")) + list(tool_dir.glob("*/*.msl"))
        )
        dump_summary[tool_name] = len(dump_paths)
        ctx.emit(
            "progress",
            stage="capture",
            pct=1.0,
            msg=f"{tool_name}: {len(dump_paths)} dumps",
            extra={"tool": tool_name, "dumps": len(dump_paths)},
        )

    ctx.emit(
        "stage_end",
        stage="capture",
        pct=1.0,
        msg=f"captured {sum(dump_summary.values())} dumps total",
        extra={"dumps_per_tool": dump_summary},
    )
    return exp


def _build_per_tool_consensus(
    exp,
    *,
    ctx,
) -> Dict[str, Dict[str, Any]]:
    """Fold each tool's dumps into a ConsensusVector and emit progress events."""
    from engine.consensus import ConsensusVector

    tools = list(exp.tool_dirs.items())
    ctx.emit(
        "stage_start",
        stage="consensus",
        pct=0.0,
        msg=f"folding consensus for {len(tools)} tools",
    )

    per_tool: Dict[str, Dict[str, Any]] = {}
    for idx, (tool_name, tool_dir) in enumerate(tools):
        dump_paths = sorted(
            list(tool_dir.glob("*/*.dump")) + list(tool_dir.glob("*/*.msl"))
        )
        if len(dump_paths) < 2:
            ctx.emit(
                "progress",
                stage="consensus",
                pct=(idx + 1) / max(len(tools), 1),
                msg=f"{tool_name}: not enough dumps ({len(dump_paths)}); skipping",
                extra={"tool": tool_name, "skipped": True},
            )
            continue

        cm = ConsensusVector()
        cm.build(dump_paths)
        aligned = cm.get_aligned_candidates()
        volatile = cm.get_volatile_regions()
        per_tool[tool_name] = {
            "consensus": cm,
            "dump_paths": dump_paths,
            "aligned": aligned,
            "volatile": volatile,
        }
        ctx.emit(
            "progress",
            stage="consensus",
            pct=(idx + 1) / max(len(tools), 1),
            msg=(
                f"{tool_name}: {len(aligned)} aligned, "
                f"{len(volatile)} volatile regions"
            ),
            extra={
                "tool": tool_name,
                "aligned_regions": len(aligned),
                "volatile_regions": len(volatile),
                "num_dumps": len(dump_paths),
            },
        )

    ctx.emit(
        "stage_end",
        stage="consensus",
        pct=1.0,
        msg=f"consensus ready for {len(per_tool)} tools",
        extra={"tools": list(per_tool.keys())},
    )
    return per_tool


def _verify_and_emit(
    exp,
    per_tool: Dict[str, Dict[str, Any]],
    *,
    output_dir: Path,
    export_format: str,
    ctx,
) -> Dict[str, Dict[str, Any]]:
    """Run decryption verification + auto-export and stream a ``verify`` event per tool."""
    from engine.verification import (
        AesCbcVerifier,
        VERIFICATION_PLAINTEXT,
        VERIFICATION_IV,
    )
    from architect.static_checker import StaticChecker
    from architect.pattern_generator import PatternGenerator

    verifier = AesCbcVerifier()
    tools = list(per_tool.items())
    ctx.emit(
        "stage_start",
        stage="verify",
        pct=0.0,
        msg=f"verifying {len(tools)} tools",
    )

    results: Dict[str, Dict[str, Any]] = {}
    for idx, (tool_name, info) in enumerate(tools):
        cm = info["consensus"]
        dump_paths = info["dump_paths"]
        aligned = info["aligned"]
        volatile = info["volatile"]

        first_data = dump_paths[0].read_bytes()
        first_key = exp.metadata["runs"][0]["key_hex"]
        key_bytes = bytes.fromhex(first_key)
        ciphertext = verifier.create_ciphertext(
            key_bytes, VERIFICATION_PLAINTEXT, VERIFICATION_IV,
        )

        dec_verified = False
        for region in aligned:
            for off in range(region.start, region.end - 31):
                candidate = first_data[off:off + 32]
                if verifier.verify(
                    candidate, ciphertext, VERIFICATION_IV,
                    VERIFICATION_PLAINTEXT,
                ):
                    dec_verified = True
                    break
            if dec_verified:
                break

        plugin_path = None
        if volatile:
            best = max(volatile, key=lambda r: r.end - r.start)
            ctx_pad = 32
            exp_offset = max(0, best.start - ctx_pad)
            exp_end = min(cm.size, best.end + ctx_pad)
            exp_length = exp_end - exp_offset

            static_mask, reference = StaticChecker.check(
                dump_paths, exp_offset, exp_length,
            )
            if reference:
                pattern = PatternGenerator.generate(
                    reference, static_mask, f"{tool_name}_aes256_key",
                )
                plugin_content = None
                if pattern:
                    if export_format in ("volatility3", "vol3"):
                        from architect.volatility3_exporter import (
                            Volatility3Exporter,
                        )
                        from architect.yara_exporter import YaraExporter
                        yara_rule = YaraExporter.export(pattern)
                        plugin_content = Volatility3Exporter.export(
                            pattern, yara_rule=yara_rule,
                        )
                    elif export_format == "yara":
                        from architect.yara_exporter import YaraExporter
                        plugin_content = YaraExporter.export(pattern)

                if plugin_content:
                    plugins_dir = output_dir / "plugins"
                    plugins_dir.mkdir(parents=True, exist_ok=True)
                    ext = ".py" if export_format in ("volatility3", "vol3") else ".yar"
                    plugin_path = plugins_dir / f"{tool_name}_aes256_key{ext}"
                    plugin_path.write_text(plugin_content)

        tool_result = {
            "tool": tool_name,
            "format": "MSL (.msl)" if tool_name == "memslicer" else "Raw (.dump)",
            "num_dumps": len(dump_paths),
            "volatile_regions": len(volatile),
            "aligned_regions": len(aligned),
            "decryption_verified": dec_verified,
            "plugin_saved": str(plugin_path) if plugin_path else None,
        }
        results[tool_name] = tool_result

        ctx.emit(
            "progress",
            stage="verify",
            pct=(idx + 1) / max(len(tools), 1),
            msg=(
                f"{tool_name}: decryption "
                f"{'verified' if dec_verified else 'not verified'}"
            ),
            extra=tool_result,
        )

    ctx.emit(
        "stage_end",
        stage="verify",
        pct=1.0,
        msg=f"verified {len(results)} tools",
        extra={"tool_results": results},
    )
    return results


def _register_plugin_artifacts(
    artifacts: List[Dict[str, Any]],
    artifact_dir: Path,
    output_dir: Path,
    tool_results: Dict[str, Dict[str, Any]],
) -> None:
    """Copy any saved plugins into the per-task artifact dir and register them.

    Plugins are written by the experiment runner into ``output_dir/plugins``.
    The TaskManager exposes artifacts relative to ``artifact_dir``, so we
    copy survivors over and register them so they're downloadable via
    the standard ``/runs/{task_id}/artifacts/{name}`` route.
    """
    import hashlib
    import shutil

    plugins_dir = artifact_dir / "plugins"
    plugins_dir.mkdir(parents=True, exist_ok=True)
    for tool_name, result in tool_results.items():
        src = result.get("plugin_saved")
        if not src:
            continue
        src_path = Path(src)
        if not src_path.is_file():
            continue
        # If the plugin already lives under the artifact dir, skip the copy.
        try:
            src_path.resolve().relative_to(artifact_dir.resolve())
            target = src_path
        except ValueError:
            target = plugins_dir / src_path.name
            shutil.copy2(src_path, target)
        size = target.stat().st_size
        sha = hashlib.sha256(target.read_bytes()).hexdigest()
        relpath = str(target.relative_to(artifact_dir))
        artifacts.append({
            "name": f"plugin_{tool_name}",
            "relpath": relpath,
            "media_type": "text/x-python"
            if target.suffix == ".py"
            else "text/plain",
            "size": size,
            "sha256": sha,
        })


def run_experiment(params: Dict[str, Any], ctx) -> Dict[str, Any]:
    """Top-level worker entry point for ``POST /api/experiment/run``.

    ``params`` keys (mirrors :class:`api.routers.experiment.ExperimentRunRequest`):

    * ``target`` (str, required): path to the target binary or script.
    * ``num_runs`` (int): iterations per tool, default 10.
    * ``tools`` (list[str] | None): subset of dump tools to use.
    * ``export_format`` (str): plugin export format, default ``volatility3``.
    * ``oracle_id`` (str | None): reserved; verification currently uses
      the bundled :class:`AesCbcVerifier`.
    * ``protocol_version`` / ``phase``: contextual tags surfaced to the
      SPA but not consumed by the engine here.

    Returns ``{"artifacts": [...], "summary": {...}}`` so the
    TaskManager can publish the terminal ``done`` event.
    """
    artifact_dir = _resolve_artifact_dir(params, ctx)

    # Lazy / optional imports — fall back to a graceful summary if any
    # of the heavyweight backends (memslicer, frida, architect exporters)
    # are missing on this machine.
    try:
        from core.dump_driver import DumpOrchestrator
    except ImportError as exc:  # pragma: no cover - environmental
        return _missing_backend(
            ctx,
            f"experiment backend unavailable: {exc}. "
            "Install with `pip install memdiver[experiment]`.",
        )

    target_path = Path(params["target"]).expanduser()
    if not target_path.is_file():
        ctx.emit("error", error=f"target not found: {target_path}")
        raise FileNotFoundError(f"target not found: {target_path}")

    num_runs = int(params.get("num_runs", 10))
    tools_param = params.get("tools")
    tools_list = list(tools_param) if tools_param else None
    export_format = str(params.get("export_format", "volatility3"))

    try:
        orch = DumpOrchestrator(tools=tools_list)
    except Exception as exc:  # pragma: no cover - defensive
        return _missing_backend(
            ctx, f"DumpOrchestrator unavailable: {exc}",
        )

    if not orch.available_tools:
        return _missing_backend(
            ctx,
            "no dump tools available on this machine "
            "(install frida-tools / memslicer / lldb to enable capture).",
        )

    # Capture stage.
    if ctx.is_cancelled():
        ctx.emit("error", error="cancelled")
        raise RuntimeError("experiment cancelled")
    exp = _capture_dumps(
        orch,
        target_path,
        num_runs,
        artifact_dir,
        ctx=ctx,
    )

    # Consensus stage — needs the engine.consensus module.
    if ctx.is_cancelled():
        ctx.emit("error", error="cancelled")
        raise RuntimeError("experiment cancelled")
    try:
        per_tool = _build_per_tool_consensus(exp, ctx=ctx)
    except ImportError as exc:
        return _missing_backend(ctx, f"consensus backend unavailable: {exc}")

    # Verify + emit stage — needs verification + architect modules.
    if ctx.is_cancelled():
        ctx.emit("error", error="cancelled")
        raise RuntimeError("experiment cancelled")
    try:
        tool_results = _verify_and_emit(
            exp,
            per_tool,
            output_dir=artifact_dir,
            export_format=export_format,
            ctx=ctx,
        )
    except ImportError as exc:
        return _missing_backend(ctx, f"verify backend unavailable: {exc}")

    artifacts: List[Dict[str, Any]] = []
    _register_plugin_artifacts(artifacts, artifact_dir, artifact_dir, tool_results)

    summary = {
        "status": "ok",
        "target": str(target_path),
        "num_runs": num_runs,
        "tools_used": list(per_tool.keys()),
        "tool_results": tool_results,
        "protocol_version": params.get("protocol_version"),
        "phase": params.get("phase"),
        "oracle_id": params.get("oracle_id"),
    }
    return {"artifacts": artifacts, "summary": summary}

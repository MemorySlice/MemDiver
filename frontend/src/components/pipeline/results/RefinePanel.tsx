/**
 * Refine panel — lets the user fold additional dumps into the
 * consensus to tighten the neighborhood variance, tracking
 * convergence (static byte count) across successive refinements.
 */

import { useState } from "react";

import { refinePipeline } from "@/api/pipeline";
import { usePipelineStore } from "@/stores/pipeline-store";
import { useHexStore } from "@/stores/hex-store";
import { inferNeighborhoodFields } from "@/utils/infer-neighborhood-fields";

export function RefinePanel() {
  const taskId = usePipelineStore((s) => s.taskId);
  const hits = usePipelineStore((s) => s.hits);
  const history = usePipelineStore((s) => s.convergenceHistory);
  const loading = usePipelineStore((s) => s.refineLoading);
  const addPoint = usePipelineStore((s) => s.addConvergencePoint);
  const setLoading = usePipelineStore((s) => s.setRefineLoading);
  const [paths, setPaths] = useState("");

  if (!taskId || hits.length === 0) return null;

  const handleRefine = async () => {
    const pathList = paths
      .split("\n")
      .map((p) => p.trim())
      .filter(Boolean);
    if (pathList.length === 0) return;
    setLoading(true);
    try {
      const resp = await refinePipeline(taskId, pathList);
      addPoint({
        n: resp.num_dumps,
        staticCount: resp.static_count,
        dynamicCount: resp.dynamic_count,
      });
      // Update the hex store neighborhood overlay with fresh variance
      if (resp.hit_neighborhoods.length > 0) {
        const nh = resp.hit_neighborhoods[0];
        const hit = hits[0];
        const keyOff = hit.offset - nh.neighborhood_start;
        const fields = inferNeighborhoodFields(
          nh.neighborhood_variance,
          keyOff,
          hit.size,
        );
        useHexStore.getState().setActiveNeighborhoodOverlay({
          hitOffset: hit.offset,
          hitSize: hit.size,
          neighborhoodStart: nh.neighborhood_start,
          variance: nh.neighborhood_variance,
          fields,
        });
      }
    } catch (err) {
      console.error("Refine failed:", err);
    } finally {
      setLoading(false);
      setPaths("");
    }
  };

  const lastPoint = history[history.length - 1];
  const prevPoint = history.length >= 2 ? history[history.length - 2] : null;
  const converged =
    prevPoint != null &&
    lastPoint != null &&
    lastPoint.staticCount === prevPoint.staticCount;

  return (
    <div className="border border-zinc-700 rounded-lg p-4 space-y-3">
      <h3 className="text-sm font-semibold text-zinc-300">
        Refine Neighborhood (Phase 2)
      </h3>

      {/* Convergence tracker */}
      {history.length > 0 && (
        <div className="flex flex-wrap gap-2 items-center text-xs">
          {history.map((pt, i) => (
            <span key={i} className="inline-flex items-center gap-1">
              {i > 0 && <span className="text-zinc-500">&rarr;</span>}
              <span className="bg-zinc-800 px-2 py-0.5 rounded font-mono">
                N={pt.n}:{" "}
                <span className="text-emerald-400">{pt.staticCount}</span>/
                <span className="text-zinc-400">
                  {pt.staticCount + pt.dynamicCount}
                </span>{" "}
                static
              </span>
            </span>
          ))}
        </div>
      )}

      {/* Convergence guidance */}
      {converged && (
        <p className="text-xs text-amber-400">
          Converged &mdash; adding more dumps unlikely to improve the pattern.
        </p>
      )}
      {!converged && history.length >= 2 && (
        <p className="text-xs text-emerald-400">
          Variance still decreasing &mdash; more dumps recommended.
        </p>
      )}

      {/* Add dumps */}
      <div className="space-y-2">
        <textarea
          className="w-full bg-zinc-900 border border-zinc-700 rounded px-2 py-1.5 text-xs font-mono text-zinc-300 placeholder-zinc-600"
          rows={3}
          placeholder="Paste additional dump paths (one per line)..."
          value={paths}
          onChange={(e) => setPaths(e.target.value)}
          disabled={loading}
        />
        <button
          className="px-3 py-1.5 text-xs font-medium bg-blue-600 hover:bg-blue-500 disabled:bg-zinc-700 disabled:text-zinc-500 rounded text-white"
          onClick={handleRefine}
          disabled={loading || !paths.trim()}
        >
          {loading ? "Folding..." : "Refine Consensus"}
        </button>
      </div>
    </div>
  );
}

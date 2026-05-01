/**
 * Pipeline run dashboard — active-stage bar, reduction funnel, stage
 * timings, live oracle log, and a hits list with "Open in hex" that
 * auto-loads the first consensus source on a cold pipeline tab.
 */

import type { JSX } from "react";

import { useAppStore } from "@/stores/app-store";
import { useHexStore } from "@/stores/hex-store";
import { usePipelineStore, type HitRecord } from "@/stores/pipeline-store";
import { inferNeighborhoodFields } from "@/utils/infer-neighborhood-fields";

import { FunnelChart } from "./FunnelChart";
import { LiveOracleLog } from "./LiveOracleLog";
import { StageTimingTable } from "./StageTimingTable";

function openHitInHex(
  hit: HitRecord,
  fallbackDump: string | null,
) {
  const hex = useHexStore.getState();
  useAppStore.getState().setHexFocus({ offset: hit.offset, length: hit.size || 32 });

  // Wire up neighborhood variance overlay when available
  if (hit.neighborhood_variance.length > 0) {
    const keyOffsetInWindow = hit.offset - hit.neighborhood_start;
    const fields = inferNeighborhoodFields(hit.neighborhood_variance, keyOffsetInWindow, hit.size);
    hex.setActiveNeighborhoodOverlay({
      hitOffset: hit.offset,
      hitSize: hit.size,
      neighborhoodStart: hit.neighborhood_start,
      variance: hit.neighborhood_variance,
      fields,
    });
  }

  if (!hex.dumpPath && fallbackDump) {
    // setDumpPath seeds HexViewer with fileSize=0 and triggers a
    // metadata refetch; defer the scroll so it lands after HexViewer
    // remounts with the real size instead of flashing an empty view.
    hex.setDumpPath(fallbackDump, 0, "raw");
    queueMicrotask(() => useHexStore.getState().scrollToOffset(hit.offset));
    return;
  }
  hex.scrollToOffset(hit.offset);
}

function HitsList(): JSX.Element | null {
  const hits = usePipelineStore((s) => s.hits);
  const sources = usePipelineStore((s) => s.form.sourcePaths);
  if (hits.length === 0) return null;
  const fallback = sources.length > 0 ? sources[0] : null;
  return (
    <div
      className="md-panel p-3 space-y-1"
      data-tour-id="pipeline-hits-list"
    >
      <div className="text-xs md-text-accent font-semibold mb-1">
        Verified hits ({hits.length})
      </div>
      <ul className="space-y-1">
        {hits.map((h, i) => (
          <li
            key={`${h.offset}-${i}`}
            className="flex items-center justify-between gap-2 text-xs"
          >
            <span className="font-mono md-text-secondary">
              0x{h.offset.toString(16).padStart(8, "0")}
              <span className="md-text-muted ml-1">({h.size} B)</span>
            </span>
            <button
              type="button"
              onClick={() => openHitInHex(h, fallback)}
              className="text-xs px-2 py-0.5 rounded bg-[var(--md-accent-blue)] text-white hover:opacity-90"
              title="Jump to this offset in the hex viewer"
            >
              Open in hex
            </button>
          </li>
        ))}
      </ul>
    </div>
  );
}

export function PipelineRunDashboard(): JSX.Element {
  const status = usePipelineStore((s) => s.status);
  const error = usePipelineStore((s) => s.error);
  const activeStage = usePipelineStore((s) => s.activeStage);
  const activeStagePct = usePipelineStore((s) => s.activeStagePct);
  const activeStageMsg = usePipelineStore((s) => s.activeStageMsg);

  const isRunning = status === "running" || status === "pending";
  const pctClamped = Math.max(0, Math.min(1, activeStagePct));

  return (
    <div className="space-y-3 text-xs md-text-secondary">
      {status === "failed" && (
        <div className="md-panel p-3 border md-border-error md-text-error">
          <div className="font-semibold mb-0.5">Pipeline failed</div>
          <div className="font-mono">{error ?? "unknown error"}</div>
        </div>
      )}

      {status === "cancelled" && (
        <div className="md-panel p-3 border md-border-warning md-text-warning">
          Task cancelled.
        </div>
      )}

      {status === "succeeded" && (
        <div className="md-text-muted italic">Pipeline completed.</div>
      )}

      {isRunning && activeStage && (
        <div className="md-panel p-3 space-y-1">
          <div className="flex justify-between text-xs">
            <span className="md-text-accent">{activeStage}</span>
            <span className="md-text-muted">
              {(pctClamped * 100).toFixed(0)}%
            </span>
          </div>
          <div className="h-1.5 rounded bg-[var(--md-bg-hover)] overflow-hidden">
            <div
              className="h-full bg-[var(--md-accent-blue)] transition-all duration-300"
              style={{ width: `${pctClamped * 100}%` }}
            />
          </div>
          {activeStageMsg && (
            <div className="text-xs md-text-muted truncate">
              {activeStageMsg}
            </div>
          )}
        </div>
      )}

      <FunnelChart />

      <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
        <StageTimingTable />
        <LiveOracleLog />
      </div>

      <HitsList />
    </div>
  );
}

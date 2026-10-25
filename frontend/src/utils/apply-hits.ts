/**
 * Shared utility for grouping analysis hits by algorithm and dispatching
 * to the results store and hex store.
 *
 * Used by: AnalysisPanel (after analysis), SessionManager (after restore),
 * ScanResultsPanel (after re-run).
 */

import type { SecretHit } from "@/api/types";
import type { HexViewMode, HighlightRegion } from "@/stores/hex-store";
import { useResultsStore } from "@/stores/results-store";
import { useHexStore } from "@/stores/hex-store";
import { useAppStore } from "@/stores/app-store";
import { secretTypeToHighlight } from "@/utils/highlight-types";

interface AnalysisResultLike {
  libraries: Array<{ hits: SecretHit[]; metadata?: Record<string, unknown> }>;
}

const HIT_VIEWS: readonly HexViewMode[] = ["raw", "vas", "va"];

/**
 * The byte view a library report's hit offsets address, from the backend's
 * `metadata.offset_view` (set by `run_file`: "vas" for .msl / gcore /
 * gdb_raw / lldb_raw, "raw" for a flat dump). `undefined` when the report
 * does not say (library-directory analysis, older saved sessions): those
 * hits keep the historical "whatever view is on screen" behaviour.
 */
export function hitOffsetView(
  metadata: Record<string, unknown> | undefined,
): HexViewMode | undefined {
  const view = metadata?.offset_view;
  return HIT_VIEWS.includes(view as HexViewMode) ? (view as HexViewMode) : undefined;
}

/**
 * Group hits by algorithm, dispatch to results store, and optionally
 * update hex highlights and candidate-key flag.
 *
 * @param withHighlights  If true, also pushes highlight regions to hex store
 *                        and sets hasCandidateKeys. Pass false for lightweight
 *                        re-runs that only update the results panel.
 */
export function applyHitsToStores(
  result: AnalysisResultLike,
  withHighlights = true,
): void {
  const hitsByAlgorithm: Record<string, SecretHit[]> = {};
  let anyHits = false;

  for (const lib of result.libraries) {
    for (const hit of lib.hits) {
      const key = hit.secret_type;
      (hitsByAlgorithm[key] ??= []).push(hit);
      anyHits = true;
    }
  }

  const resultsState = useResultsStore.getState();
  for (const [algoName, hits] of Object.entries(hitsByAlgorithm)) {
    resultsState.setAlgorithmResults(algoName, hits);
  }

  if (withHighlights) {
    const regions: HighlightRegion[] = result.libraries.flatMap((lib) => {
      const view = hitOffsetView(lib.metadata);
      return lib.hits.map((hit) => ({
        offset: hit.offset,
        length: hit.length,
        type: secretTypeToHighlight(hit.secret_type),
        label: `${hit.secret_type} (${hit.library || "unknown"})`,
        ...(view ? { view } : {}),
      }));
    });
    const hex = useHexStore.getState();
    hex.setHighlightedRegions(regions);
    // Put the viewer in the view the offsets were computed in, so the
    // highlights land on the hit bytes (no-op on a single-view dump).
    const hitView = regions.find((r) => r.view)?.view;
    if (hitView) hex.showView(hitView);
    if (anyHits) useAppStore.getState().setHasCandidateKeys(true);
  }
}

/**
 * Group flat hits (e.g., from session restore) by secret_type and
 * dispatch to results store. Handles unknown/missing secret_type gracefully.
 */
export function applyFlatHitsToStore(hits: unknown[]): void {
  const hitsByAlgo: Record<string, SecretHit[]> = {};
  for (const hit of hits) {
    const key = (hit as Record<string, unknown>).secret_type as string ?? "restored";
    (hitsByAlgo[key] ??= []).push(hit as SecretHit);
  }
  const store = useResultsStore.getState();
  for (const [algo, algoHits] of Object.entries(hitsByAlgo)) {
    store.setAlgorithmResults(algo, algoHits);
  }
}

/** A located address of an analysis-record entry (backend `Location.to_dict`). */
export interface AnnotationLocation {
  space: string;
  value: number;
  [extra: string]: unknown;
}

/** One analysis-record entry (backend schema: `analysis/record.py`). */
export interface AnnotationEntry {
  id: string;
  capture_id?: string | null;
  kind: string;
  label?: string;
  locations: AnnotationLocation[];
  length?: number | null;
  payload?: Record<string, unknown> | null;
}

export interface ApplyAnnotationsOptions {
  /** Only locations whose `space` equals this are considered. */
  space: string;
  /**
   * Caller-owned coordinate translation: the byte offset in the view being
   * painted, or null when the location cannot be placed there (skipped; an
   * offset is never invented).
   */
  toOffset: (location: AnnotationLocation) => number | null;
  /** Stamped on every region so only the pane showing this dump paints it. */
  dumpPath?: string;
  /** The byte view the offsets address; unset = whatever is on screen. */
  view?: HexViewMode;
}

/**
 * Turn analysis-record entries into generic-kind highlight regions.
 *
 * `kind` is `payload.highlight_kind` when it is a non-empty string, else the
 * entry kind. A missing/invalid length paints one byte. The entry label (or
 * its kind) becomes the cell tooltip.
 */
export function applyAnnotations(
  entries: readonly AnnotationEntry[],
  opts: ApplyAnnotationsOptions,
): HighlightRegion[] {
  const regions: HighlightRegion[] = [];
  for (const entry of entries) {
    const override = entry.payload?.highlight_kind;
    const kind = typeof override === "string" && override ? override : entry.kind;
    const length =
      typeof entry.length === "number" && Number.isFinite(entry.length) && entry.length > 0
        ? entry.length
        : 1;
    for (const location of entry.locations) {
      if (location.space !== opts.space) continue;
      const offset = opts.toOffset(location);
      if (offset === null || !Number.isFinite(offset) || offset < 0) continue;
      regions.push({
        offset,
        length,
        type: "pattern",
        label: entry.label || entry.kind,
        kind,
        ...(opts.dumpPath !== undefined ? { dumpPath: opts.dumpPath } : {}),
        ...(opts.view ? { view: opts.view } : {}),
      });
    }
  }
  return regions;
}

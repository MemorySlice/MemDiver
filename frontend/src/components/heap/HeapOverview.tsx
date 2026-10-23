/**
 * Side-panel summary of one dump's heap: which allocator, how sure, on what
 * platform, where its regions are, and how its chunks split by state.
 *
 * Reads the heap store only (detection + summary, fetched on show by
 * `useHeapOverviewData`); region clicks move the hex viewer through
 * `heap-navigation`.
 */

import { useState } from "react";
import type { TFunction } from "i18next";
import { useTranslation } from "react-i18next";
import { useShallow } from "zustand/react/shallow";

import { HEAP_CHUNK_STATES } from "@/api/heap";
import type {
  HeapAllocatorChoice,
  HeapAllocatorKind,
  HeapEvidence,
  HeapPlatform,
  HeapRegion,
} from "@/api/types";
import { useHeapOverviewData } from "@/hooks/useHeapData";
import { selectHeapDump, useHeapStore } from "@/stores/heap-store";
import { formatBytes } from "@/utils/format-bytes";
import { HEAP_ALLOCATOR_CHOICES, confidencePercent, formatAddress } from "./heap-format";
import { jumpHexToVa } from "./heap-navigation";

interface Props {
  dumpPath: string;
}

export function HeapOverview({ dumpPath }: Props) {
  const { t } = useTranslation("heap");
  useHeapOverviewData(dumpPath);
  const entry = useHeapStore(
    useShallow((s) => {
      const e = selectHeapDump(dumpPath)(s);
      return {
        allocator: e.allocator,
        detection: e.detection,
        detectionStatus: e.detectionStatus,
        detectionError: e.detectionError,
        summary: e.summary,
        summaryStatus: e.summaryStatus,
        summaryError: e.summaryError,
      };
    }),
  );

  if (!dumpPath) {
    return <p className="p-3 text-xs md-text-muted">{t("overview.noDump")}</p>;
  }

  const { detection, summary } = entry;
  const loading = entry.detectionStatus === "loading" || entry.summaryStatus === "loading";
  const error = entry.summaryError ?? entry.detectionError;
  const kind: HeapAllocatorKind | null = summary?.allocator ?? detection?.best ?? null;
  const confidence = summary?.confidence ?? detection?.confidence ?? 0;
  const platform = summary?.platform ?? detection?.platform ?? null;
  const evidence = summary?.evidence?.length
    ? summary.evidence
    : (detection?.candidates.find((c) => c.kind === detection.best)?.evidence ?? []);
  const empty =
    entry.summaryStatus === "ready" && summary !== null &&
    summary.chunk_count === 0 && summary.regions.length === 0;

  return (
    <div className="p-3 space-y-3 text-xs" data-testid="heap-overview">
      <h3 className="font-semibold md-text-secondary">{t("panels.overview")}</h3>
      <AllocatorSelector dumpPath={dumpPath} value={entry.allocator} />

      {loading && (
        <p role="status" className="flex items-center gap-2 md-text-muted">
          <span className="md-spinner" aria-hidden="true" />
          {t("overview.loading")}
        </p>
      )}
      {error && <HeapErrorNotice dumpPath={dumpPath} message={error} />}

      {kind && (
        <AllocatorBadges
          kind={kind}
          confidence={confidence}
          hinted={detection?.hinted ?? false}
          partial={summary?.partial ?? false}
          heuristic={summary?.heuristic ?? false}
        />
      )}
      {empty && <p className="md-text-muted" data-testid="heap-overview-empty">{t("overview.empty")}</p>}

      {(platform || summary) && (
        <dl className="grid grid-cols-[auto_1fr] gap-x-3 gap-y-1">
          <dt className="md-text-muted">{t("overview.platform")}</dt>
          <dd data-testid="heap-platform">{platformText(t, platform)}</dd>
          <dt className="md-text-muted">{t("overview.versionHint")}</dt>
          <dd>{summary?.version_hint ?? t("overview.versionUnknown")}</dd>
          {summary && (
            <>
              <dt className="md-text-muted">{t("overview.chunkCount")}</dt>
              <dd>{summary.chunk_count.toLocaleString()}</dd>
              <dt className="md-text-muted">{t("overview.metadataBytes")}</dt>
              <dd>{formatBytes(summary.metadata_bytes)}</dd>
              <dt className="md-text-muted">{t("overview.freeListCount")}</dt>
              <dd>{summary.free_list_count.toLocaleString()}</dd>
            </>
          )}
        </dl>
      )}

      {summary && <StateCounts counts={summary.counts_by_state} bytes={summary.bytes_by_state} />}
      {summary && <RegionList dumpPath={dumpPath} regions={summary.regions} />}
      {(summary || detection) && <EvidenceList evidence={evidence} />}
      {detection && detection.candidates.length > 1 && (
        <section>
          <h4 className="font-semibold md-text-muted mb-1">{t("overview.candidates")}</h4>
          <ul className="space-y-0.5" data-testid="heap-candidates">
            {detection.candidates
              .filter((c) => c.kind !== detection.best)
              .map((c) => (
                <li key={c.kind} className="flex justify-between gap-2">
                  <span>{t(`allocators.${c.kind}`)}</span>
                  <span className="md-text-muted">
                    {t("badges.confidence", { value: confidencePercent(c.score) })}
                  </span>
                </li>
              ))}
          </ul>
        </section>
      )}
      {summary && summary.diagnostics.length > 0 && (
        <section>
          <h4 className="font-semibold md-text-muted mb-1">{t("overview.diagnostics")}</h4>
          <ul className="space-y-0.5 md-text-warning" data-testid="heap-diagnostics">
            {summary.diagnostics.map((d, i) => (
              <li key={i}>{d}</li>
            ))}
          </ul>
        </section>
      )}
    </div>
  );
}

type Translate = TFunction<"heap">;

function platformText(t: Translate, platform: HeapPlatform | null): string {
  if (!platform) return t("overview.platformUnknown");
  return t("overview.platformValue", {
    os: platform.os,
    arch: platform.arch,
    bits: platform.pointer_size * 8,
    endianness: platform.endianness,
  });
}

function AllocatorSelector({ dumpPath, value }: { dumpPath: string; value: HeapAllocatorChoice }) {
  const { t } = useTranslation("heap");
  const setAllocator = useHeapStore((s) => s.setAllocator);
  return (
    <label className="flex items-center gap-2">
      <span className="md-text-muted">{t("overview.allocator")}</span>
      <select
        value={value}
        onChange={(e) => setAllocator(dumpPath, e.target.value as HeapAllocatorChoice)}
        data-testid="heap-allocator-select"
        className="flex-1 px-1 py-0.5 rounded border border-[var(--md-border)] bg-transparent"
      >
        {HEAP_ALLOCATOR_CHOICES.map((choice) => (
          <option key={choice} value={choice}>
            {t(`allocators.${choice}`)}
          </option>
        ))}
      </select>
    </label>
  );
}

interface BadgeProps {
  kind: HeapAllocatorKind;
  confidence: number;
  hinted: boolean;
  partial: boolean;
  heuristic: boolean;
}

function AllocatorBadges({ kind, confidence, hinted, partial, heuristic }: BadgeProps) {
  const { t } = useTranslation("heap");
  const badge = "px-1.5 py-0.5 rounded";
  return (
    <div className="flex flex-wrap items-center gap-1" data-testid="heap-allocator-badges">
      <span className={`${badge} md-bg-cyan-subtle font-semibold`} data-testid="heap-allocator-badge">
        {t(`allocators.${kind}`)}
      </span>
      <span className={`${badge} md-bg-neutral-subtle`}>
        {t("badges.confidence", { value: confidencePercent(confidence) })}
      </span>
      {hinted && <span className={`${badge} md-bg-info-subtle`}>{t("badges.hinted")}</span>}
      {partial && (
        <span className={`${badge} md-bg-warning-subtle`} title={t("badges.partialHint")} data-testid="heap-badge-partial">
          {t("badges.partial")}
        </span>
      )}
      {heuristic && (
        <span className={`${badge} md-bg-warning-subtle`} title={t("badges.heuristicHint")} data-testid="heap-badge-heuristic">
          {t("badges.heuristic")}
        </span>
      )}
    </div>
  );
}

function HeapErrorNotice({ dumpPath, message }: { dumpPath: string; message: string }) {
  const { t } = useTranslation("heap");
  const retry = () => {
    const store = useHeapStore.getState();
    void store.loadDetection(dumpPath);
    void store.loadSummary(dumpPath);
  };
  return (
    <div role="alert" className="p-2 rounded md-bg-error-subtle md-text-error flex items-start gap-2">
      <span className="flex-1 break-words">{message}</span>
      <button
        type="button"
        onClick={retry}
        className="px-1.5 rounded border border-[var(--md-border)] hover:bg-[var(--md-bg-hover)]"
      >
        {t("overview.retry")}
      </button>
    </div>
  );
}

interface StateCountsProps {
  counts: Partial<Record<string, number>>;
  bytes: Partial<Record<string, number>>;
}

function StateCounts({ counts, bytes }: StateCountsProps) {
  const { t } = useTranslation("heap");
  const present = HEAP_CHUNK_STATES.filter((s) => (counts[s] ?? 0) > 0);
  if (present.length === 0) return null;
  return (
    <section>
      <h4 className="font-semibold md-text-muted mb-1">{t("overview.countsByState")}</h4>
      <ul className="space-y-0.5" data-testid="heap-state-counts">
        {present.map((state) => (
          <li key={state} className="flex justify-between gap-2" data-heap-state={state}>
            <span>{t(`states.${state}`)}</span>
            <span className="md-text-muted">
              {(counts[state] ?? 0).toLocaleString()} · {formatBytes(bytes[state] ?? 0)}
            </span>
          </li>
        ))}
      </ul>
    </section>
  );
}

function RegionList({ dumpPath, regions }: { dumpPath: string; regions: HeapRegion[] }) {
  const { t } = useTranslation("heap");
  const [failedVa, setFailedVa] = useState<number | null>(null);

  const jump = (region: HeapRegion) => {
    setFailedVa(null);
    jumpHexToVa(dumpPath, region.va)
      .then((ok) => { if (!ok) setFailedVa(region.va); })
      .catch(() => setFailedVa(region.va));
  };

  return (
    <section>
      <h4 className="font-semibold md-text-muted mb-1">{t("panels.regions")}</h4>
      {regions.length === 0 ? (
        <p className="md-text-muted">{t("overview.noRegions")}</p>
      ) : (
        <ul className="space-y-0.5" data-testid="heap-regions">
          {regions.map((r) => (
            <li key={`${r.va}-${r.name}`}>
              <button
                type="button"
                onClick={() => jump(r)}
                title={t("overview.jumpToRegion", { name: r.name || formatAddress(r.va) })}
                className="w-full text-left px-1 rounded hover:bg-[var(--md-bg-hover)] flex justify-between gap-2"
              >
                <span className="font-mono truncate">{formatAddress(r.va)}</span>
                <span className="truncate md-text-secondary">{r.name || r.kind}</span>
                <span className="md-text-muted shrink-0">{formatBytes(r.size)}</span>
              </button>
            </li>
          ))}
        </ul>
      )}
      {failedVa !== null && (
        <p role="status" className="mt-1 md-text-warning">{t("overview.regionUnmapped")}</p>
      )}
    </section>
  );
}

function EvidenceList({ evidence }: { evidence: HeapEvidence[] }) {
  const { t } = useTranslation("heap");
  return (
    <details data-testid="heap-evidence">
      <summary className="cursor-pointer font-semibold md-text-muted">
        {t("overview.evidenceToggle", { count: evidence.length })}
      </summary>
      {evidence.length === 0 ? (
        <p className="mt-1 md-text-muted">{t("evidence.empty")}</p>
      ) : (
        <table className="mt-1 w-full">
          <thead>
            <tr className="md-text-muted text-left">
              <th className="font-normal pr-2">{t("evidence.source")}</th>
              <th className="font-normal pr-2">{t("evidence.detail")}</th>
              <th className="font-normal text-right">{t("evidence.weight")}</th>
            </tr>
          </thead>
          <tbody>
            {evidence.map((e, i) => (
              <tr key={i} className="align-top">
                <td className="pr-2 font-mono">{e.source}</td>
                <td className="pr-2 break-words">{e.detail}</td>
                <td className="text-right">{e.weight.toFixed(2)}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </details>
  );
}

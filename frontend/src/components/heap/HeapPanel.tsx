/**
 * The heap-mode bottom panel: chunk table, size histogram and free-list tree
 * on the left, the selected chunk's inspector on the right, and the heap role
 * legend on top.
 */

import { useState } from "react";
import { useTranslation } from "react-i18next";

import { SegmentedControl } from "@/components/common/SegmentedControl";
import { HeapLegend } from "@/components/hex/HeapLegend";
import { useHeapOverviewData } from "@/hooks/useHeapData";
import { selectHeapDump, useHeapStore } from "@/stores/heap-store";
import { HeapChunkInspector } from "./HeapChunkInspector";
import { HeapChunkTable } from "./HeapChunkTable";
import { HeapFreeLists } from "./HeapFreeLists";
import { HeapSizeHistogram } from "./HeapSizeHistogram";

type HeapView = "chunks" | "histogram" | "freeLists";
const HEAP_VIEWS: readonly HeapView[] = ["chunks", "histogram", "freeLists"];

interface Props {
  dumpPath: string;
}

export function HeapPanel({ dumpPath }: Props) {
  const { t } = useTranslation("heap");
  const [view, setView] = useState<HeapView>("chunks");
  useHeapOverviewData(dumpPath);

  if (!dumpPath) {
    return <p className="p-3 text-sm md-text-muted">{t("overview.noDump")}</p>;
  }

  return (
    <div className="h-full flex flex-col min-h-0" data-testid="heap-panel">
      <div className="flex flex-wrap items-center gap-3 px-3 py-1 border-b border-[var(--md-border)] text-xs">
        <SegmentedControl
          aria-label={t("panels.views")}
          selected={view}
          onSelect={(id) => setView(id as HeapView)}
          options={HEAP_VIEWS.map((id) => ({ id, label: t(`panels.${id}`), testId: `heap-view-${id}` }))}
        />
        <HeapLegend dumpPath={dumpPath} />
      </div>
      <div className="flex-1 flex min-h-0">
        <div className="flex-1 min-w-0 min-h-0 overflow-auto">
          {view === "chunks" && <HeapChunkTable dumpPath={dumpPath} />}
          {view === "histogram" && <HistogramView dumpPath={dumpPath} />}
          {view === "freeLists" && <HeapFreeLists dumpPath={dumpPath} />}
        </div>
        <aside className="w-72 shrink-0 border-l border-[var(--md-border)] overflow-auto">
          <HeapChunkInspector dumpPath={dumpPath} />
        </aside>
      </div>
    </div>
  );
}

function HistogramView({ dumpPath }: Props) {
  const { t } = useTranslation("heap");
  const buckets = useHeapStore((s) => selectHeapDump(dumpPath)(s).summary?.size_histogram);
  const status = useHeapStore((s) => selectHeapDump(dumpPath)(s).summaryStatus);
  const error = useHeapStore((s) => selectHeapDump(dumpPath)(s).summaryError);
  if (error) return <p role="alert" className="p-2 text-xs md-text-error">{error}</p>;
  if (!buckets) {
    return (
      <p role="status" className="p-2 text-xs md-text-muted">
        {status === "loading" ? t("overview.loading") : t("histogram.empty")}
      </p>
    );
  }
  return <HeapSizeHistogram buckets={buckets} />;
}

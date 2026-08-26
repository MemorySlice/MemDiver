import { useState, useCallback, useRef } from "react";
import { useShallow } from "zustand/react/shallow";
import { useTranslation } from "react-i18next";
import { useConsensusIncrementalStore } from "@/stores/consensus-incremental-store";
import { EmptyState } from "@/components/common/EmptyState";
import { LiveConsensusIcon } from "@/components/common/Icons";

function Sparkline({ values }: { values: number[] }) {
  const { t } = useTranslation("analysis");
  if (values.length < 2) {
    return (
      <div className="h-10 flex items-center text-[10px] md-text-muted">
        {t("consensus.sparklineHint")}
      </div>
    );
  }
  const max = Math.max(...values, 1);
  const width = 180;
  const height = 40;
  const step = width / Math.max(values.length - 1, 1);
  const points = values
    .map((v, i) => `${(i * step).toFixed(1)},${(height - (v / max) * height).toFixed(1)}`)
    .join(" ");
  return (
    <svg
      width={width}
      height={height}
      className="block"
      role="img"
      aria-label={t("consensus.sparklineAria")}
    >
      <polyline
        fill="none"
        stroke="var(--md-accent-blue)"
        strokeWidth={1.5}
        points={points}
      />
    </svg>
  );
}

export function ConsensusBuilder() {
  const { t } = useTranslation("analysis");
  const {
    sessionId,
    size,
    numDumps,
    status,
    liveStats,
    history,
    finalResult,
    error,
    begin,
    addFile,
    finalize,
    reset,
  } = useConsensusIncrementalStore(
    useShallow((s) => ({
      sessionId: s.sessionId,
      size: s.size,
      numDumps: s.numDumps,
      status: s.status,
      liveStats: s.liveStats,
      history: s.history,
      finalResult: s.finalResult,
      error: s.error,
      begin: s.begin,
      addFile: s.addFile,
      finalize: s.finalize,
      reset: s.reset,
    })),
  );

  const [sizeInput, setSizeInput] = useState<string>("1048576");
  const fileInputRef = useRef<HTMLInputElement>(null);

  const handleBegin = useCallback(() => {
    const parsed = parseInt(sizeInput, 10);
    if (!Number.isFinite(parsed) || parsed <= 0) return;
    void begin(parsed);
  }, [begin, sizeInput]);

  const handleFilePick = useCallback(
    async (event: React.ChangeEvent<HTMLInputElement>) => {
      const files = event.target.files;
      if (!files || files.length === 0) return;
      for (const file of Array.from(files)) {
        await addFile(file);
      }
      if (fileInputRef.current) fileInputRef.current.value = "";
    },
    [addFile],
  );

  const handleDrop = useCallback(
    async (event: React.DragEvent<HTMLDivElement>) => {
      event.preventDefault();
      const files = event.dataTransfer.files;
      if (!files || files.length === 0) return;
      for (const file of Array.from(files)) {
        await addFile(file);
      }
    },
    [addFile],
  );

  if (status === "idle" || !sessionId) {
    return (
      <EmptyState
        icon={<LiveConsensusIcon />}
        title={t("consensus.emptyTitle")}
        description={t("consensus.emptyDescription")}
        primaryCta={{ label: t("consensus.startSession"), onClick: handleBegin }}
        secondary={{ label: t("consensus.aboutConsensus"), href: "/docs/visualizations/consensus.md" }}
        data-testid="live-consensus-empty"
      >
        <label className="flex flex-col items-start gap-1 mt-[var(--space-3)] text-[var(--text-xs)]" style={{ color: "var(--md-text-secondary)" }}>
          <span>{t("consensus.sizeLabel")}</span>
          <input
            type="number"
            value={sizeInput}
            onChange={(e) => setSizeInput(e.target.value)}
            className="md-input w-40"
            min={1}
          />
        </label>
        {error && <p className="md-text-error mt-[var(--space-2)]">{error}</p>}
      </EmptyState>
    );
  }

  if (status === "finalized" && finalResult) {
    return (
      <div className="p-3 text-xs">
        <h3 className="font-semibold mb-2">{t("consensus.finalizedTitle")}</h3>
        <p className="md-text-muted mb-2">
          {t("consensus.finalizedSummary", { dumps: finalResult.num_dumps, bytes: finalResult.size.toLocaleString() })}
        </p>
        <table className="w-full max-w-sm mb-3">
          <tbody>
            {Object.entries(finalResult.classification_counts).map(
              ([cls, count]) => (
                <tr key={cls}>
                  <td className="pr-2 capitalize">{cls}</td>
                  <td className="text-right md-text-muted">
                    {count.toLocaleString()}
                  </td>
                </tr>
              ),
            )}
          </tbody>
        </table>
        <p className="md-text-muted mb-2">
          {t("consensus.varianceSummary", { mean: finalResult.variance_summary.mean.toFixed(2), max: finalResult.variance_summary.max.toFixed(2) })}
        </p>
        <button onClick={reset} className="md-button">
          {t("consensus.newSession")}
        </button>
      </div>
    );
  }

  return (
    <div className="p-3 text-xs">
      <div className="flex items-center justify-between mb-2">
        <h3 className="font-semibold">{t("consensus.title")}</h3>
        <span className="md-text-muted">
          {t("consensus.dumpSummary", { count: numDumps, bytes: size.toLocaleString() })}
        </span>
      </div>

      <div
        onDrop={handleDrop}
        onDragOver={(e) => e.preventDefault()}
        className="border border-dashed border-[var(--md-border)] rounded p-3 mb-2 text-center cursor-pointer md-bg-tertiary"
        onClick={() => fileInputRef.current?.click()}
      >
        {t("consensus.dropHint")}
        <input
          ref={fileInputRef}
          type="file"
          multiple
          hidden
          onChange={handleFilePick}
        />
      </div>

      <div className="flex items-center gap-3 mb-2">
        <Sparkline values={history} />
        <div className="text-[11px] md-text-muted">
          {liveStats ? (
            <>
              <div>{t("consensus.statMean", { value: liveStats.mean_variance.toFixed(2) })}</div>
              <div>{t("consensus.statMax", { value: liveStats.max_variance.toFixed(2) })}</div>
            </>
          ) : (
            <div>{t("consensus.noStats")}</div>
          )}
        </div>
      </div>

      {liveStats && liveStats.top_offsets.length > 0 && (
        <details className="mb-2">
          <summary className="cursor-pointer md-text-muted">
            {t("consensus.topOffsets")}
          </summary>
          <ul className="mt-1">
            {liveStats.top_offsets.map((t) => (
              <li key={t.offset} className="font-mono">
                0x{t.offset.toString(16)} → {t.variance.toFixed(1)}
              </li>
            ))}
          </ul>
        </details>
      )}

      <div className="flex gap-2">
        <button
          onClick={() => finalize()}
          disabled={numDumps < 2}
          className="md-button-primary disabled:opacity-50"
        >
          {t("consensus.finalize")}
        </button>
        <button onClick={reset} className="md-button">
          {t("common:cancel")}
        </button>
      </div>

      {error && <p className="md-text-error mt-2">{error}</p>}
    </div>
  );
}

import { useState, useCallback, useMemo, useRef } from "react";
import { useShallow } from "zustand/react/shallow";
import { useTranslation } from "react-i18next";
import { useConsensusIncrementalStore } from "@/stores/consensus-incremental-store";
import { useConsensusStore } from "@/stores/consensus-store";
import { useDumpStore, type DumpEntry } from "@/stores/dump-store";
import { importDumpFile } from "@/api/dump-import";
import { EmptyState } from "@/components/common/EmptyState";
import { LiveConsensusIcon } from "@/components/common/Icons";

/**
 * Consensus width used only when the session has no dumps at all.
 *
 * It used to be the hard-coded default for EVERY session, which silently
 * started a 1 MiB consensus over a 231 MB capture. The width now follows the
 * anchor dump; this constant is the last resort for an empty dump set, where
 * there is nothing to follow.
 */
const FALLBACK_SIZE = 1048576;

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

/**
 * What this live fold does NOT do, said out loud.
 *
 * The incremental path is flat-offset Welford (`build_incremental` /
 * `add_source`): every dump is truncated to the session width and compared
 * byte-for-byte at the same FILE offset. There is no ASLR/VA alignment, unlike
 * the batch `POST /api/analysis/consensus` path the Dumps tab runs. On `.msl`
 * captures that makes "the byte at offset X" a different byte in each dump, so
 * an analyst reading these variance numbers as ASLR-corrected would be reading
 * noise. Silent misalignment is the worst failure mode here, so the note is
 * always visible — it never blocks the action.
 */
function AlignmentNotes({
  selectedDumps,
  size,
}: {
  selectedDumps: DumpEntry[];
  size: number;
}) {
  const { t } = useTranslation("analysis");
  const hasMsl = selectedDumps.some((d) => d.format === "msl");
  const sizes = selectedDumps.map((d) => d.size);
  const smallest = sizes.length > 0 ? Math.min(...sizes) : 0;
  const sizesDiffer = new Set(sizes).size > 1;
  const exceedsSmallest = sizes.length > 0 && size > smallest;

  if (!hasMsl && !sizesDiffer && !exceedsSmallest) return null;

  return (
    <div className="mt-[var(--space-2)] space-y-1 text-left text-[11px]">
      {hasMsl && (
        <p
          data-testid="consensus-msl-note"
          style={{ color: "var(--md-accent-orange)" }}
        >
          {t("consensus.mslNoAlignmentNote")}
        </p>
      )}
      {sizesDiffer && (
        <p data-testid="consensus-truncation-note" className="md-text-muted">
          {t("consensus.truncationNote", { bytes: size.toLocaleString() })}
        </p>
      )}
      {exceedsSmallest && (
        <p
          data-testid="consensus-oversize-note"
          style={{ color: "var(--md-accent-orange)" }}
        >
          {t("consensus.oversizeNote", {
            bytes: size.toLocaleString(),
            smallest: smallest.toLocaleString(),
          })}
        </p>
      )}
    </div>
  );
}

/**
 * Live view of the consensus over THE dumps of this session.
 *
 * This tab used to be a second, unrelated inbox: it hard-coded a 1 MiB width,
 * knew nothing about the dumps already loaded, and its only ingestion path was
 * a browser upload that could not name a server-side dump. So adding a dump
 * here put it "not in relation to the dump of that session" — structurally, not
 * by accident.
 *
 * Now there is ONE dump set:
 *   - the session is seeded from `getSelectedDumpPaths()` and sized from the
 *     anchor dump (still editable);
 *   - the dropzone survives, but an upload through it takes the SAME route as
 *     the Import tab (`importDumpFile`) and is then folded in BY SERVER PATH;
 *   - Finalize is no longer a dead end — the finalized `session_id` is a valid
 *     `consensus_id` (one shared `ConsensusSessionManager`), so it is handed to
 *     `consensus-store` and the hex overlay can light up.
 */
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
    addPath,
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
      addPath: s.addPath,
      finalize: s.finalize,
      reset: s.reset,
    })),
  );

  const dumps = useDumpStore((s) => s.dumps);
  const selectedDumpIds = useDumpStore((s) => s.selectedDumpIds);
  const activeDumpId = useDumpStore((s) => s.activeDumpId);

  // Mirrors `getSelectedDumpPaths()`: an empty selection means "everything".
  const selectedDumps = useMemo(() => {
    if (selectedDumpIds.length === 0) return dumps;
    const chosen = new Set(selectedDumpIds);
    return dumps.filter((d) => chosen.has(d.id));
  }, [dumps, selectedDumpIds]);

  // The anchor pane is the alignment anchor everywhere else in the app, so it
  // is also the dump whose length sets the consensus width.
  const anchorDump = useMemo(
    () =>
      selectedDumps.find((d) => d.id === activeDumpId) ?? selectedDumps[0] ?? null,
    [selectedDumps, activeDumpId],
  );

  // `null` means "still following the anchor dump". The control stays fully
  // editable; typing in it simply stops the default from moving underneath the
  // analyst.
  const [sizeOverride, setSizeOverride] = useState<string | null>(null);
  const defaultSize = anchorDump?.size ?? FALLBACK_SIZE;
  const sizeInput = sizeOverride ?? String(defaultSize);
  const parsedSize = parseInt(sizeInput, 10);

  const [importing, setImporting] = useState<string | null>(null);
  const [importError, setImportError] = useState<string | null>(null);
  const fileInputRef = useRef<HTMLInputElement>(null);

  const handleBegin = useCallback(async () => {
    if (!Number.isFinite(parsedSize) || parsedSize <= 0) return;
    await begin(parsedSize);
    if (!useConsensusIncrementalStore.getState().sessionId) return;
    // Seed from the dumps the analyst already selected, by SERVER PATH — the
    // one thing the old upload-only channel could never do.
    for (const path of useDumpStore.getState().getSelectedDumpPaths()) {
      await addPath(path);
    }
  }, [addPath, begin, parsedSize]);

  const handleFiles = useCallback(
    async (files: File[]) => {
      setImportError(null);
      for (const file of files) {
        setImporting(file.name);
        try {
          // Same import as the Import tab: upload, convert, register in the
          // dump store (which selects it), THEN fold it in by server path.
          const imported = await importDumpFile(file);
          await addPath(imported.path);
        } catch (err) {
          setImportError(err instanceof Error ? err.message : String(err));
        }
      }
      setImporting(null);
    },
    [addPath],
  );

  const handleFilePick = useCallback(
    async (event: React.ChangeEvent<HTMLInputElement>) => {
      const files = event.target.files;
      if (!files || files.length === 0) return;
      await handleFiles(Array.from(files));
      if (fileInputRef.current) fileInputRef.current.value = "";
    },
    [handleFiles],
  );

  const handleDrop = useCallback(
    async (event: React.DragEvent<HTMLDivElement>) => {
      event.preventDefault();
      const files = event.dataTransfer.files;
      if (!files || files.length === 0) return;
      await handleFiles(Array.from(files));
    },
    [handleFiles],
  );

  const handleFinalize = useCallback(async () => {
    await finalize();
    const finished = useConsensusIncrementalStore.getState();
    if (finished.status !== "finalized" || !finished.finalResult) return;
    // The finalized session id IS a consensus id: one process-wide
    // `ConsensusSessionManager` backs both routers, and
    // `/analysis/consensus/range` resolves it through `manager.get(...)`.
    useConsensusStore.getState().adoptIncremental({
      consensusId: finished.finalResult.session_id,
      size: finished.finalResult.size,
      numDumps: finished.finalResult.num_dumps,
      counts: finished.finalResult.classification_counts,
    });
  }, [finalize]);

  const handleShowOverlay = useCallback(() => {
    useConsensusStore.getState().setOverlayEnabled(true);
  }, []);

  if (status === "idle" || !sessionId) {
    return (
      <EmptyState
        icon={<LiveConsensusIcon />}
        title={t("consensus.emptyTitle")}
        description={t("consensus.emptyDescription")}
        primaryCta={{
          label: t("consensus.startSession"),
          onClick: () => void handleBegin(),
        }}
        secondary={{ label: t("consensus.aboutConsensus"), doc: "visualizations/consensus.md" }}
        data-testid="live-consensus-empty"
      >
        <div
          className="mt-[var(--space-3)] w-full text-left text-[var(--text-xs)]"
          style={{ color: "var(--md-text-secondary)" }}
          data-testid="consensus-seed-list"
        >
          <p className="font-semibold">{t("consensus.seedHeading")}</p>
          {selectedDumps.length === 0 ? (
            <p className="md-text-muted">{t("consensus.seedEmpty")}</p>
          ) : (
            <ul className="mt-1">
              {selectedDumps.map((d) => (
                <li key={d.id} className="font-mono truncate" title={d.path}>
                  {d.id === anchorDump?.id
                    ? t("consensus.seedAnchorEntry", {
                        name: d.name,
                        bytes: d.size.toLocaleString(),
                      })
                    : t("consensus.seedEntry", {
                        name: d.name,
                        bytes: d.size.toLocaleString(),
                      })}
                </li>
              ))}
            </ul>
          )}
        </div>

        <label className="flex flex-col items-start gap-1 mt-[var(--space-3)] text-[var(--text-xs)]" style={{ color: "var(--md-text-secondary)" }}>
          <span>{t("consensus.sizeLabel")}</span>
          <input
            type="number"
            data-testid="consensus-size-input"
            value={sizeInput}
            onChange={(e) => setSizeOverride(e.target.value)}
            className="md-input w-40"
            min={1}
          />
          <span className="md-text-muted">
            {anchorDump
              ? t("consensus.sizeHintAnchor", { name: anchorDump.name })
              : t("consensus.sizeHintNoAnchor")}
          </span>
        </label>

        <AlignmentNotes
          selectedDumps={selectedDumps}
          size={Number.isFinite(parsedSize) ? parsedSize : 0}
        />

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
        <div className="flex gap-2">
          <button
            onClick={handleShowOverlay}
            data-testid="consensus-show-overlay"
            className="md-button-primary"
          >
            {t("consensus.showInOverlay")}
          </button>
          <button onClick={reset} className="md-button">
            {t("consensus.newSession")}
          </button>
        </div>
        <AlignmentNotes selectedDumps={selectedDumps} size={finalResult.size} />
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
        data-testid="consensus-dropzone"
        className="border border-dashed border-[var(--md-border)] rounded p-3 mb-2 text-center cursor-pointer md-bg-tertiary"
        onClick={() => fileInputRef.current?.click()}
      >
        {importing ? t("consensus.importing", { name: importing }) : t("consensus.dropHint")}
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
            {liveStats.top_offsets.map((entry) => (
              <li key={entry.offset} className="font-mono">
                0x{entry.offset.toString(16)} → {entry.variance.toFixed(1)}
              </li>
            ))}
          </ul>
        </details>
      )}

      <div className="flex gap-2">
        <button
          onClick={() => void handleFinalize()}
          disabled={numDumps < 2}
          className="md-button-primary disabled:opacity-50"
        >
          {t("consensus.finalize")}
        </button>
        <button onClick={reset} className="md-button">
          {t("common:cancel")}
        </button>
      </div>

      <AlignmentNotes selectedDumps={selectedDumps} size={size} />

      {importError && <p className="md-text-error mt-2">{importError}</p>}
      {error && <p className="md-text-error mt-2">{error}</p>}
    </div>
  );
}

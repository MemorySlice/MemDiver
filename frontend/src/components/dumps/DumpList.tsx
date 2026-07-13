import { useTranslation } from "react-i18next";
import { useDumpStore } from "../../stores/dump-store";
import { useConsensusStore } from "../../stores/consensus-store";
import { useAppStore } from "@/stores/app-store";
import { AddDumpButton } from "./AddDumpButton";
import { TagStatusBadge } from "./TagStatusBadge";
import { TagStatusUnlock } from "./TagStatusUnlock";

function formatSize(bytes: number): string {
  if (bytes < 0) return "--";
  if (bytes === 0) return "0 B";
  return `${(bytes / 1024).toFixed(1)} KB`;
}

export function DumpList() {
  const { t } = useTranslation("dumps");
  const dumps = useDumpStore((s) => s.dumps);
  const activeDumpId = useDumpStore((s) => s.activeDumpId);
  const setActiveDump = useDumpStore((s) => s.setActiveDump);
  const removeDump = useDumpStore((s) => s.removeDump);
  const toggleSameProcess = useDumpStore((s) => s.toggleSameProcess);
  const aslrNormalize = useDumpStore((s) => s.aslrNormalize);
  const toggleAslrNormalize = useDumpStore((s) => s.toggleAslrNormalize);
  const getDumpPaths = useDumpStore((s) => s.getDumpPaths);

  const consensusLoading = useConsensusStore((s) => s.loading);
  const consensusError = useConsensusStore((s) => s.error);
  const consensusAvailable = useConsensusStore((s) => s.available);
  const consensusCounts = useConsensusStore((s) => s.counts);
  const overlayEnabled = useConsensusStore((s) => s.overlayEnabled);
  const toggleOverlay = useConsensusStore((s) => s.toggleOverlay);
  const runConsensus = useConsensusStore((s) => s.runConsensus);

  const mode = useAppStore((s) => s.mode);
  const canRunConsensus = dumps.length >= 2 && !consensusLoading;
  const allRaw = dumps.length > 0 && dumps.every((d) => d.format === "raw");

  const handleRunConsensus = () => {
    runConsensus(getDumpPaths(), aslrNormalize);
  };

  return (
    <div className="p-3 space-y-3 text-xs">
      <h3 className="text-sm font-semibold md-text-accent">{t("list.title")}</h3>

      <AddDumpButton />

      {dumps.length === 0 ? (
        <p className="md-text-muted">{t("list.empty")}</p>
      ) : (
        <div className="space-y-1">
          {dumps.map((d) => (
            <div
              key={d.id}
              onClick={() => setActiveDump(d.id)}
              className="flex items-center gap-2 p-2 rounded cursor-pointer hover:bg-[var(--md-bg-hover)]"
              style={{
                border: d.id === activeDumpId
                  ? "1.5px solid var(--md-accent)"
                  : "1px solid var(--md-border)",
              }}
            >
              <div className="flex-1 min-w-0">
                <div className="font-mono truncate" title={d.path}>{d.name}</div>
                <div className="flex items-center gap-2 mt-0.5 md-text-muted">
                  <span>{formatSize(d.size)}</span>
                  <span
                    className="px-1.5 py-0.5 rounded text-[10px] font-semibold uppercase"
                    style={{
                      background: d.format === "msl"
                        ? "var(--md-accent)"
                        : "var(--md-bg-tertiary)",
                      color: d.format === "msl"
                        ? "var(--md-bg-primary)"
                        : "var(--md-text-primary)",
                    }}
                  >
                    {d.format}
                  </span>
                  <TagStatusBadge status={d.tagStatus} />
                </div>
                {d.tagStatus === "missing_key" && (
                  <TagStatusUnlock dumpId={d.id} />
                )}
              </div>

              <label
                className="flex items-center gap-1 text-[10px] md-text-muted"
                onClick={(e) => e.stopPropagation()}
                title={t("list.sameTitle")}
              >
                <input
                  type="checkbox"
                  checked={d.sameProcess}
                  onChange={() => toggleSameProcess(d.id)}
                />
                {t("list.sameLabel")}
              </label>

              <button
                onClick={(e) => { e.stopPropagation(); removeDump(d.id); }}
                className="px-1 hover:text-[var(--md-accent-red)]"
                title={t("list.removeTitle")}
              >
                x
              </button>
            </div>
          ))}
        </div>
      )}

      {mode === "exploration" && (
        <>
          <hr className="border-[var(--md-border)]" />

          <div className="space-y-2">
            <label
              className={`flex items-center gap-2 ${allRaw ? "opacity-50 cursor-not-allowed" : "cursor-pointer"}`}
              title={allRaw ? t("consensus.aslrDisabledTitle") : undefined}
            >
              <input
                type="checkbox"
                checked={aslrNormalize}
                onChange={toggleAslrNormalize}
                disabled={allRaw}
              />
              <span>{t("consensus.aslrLabel")}</span>
            </label>
            {allRaw && (
              <p className="text-[10px] md-text-muted ml-5">
                {t("consensus.aslrHint")}
              </p>
            )}

            <button
              onClick={handleRunConsensus}
              disabled={!canRunConsensus}
              className="w-full px-3 py-1.5 text-xs font-medium rounded border border-[var(--md-border)] hover:bg-[var(--md-bg-hover)] disabled:opacity-40"
            >
              {consensusLoading ? t("consensus.running") : t("consensus.run")}
            </button>

            {consensusLoading && (
              <div className="flex items-center gap-2 md-text-muted">
                <span className="inline-block w-3 h-3 border-2 border-current border-t-transparent rounded-full animate-spin" />
                {t("consensus.computing")}
              </div>
            )}

            {consensusError && (
              <p className="text-[var(--md-accent-red)]">{consensusError}</p>
            )}

            {consensusAvailable && consensusCounts && (
              <div className="md-text-muted space-y-0.5">
                {Object.entries(consensusCounts).map(([label, count]) => (
                  <div key={label} className="flex justify-between">
                    <span>{label}</span>
                    <span className="font-mono">{count}</span>
                  </div>
                ))}
              </div>
            )}

            <label className="flex items-center gap-2 cursor-pointer">
              <input
                type="checkbox"
                checked={overlayEnabled}
                onChange={toggleOverlay}
                disabled={!consensusAvailable}
              />
              <span className={!consensusAvailable ? "opacity-40" : ""}>
                {t("consensus.overlayLabel")}
              </span>
            </label>
          </div>
        </>
      )}
    </div>
  );
}

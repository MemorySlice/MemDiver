import { useDumpStore } from "../../stores/dump-store";
import { useConsensusStore } from "../../stores/consensus-store";
import { useAppStore } from "@/stores/app-store";
import { AddDumpButton } from "./AddDumpButton";

function formatSize(bytes: number): string {
  if (bytes === 0) return "--";
  return `${(bytes / 1024).toFixed(1)} KB`;
}

export function DumpList() {
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
      <h3 className="text-sm font-semibold md-text-accent">Loaded Dumps</h3>

      <AddDumpButton />

      {dumps.length === 0 ? (
        <p className="md-text-muted">No dumps loaded.</p>
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
                </div>
              </div>

              <label
                className="flex items-center gap-1 text-[10px] md-text-muted"
                onClick={(e) => e.stopPropagation()}
                title="Mark as same process for consensus"
              >
                <input
                  type="checkbox"
                  checked={d.sameProcess}
                  onChange={() => toggleSameProcess(d.id)}
                />
                Same
              </label>

              <button
                onClick={(e) => { e.stopPropagation(); removeDump(d.id); }}
                className="px-1 hover:text-[var(--md-accent-red)]"
                title="Remove dump"
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
              title={allRaw ? "ASLR normalization requires MSL files with region metadata" : undefined}
            >
              <input
                type="checkbox"
                checked={aslrNormalize}
                onChange={toggleAslrNormalize}
                disabled={allRaw}
              />
              <span>ASLR Normalization</span>
            </label>
            {allRaw && (
              <p className="text-[10px] md-text-muted ml-5">
                Convert to MSL via Import tab for ASLR support
              </p>
            )}

            <button
              onClick={handleRunConsensus}
              disabled={!canRunConsensus}
              className="w-full px-3 py-1.5 text-xs font-medium rounded border border-[var(--md-border)] hover:bg-[var(--md-bg-hover)] disabled:opacity-40"
            >
              {consensusLoading ? "Running..." : "Run Consensus"}
            </button>

            {consensusLoading && (
              <div className="flex items-center gap-2 md-text-muted">
                <span className="inline-block w-3 h-3 border-2 border-current border-t-transparent rounded-full animate-spin" />
                Computing consensus...
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
                Show overlay in hex view
              </span>
            </label>
          </div>
        </>
      )}
    </div>
  );
}

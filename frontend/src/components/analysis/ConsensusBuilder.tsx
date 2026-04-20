import { useState, useCallback, useRef } from "react";
import { useConsensusIncrementalStore } from "@/stores/consensus-incremental-store";

function Sparkline({ values }: { values: number[] }) {
  if (values.length < 2) {
    return (
      <div className="h-10 flex items-center text-[10px] md-text-muted">
        sparkline appears after 2+ dumps
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
      aria-label="max variance over time"
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
  } = useConsensusIncrementalStore();

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
      <div className="p-3 text-xs">
        <h3 className="font-semibold mb-2">Incremental Consensus</h3>
        <p className="md-text-muted mb-2">
          Fold dumps into a consensus matrix one at a time. Suitable for live
          investigations where dumps arrive sequentially.
        </p>
        <label className="block mb-1">Consensus size (bytes)</label>
        <input
          type="number"
          value={sizeInput}
          onChange={(e) => setSizeInput(e.target.value)}
          className="md-input w-40 mr-2"
          min={1}
        />
        <button onClick={handleBegin} className="md-button-primary">
          Start session
        </button>
        {error && <p className="text-red-500 mt-2">{error}</p>}
      </div>
    );
  }

  if (status === "finalized" && finalResult) {
    return (
      <div className="p-3 text-xs">
        <h3 className="font-semibold mb-2">Incremental Consensus — Finalized</h3>
        <p className="md-text-muted mb-2">
          {finalResult.num_dumps} dumps / {finalResult.size.toLocaleString()} bytes
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
          mean var {finalResult.variance_summary.mean.toFixed(2)}, max{" "}
          {finalResult.variance_summary.max.toFixed(2)}
        </p>
        <button onClick={reset} className="md-button">
          New session
        </button>
      </div>
    );
  }

  return (
    <div className="p-3 text-xs">
      <div className="flex items-center justify-between mb-2">
        <h3 className="font-semibold">Incremental Consensus</h3>
        <span className="md-text-muted">
          {numDumps} dump{numDumps === 1 ? "" : "s"} · {size.toLocaleString()} bytes
        </span>
      </div>

      <div
        onDrop={handleDrop}
        onDragOver={(e) => e.preventDefault()}
        className="border border-dashed border-[var(--md-border)] rounded p-3 mb-2 text-center cursor-pointer md-bg-tertiary"
        onClick={() => fileInputRef.current?.click()}
      >
        Drop a .dump or .msl here, or click to pick.
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
              <div>mean {liveStats.mean_variance.toFixed(2)}</div>
              <div>max {liveStats.max_variance.toFixed(2)}</div>
            </>
          ) : (
            <div>no stats yet</div>
          )}
        </div>
      </div>

      {liveStats && liveStats.top_offsets.length > 0 && (
        <details className="mb-2">
          <summary className="cursor-pointer md-text-muted">
            top variance offsets
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
          Finalize
        </button>
        <button onClick={reset} className="md-button">
          Cancel
        </button>
      </div>

      {error && <p className="text-red-500 mt-2">{error}</p>}
    </div>
  );
}

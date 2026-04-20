import { useState, useCallback, useMemo } from "react";
import { runAnalysis } from "@/api/client";
import { useResultsStore, type SortField } from "@/stores/results-store";
import { useAppStore } from "@/stores/app-store";
import { downloadJsonFile } from "@/utils/download";
import { secretTypeToHighlight } from "@/utils/highlight-types";
import { applyHitsToStores } from "@/utils/apply-hits";
import type { SecretHit } from "@/api/types";

const MAX_VISIBLE = 100;

function hexOffset(offset: number): string {
  return `0x${offset.toString(16).toUpperCase().padStart(8, "0")}`;
}

export function ScanResultsPanel() {
  const { algorithmResults, filterAlgorithm, sortField, sortDirection, setFilter, setSort, getFilteredHits, getTotalHitCount } = useResultsStore();
  const [collapsed, setCollapsed] = useState<Record<string, boolean>>({});

  const algos = Object.keys(algorithmResults);
  const filtered = useMemo(() => getFilteredHits(), [algorithmResults, filterAlgorithm, sortField, sortDirection]);
  const totalCount = useMemo(() => getTotalHitCount(), [algorithmResults]);

  const toggleCollapse = useCallback((algo: string) => {
    setCollapsed((prev) => ({ ...prev, [algo]: !prev[algo] }));
  }, []);

  const cycleSort = useCallback((field: SortField) => {
    if (sortField === field) {
      setSort(field, sortDirection === "asc" ? "desc" : "asc");
    } else {
      setSort(field, "asc");
    }
  }, [sortField, sortDirection, setSort]);

  const handleRowClick = useCallback((offset: number, length: number) => {
    useAppStore.getState().setHexFocus({ offset, length });
  }, []);

  const buildRequest = useCallback(() => {
    const { selectedLibraries, selectedPhase, protocolVersion, datasetRoot, keylogFilename } = useAppStore.getState();
    if (!selectedLibraries.length || !selectedPhase || !protocolVersion) return null;
    return {
      library_dirs: selectedLibraries.map((lib) => `${datasetRoot}/${lib}`),
      phase: selectedPhase,
      protocol_version: protocolVersion,
      keylog_filename: keylogFilename,
    };
  }, []);

  const bridgeResults = useCallback((res: { libraries: { hits: SecretHit[] }[] }) => {
    applyHitsToStores(res, false);
  }, []);

  const handleRerun = useCallback(async (algo: string) => {
    const req = buildRequest();
    if (!req) return;
    const resultsState = useResultsStore.getState();
    resultsState.setAlgorithmRunning(algo, true);
    try {
      const res = await runAnalysis(req);
      bridgeResults(res);
    } catch (e) {
      resultsState.setAlgorithmError?.(algo, e instanceof Error ? e.message : "Re-run failed");
    } finally {
      useResultsStore.getState().setAlgorithmRunning(algo, false);
    }
  }, [buildRequest, bridgeResults]);

  const handleRerunAll = useCallback(async () => {
    const req = buildRequest();
    if (!req) return;
    const resultsState = useResultsStore.getState();
    for (const algo of Object.keys(resultsState.algorithmResults)) {
      resultsState.setAlgorithmRunning(algo, true);
    }
    try {
      const res = await runAnalysis(req);
      bridgeResults(res);
    } catch {
      // errors are visible per-algorithm
    } finally {
      const state = useResultsStore.getState();
      for (const algo of Object.keys(state.algorithmResults)) {
        state.setAlgorithmRunning(algo, false);
      }
    }
  }, [buildRequest, bridgeResults]);

  if (algos.length === 0) {
    return (
      <div className="p-4 text-center md-text-muted text-xs">
        Run analysis to see results here.
      </div>
    );
  }

  // Group filtered hits by algorithm
  const grouped: Record<string, typeof filtered> = {};
  for (const item of filtered) {
    (grouped[item.algorithm] ??= []).push(item);
  }

  return (
    <div className="p-2 space-y-2 text-xs">
      {/* Toolbar */}
      <div className="flex items-center gap-2 flex-wrap">
        <select value={filterAlgorithm ?? ""} onChange={(e) => setFilter(e.target.value || null)}
          className="px-1.5 py-1 rounded border border-[var(--md-border)] bg-[var(--md-bg-secondary)] text-[var(--md-text-primary)] text-xs">
          <option value="">All Algorithms</option>
          {algos.map((a) => <option key={a} value={a}>{a}</option>)}
        </select>

        {(["offset", "confidence", "length"] as SortField[]).map((f) => (
          <button key={f} onClick={() => cycleSort(f)}
            className="px-1.5 py-1 rounded border border-[var(--md-border)] hover:bg-[var(--md-bg-hover)] transition-colors"
            style={sortField === f ? { borderColor: "var(--md-accent-blue)", color: "var(--md-accent-blue)" } : undefined}>
            {f}{sortField === f ? (sortDirection === "asc" ? " \u2191" : " \u2193") : ""}
          </button>
        ))}

        <button onClick={handleRerunAll}
          className="px-2 py-1 rounded border border-[var(--md-border)] hover:bg-[var(--md-bg-hover)] ml-auto transition-colors"
          style={{ borderColor: "var(--md-accent-blue)", color: "var(--md-accent-blue)" }}>
          Re-run All
        </button>

        <button onClick={() => downloadJsonFile(filtered, "memdiver-results.json")}
          className="px-2 py-1 rounded border border-[var(--md-border)] hover:bg-[var(--md-bg-hover)] transition-colors">
          Export JSON
        </button>

        <span className="md-text-muted whitespace-nowrap">{totalCount} hits</span>
      </div>

      {/* Algorithm sections */}
      {algos.map((algo) => {
        const entry = algorithmResults[algo];
        const isCollapsed = collapsed[algo] ?? false;
        const hits = grouped[algo] ?? [];
        const overflow = hits.length > MAX_VISIBLE;

        return (
          <div key={algo} className="border border-[var(--md-border)] rounded">
            {/* Section header */}
            <button onClick={() => toggleCollapse(algo)}
              className="w-full flex items-center gap-2 px-2 py-1.5 hover:bg-[var(--md-bg-hover)] transition-colors text-left">
              <span className="font-mono">{isCollapsed ? "\u25B6" : "\u25BC"}</span>
              <span
                className="inline-block w-2.5 h-2.5 rounded-full flex-shrink-0"
                style={{ background: `var(--md-hl-${secretTypeToHighlight(algo)})` }}
              />
              <span className="font-medium">{algo}</span>
              <span className="px-1.5 rounded-full text-[10px]"
                style={{ background: "var(--md-accent-blue)", color: "#fff" }}>
                {entry.hits.length}
              </span>
              {entry.running && (
                <span className="ml-1 animate-spin inline-block w-3 h-3 border border-t-transparent rounded-full"
                  style={{ borderColor: "var(--md-accent-blue)", borderTopColor: "transparent" }} />
              )}
              {entry.error && <span style={{ color: "var(--md-accent-red)" }} className="ml-1 truncate">{entry.error}</span>}
              <button
                className="ml-auto px-1.5 py-0.5 rounded border border-[var(--md-border)] hover:bg-[var(--md-bg-hover)] text-[10px] transition-colors"
                disabled={entry.running}
                onClick={(e) => { e.stopPropagation(); handleRerun(algo); }}>
                {entry.running ? "Running..." : "Re-run"}
              </button>
            </button>

            {/* Result rows */}
            {!isCollapsed && hits.length > 0 && (
              <table className="w-full text-[10px]">
                <thead>
                  <tr className="md-text-muted border-t border-[var(--md-border)]">
                    {([["Offset", "offset"], ["Len", "length"], ["Conf", "confidence"], ["Type", "algorithm"]] as const).map(([label, field]) => (
                      <th
                        key={field}
                        className="text-left px-2 py-0.5 cursor-pointer select-none hover:text-[var(--md-accent-blue)] transition-colors"
                        onClick={() => cycleSort(field as SortField)}
                      >
                        {label}{sortField === field ? (sortDirection === "asc" ? " \u2191" : " \u2193") : ""}
                      </th>
                    ))}
                  </tr>
                </thead>
                <tbody>
                  {hits.slice(0, MAX_VISIBLE).map(({ hit }, i) => (
                    <tr key={i}
                      onClick={() => handleRowClick(hit.offset, hit.length)}
                      className="cursor-pointer hover:bg-[var(--md-bg-hover)] transition-colors border-t border-[var(--md-border)]">
                      <td className="px-2 py-0.5 font-mono">{hexOffset(hit.offset)}</td>
                      <td className="px-2 py-0.5">{hit.length}</td>
                      <td className="px-2 py-0.5">{hit.confidence != null ? `${Math.round(hit.confidence * 100)}%` : "\u2014"}</td>
                      <td className="px-2 py-0.5">{hit.secret_type}</td>
                    </tr>
                  ))}
                  {overflow && (
                    <tr><td colSpan={4} className="px-2 py-1 md-text-muted">...and {hits.length - MAX_VISIBLE} more</td></tr>
                  )}
                </tbody>
              </table>
            )}

            {!isCollapsed && hits.length === 0 && !entry.running && (
              <div className="px-2 py-1 md-text-muted border-t border-[var(--md-border)]">No hits</div>
            )}
          </div>
        );
      })}
    </div>
  );
}

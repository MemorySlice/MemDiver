import { useCallback, useEffect, useState } from "react";
import { listSessions, loadSession, deleteSession } from "@/api/client";
import type { SessionInfo, SecretHit } from "@/api/types";
import { useAppStore } from "@/stores/app-store";
import { useAnalysisStore } from "@/stores/analysis-store";
import { useResultsStore } from "@/stores/results-store";
import { ThemeToggle } from "@/components/ThemeToggle";

const MODE_LABELS: Record<string, string> = {
  single_file: "File",
  run_directory: "Directory",
  dataset: "Dataset",
};

function formatDate(iso: string): string {
  if (!iso) return "";
  try {
    return new Date(iso).toLocaleString();
  } catch {
    return iso;
  }
}

export function SessionLanding() {
  const [sessions, setSessions] = useState<SessionInfo[]>([]);
  const [loading, setLoading] = useState(true);
  const [loadingSession, setLoadingSession] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const setAppView = useAppStore((s) => s.setAppView);

  const refresh = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const data = await listSessions();
      setSessions(data.sessions);
    } catch (e) {
      setError(e instanceof Error ? e.message : "Failed to load sessions");
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => { refresh(); }, [refresh]);

  const handleLoad = async (name: string) => {
    setLoadingSession(name);
    try {
      const snap = await loadSession(name);
      useAppStore.getState().restoreSession(snap);
      if (snap.analysis_result) {
        const setResult = useAnalysisStore.getState().setResult;
        setResult(snap.analysis_result as unknown as Parameters<typeof setResult>[0]);
        const libs = (snap.analysis_result as { libraries?: { hits?: unknown[] }[] }).libraries ?? [];
        const hits = libs.flatMap((l) => l.hits ?? []);
        if (hits.length > 0) {
          useResultsStore.getState().setAlgorithmResults("restored", hits as SecretHit[]);
        }
      }
    } catch (e) {
      setError(e instanceof Error ? e.message : "Failed to load session");
      setLoadingSession(null);
    }
  };

  const handleDelete = async (name: string) => {
    if (!window.confirm(`Delete session "${name}"?`)) return;
    try {
      await deleteSession(name);
      refresh();
    } catch {
      // ignore
    }
  };

  return (
    <div className="h-screen flex flex-col" style={{ background: "var(--md-bg-primary)" }}>
      {/* Header */}
      <div className="flex items-center justify-between px-6 py-4 border-b border-[var(--md-border)]">
        <div className="flex items-center gap-3">
          <img src="/memdiver-logo.svg" alt="" className="h-8 w-8" />
          <span className="text-xl font-bold md-text-accent">MemDiver</span>
        </div>
        <ThemeToggle />
      </div>

      {/* Content */}
      <div className="flex-1 overflow-auto flex items-start justify-center pt-12 px-4">
        <div className="w-full max-w-2xl space-y-6">
          <div className="flex items-center justify-between">
            <h2 className="text-lg font-semibold">Sessions</h2>
            <button
              onClick={() => setAppView("wizard")}
              className="px-4 py-2 rounded text-white text-sm font-medium transition-opacity hover:opacity-90"
              style={{ background: "var(--md-accent-blue)" }}
            >
              New Session
            </button>
          </div>

          {loading ? (
            <p className="text-sm md-text-muted py-8 text-center">Loading sessions...</p>
          ) : error ? (
            <div className="text-center py-8 space-y-2">
              <p className="text-sm" style={{ color: "var(--md-accent-red)" }}>{error}</p>
              <button onClick={refresh} className="text-xs px-2 py-1 rounded border border-[var(--md-border)] hover:bg-[var(--md-bg-hover)]">
                Retry
              </button>
            </div>
          ) : sessions.length === 0 ? (
            <div className="text-center py-12 space-y-3">
              <p className="text-sm md-text-muted">No saved sessions yet.</p>
              <p className="text-xs md-text-muted">Click "New Session" to start analyzing a memory dump.</p>
            </div>
          ) : (
            <div className="space-y-2">
              {sessions.map((s) => (
                <div
                  key={s.path}
                  className="md-panel p-3 flex items-center gap-3 hover:bg-[var(--md-bg-hover)] transition-colors rounded"
                >
                  <div className="flex-1 min-w-0">
                    <div className="flex items-center gap-2">
                      <span className="font-medium text-sm truncate">{s.display_name || s.name}</span>
                      {s.input_mode && (
                        <span
                          className="text-[10px] px-1.5 py-0.5 rounded uppercase shrink-0"
                          style={{
                            background: "var(--md-accent-blue)",
                            color: "white",
                            opacity: 0.8,
                          }}
                        >
                          {MODE_LABELS[s.input_mode] ?? s.input_mode}
                        </span>
                      )}
                      {s.mode && (
                        <span className="text-[10px] md-text-muted shrink-0">{s.mode}</span>
                      )}
                    </div>
                    {s.input_path && (
                      <p className="text-xs md-text-muted font-mono truncate mt-0.5" title={s.input_path}>
                        {s.input_path}
                      </p>
                    )}
                    {s.created_at && (
                      <p className="text-[10px] md-text-muted mt-0.5">{formatDate(s.created_at)}</p>
                    )}
                  </div>
                  <div className="flex gap-2 shrink-0">
                    <button
                      onClick={() => handleLoad(s.name)}
                      disabled={loadingSession === s.name}
                      className="px-3 py-1 text-xs rounded border border-[var(--md-border)] hover:bg-[var(--md-accent-blue)] hover:text-white transition-colors disabled:opacity-50"
                    >
                      {loadingSession === s.name ? "Loading..." : "Load"}
                    </button>
                    <button
                      onClick={() => handleDelete(s.name)}
                      className="px-2 py-1 text-xs rounded border border-[var(--md-border)] hover:bg-[var(--md-accent-red)] hover:text-white transition-colors"
                    >
                      Delete
                    </button>
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

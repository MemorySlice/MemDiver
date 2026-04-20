import { useCallback, useEffect, useState } from "react";
import { listSessions, saveSession, loadSession, deleteSession } from "@/api/client";
import type { SessionInfo } from "@/api/types";
import { useAppStore } from "@/stores/app-store";
import { useAnalysisStore } from "@/stores/analysis-store";
import { applyFlatHitsToStore } from "@/utils/apply-hits";
import { buildSessionSnapshot } from "@/utils/buildSessionSnapshot";

export function SessionManager() {
  const [sessions, setSessions] = useState<SessionInfo[]>([]);
  const [loading, setLoading] = useState(false);
  const [saveName, setSaveName] = useState("");
  const [message, setMessage] = useState<string | null>(null);

  // Only reads one action and no state fields — grab the action directly
  // so the component stays out of every app-store subscriber's re-render
  // cycle. Actions in Zustand are stable references, so this never
  // re-renders from store changes.
  const restoreSession = useAppStore((s) => s.restoreSession);
  const setResult = useAnalysisStore((s) => s.setResult);

  const refresh = useCallback(async () => {
    setLoading(true);
    try {
      const data = await listSessions();
      setSessions(data.sessions);
    } catch {
      // silently ignore — sessions may not be available
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => { refresh(); }, [refresh]);

  const handleSave = async () => {
    try {
      await saveSession(buildSessionSnapshot(saveName || "session"));
      setMessage("Session saved");
      setSaveName("");
      refresh();
    } catch (e) {
      setMessage(e instanceof Error ? e.message : "Save failed");
    }
  };

  const handleLoad = async (name: string) => {
    try {
      const snap = await loadSession(name);
      restoreSession(snap);
      if (snap.analysis_result) {
        setResult(snap.analysis_result as unknown as Parameters<typeof setResult>[0]);
        const libs = (snap.analysis_result as { libraries?: { hits?: unknown[] }[] }).libraries ?? [];
        const hits = libs.flatMap((l) => l.hits ?? []);
        if (hits.length > 0) {
          applyFlatHitsToStore(hits);
        }
      }
      setMessage(`Loaded: ${name}`);
    } catch (e) {
      setMessage(e instanceof Error ? e.message : "Load failed");
    }
  };

  const handleDelete = async (name: string) => {
    try {
      await deleteSession(name);
      refresh();
    } catch {
      // ignore
    }
  };

  return (
    <div className="p-3 space-y-3 text-xs">
      <h3 className="text-sm font-semibold md-text-accent">Sessions</h3>

      <div className="flex gap-1">
        <input
          value={saveName}
          onChange={(e) => setSaveName(e.target.value)}
          placeholder="Session name"
          className="flex-1 px-1.5 py-0.5 rounded border border-[var(--md-border)] bg-[var(--md-bg-secondary)]"
        />
        <button onClick={handleSave}
          className="px-2 py-0.5 rounded border border-[var(--md-border)] hover:bg-[var(--md-bg-hover)]">
          Save
        </button>
      </div>

      {message && <p className="md-text-muted">{message}</p>}

      {loading ? (
        <p className="md-text-muted">Loading sessions...</p>
      ) : sessions.length === 0 ? (
        <p className="md-text-muted">No saved sessions.</p>
      ) : (
        <div className="space-y-1">
          {sessions.map((s) => (
            <div key={s.path} className="flex items-center justify-between p-1.5 rounded hover:bg-[var(--md-bg-hover)]">
              <div className="flex-1 min-w-0">
                <div className="font-medium truncate" title={s.display_name || s.name}>{s.display_name || s.name}</div>
                <div className="md-text-muted truncate" title={`${s.created_at} | ${s.mode}`}>{s.created_at} | {s.mode}</div>
              </div>
              <div className="flex gap-1 ml-2 shrink-0">
                <button onClick={() => handleLoad(s.name)}
                  className="px-1 hover:text-[var(--md-accent-blue)]">
                  Load
                </button>
                <button onClick={() => handleDelete(s.name)}
                  className="px-1 hover:text-[var(--md-accent-red)]">
                  x
                </button>
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

/**
 * Oracle upload + arm workflow.
 *
 * Steps surfaced to the user, in order:
 *  1. Drop or browse for a ``.py`` file (≤1 MB).
 *  2. See the server-computed sha256 + detected Shape (1 stateless /
 *     2 stateful) and the first ~50 lines of source for a sanity check.
 *  3. Click "Arm oracle" — this POSTs the sha256 back, the server
 *     re-hashes on disk, and flips the ``armed`` flag if both match.
 *     An armed oracle is the only kind the pipeline's ``/run``
 *     endpoint will accept.
 *
 * Security posture: the server refuses uploads when
 * ``MEMDIVER_ORACLE_DIR`` is unset and enforces a 1 MB cap, 0o600
 * permissions, and pycache purge. The client does nothing security-
 * sensitive — we only show the data the server returned.
 */

import { useRef, useState } from "react";

import type { OracleEntry } from "@/api/oracles";
import { usePipelineStore } from "@/stores/pipeline-store";
import { useOracleStore } from "@/stores/oracle-store";

const MAX_UPLOAD_BYTES = 1_000_000;

function shortSha(sha: string): string {
  return sha.length >= 12 ? sha.slice(0, 12) + "…" : sha;
}

export function OracleUpload() {
  const uploaded = useOracleStore((s) => s.uploaded);
  const selectedOracleId = useOracleStore((s) => s.selectedOracleId);
  const loading = useOracleStore((s) => s.loading);
  const error = useOracleStore((s) => s.error);
  const upload = useOracleStore((s) => s.upload);
  const arm = useOracleStore((s) => s.arm);
  const remove = useOracleStore((s) => s.remove);
  const selectOracle = useOracleStore((s) => s.selectOracle);
  const clearError = useOracleStore((s) => s.clearError);
  const updateForm = usePipelineStore((s) => s.updateForm);

  const inputRef = useRef<HTMLInputElement>(null);
  const [description, setDescription] = useState("");
  const [localError, setLocalError] = useState<string | null>(null);

  const selectedEntry = uploaded.find((o) => o.id === selectedOracleId) ?? null;

  async function handleFile(file: File): Promise<void> {
    setLocalError(null);
    clearError();
    if (file.size > MAX_UPLOAD_BYTES) {
      setLocalError(
        `Oracle file is ${file.size} bytes; the server cap is ${MAX_UPLOAD_BYTES}.`,
      );
      return;
    }
    const entry = await upload(file, description || undefined);
    if (entry) {
      updateForm({ oracleId: entry.id, oracleSha256: null });
    }
  }

  async function handleArm(entry: OracleEntry): Promise<void> {
    const ok = await arm(entry.id, entry.sha256);
    if (ok) {
      updateForm({ oracleId: entry.id, oracleSha256: entry.sha256 });
    }
  }

  async function handleRemove(entry: OracleEntry): Promise<void> {
    const ok = await remove(entry.id);
    if (ok && selectedOracleId === entry.id) {
      updateForm({ oracleId: null, oracleSha256: null });
    }
  }

  return (
    <div className="space-y-3">
      <div
        className="md-panel p-4 text-xs text-center cursor-pointer hover:bg-[var(--md-bg-hover)] transition-colors"
        onClick={() => inputRef.current?.click()}
        onDragOver={(e) => {
          e.preventDefault();
        }}
        onDrop={(e) => {
          e.preventDefault();
          const f = e.dataTransfer.files[0];
          if (f) void handleFile(f);
        }}
      >
        <input
          ref={inputRef}
          type="file"
          accept=".py,text/x-python"
          className="hidden"
          onChange={(e) => {
            const f = e.target.files?.[0];
            if (f) void handleFile(f);
            if (inputRef.current) inputRef.current.value = "";
          }}
        />
        <div className="md-text-accent font-semibold mb-1">
          Drop an oracle .py file here
        </div>
        <div className="md-text-muted">
          Up to 1 MB. Shape 1 (stateless <code>verify</code>) and Shape 2
          (stateful <code>build_oracle</code>) are auto-detected.
        </div>
      </div>

      <div>
        <label className="block text-xs md-text-muted mb-1">
          Description (optional)
        </label>
        <input
          type="text"
          value={description}
          onChange={(e) => setDescription(e.target.value)}
          placeholder="e.g. gocryptfs DFRWS oracle"
          className="w-full px-2 py-1 text-xs bg-[var(--md-bg-primary)] border border-[var(--md-border)] rounded"
        />
      </div>

      {(localError || error) && (
        <div className="text-xs md-text-error">
          {localError || error}
        </div>
      )}
      {loading && (
        <div className="text-xs md-text-muted">Processing upload…</div>
      )}

      {uploaded.length > 0 && (
        <div className="space-y-2">
          <div className="text-xs md-text-muted font-semibold uppercase tracking-wide">
            Uploaded oracles
          </div>
          {uploaded.map((o) => {
            const isSelected = selectedOracleId === o.id;
            return (
              <div
                key={o.id}
                className={`md-panel p-3 space-y-2 cursor-pointer transition-colors ${
                  isSelected
                    ? "border-2 border-[var(--md-accent-blue)]"
                    : "hover:bg-[var(--md-bg-hover)]"
                }`}
                onClick={() => selectOracle(o.id)}
              >
                <div className="flex items-center justify-between gap-2">
                  <div className="flex items-center gap-2 min-w-0">
                    <span className="md-text-accent font-mono text-xs truncate">
                      {o.filename}
                    </span>
                    <span className="inline-block text-[10px] uppercase tracking-wide text-white rounded px-1.5 py-0.5 bg-indigo-700">
                      Shape {o.shape}
                    </span>
                    {o.armed ? (
                      <span
                        className="inline-block text-[10px] uppercase tracking-wide text-white rounded px-1.5 py-0.5"
                        style={{ background: "var(--md-accent-green)" }}
                      >
                        Armed
                      </span>
                    ) : (
                      <span
                        className="inline-block text-[10px] uppercase tracking-wide text-white rounded px-1.5 py-0.5"
                        style={{ background: "var(--md-accent-orange)" }}
                      >
                        Unarmed
                      </span>
                    )}
                  </div>
                  <div className="flex items-center gap-1">
                    {!o.armed && (
                      <button
                        type="button"
                        onClick={(e) => {
                          e.stopPropagation();
                          void handleArm(o);
                        }}
                        className="text-xs px-2 py-1 rounded bg-[var(--md-accent-blue)] text-white hover:opacity-90"
                        title="Confirm sha256 and mark this oracle safe to execute"
                      >
                        Arm oracle
                      </button>
                    )}
                    <button
                      type="button"
                      onClick={(e) => {
                        e.stopPropagation();
                        void handleRemove(o);
                      }}
                      className="text-xs px-2 py-1 rounded bg-[var(--md-bg-hover)] md-text-secondary hover:bg-red-700 hover:text-white"
                    >
                      Delete
                    </button>
                  </div>
                </div>
                <div className="text-[10px] md-text-muted font-mono">
                  sha256: {shortSha(o.sha256)} · {o.size} bytes
                </div>
                {o.description && (
                  <div className="text-xs md-text-muted italic">
                    {o.description}
                  </div>
                )}
                {isSelected && selectedEntry === o && o.head_lines.length > 0 && (
                  <pre className="text-[10px] font-mono bg-[var(--md-bg-primary)] p-2 rounded border border-[var(--md-border)] overflow-x-auto max-h-40">
                    {o.head_lines.slice(0, 30).join("\n")}
                    {o.head_lines.length > 30 && "\n…"}
                  </pre>
                )}
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
}

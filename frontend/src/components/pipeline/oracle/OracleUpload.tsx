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
import { useTranslation } from "react-i18next";

import type { OracleEntry } from "@/api/oracles";
import { usePipelineStore } from "@/stores/pipeline-store";
import { useOracleStore } from "@/stores/oracle-store";

const MAX_UPLOAD_BYTES = 1_000_000;

function shortSha(sha: string): string {
  return sha.length >= 12 ? sha.slice(0, 12) + "…" : sha;
}

export function OracleUpload() {
  const { t } = useTranslation("pipeline");
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
        t("oracle.upload.sizeError", { size: file.size, cap: MAX_UPLOAD_BYTES }),
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
        role="button"
        tabIndex={0}
        aria-label={t("oracle.upload.dropTitle")}
        className="md-panel p-4 text-xs text-center cursor-pointer hover:bg-[var(--md-bg-hover)] transition-colors"
        onClick={() => inputRef.current?.click()}
        onKeyDown={(e) => {
          if (e.key === "Enter" || e.key === " ") {
            e.preventDefault();
            inputRef.current?.click();
          }
        }}
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
          {t("oracle.upload.dropTitle")}
        </div>
        <div className="md-text-muted">
          {t("oracle.upload.dropBodyPrefix")} <code>verify</code>
          {t("oracle.upload.dropBodyMid")} <code>build_oracle</code>
          {t("oracle.upload.dropBodyTail")}
        </div>
      </div>

      <div>
        <label className="block text-xs md-text-muted mb-1">
          {t("oracle.upload.descriptionLabel")}
        </label>
        <input
          type="text"
          value={description}
          onChange={(e) => setDescription(e.target.value)}
          placeholder={t("oracle.upload.descriptionPlaceholder")}
          className="w-full px-2 py-1 text-xs bg-[var(--md-bg-primary)] border border-[var(--md-border)] rounded"
        />
      </div>

      {(localError || error) && (
        <div className="text-xs md-text-error">
          {localError || error}
        </div>
      )}
      {loading && (
        <div className="text-xs md-text-muted">{t("oracle.upload.processing")}</div>
      )}

      {uploaded.length > 0 && (
        <div className="space-y-2">
          <div className="text-xs md-text-muted font-semibold uppercase tracking-wide">
            {t("oracle.upload.uploadedHeading")}
          </div>
          {uploaded.map((o) => {
            const isSelected = selectedOracleId === o.id;
            return (
              <div
                key={o.id}
                role="button"
                tabIndex={0}
                aria-selected={isSelected}
                className={`md-panel p-3 space-y-2 cursor-pointer transition-colors ${
                  isSelected
                    ? "border-2 border-[var(--md-accent-blue)]"
                    : "hover:bg-[var(--md-bg-hover)]"
                }`}
                onClick={() => selectOracle(o.id)}
                onKeyDown={(e) => {
                  if (e.key === "Enter" || e.key === " ") {
                    e.preventDefault();
                    selectOracle(o.id);
                  }
                }}
              >
                <div className="flex items-center justify-between gap-2">
                  <div className="flex items-center gap-2 min-w-0">
                    <span className="md-text-accent font-mono text-xs truncate">
                      {o.filename}
                    </span>
                    <span className="inline-block text-[10px] uppercase tracking-wide md-text-on-accent rounded px-1.5 py-0.5 bg-[var(--md-accent-purple)]">
                      {t("oracle.upload.shape", { shape: o.shape })}
                    </span>
                    {o.armed ? (
                      <span
                        className="inline-block text-[10px] uppercase tracking-wide md-text-on-accent rounded px-1.5 py-0.5"
                        style={{ background: "var(--md-accent-green)" }}
                      >
                        {t("oracle.upload.armed")}
                      </span>
                    ) : (
                      <span
                        className="inline-block text-[10px] uppercase tracking-wide md-text-on-accent rounded px-1.5 py-0.5"
                        style={{ background: "var(--md-accent-orange)" }}
                      >
                        {t("oracle.upload.unarmed")}
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
                        className="text-xs px-2 py-1 rounded bg-[var(--md-accent-blue)] md-text-on-accent hover:opacity-90"
                        title={t("oracle.upload.armTitle")}
                      >
                        {t("oracle.upload.arm")}
                      </button>
                    )}
                    <button
                      type="button"
                      onClick={(e) => {
                        e.stopPropagation();
                        void handleRemove(o);
                      }}
                      className="text-xs px-2 py-1 rounded bg-[var(--md-bg-hover)] md-text-secondary hover:bg-[var(--md-accent-red)] hover:text-[var(--md-bg-primary)]"
                    >
                      {t("common:delete")}
                    </button>
                  </div>
                </div>
                <div className="text-[10px] md-text-muted font-mono">
                  {t("oracle.upload.shaMeta", { sha: shortSha(o.sha256), size: o.size })}
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

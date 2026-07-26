/**
 * Stage 1 — dump source paths.
 *
 * The user lists the raw ``.dump`` or ``.msl`` files that will be
 * folded into the consensus matrix. v1 is a minimal path-editor:
 * type / paste paths, one per line, and they're handed to the
 * backend as absolute strings. The server validates each path
 * exists before dispatching the worker.
 *
 * Dragging files in and auto-resolving their absolute paths is a
 * v2 enhancement — the browser sandbox prevents us from seeing a
 * File's real filesystem path anyway, so drag-drop would need to
 * upload via ``/api/dumps/upload`` and then reference the server
 * copy. For now we trust the analyst to provide real paths.
 */

import { useState } from "react";
import { useTranslation } from "react-i18next";

import type { WizardStage } from "@/stores/pipeline-store";
import { usePipelineStore } from "@/stores/pipeline-store";

interface Props {
  onAdvance: (next: WizardStage) => void;
}

export function StageDumps({ onAdvance }: Props) {
  const { t } = useTranslation("pipeline");
  const sourcePaths = usePipelineStore((s) => s.form.sourcePaths);
  const updateForm = usePipelineStore((s) => s.updateForm);

  const [draft, setDraft] = useState<string>("");

  const pasteLines = (): void => {
    const lines = draft
      .split("\n")
      .map((l) => l.trim())
      .filter((l) => l.length > 0);
    if (lines.length === 0) return;
    updateForm({
      sourcePaths: Array.from(new Set([...sourcePaths, ...lines])),
    });
    setDraft("");
  };

  const removeAt = (idx: number): void => {
    updateForm({
      sourcePaths: sourcePaths.filter((_, i) => i !== idx),
    });
  };

  const clearAll = (): void => {
    updateForm({ sourcePaths: [] });
  };

  const canAdvance = sourcePaths.length >= 1;

  return (
    <div className="p-4 space-y-3">
      <div>
        <h3 className="text-sm font-semibold md-text-accent">
          {t("stages.dumps.title")}
        </h3>
        <p className="text-xs md-text-muted">
          {t("stages.dumps.subtitlePrefix")} <code>.dump</code>{" "}
          {t("stages.dumps.subtitleAnd")} <code>.msl</code>{" "}
          {t("stages.dumps.subtitleBody")}
        </p>
      </div>

      <div className="md-panel p-3 space-y-2">
        <textarea
          value={draft}
          onChange={(e) => setDraft(e.target.value)}
          placeholder={"/Users/me/dataset/run_0001/gdb_raw.bin\n/Users/me/dataset/run_0002/gdb_raw.bin\n…"}
          rows={4}
          className="w-full px-2 py-1 text-xs bg-[var(--md-bg-primary)] border border-[var(--md-border)] rounded font-mono"
        />
        <div className="flex items-center justify-between">
          <button
            type="button"
            onClick={pasteLines}
            disabled={draft.trim().length === 0}
            className="text-xs px-2 py-1 rounded bg-[var(--md-accent-blue)] text-white disabled:opacity-50"
          >
            {t("stages.dumps.addPaths")}
          </button>
          {sourcePaths.length > 0 && (
            <button
              type="button"
              onClick={clearAll}
              className="text-xs px-2 py-1 rounded bg-[var(--md-bg-hover)] md-text-secondary hover:bg-[var(--md-accent-red)] hover:text-white"
            >
              {t("stages.dumps.clearAll")}
            </button>
          )}
        </div>
      </div>

      {sourcePaths.length > 0 ? (
        <div className="md-panel">
          <div className="px-3 py-2 border-b border-[var(--md-border)] text-xs md-text-muted">
            {t("stages.dumps.selectedCount", { count: sourcePaths.length })}
          </div>
          <ul className="max-h-48 overflow-y-auto divide-y divide-[var(--md-border)]">
            {sourcePaths.map((path, idx) => (
              <li
                key={`${path}-${idx}`}
                className="flex items-center gap-2 px-3 py-1.5 text-[11px] font-mono"
              >
                <span className="md-text-muted w-6 text-right">
                  {idx + 1}
                </span>
                <span className="flex-1 truncate">{path}</span>
                <button
                  type="button"
                  onClick={() => removeAt(idx)}
                  className="md-text-muted hover:text-[var(--md-accent-red)]"
                  aria-label={t("stages.dumps.removePath", { path })}
                >
                  ×
                </button>
              </li>
            ))}
          </ul>
        </div>
      ) : (
        <div className="md-panel p-3 text-xs md-text-muted text-center">
          {t("stages.dumps.empty")}
        </div>
      )}

      <div className="flex justify-between items-center pt-2">
        <button
          type="button"
          onClick={() => onAdvance("recipe")}
          className="text-xs px-3 py-1.5 rounded bg-[var(--md-bg-hover)] md-text-secondary hover:bg-[var(--md-border)]"
        >
          {t("stages.dumps.back")}
        </button>
        <button
          type="button"
          disabled={!canAdvance}
          onClick={() => onAdvance("oracle")}
          className="text-xs px-3 py-1.5 rounded bg-[var(--md-accent-blue)] text-white disabled:opacity-50"
        >
          {t("stages.dumps.next")}
        </button>
      </div>
    </div>
  );
}

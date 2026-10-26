import { useState } from "react";
import { useTranslation } from "react-i18next";

import {
  KEYLOG_LABELS, MAX_KEYLOG_BYTES, countKeylogLines,
  type KeylogDraft, type KeylogSource,
} from "./keylog-helpers";

const inputClass =
  "w-full px-1 py-0.5 text-xs rounded border border-[var(--md-border)] bg-[var(--md-bg-secondary)]";
const baseName = (p: string) => p.split("/").pop() || p;

export interface LoadedKeylog { name: string; text: string; lines: number }

/** Pick a key log from this browser: read as text, refuse above 4 MiB before reading. */
export function KeylogFilePicker(props: {
  loaded: { name: string; lines: number } | null;
  onLoaded: (file: LoadedKeylog | null) => void;
}) {
  const { t } = useTranslation("objectModel");
  const { loaded, onLoaded } = props;
  const [error, setError] = useState<string | null>(null);

  const onPick = (file: File | undefined) => {
    setError(null);
    if (!file) return;
    if (file.size > MAX_KEYLOG_BYTES) {
      onLoaded(null);
      setError(t("keylog.fileTooLarge", { name: file.name, max: MAX_KEYLOG_BYTES / (1024 * 1024) }));
      return;
    }
    const reader = new FileReader();
    reader.onload = () => {
      const text = typeof reader.result === "string" ? reader.result : "";
      onLoaded({ name: file.name, text, lines: countKeylogLines(text) });
    };
    reader.onerror = () => { onLoaded(null); setError(t("keylog.fileReadFailed", { name: file.name })); };
    reader.readAsText(file);
  };

  return (
    <div className="flex flex-col gap-0.5">
      <input
        type="file" aria-label={t("keylog.chooseFile")} className="text-xs"
        onChange={(e) => onPick(e.target.files?.[0])}
      />
      {loaded && (
        <p data-testid="keylog-file-summary">{t("keylog.fileSummary", { name: loaded.name, count: loaded.lines })}</p>
      )}
      {error && <p role="alert" data-testid="keylog-file-error" className="text-[var(--md-variance-key-candidate)]">{error}</p>}
    </div>
  );
}

/** The key-log learning input: where the log comes from, the anchor label and related labels. */
export function KeylogInput(props: {
  paths: string[]; draft: KeylogDraft; onChange: (draft: KeylogDraft) => void;
}) {
  const { t } = useTranslation("objectModel");
  const { paths, draft, onChange } = props;
  const patch = (change: Partial<KeylogDraft>) => onChange({ ...draft, ...change });
  const relatedChoices = KEYLOG_LABELS.filter((l) => l !== draft.anchorLabel);
  const toggle = (label: string, on: boolean) =>
    patch({ unrelated: on ? draft.unrelated.filter((l) => l !== label) : [...draft.unrelated, label] });

  return (
    <div className="flex flex-col gap-1" data-testid="keylog-input">
      <p className="md-text-muted">{t("keylog.explain")}</p>
      <select
        aria-label={t("keylog.sourceLabel")} className={inputClass} value={draft.source}
        onChange={(e) => patch({ source: e.target.value as KeylogSource })}
      >
        {(["file", "path", "perDump"] as const).map((s) => (
          <option key={s} value={s}>{t(`keylog.source.${s}`)}</option>
        ))}
      </select>
      {draft.source === "file" && (
        <KeylogFilePicker
          loaded={draft.text !== "" ? { name: draft.fileName, lines: draft.lines } : null}
          onLoaded={(f) => patch(f
            ? { fileName: f.name, text: f.text, lines: f.lines }
            : { fileName: "", text: "", lines: 0 })}
        />
      )}
      {draft.source === "path" && (
        <input
          aria-label={t("keylog.pathLabel")} placeholder={t("keylog.pathLabel")} className={inputClass}
          value={draft.path} onChange={(e) => patch({ path: e.target.value })}
        />
      )}
      {draft.source === "perDump" && paths.map((p) => (
        <label key={p} className="flex items-center gap-1">
          <span className="w-24 truncate" title={p}>{baseName(p)}</span>
          <input
            aria-label={t("keylog.pathFor", { dump: baseName(p) })} className={inputClass}
            value={draft.perDump[p] ?? ""}
            onChange={(e) => patch({ perDump: { ...draft.perDump, [p]: e.target.value } })}
          />
        </label>
      ))}
      <label className="flex flex-col">
        {t("keylog.anchorLabel")}
        <select
          aria-label={t("keylog.anchorLabel")} className={inputClass} value={draft.anchorLabel}
          onChange={(e) => patch({ anchorLabel: e.target.value })}
        >
          <option value="">{t("keylog.anchorAutomatic")}</option>
          {KEYLOG_LABELS.map((l) => <option key={l} value={l}>{l}</option>)}
        </select>
      </label>
      <p className="md-text-muted">{t("keylog.anchorHint")}</p>
      <fieldset className="flex flex-col" data-testid="keylog-related">
        <legend className="md-text-muted">{t("keylog.relatedLabels")}</legend>
        {relatedChoices.map((l) => (
          <label key={l} className="flex items-center gap-1">
            <input
              type="checkbox" aria-label={t("keylog.relatedLabel", { label: l })}
              checked={!draft.unrelated.includes(l)} onChange={(e) => toggle(l, e.target.checked)}
            />
            {l}
          </label>
        ))}
      </fieldset>
    </div>
  );
}

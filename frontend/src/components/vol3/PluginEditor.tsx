import { useCallback, useEffect, useState } from "react";
import { useTranslation } from "react-i18next";

import { readableFailure } from "@/api/client";
import {
  checkVol3Source, getVol3Source, listVol3Sources, putVol3Source, scaffoldVol3Plugin,
  type Vol3CheckOutcome, type Vol3RunRequest, type Vol3SourceMeta,
} from "@/api/vol3";
import { CheckResultView } from "./CheckResultView";
import { FixturesSection } from "./FixturesSection";
import { SourceEditor } from "./SourceEditor";

const inputClass =
  "w-full px-2 py-1 text-xs rounded border border-[var(--md-border)] bg-[var(--md-bg-secondary)]";
const buttonClass =
  "px-2 py-1 text-xs rounded border border-[var(--md-border)] hover:bg-[var(--md-bg-hover)] disabled:opacity-40";

/** The editor highlights the failing line only when the failure names one. */
const errorLineOf = (outcome: Vol3CheckOutcome | null) =>
  outcome && !outcome.ok ? outcome.error.line : null;

/**
 * Write, check, save and run a user plugin (T2.5), and keep fixtures for it (T2.8).
 * Runs go through `onRun` so the Vol3 panel shows them in its one results table.
 */
export function PluginEditor({ viewPath, caseDir, running, onRun }: {
  viewPath: string;
  caseDir: string;
  running: boolean;
  onRun: (req: Vol3RunRequest) => void;
}) {
  const { t } = useTranslation("vol3");
  const [name, setName] = useState("");
  const [perProcess, setPerProcess] = useState(true);
  const [source, setSource] = useState("");
  /** Name and text as last stored in the case; null while the source was never saved. */
  const [saved, setSaved] = useState<{ name: string; source: string } | null>(null);
  const [storedAll, setStored] = useState<Vol3SourceMeta[]>([]);
  const [outcome, setOutcome] = useState<Vol3CheckOutcome | null>(null);
  const [external, setExternal] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const case_ = caseDir.trim();
  const hasCase = case_ !== "";
  const stored = hasCase ? storedAll : [];

  const refreshStored = useCallback(() => {
    if (!hasCase) return;
    listVol3Sources(case_).then((l) => setStored(l.sources)).catch((e) => setError(readableFailure(e)));
  }, [case_, hasCase]);
  useEffect(refreshStored, [refreshStored]);

  const guarded = (work: () => Promise<void>) => async () => {
    setError(null);
    try { await work(); } catch (e) { setError(readableFailure(e)); }
  };

  const scaffold = guarded(async () => {
    const made = await scaffoldVol3Plugin(name.trim(), perProcess);
    setSource(made.source);
    setOutcome(null);
    setSaved(null);
    setExternal(false);
  });

  const load = (storedName: string) => guarded(async () => {
    const doc = await getVol3Source(case_, storedName);
    setName(doc.name);
    setSource(doc.source);
    setSaved({ name: doc.name, source: doc.source });
    setExternal(doc.modified_externally === true);
    setOutcome(null);
  })();

  const save = guarded(async () => {
    const answer = await putVol3Source(case_, name.trim(), source, viewPath || undefined);
    setSaved({ name: answer.stored.name, source });
    setOutcome(answer.check);
    setExternal(false);
    refreshStored();
  });

  const check = guarded(async () => {
    setOutcome(await checkVol3Source({ source, view_path: viewPath || undefined }));
  });

  const dirty = saved === null || saved.source !== source;
  const run = () => {
    // A stored, unchanged source runs by name; anything else runs as raw text.
    if (saved && !dirty) onRun({ view_path: viewPath, source_name: saved.name, case_dir: case_ });
    else onRun({ view_path: viewPath, source, case_dir: case_ || undefined });
  };

  const hasSource = source.trim() !== "";
  return (
    <div className="space-y-2" data-testid="plugin-editor">
      <p role="note" data-testid="editor-warning" className="font-medium"
        style={{ color: "var(--md-accent-orange)" }}>{t("editor.warning")}</p>
      {external && (
        <p role="status" data-testid="external-edit-notice" style={{ color: "var(--md-accent-orange)" }}>
          {t("editor.externalEdit")}</p>
      )}
      {error && <p role="alert" data-testid="editor-error" style={{ color: "var(--md-accent-red)" }}>{error}</p>}
      <div className="flex gap-2 items-center">
        <input type="text" value={name} onChange={(e) => setName(e.target.value)} className={inputClass}
          aria-label={t("editor.name")} placeholder={t("editor.name")} data-testid="editor-name" />
        <label className="flex items-center gap-1 whitespace-nowrap">
          <input type="checkbox" checked={perProcess} onChange={(e) => setPerProcess(e.target.checked)}
            data-testid="editor-per-process" />{t("editor.perProcess")}</label>
        <button type="button" className={`${buttonClass} whitespace-nowrap`} data-testid="editor-scaffold"
          disabled={name.trim() === ""} onClick={() => void scaffold()}>{t("editor.scaffold")}</button>
      </div>
      <div className="flex gap-2 items-center">
        <select value="" aria-label={t("editor.load")} data-testid="editor-load" className={inputClass}
          disabled={!hasCase || stored.length === 0} onChange={(e) => e.target.value && load(e.target.value)}>
          <option value="">{stored.length === 0 ? t("editor.noStored") : t("editor.load")}</option>
          {stored.map((s) => <option key={s.name} value={s.name}>{`${s.name} (v${s.version ?? "?"})`}</option>)}
        </select>
      </div>
      <SourceEditor value={source} onChange={setSource} errorLine={errorLineOf(outcome)} />
      <div className="flex gap-2">
        <button type="button" className={buttonClass} data-testid="editor-save"
          disabled={!hasCase || !hasSource || name.trim() === ""} onClick={() => void save()}>{t("editor.save")}</button>
        <button type="button" className={buttonClass} data-testid="editor-check"
          disabled={!hasSource} onClick={() => void check()}>{t("editor.check.button")}</button>
        <button type="button" className={buttonClass} data-testid="editor-run"
          disabled={!viewPath || !hasSource || running} onClick={run}>{t("editor.run")}</button>
      </div>
      {!hasCase && <p className="md-text-muted" data-testid="editor-needs-case">{t("editor.needCase")}</p>}
      {!viewPath && <p className="md-text-muted" data-testid="editor-needs-view">{t("run.needView")}</p>}
      {saved && dirty && hasSource && <p className="md-text-muted" data-testid="editor-unsaved">{t("editor.unsaved")}</p>}
      {outcome && <CheckResultView outcome={outcome} />}
      <FixturesSection caseDir={caseDir} viewPath={viewPath} sourceName={saved && !dirty ? saved.name : null} />
    </div>
  );
}

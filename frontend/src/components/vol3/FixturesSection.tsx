import { useCallback, useEffect, useState } from "react";
import { useTranslation } from "react-i18next";

import { readableFailure } from "@/api/client";
import {
  listVol3Fixtures, putVol3Fixture, runVol3Fixture, type Vol3Fixture, type Vol3FixtureRun,
} from "@/api/vol3";
import {
  buildPredicate, COLUMN_OPS, describePredicate, emptyPredicateDraft, PREDICATE_KINDS,
  type PredicateDraft, type PredicateKind,
} from "./fixture-predicates";
import { VerdictBadge } from "./VerdictBadge";

const inputClass =
  "w-full px-2 py-1 text-xs rounded border border-[var(--md-border)] bg-[var(--md-bg-secondary)]";
const buttonClass =
  "px-2 py-1 text-xs rounded border border-[var(--md-border)] hover:bg-[var(--md-bg-hover)] disabled:opacity-40";

/** Fixtures of the case (D13): list with last verdict, create for the current plugin, run. */
export function FixturesSection({ caseDir, viewPath, sourceName }: {
  caseDir: string;
  viewPath: string;
  /** The stored plugin the new fixture targets; null while the source is unsaved. */
  sourceName: string | null;
}) {
  const { t } = useTranslation("vol3");
  const [fixtures, setFixtures] = useState<Vol3Fixture[]>([]);
  const [runs, setRuns] = useState<Record<string, Vol3FixtureRun>>({});
  const [name, setName] = useState("");
  const [draft, setDraft] = useState<PredicateDraft>(emptyPredicateDraft());
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState<string | null>(null);
  const enabled = caseDir.trim() !== "";

  const refresh = useCallback(() => {
    if (!enabled) return Promise.resolve();
    return listVol3Fixtures(caseDir.trim()).then((l) => setFixtures(l.fixtures))
      .catch((e) => setError(readableFailure(e)));
  }, [caseDir, enabled]);
  useEffect(() => { void refresh(); }, [refresh]);

  const patch = (p: Partial<PredicateDraft>) => setDraft((d) => ({ ...d, ...p }));

  const create = async () => {
    setError(null);
    const built = buildPredicate(draft);
    if (!built.ok) { setError(t(`editor.fixtures.error.${built.error}`)); return; }
    try {
      await putVol3Fixture(caseDir.trim(), name.trim(), {
        view_path: viewPath, expect: [built.predicate], source_name: sourceName ?? undefined });
      await refresh();
    } catch (e) { setError(readableFailure(e)); }
  };

  const run = async (fixtureName: string) => {
    setError(null);
    setBusy(fixtureName);
    try {
      const outcome = await runVol3Fixture(caseDir.trim(), fixtureName, viewPath || undefined);
      setRuns((r) => ({ ...r, [fixtureName]: outcome }));
    } catch (e) { setError(readableFailure(e)); }
    setBusy(null);
  };

  const canCreate = enabled && !!viewPath && !!sourceName && name.trim() !== "";
  const needsCount = draft.kind === "min_rows" || draft.kind === "max_rows";
  return (
    <section className="space-y-2" data-testid="fixtures-section">
      <h4 className="font-semibold">{t("editor.fixtures.title")}</h4>
      {!enabled && <p className="md-text-muted" data-testid="fixtures-needs-case">{t("editor.fixtures.needCase")}</p>}
      {error && <p role="alert" data-testid="fixtures-error" style={{ color: "var(--md-accent-red)" }}>{error}</p>}
      <ul className="space-y-1" data-testid="fixture-list">
        {(enabled ? fixtures : []).map((f) => {
          const last = runs[f.name];
          return (
            <li key={f.name} data-testid="fixture-item" className="rounded border border-[var(--md-border)] p-1 space-y-0.5">
              <div className="flex items-center gap-2">
                <span className="font-mono flex-1 truncate">{f.name}</span>
                {last ? <VerdictBadge verdict={last.verdict} />
                  : <span className="md-text-muted" data-testid="fixture-not-run">{t("editor.fixtures.notRun")}</span>}
                <button type="button" className={buttonClass} data-testid="fixture-run"
                  disabled={busy !== null} onClick={() => void run(f.name)}>{t("editor.fixtures.run")}</button>
              </div>
              <p className="md-text-muted font-mono truncate">{f.expect.map(describePredicate).join(" ")}</p>
              {last && (
                <div data-testid="fixture-details" className="space-y-0.5">
                  {last.reason && <p className="md-text-secondary">{last.reason}</p>}
                  <ul className="ml-3">
                    {last.predicates.map((p, i) => (
                      <li key={i} data-testid="fixture-predicate" data-ok={p.ok ? "true" : "false"}>
                        <span aria-hidden="true">{p.ok ? "✓" : "✗"}</span>{" "}
                        {p.ok ? t("editor.fixtures.predOk") : t("editor.fixtures.predFail")}{p.detail ? `: ${p.detail}` : ""}
                      </li>
                    ))}
                  </ul>
                </div>
              )}
            </li>
          );
        })}
        {enabled && fixtures.length === 0 && <li className="md-text-muted">{t("editor.fixtures.none")}</li>}
      </ul>
      <div className="space-y-1 rounded border border-[var(--md-border)] p-2" data-testid="fixture-form">
        <p className="font-medium">{t("editor.fixtures.create")}</p>
        <input type="text" value={name} onChange={(e) => setName(e.target.value)} className={inputClass}
          aria-label={t("editor.fixtures.name")} placeholder={t("editor.fixtures.name")} data-testid="fixture-name" />
        <select value={draft.kind} onChange={(e) => patch({ kind: e.target.value as PredicateKind })}
          className={inputClass} aria-label={t("editor.fixtures.kind")} data-testid="fixture-kind">
          {PREDICATE_KINDS.map((k) => <option key={k} value={k}>{t(`editor.fixtures.kinds.${k}`)}</option>)}
        </select>
        {!needsCount && (
          <div className="grid grid-cols-2 gap-1">
            <input type="text" value={draft.column} onChange={(e) => patch({ column: e.target.value })}
              className={inputClass} aria-label={t("editor.fixtures.column")} placeholder={t("editor.fixtures.column")} data-testid="fixture-column" />
            {draft.kind === "column_all" && (
              <select value={draft.op} onChange={(e) => patch({ op: e.target.value })} className={inputClass}
                aria-label={t("editor.fixtures.op")} data-testid="fixture-op">
                {COLUMN_OPS.map((o) => <option key={o} value={o}>{o}</option>)}
              </select>
            )}
            <input type="text" value={draft.value} onChange={(e) => patch({ value: e.target.value })}
              className={inputClass} aria-label={t("editor.fixtures.value")} placeholder={t("editor.fixtures.value")} data-testid="fixture-value" />
          </div>
        )}
        {(needsCount || draft.kind === "row_where") && (
          <input type="text" value={draft.count} onChange={(e) => patch({ count: e.target.value })}
            className={inputClass} data-testid="fixture-count"
            aria-label={draft.kind === "row_where" ? t("editor.fixtures.countAtLeast") : t("editor.fixtures.count")}
            placeholder={draft.kind === "row_where" ? t("editor.fixtures.countAtLeast") : t("editor.fixtures.count")} />
        )}
        <button type="button" className={buttonClass} disabled={!canCreate} data-testid="fixture-create"
          onClick={() => void create()}>{t("editor.fixtures.createButton")}</button>
        {enabled && !sourceName && <p className="md-text-muted" data-testid="fixtures-needs-save">{t("editor.fixtures.needSave")}</p>}
        {!viewPath && <p className="md-text-muted">{t("run.needView")}</p>}
      </div>
    </section>
  );
}

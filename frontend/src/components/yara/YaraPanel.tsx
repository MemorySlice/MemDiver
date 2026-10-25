import { useCallback, useEffect, useMemo, useState } from "react";
import { useTranslation } from "react-i18next";

import { readableFailure } from "@/api/client";
import {
  checkYaraRule, type RuleScope, type YaraCheckResult, type YaraError, type YaraScanResult,
} from "@/api/yara";
import { DetectorFixtureBadge } from "@/components/detectors/DetectorFixtureBadge";
import { scanAddressOf } from "@/components/keyfinders/keyfinder-hits";
import { SourceEditor } from "@/components/vol3/SourceEditor";
import { useActiveDump } from "@/hooks/useActiveDump";
import { useHexStore } from "@/stores/hex-store";
import { useImageStore } from "@/stores/image-store";
import type { ImportReport } from "./import-local-rules";
import { SavedRulesList } from "./SavedRulesList";
import { YaraHitsTable } from "./YaraHitsTable";
import { goToYaraHit, paintYaraHits, planYaraHighlights } from "./yara-hits";
import { useSavedRules } from "./useSavedRules";
import { useYaraScan, type YaraScanState } from "./useYaraScan";

const inputClass =
  "w-full px-2 py-1 text-xs rounded border border-[var(--md-border)] bg-[var(--md-bg-secondary)]";
const buttonClass =
  "px-2 py-1 text-xs rounded border border-[var(--md-border)] hover:bg-[var(--md-bg-hover)] disabled:opacity-40";

type Region = "view" | "selection";

/** A check answer is keyed by the source it describes, so an edit retires it by derivation. */
interface Checked { source: string; result: YaraCheckResult }

/**
 * The stored rule the editor text came from; scanning by name is allowed while the text is
 * unchanged. `caseDir` is the case the rule was read from (empty for the library): a case rule
 * is only the same rule while the panel still points at that case.
 */
interface Loaded { name: string; scope: RuleScope; caseDir: string; source: string; external: boolean }

/** The line to mark for an error: the precise one, else libyara's own. */
const markedLine = (e: YaraError | undefined): number | null => e?.line ?? e?.reported_line ?? null;

/** Write, compile-check and run a YARA rule over the open dump's captured bytes. */
export function YaraPanel() {
  const { t } = useTranslation("yara");
  const dumpPath = useActiveDump()?.path ?? "";
  const caseDir = useImageStore((s) => s.caseDir);
  const setCaseDir = useImageStore((s) => s.setCaseDir);
  const selection = useHexStore((s) => s.selection);
  const viewMode = useHexStore((s) => s.viewMode);
  const multiView = useHexStore((s) => s.availableViews.length > 1);
  const vaSpanStart = useHexStore((s) => s.vaSpanStart);
  const pageStatesLoaded = useHexStore((s) => s.pageStatesLoaded);
  const [source, setSource] = useState(() => t("editor.starter"));
  const [name, setName] = useState("");
  const [checked, setChecked] = useState<Checked | null>(null);
  const [region, setRegion] = useState<Region>("view");
  const [answer, setAnswer] = useState<{ scan: YaraScanResult; context: string } | null>(null);
  const context = `${dumpPath}\u0000${viewMode}`;
  // A result belongs to the dump and view it was scanned in; it simply stops existing in another.
  const result = answer !== null && answer.context === context ? answer.scan : null;
  const setResult = useCallback((scan: YaraScanResult | null) => {
    setAnswer(scan === null ? null : { scan, context });
  }, [context]);
  const [checking, setChecking] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [scope, setScope] = useState<RuleScope>("library");
  const [loaded, setLoaded] = useState<Loaded | null>(null);
  const [note, setNote] = useState<string | null>(null);
  const [active, setActive] = useState<number | null>(null);
  const saved = useSavedRules(caseDir);
  const hasCase = caseDir.trim() !== "";

  const check = checked && checked.source === source ? checked.result : null;
  const errorLine = check && !check.valid ? markedLine(check.errors[0]) : null;
  const hasSource = source.trim() !== "";
  const hasSelection = selection !== null;
  const effectiveRegion: Region = hasSelection ? region : "view";

  const paint = useCallback((scan: YaraScanResult) => {
    paintYaraHits(planYaraHighlights(
      scan.rows, scan.view, useHexStore.getState().vaSpanStart, scan.dump_path).regions);
  }, []);

  const showResult = useCallback((scan: YaraScanResult) => {
    setResult(scan);
    setActive(null);
    paint(scan);
  }, [paint, setResult]);
  const job = useYaraScan(showResult);
  const resetJob = job.reset;
  const running = job.state.status === "running";
  const busy = checking || running;

  // The `va` view's span start arrives with the page states; hits placed before then were
  // rebased by 0. Re-paint them once it is known.
  useEffect(() => {
    if (result?.view === "va" && vaSpanStart !== 0) paint(result);
  }, [vaSpanStart]); // eslint-disable-line react-hooks/exhaustive-deps

  // A result is placed against ONE dump and view: when either changes its rows would navigate
  // to the wrong bytes, and a scan still in flight must not land in the new context.
  useEffect(() => {
    resetJob();
    paintYaraHits([]);
  }, [dumpPath, viewMode, resetJob]);

  const skippedNote = useMemo(() => {
    if (!result) return null;
    const { skipped } = planYaraHighlights(result.rows, result.view, vaSpanStart, result.dump_path);
    return skipped > 0 ? t("results.skipped", { count: skipped }) : null;
  }, [result, vaSpanStart, t]);

  const guarded = async (work: () => Promise<void>) => {
    setError(null);
    setChecking(true);
    try { await work(); } catch (e) { setError(readableFailure(e)); }
    setChecking(false);
  };

  // A stored rule whose text is untouched is scanned BY NAME, so the scan runs exactly what
  // the store holds. A library rule is resolved without the case (a case namesake must not answer).
  const byName = loaded && loaded.source === source && !loaded.external
    && (loaded.scope === "library" || (hasCase && loaded.caseDir === caseDir.trim()));

  const compile = () => guarded(async () => {
    setChecked({ source, result: await checkYaraRule(source) });
  });

  const scanRequest = () => {
    // A packed dump's "raw" file view is not a scannable address space: omit the view so the
    // backend scans the captured bytes (its default, "va").
    const rawOfPacked = multiView && viewMode === "raw";
    const view = multiView && !rawOfPacked ? viewMode : undefined;
    const span = effectiveRegion === "selection" && selection
      ? { start: Math.min(selection.anchor, selection.active),
          length: Math.abs(selection.active - selection.anchor) + 1 }
      : null;
    const offset = span && !rawOfPacked ? scanAddressOf(span.start, view ?? "raw", vaSpanStart) : null;
    if (span && offset === null) return null;
    const rule = byName && loaded
      ? { rule_name: loaded.name, ...(loaded.scope === "case" ? { case_dir: caseDir.trim() } : {}) }
      : { rule_source: source };
    return { dump_path: dumpPath, ...rule, ...(view ? { view } : {}),
      ...(span && offset !== null ? { offset, length: span.length } : {}) };
  };

  const run = () => guarded(async () => {
    const request = scanRequest();
    if (request === null) { setNote(t("region.unsafe")); return; }
    setNote(null);
    // A new run retires the previous answer: a cancelled or failed scan shows no stale hits.
    setResult(null);
    paintYaraHits([]);
    const answer = await checkYaraRule(source);
    setChecked({ source, result: answer });
    if (!answer.valid) return;
    // The `va` view's address map is only fetched on demand; hits cannot be placed without it.
    useHexStore.getState().fetchPageStates();
    await job.run(request);
  });

  const save = async () => {
    const trimmed = name.trim();
    const outcome = await saved.save(trimmed, source, scope);
    if (!outcome.ok || !outcome.put) { setNote(t("saved.failed", { message: outcome.error ?? "" })); return; }
    const { stored } = outcome.put;
    setLoaded({ name: trimmed, scope, caseDir: scope === "case" ? caseDir.trim() : "", source, external: false });
    const vars = { name: trimmed, scope: t(`saved.scope.${scope}`), version: stored.version ?? 0 };
    setNote(stored.compiles === false ? t("saved.savedBroken", vars) : t("saved.savedOk", vars));
  };

  const load = async (ruleName: string, ruleScope: RuleScope) => {
    try {
      const doc = await saved.load(ruleName, ruleScope);
      setSource(doc.source);
      setName(doc.name);
      setScope(doc.scope);
      setLoaded({ name: doc.name, scope: doc.scope, caseDir: doc.scope === "case" ? caseDir.trim() : "",
        source: doc.source, external: doc.modified_externally });
      setNote(doc.modified_externally ? t("saved.externalNotice") : null);
    } catch (e) {
      setNote(t("saved.loadFailed", { message: readableFailure(e) }));
    }
  };

  const remove = async (ruleName: string, ruleScope: RuleScope) => {
    const failure = await saved.remove(ruleName, ruleScope);
    if (failure !== null) { setNote(t("saved.deleteFailed", { message: failure })); return; }
    if (loaded?.name === ruleName && loaded.scope === ruleScope) setLoaded(null);
    setNote(t("saved.deleted", { name: ruleName, scope: t(`saved.scope.${ruleScope}`) }));
  };

  const scopeNeedsCase = scope === "case" && !hasCase;

  const notReady = result?.view === "va" && !pageStatesLoaded;
  const click = (i: number) => {
    if (!result) return;
    if (notReady) { useHexStore.getState().fetchPageStates(); setNote(t("results.notReady")); return; }
    setActive(i);
    setNote(goToYaraHit(result.rows[i], result.view) ? null : t("results.unplaceable"));
  };

  const shownNote = note ?? skippedNote;
  return (
    <div data-testid="yara-panel" className="p-2 space-y-3 overflow-auto h-full text-xs">
      <h3 className="font-semibold md-text-accent">{t("title")}</h3>
      {!dumpPath && <p className="md-text-muted" data-testid="yara-no-dump">{t("noDump")}</p>}
      <section className="space-y-1" aria-label={t("saved.title")}>
        <h4 className="md-text-secondary">{t("saved.title")}</h4>
        <ImportNotice report={saved.importReport} />

        {saved.error && (
          <p role="alert" data-testid="yara-rules-error" style={{ color: "var(--md-accent-red)" }}>
            {t("saved.listFailed", { message: saved.error })}</p>
        )}
        <SavedRulesList rules={saved.rules} onLoad={(n, sc) => void load(n, sc)}
          onDelete={(n, sc) => void remove(n, sc)}
          loadedKey={loaded ? `${loaded.scope}:${loaded.name}` : null} />
      </section>
      <SourceEditor value={source} onChange={setSource} errorLine={errorLine} ariaLabel={t("editor.label")} />
      <div className="flex gap-2 items-center">
        <input type="text" value={name} onChange={(e) => setName(e.target.value)} className={inputClass}
          aria-label={t("editor.name")} placeholder={t("editor.namePlaceholder")} data-testid="yara-name" />
        <select value={scope} onChange={(e) => setScope(e.target.value as RuleScope)}
          aria-label={t("saved.scope.label")} data-testid="yara-scope" className={inputClass} style={{ width: "auto" }}>
          <option value="library">{t("saved.scope.library")}</option>
          <option value="case">{t("saved.scope.case")}</option>
        </select>
        <button type="button" className={buttonClass} data-testid="yara-save" title={t("saved.saveHint")}
          disabled={!hasSource || name.trim() === "" || scopeNeedsCase || busy} onClick={() => void save()}>
          {t("saved.save")}</button>
      </div>
      <input type="text" value={caseDir} onChange={(e) => setCaseDir(e.target.value)} className={inputClass}
        aria-label={t("saved.caseDir")} placeholder={t("saved.caseDir")} data-testid="yara-case-dir" />
      {saved.caseError && (
        <p role="alert" data-testid="yara-case-error" style={{ color: "var(--md-accent-orange)" }}>
          {t("saved.caseError", { message: saved.caseError })}</p>
      )}
      {scopeNeedsCase && <p className="md-text-muted" data-testid="yara-case-needed">{t("saved.scope.caseNeeded")}</p>}
      <fieldset className="space-y-1">
        <legend className="md-text-secondary">{t("region.legend")}</legend>
        {(["view", "selection"] as const).map((r) => (
          <label key={r} className="flex items-center gap-1.5">
            <input type="radio" name="yara-region" checked={effectiveRegion === r}
              disabled={r === "selection" && !hasSelection} onChange={() => setRegion(r)}
              data-testid={`yara-region-${r}`} />
            <span>{t(`region.${r}`)}</span>
          </label>
        ))}
      </fieldset>
      <div className="flex gap-2">
        <button type="button" className={buttonClass} data-testid="yara-compile"
          disabled={!hasSource || busy} onClick={() => void compile()}>{t("check.button")}</button>
        <button type="button" className={buttonClass} data-testid="yara-run"
          disabled={!hasSource || dumpPath === "" || busy} onClick={() => void run()}>
          {busy ? t("run.running") : t("run.button")}</button>
      </div>
      <DetectorFixtureBadge artifactKind="yara" artifact={source} caseDir={caseDir.trim() || undefined} />
      {running && <JobProgress state={job.state} onCancel={() => void job.cancel()} />}
      {job.state.status === "cancelled" && (
        <p data-testid="yara-cancelled" className="md-text-muted">{t("run.cancelled")}</p>
      )}
      {job.state.status === "error" && job.state.error && (
        <p role="alert" data-testid="yara-job-error" style={{ color: "var(--md-accent-red)" }}>
          {t("run.error", { message: job.state.error })}</p>
      )}
      {error && <p role="alert" data-testid="yara-error" style={{ color: "var(--md-accent-red)" }}>{t("run.error", { message: error })}</p>}
      {check && <CheckView check={check} />}
      {shownNote && <p role="status" data-testid="yara-note" className="md-text-muted">{shownNote}</p>}
      {result && <ResultView result={result} active={active} onRowClick={click} />}
    </div>
  );
}

function failureHeading(e: YaraError, t: (key: string, o?: Record<string, unknown>) => string): string {
  const line = markedLine(e);
  if (line === null) return t("check.failed");
  return e.column ? t("check.failedAtColumn", { line, column: e.column }) : t("check.failedAt", { line });
}

function ImportNotice({ report }: { report: ImportReport | null }) {
  const { t } = useTranslation("yara");
  if (report === null) return null;
  return (
    <div role="status" data-testid="yara-import-report" className="md-text-secondary space-y-0.5">
      {report.imported.length > 0 && <p>{t("saved.import.done", { count: report.imported.length })}</p>}
      {report.skipped.length > 0 && (
        <p style={{ color: "var(--md-accent-orange)" }}>
          {t("saved.import.skipped", { count: report.skipped.length, names: report.skipped.join(", ") })}</p>
      )}
      {report.invalid.length > 0 && (
        <p style={{ color: "var(--md-accent-orange)" }} data-testid="yara-import-invalid">
          {t("saved.import.invalid", { count: report.invalid.length,
            names: report.invalid.map((f) => f.name || "(empty)").join(", ") })}</p>
      )}
      {report.failed.length > 0 && (
        <p style={{ color: "var(--md-accent-red)" }}>
          {t("saved.import.failed", { names: report.failed.map((f) => f.name).join(", ") })}</p>
      )}
    </div>
  );
}

function JobProgress({ state, onCancel }: { state: YaraScanState; onCancel: () => void }) {
  const { t } = useTranslation("yara");
  const pct = state.pct === null ? null : Math.round(state.pct * 100);
  return (
    <div role="status" data-testid="yara-progress" className="space-y-1 md-text-secondary">
      <div className="flex items-center gap-2">
        <span>{state.msg ?? t("run.progress")}{pct !== null ? ` ${t("run.pct", { pct })}` : ""}</span>
        {state.taskId && (
          <button type="button" className={buttonClass} onClick={onCancel} data-testid="yara-cancel">
            {t("run.cancel")}</button>
        )}
      </div>
      <div role="progressbar" aria-label={t("run.progress")} aria-busy="true" aria-valuemin={0}
        aria-valuemax={100} {...(pct !== null ? { "aria-valuenow": pct } : {})}
        className="h-1 rounded bg-[var(--md-border)] overflow-hidden">
        <div className="h-full bg-[var(--md-accent-blue)]" style={{ width: `${pct ?? 33}%` }} />
      </div>
    </div>
  );
}

function CheckView({ check }: { check: YaraCheckResult }) {
  const { t } = useTranslation("yara");
  return (
    <div className="space-y-0.5" data-testid="yara-check">
      {check.valid ? (
        <p role="status" data-testid="yara-check-ok" style={{ color: "var(--md-accent-green)" }}>
          {t("check.ok", { names: check.rule_names.join(", ") })}</p>
      ) : (
        <div role="alert" data-testid="yara-check-error" style={{ color: "var(--md-accent-red)" }}>
          {check.errors.map((e, i) => (
            <p key={i}>
              <span className="font-medium">{failureHeading(e, t)}</span>
              {": "}{e.message}
              {e.rule ? ` (${t("check.rule", { rule: e.rule })})` : ""}
              {e.hint && <span className="block md-text-secondary" data-testid="yara-check-hint">{e.hint}</span>}
            </p>
          ))}
        </div>
      )}
      {check.warnings.map((w) => (
        <p key={w.code} role="note" data-testid="yara-check-warning" style={{ color: "var(--md-accent-orange)" }}>
          {w.message}</p>
      ))}
    </div>
  );
}

function ResultView({ result, active, onRowClick }: {
  result: YaraScanResult; active: number | null; onRowClick: (i: number) => void;
}) {
  const { t } = useTranslation("yara");
  const cov = result.coverage;
  const deadRule = result.warnings.some((w) => w.code === "yara.pattern_over_scan_limit");
  const reason = result.incomplete_reason
    ? t(`results.reason.${result.incomplete_reason}`, { defaultValue: result.incomplete_reason })
    : deadRule ? t("results.reason.scan_limit") : null;
  return (
    <section className="space-y-1" aria-label={t("results.title")}>
      <p data-testid="yara-summary" className="md-text-secondary">
        {t("results.summary", { count: result.row_count, view: result.view })}</p>
      {result.rule_name && result.scope && (
        <p data-testid="yara-by-name" className="md-text-muted">
          {t("results.byName", { name: result.rule_name, scope: t(`saved.scope.${result.scope}`) })}</p>
      )}
      <p data-testid="yara-coverage" className="md-text-muted">
        {t("results.coverage", { scanned: cov.bytes_scanned, captured: cov.captured_bytes,
          runs: cov.runs_scanned, gaps: cov.gaps_skipped })}</p>
      {result.warnings.map((w) => (
        <p key={w.code} role="alert" data-testid="yara-scan-warning" style={{ color: "var(--md-accent-orange)" }}>
          {w.message}</p>
      ))}
      {result.truncated && (
        <p role="alert" data-testid="yara-truncated" style={{ color: "var(--md-accent-orange)" }}>
          {t("results.truncated", { limit: result.limit })}</p>
      )}
      {!result.complete && !result.truncated && reason && (
        <p role="alert" data-testid="yara-incomplete" style={{ color: "var(--md-accent-orange)" }}>
          {t("results.incomplete", { reason })}</p>
      )}
      {result.errors.map((e, i) => (
        <p key={i} role="alert" data-testid="yara-scan-error" style={{ color: "var(--md-accent-orange)" }}>{e}</p>
      ))}
      {result.rows.length === 0
        ? <p data-testid="yara-empty" className="md-text-muted">
          {result.complete && !deadRule ? t("results.empty") : t("results.emptyNotProof", { reason: reason ?? "" })}</p>
        : <YaraHitsTable rows={result.rows} active={active} onRowClick={onRowClick} />}
    </section>
  );
}

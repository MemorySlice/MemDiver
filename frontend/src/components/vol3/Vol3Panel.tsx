import { useEffect, useMemo, useRef, useState } from "react";
import { useTranslation } from "react-i18next";

import { readableFailure } from "@/api/client";
import {
  describeVol3Plugin, listVol3Plugins, type Vol3Plugin, type Vol3PluginDescription, type Vol3QueryResult,
  type Vol3Requirement, type Vol3RunResult,
} from "@/api/vol3";
import { isMdview } from "@/components/image/open-view-in-workspace";
import { useActiveDump } from "@/hooks/useActiveDump";
import { useHexStore } from "@/stores/hex-store";
import { useImageStore } from "@/stores/image-store";
import { useSelectionStore } from "@/stores/selection-store";
import { ArgsForm } from "./ArgsForm";
import { PluginEditor } from "./PluginEditor";
import { PluginPicker } from "./PluginPicker";
import { ProcessTree } from "./ProcessTree";
import { QueryBox } from "./QueryBox";
import { ResultActions } from "./ResultActions";
import { ResultsTable } from "./ResultsTable";
import { RuleEditor } from "./RuleEditor";
import { canBuildTree } from "./process-tree";
import { useTableRules } from "./useTableRules";
import type { ColumnOverrides } from "./vol3-columns";
import { RunSummary } from "./RunSummary";
import { useVol3Run } from "./useVol3Run";
import { useViewContext } from "./useViewContext";
import { buildArgs, initialDraft, type ArgDraft, type ArgErrors } from "./vol3-args";
import {
  QUERY_HIGHLIGHT_PLUGIN, addressRef, paintPluginHighlights, planColumnHighlights, planQueryHighlights, rowPid,
} from "./vol3-highlights";
import { resolveOffset, type NavResolution } from "./vol3-navigation";

const inputClass =
  "w-full px-2 py-1 text-xs rounded border border-[var(--md-border)] bg-[var(--md-bg-secondary)]";
const buttonClass =
  "px-2 py-1 text-xs rounded border border-[var(--md-border)] hover:bg-[var(--md-bg-hover)] disabled:opacity-40";

const MODES = ["run", "editor", "processes", "query"] as const;
type Mode = (typeof MODES)[number];
const PROCESS_PLUGIN = "linux.pstree.PsTree";
const isProcessListing = (r: Vol3RunResult) => /ps(list|tree|scan)/i.test(r.plugin) && canBuildTree(r.columns);

const pidArgument = (reqs: readonly Vol3Requirement[]) =>
  reqs.find((r) => r.type === "array" && (r.name === "pid" || r.name === "pids"))?.name ?? null;

/** Run a Volatility 3 plugin over the active `.mdview` and work with its rows. */
export function Vol3Panel() {
  const { t } = useTranslation("vol3");
  const activePath = useActiveDump()?.path ?? "";
  const viewPath = isMdview(activePath) ? activePath : "";
  const caseDir = useImageStore((s) => s.caseDir);
  const [plugins, setPlugins] = useState<Vol3Plugin[]>([]);
  const [selected, setSelected] = useState("");
  const [description, setDescription] = useState<Vol3PluginDescription | null>(null);
  const [draft, setDraft] = useState<ArgDraft>({});
  const [errors, setErrors] = useState<ArgErrors>({});
  const [overrides, setOverrides] = useState<ColumnOverrides>({});
  const [limit, setLimit] = useState("10000");
  const [timeoutS, setTimeoutS] = useState("30");
  const [asJob, setAsJob] = useState(false);
  const [loadError, setLoadError] = useState<string | null>(null);
  const [mode, setMode] = useState<Mode>("run");
  const [processResult, setProcessResult] = useState<Vol3RunResult | null>(null);
  const [filterToPid, setFilterToPid] = useState(false);
  const [queryNote, setQueryNote] = useState<string | null>(null);
  const selectedPid = useSelectionStore((s) => s.pid);
  const lastAutoPid = useRef<string>("");
  const [hint, setHint] = useState<NavResolution | null>(null);
  const { state, run, cancel } = useVol3Run();
  const result = state.result;
  const { ctx, loadIntervals, view } = useViewContext(viewPath, result);
  const requirements = useMemo(() => description?.requirements ?? [], [description]);
  const pidArg = pidArgument(requirements);
  const captureId = view?.capture_id ?? result?.view?.capture_id ?? result?.capture_id ?? null;
  const tableRules = useTableRules(caseDir, captureId);
  const visibleRowIndices = useMemo(() => {
    if (!result || !filterToPid || selectedPid === null) return undefined;
    return result.rows.map((_, i) => i).filter((i) => rowPid(result, i) === selectedPid);
  }, [result, filterToPid, selectedPid]);
  const resultHasPid = Boolean(result?.columns.some((c) => c.name.trim().toLowerCase() === "pid"));

  // The view's capture is the selection's capture (D14); a different capture drops the pid.
  useEffect(() => { useSelectionStore.getState().setCaptureId(captureId); }, [captureId]);
  // Remember the latest process listing (adjusting state while rendering, not in an effect).
  const [seenResult, setSeenResult] = useState<Vol3RunResult | null>(null);
  if (result !== seenResult) {
    setSeenResult(result);
    if (result && isProcessListing(result)) setProcessResult(result);
  }
  // Default the plugin's pid argument to the selected process, visibly, unless the
  // process view already fixes it or the user typed their own value.
  useEffect(() => {
    if (!pidArg || ctx.kind === "process") return;
    const next = selectedPid === null ? "" : String(selectedPid);
    setDraft((d) => {
      const current = d[pidArg];
      if (current !== "" && current !== lastAutoPid.current) return d;
      lastAutoPid.current = next;
      return { ...d, [pidArg]: next };
    });
  }, [pidArg, selectedPid, ctx.kind, description]);

  useEffect(() => {
    listVol3Plugins().then((l) => setPlugins(l.plugins)).catch((e) => setLoadError(readableFailure(e)));
  }, []);

  const choose = (name: string) => {
    setSelected(name);
    setDescription(null);
    setOverrides({});
    setErrors({});
    describeVol3Plugin(name)
      .then((d) => { setDescription(d); setDraft(initialDraft(d.requirements)); })
      .catch((e) => setLoadError(readableFailure(e)));
  };

  const loadProcessTree = () => {
    void run({ view_path: viewPath, plugin: PROCESS_PLUGIN, case_dir: caseDir.trim() });
  };

  const sendQueryToHighlights = async (q: Vol3QueryResult) => {
    const intervals = ctx.mode === "vas" ? await loadIntervals() : null;
    const plan = planQueryHighlights(q, ctx, intervals, { dumpPath: viewPath });
    paintPluginHighlights(QUERY_HIGHLIGHT_PLUGIN, plan.regions);
    setQueryNote(plan.placed === 0
      ? t(plan.firstRefusal && !plan.firstRefusal.ok ? plan.firstRefusal.hint : "nav.noAddress",
          plan.firstRefusal && !plan.firstRefusal.ok ? plan.firstRefusal.params : undefined)
      : t("query.placed", { placed: plan.placed, skipped: plan.skipped }));
  };

  const start = () => {
    const built = buildArgs(requirements, draft);
    setErrors(built.errors);
    if (Object.keys(built.errors).length > 0) return;
    void run({
      view_path: viewPath, plugin: selected, args: built.args, case_dir: caseDir.trim(),
      limit: Number(limit) || undefined, timeout_s: Number(timeoutS) || undefined,
      column_map: Object.keys(overrides).length ? overrides as Record<string, string | null> : undefined,
      async: asJob || undefined,
    });
  };

  const rowClick = async (row: number) => {
    if (!result) return;
    const refs = result.columns.map((c) => addressRef(result, row, c.name)).filter((r) => r !== null);
    const intervals = ctx.mode === "vas" ? await loadIntervals() : null;
    const tried = refs.map((ref) => resolveOffset(ref, ctx, intervals));
    const hit = tried.find((r) => r.ok);
    if (hit?.ok) {
      setHint(null);
      useHexStore.getState().scrollToOffset(hit.offset);
    } else {
      setHint(tried[0] ?? { ok: false, hint: "nav.noAddress" });
    }
  };

  const highlight = async (column: string) => {
    if (!result) return;
    const intervals = ctx.mode === "vas" ? await loadIntervals() : null;
    const plan = planColumnHighlights(result, column, ctx, intervals, { dumpPath: viewPath });
    paintPluginHighlights(result.plugin, plan.regions);
    setHint(plan.placed === 0 ? (plan.firstRefusal ?? { ok: false, hint: "nav.noAddress" }) : null);
  };

  const running = state.status === "running";
  const pct = state.pct === null ? null : Math.round(state.pct * 100);
  return (
    <div data-testid="vol3-panel" className="p-2 space-y-3 overflow-auto h-full text-xs">
      <h3 className="font-semibold md-text-accent">{t("title")}</h3>
      {loadError && <p role="alert" data-testid="vol3-load-error" style={{ color: "var(--md-accent-red)" }}>{loadError}</p>}
      <label className="block space-y-0.5"><span className="md-text-secondary">{t("run.caseDir")}</span>
        <input type="text" value={caseDir} onChange={(e) => useImageStore.getState().setCaseDir(e.target.value)}
            placeholder={t("run.casePlaceholder")} className={inputClass} data-testid="vol3-case-dir" /></label>
      <div role="tablist" aria-label={t("mode.label")} className="flex flex-wrap gap-1" data-testid="vol3-mode">
        {MODES.map((m) => (
          <button key={m} type="button" role="tab" aria-selected={mode === m} data-testid={`vol3-mode-${m}`}
            onClick={() => setMode(m)}
            className={`${buttonClass} ${mode === m ? "bg-[var(--md-bg-hover)] md-text-accent" : ""}`}>{t(`mode.${m}`)}</button>
        ))}
      </div>
      {/* Hidden, not unmounted: switching to Run must not discard the source being edited. */}
      <div hidden={mode !== "editor"}>
        <PluginEditor viewPath={viewPath} caseDir={caseDir} running={state.status === "running"}
          onRun={(req) => void run(req)} />
      </div>
      {mode === "processes" && (
        <ProcessTree result={processResult} loading={running} onLoad={loadProcessTree} />
      )}
      {mode === "query" && (
        <QueryBox caseDir={caseDir} note={queryNote} onSendToHighlights={(q) => void sendQueryToHighlights(q)} />
      )}
      {mode === "run" && (
        <>
          <PluginPicker plugins={plugins} selected={selected} onSelect={choose} />
          {description && (
            <ArgsForm requirements={requirements} draft={draft} errors={errors}
              pidAutoFill={ctx.kind === "process" ? pidArg : null}
              selectedPid={ctx.kind === "process" || pidArg === null ? null : selectedPid}
              selectedPidArg={pidArg}
              onChange={(name, value) => setDraft((d) => ({ ...d, [name]: value }))} />
          )}
          <div className="grid grid-cols-2 gap-2">
            <label className="space-y-0.5"><span className="md-text-secondary">{t("run.limit")}</span>
              <input type="text" value={limit} onChange={(e) => setLimit(e.target.value)} className={inputClass} data-testid="run-limit" /></label>
            <label className="space-y-0.5"><span className="md-text-secondary">{t("run.timeout")}</span>
              <input type="text" value={timeoutS} onChange={(e) => setTimeoutS(e.target.value)} className={inputClass} data-testid="run-timeout" /></label>
          </div>
          <label className="flex items-center gap-1"><input type="checkbox" checked={asJob} onChange={(e) => setAsJob(e.target.checked)} data-testid="run-async" />
            <span>{t("run.async")}</span></label>
          <div className="flex gap-2">
            <button type="button" className={buttonClass} data-testid="vol3-run"
              disabled={!viewPath || !selected || !description || running || state.status === "cancelling"} onClick={start}>{t("run.button")}</button>
            {running && state.taskId && <button type="button" className={buttonClass} data-testid="vol3-cancel"
              onClick={() => void cancel()}>{t("run.cancel")}</button>}
          </div>
        </>
      )}
      {mode === "run" && !viewPath && <p className="md-text-muted" data-testid="needs-view">{t("run.needView")}</p>}
      {running && (
        <p role="status" data-testid="vol3-progress">
          {state.msg ?? t("run.running")}{pct !== null && ` ${t("run.progress", { pct })}`}</p>
      )}
      {state.status === "cancelling" && <p role="status" data-testid="vol3-cancelling">{t("run.cancelling")}</p>}
      {state.status === "cancelled" && <p role="status" data-testid="vol3-cancelled">{t("run.cancelled")}</p>}
      {state.status === "error" && <p role="alert" data-testid="vol3-error" style={{ color: "var(--md-accent-red)" }}>{state.error}</p>}
      {result && (
        <>
          <RunSummary result={result} />
          {Object.keys(overrides).length > 0 && <p className="md-text-muted" data-testid="override-hint">{t("table.reRunHint")}</p>}
          {resultHasPid && (
            <label className="flex items-center gap-1" data-testid="pid-filter">
              <input type="checkbox" checked={filterToPid} disabled={selectedPid === null}
                onChange={(e) => setFilterToPid(e.target.checked)} data-testid="pid-filter-toggle" />
              <span>{selectedPid === null ? t("selection.filterNone") : t("selection.filter", { pid: selectedPid })}</span>
            </label>
          )}
          <ResultsTable result={result} overrides={overrides} rules={tableRules.rules}
            indices={visibleRowIndices} onRowClick={(r) => void rowClick(r)}
            onOverride={(column, space) => setOverrides((o) => {
              const next = { ...o };
              if (space === undefined) delete next[column]; else next[column] = space;
              return next;
            })} />
          {hint && !hint.ok && (
            <p role="status" data-testid="vol3-nav-hint" className="md-text-muted">{t(hint.hint, hint.params)}</p>
          )}
          <ResultActions result={result} caseDir={caseDir} onHighlight={(c) => void highlight(c)} />
        </>
      )}
      {mode === "run" && (
        <details data-testid="rules-details">
          <summary className="cursor-pointer md-text-secondary">{t("rules.title")}</summary>
          <RuleEditor stored={tableRules.stored} ready={tableRules.ready} error={tableRules.error}
            plugin={result?.plugin ?? selected} columns={result?.columns.map((c) => c.name) ?? []}
            onAdd={(rule) => void tableRules.add(rule)} onDisable={(rule) => void tableRules.disable(rule)} />
        </details>
      )}
    </div>
  );
}

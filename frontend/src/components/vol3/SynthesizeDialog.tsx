import { useCallback, useEffect, useRef, useState } from "react";
import { useTranslation } from "react-i18next";

import {
  cancelVol3Job, getVol3SynthJobPayload, isJobTicket, KNOWN_ORACLE_KINDS, listFormatOracles,
  suggestFormatOracle, synthesizeVol3Plugin, vol3ErrorOf,
  type FormatOracleSuggestion, type Vol3JobTicket, type Vol3SynthesizeRequest, type Vol3SynthesizeResult,
} from "@/api/vol3";
import type { TaskProgressEvent } from "@/api/websocket";
import { ApiErrorHint } from "@/components/common/ApiErrorHint";
import { Modal } from "@/components/common/Modal";
import { useJobRun, type JobRunState } from "@/hooks/useJobRun";
import { useDumpStore } from "@/stores/dump-store";
import { SynthesizeResult } from "./SynthesizeResult";
import {
  buildSynthRequest, defaultPluginName, maskSecret, validateDraft, type SynthDraft, type SynthDumpDraft,
} from "./synth-utils";
import { buttonClass, inputClass } from "./styles";

export interface SynthesizeDialogProps {
  /** Dumps the key was located in (prefilled from the current context). */
  initialDumps: readonly string[];
  /**
   * The located key, for the FIRST dump. Held in component state only: never
   * rendered in full, never put in a URL or browser storage.
   */
  initialSecretHex?: string;
  initialCaseDir?: string;
  onClose: () => void;
  /** Called with a result whose plugin was stored (e.g. to refresh a source list). */
  onSynthesized?: (result: Vol3SynthesizeResult) => void;
}

const emptyDump = (path = "", secretHex = ""): SynthDumpDraft => ({ path, secretHex, samplePath: "" });

function initialDraft(p: SynthesizeDialogProps): SynthDraft {
  const dumps = p.initialDumps.length > 0
    ? p.initialDumps.map((path, i) => emptyDump(path, i === 0 ? p.initialSecretHex ?? "" : ""))
    : [emptyDump("", p.initialSecretHex ?? "")];
  const oracleKind = KNOWN_ORACLE_KINDS[0];
  return {
    dumps, name: defaultPluginName(oracleKind), oracleKind, caseDir: p.initialCaseDir ?? "",
    context: "64", verifyOnMsl: true, allowHighEntropy: false,
    fullImage: "", pid: "", fullImageSample: "", fullImageSecretHex: "", symbolDirs: "",
  };
}

/** A refused request or a failed job: the server's message and, when it has one, its code. */
interface SynthFailure { code: string | null; message: string }

/** An active job: its POST in flight, waiting behind other jobs, running, or being cancelled. */
type SynthJobPhase = "submitting" | "queued" | "running" | "cancelling";

const ELAPSED_TICK_MS = 1000;

/** The `error` a task's terminal event carries when it was cancelled (TaskManager / runner). */
const JOB_CANCELLED_ERROR = "cancelled";

/** `m:ss` of a whole number of seconds. */
const formatElapsed = (seconds: number) => `${Math.floor(seconds / 60)}:${String(seconds % 60).padStart(2, "0")}`;

/** The phase of an active run (`null` once idle or terminal); queued until the server admits the job. */
function phaseOf(state: JobRunState<unknown>, admitted: boolean): SynthJobPhase | null {
  if (state.status === "cancelling") return "cancelling";
  if (state.status !== "running") return null;
  if (state.taskId === null) return "submitting";
  return admitted ? "running" : "queued";
}

/** The capability code a failed job's `error` event carries in `extra.code`, when the server knows it. */
function jobErrorCode(event: { extra?: Record<string, unknown> | null }): string | null {
  const code = event.extra?.code;
  return typeof code === "string" && code !== "" ? code : null;
}

/** Whole seconds since `restart()` on the client clock, ticking once a second while `ticking`. */
function useElapsedSeconds(ticking: boolean) {
  const [startedAt, setStartedAt] = useState<number | null>(null);
  const [now, setNow] = useState(0);
  useEffect(() => {
    if (!ticking) return;
    const id = setInterval(() => setNow(Date.now()), ELAPSED_TICK_MS);
    return () => clearInterval(id);
  }, [ticking]);
  const restart = useCallback(() => {
    const t0 = Date.now();
    setStartedAt(t0);
    setNow(t0);
  }, []);
  return { elapsedS: startedAt === null ? 0 : Math.max(0, Math.floor((now - startedAt) / 1000)), restart };
}

/**
 * Cancel a still-active job when the dialog goes away (Close, Escape, or the
 * host unmounting it), so no job keeps running unseen. `reset` is stable.
 */
function useCancelOnUnmount(active: boolean, reset: () => void) {
  const activeRef = useRef(active);
  useEffect(() => { activeRef.current = active; }, [active]);
  useEffect(() => () => { if (activeRef.current) reset(); }, [reset]);
}

/** The refusal of the POST itself: `useJobRun` keeps only its readable text, this keeps the code. */
function useRefusalCapture() {
  const [refusal, setRefusal] = useState<SynthFailure | null>(null);
  const submit = useCallback(async (req: Vol3SynthesizeRequest) => {
    try {
      return await synthesizeVol3Plugin(req);
    } catch (err) {
      const refused = vol3ErrorOf(err);
      setRefusal(refused);
      throw err;
    }
  }, []);
  return { refusal, clearRefusal: () => setRefusal(null), submit };
}

/**
 * The synthesize request as a background job (`async: true`) followed through
 * `useJobRun`: queued until the server admits it (its first `stage_start`),
 * then running with the server's latest progress message, until `done` (the
 * stored payload is the result), a failure (message + code), or a cancel.
 */
function useSynthJob(onSynthesized?: (result: Vol3SynthesizeResult) => void) {
  const { refusal, clearRefusal, submit } = useRefusalCapture();
  const [admitted, setAdmitted] = useState(false);
  const [jobCode, setJobCode] = useState<string | null>(null);
  const onEvent = useCallback((event: TaskProgressEvent) => {
    if (event.type === "stage_start" || event.type === "progress") setAdmitted(true);
    else if (event.type === "error") setJobCode(jobErrorCode(event));
  }, []);
  const onResult = useCallback((result: Vol3SynthesizeResult) => {
    if (result.stored) onSynthesized?.(result);
  }, [onSynthesized]);
  const { state, run, cancel, reset } = useJobRun<Vol3SynthesizeRequest, Vol3SynthesizeResult, Vol3JobTicket>({
    submit, isTicket: isJobTicket, getPayload: getVol3SynthJobPayload, cancelJob: cancelVol3Job,
    noPayloadKey: "vol3:synth.job.noPayload", cancelMode: "awaitTerminal", onEvent, onResult,
  });
  const phase = phaseOf(state, admitted);
  const { elapsedS, restart } = useElapsedSeconds(phase !== null);
  useCancelOnUnmount(phase !== null, reset);

  const start = (req: Vol3SynthesizeRequest) => {
    clearRefusal();
    setAdmitted(false);
    setJobCode(null);
    restart();
    // Always a job: the dialog follows it (queue, progress, cancel) instead of holding one long POST.
    return run({ ...req, async: true });
  };
  // A job cancelled elsewhere (another tab, the API, a server shutdown) ends with
  // the task's own `error: "cancelled"`: that is a cancel, not a failure.
  const cancelledElsewhere = state.status === "error" && !refusal && state.error === JOB_CANCELLED_ERROR;
  const failure: SynthFailure | null = state.status !== "error" || cancelledElsewhere ? null
    : refusal ?? { code: jobCode, message: state.error ?? "" };
  return {
    phase, elapsedS, msg: state.msg, failure, start, cancel,
    result: state.status === "done" ? state.result : null,
    cancelled: state.status === "cancelled" || cancelledElsewhere,
  };
}

/** Queued / running / cancelling, the client-side elapsed time, the server's message, and Cancel. */
function SynthJobStatus({ phase, elapsedS, msg, onCancel }: {
  phase: SynthJobPhase; elapsedS: number; msg: string | null; onCancel: () => void;
}) {
  const { t } = useTranslation("vol3");
  return (
    <div className="space-y-0.5 p-1 rounded border border-[var(--md-border)]" data-testid="synth-job">
      <div className="flex items-center gap-2">
        <span role="status" className="md-text-secondary" data-testid="synth-job-state" data-state={phase}>
          {t(`synth.job.state.${phase}`)}</span>
        <span className="font-mono md-text-muted" data-testid="synth-job-elapsed">
          {t("synth.job.elapsed", { time: formatElapsed(elapsedS) })}</span>
        {phase !== "submitting" && (
          <button type="button" className={buttonClass} disabled={phase === "cancelling"}
            onClick={onCancel} data-testid="synth-job-cancel">{t("synth.job.cancel")}</button>
        )}
      </div>
      {phase === "queued" && <p className="md-text-muted" data-testid="synth-job-queued">{t("synth.job.queuedHint")}</p>}
      {/* The server's own (English) phase message, verbatim like the other job UIs. */}
      <p aria-live="polite" className="font-mono md-text-muted break-all" data-testid="synth-job-msg">{msg}</p>
    </div>
  );
}

const SUGGEST_DEBOUNCE_MS = 400;

/** The oracle kinds from the server's listing; the offline list when that route fails. */
function useOracleKinds(): readonly string[] {
  const [kinds, setKinds] = useState<readonly string[]>(KNOWN_ORACLE_KINDS);
  useEffect(() => {
    let alive = true;
    listFormatOracles()
      .then((r) => { if (alive && r.formats.length > 0) setKinds(r.formats.map((f) => f.kind)); })
      .catch(() => { /* keep the offline fallback */ });
    return () => { alive = false; };
  }, []);
  return kinds;
}

/**
 * Ask the server which oracle fits the first dump (debounced on its path) and
 * hand the suggestion to `apply`. A failed or empty answer is silent.
 */
function useOracleSuggestion(firstDumpPath: string, apply: (s: FormatOracleSuggestion) => void) {
  const [suggestion, setSuggestion] = useState<FormatOracleSuggestion | null>(null);
  const applyRef = useRef(apply);
  useEffect(() => { applyRef.current = apply; });
  useEffect(() => {
    const path = firstDumpPath.trim();
    if (path === "") return;
    let alive = true;
    const timer = setTimeout(() => {
      suggestFormatOracle(path).then((r) => {
        if (!alive) return;
        setSuggestion(r.suggestion);
        if (r.suggestion) applyRef.current(r.suggestion);
      }).catch(() => { if (alive) setSuggestion(null); });
    }, SUGGEST_DEBOUNCE_MS);
    return () => { alive = false; clearTimeout(timer); };
  }, [firstDumpPath]);
  return firstDumpPath.trim() === "" ? null : suggestion;
}

/**
 * "Export as Volatility 3 plugin": a located key -> a standalone plugin proven
 * by its oracle (`POST /api/vol3/synthesize`, run as a background job), then
 * run under stock vol.
 */
export function SynthesizeDialog(props: SynthesizeDialogProps) {
  const { t } = useTranslation("vol3");
  const { onClose, onSynthesized } = props;
  const [draft, setDraft] = useState<SynthDraft>(() => initialDraft(props));
  const [errors, setErrors] = useState<string[]>([]);
  const nameRef = useRef<HTMLInputElement>(null);
  const job = useSynthJob(onSynthesized);
  const busy = job.phase !== null;
  const kinds = useOracleKinds();
  const kindTouched = useRef(false);
  // The sample path the LAST suggestion filled in: a later suggestion (the first
  // dump changed) may replace it, but never a path the user typed. Each run has
  // its own key, so a sample left over from another dump would prove nothing.
  const autoSample = useRef("");

  const applySuggestion = useCallback((s: FormatOracleSuggestion) => {
    setDraft((d) => ({
      ...d,
      // Never override a kind the user picked by hand.
      ...(kindTouched.current ? {} : {
        oracleKind: s.kind,
        name: d.name === defaultPluginName(d.oracleKind) ? defaultPluginName(s.kind) : d.name,
      }),
      dumps: d.dumps.map((x, i) => {
        if (i !== 0 || (x.samplePath !== "" && x.samplePath !== autoSample.current)) return x;
        const samplePath = s.sample_path ?? "";
        autoSample.current = samplePath;
        return { ...x, samplePath };
      }),
    }));
  }, []);
  const suggestion = useOracleSuggestion(draft.dumps[0]?.path ?? "", applySuggestion);

  const set = <K extends keyof SynthDraft>(key: K, value: SynthDraft[K]) =>
    setDraft((d) => ({ ...d, [key]: value }));
  const setDump = (i: number, patch: Partial<SynthDumpDraft>) =>
    setDraft((d) => ({ ...d, dumps: d.dumps.map((x, j) => (j === i ? { ...x, ...patch } : x)) }));

  const submit = () => {
    const found = validateDraft(draft);
    setErrors(found);
    if (found.length > 0) return;
    // An encrypted `.msl` container's own key material (not the secret).
    const container = useDumpStore.getState().getKeyMaterialByPath(draft.dumps[0].path.trim()) ?? {};
    void job.start(buildSynthRequest(draft, container));
  };

  const filledDumps = draft.dumps.filter((d) => d.path.trim() !== "").length;
  return (
    <Modal title={t("synth.title")} onClose={onClose} closeOnBackdrop={false} initialFocusRef={nameRef}
      testId="synth-dialog"
      footer={(
        <>
          <button type="button" className={buttonClass} onClick={onClose} data-testid="synth-close">
            {t("common:close")}</button>
          <button type="button" className={`${buttonClass} md-text-accent`} disabled={busy}
            onClick={submit} data-testid="synth-submit">
            {busy ? t("synth.busy") : t("synth.submit")}</button>
        </>
      )}>
      <div className="space-y-2 text-xs">
        <p className="md-text-muted">{t("synth.intro")}</p>
        <fieldset className="space-y-1" data-testid="synth-dumps">
          <legend className="md-text-secondary">{t("synth.dumps.legend")}</legend>
          {draft.dumps.map((d, i) => (
            <div key={i} className="space-y-0.5 p-1 rounded border border-[var(--md-border)]" data-testid="synth-dump">
              <input type="text" className={`${inputClass} font-mono`} value={d.path}
                aria-label={t("synth.dumps.path", { n: i + 1 })} placeholder={t("synth.dumps.pathPlaceholder")}
                onChange={(e) => setDump(i, { path: e.target.value })} data-testid="synth-dump-path" />
              <div className="flex items-center gap-1">
                <input type="password" autoComplete="off" spellCheck={false} className={`${inputClass} font-mono`}
                  value={d.secretHex} aria-label={t("synth.dumps.secret", { n: i + 1 })}
                  placeholder={i === 0 ? t("synth.dumps.secretPlaceholder") : t("synth.dumps.secretSamePlaceholder")}
                  onChange={(e) => setDump(i, { secretHex: e.target.value })} data-testid="synth-dump-secret" />
                {d.secretHex && (
                  <span className="font-mono md-text-muted whitespace-nowrap" data-testid="synth-dump-secret-mask">
                    {maskSecret(d.secretHex)}</span>
                )}
              </div>
              <input type="text" className={`${inputClass} font-mono`} value={d.samplePath}
                aria-label={t("synth.dumps.sample", { n: i + 1 })} placeholder={t("synth.dumps.samplePlaceholder")}
                onChange={(e) => setDump(i, { samplePath: e.target.value })} data-testid="synth-dump-sample" />
              {draft.dumps.length > 1 && (
                <button type="button" className={buttonClass} data-testid="synth-dump-remove"
                  aria-label={t("synth.dumps.removeAria", { n: i + 1 })}
                  onClick={() => set("dumps", draft.dumps.filter((_, j) => j !== i))}>{t("synth.dumps.remove")}</button>
              )}
            </div>
          ))}
          <button type="button" className={buttonClass} data-testid="synth-dump-add"
            onClick={() => set("dumps", [...draft.dumps, emptyDump()])}>{t("synth.dumps.add")}</button>
          {filledDumps === 1 && !draft.allowHighEntropy && (
            <p className="md-text-muted" data-testid="synth-single-dump-hint">{t("synth.dumps.singleHint")}</p>
          )}
        </fieldset>
        <div className="grid grid-cols-2 gap-2">
          <label className="space-y-0.5"><span className="md-text-secondary">{t("synth.name")}</span>
            <input ref={nameRef} type="text" className={`${inputClass} font-mono`} value={draft.name}
              onChange={(e) => set("name", e.target.value)} data-testid="synth-name" /></label>
          <label className="space-y-0.5"><span className="md-text-secondary">{t("synth.oracle")}</span>
            <select className={inputClass} value={draft.oracleKind} data-testid="synth-oracle"
              onChange={(e) => { kindTouched.current = true; setDraft((d) => ({
                ...d, oracleKind: e.target.value,
                // Follow the kind while the name is still the previous kind's default.
                name: d.name === defaultPluginName(d.oracleKind) ? defaultPluginName(e.target.value) : d.name,
              })); }}>
              {(kinds.includes(draft.oracleKind) ? kinds : [draft.oracleKind, ...kinds])
                .map((k) => <option key={k} value={k}>{k}</option>)}
            </select></label>
        </div>
        {suggestion && (
          <p className="md-text-muted break-all" data-testid="synth-oracle-suggestion">
            {t("synth.suggestion", { reason: suggestion.reason, confidence: t(`synth.confidence.${suggestion.confidence}`) })}</p>
        )}
        <label className="block space-y-0.5"><span className="md-text-secondary">{t("synth.case")}</span>
          <input type="text" className={`${inputClass} font-mono`} value={draft.caseDir}
            placeholder={t("synth.casePlaceholder")} onChange={(e) => set("caseDir", e.target.value)}
            data-testid="synth-case" /></label>
        {draft.caseDir.trim() === "" && <p className="md-text-muted" data-testid="synth-no-case">{t("synth.noCase")}</p>}
        <details data-testid="synth-full-image">
          <summary className="cursor-pointer md-text-secondary">{t("synth.fullImage.legend")}</summary>
          <div className="space-y-1 pt-1">
            <label className="block space-y-0.5"><span className="md-text-secondary">{t("synth.fullImage.path")}</span>
              <input type="text" className={`${inputClass} font-mono`} value={draft.fullImage}
                onChange={(e) => set("fullImage", e.target.value)} data-testid="synth-full-image-path" /></label>
            <div className="grid grid-cols-2 gap-2">
              <label className="space-y-0.5"><span className="md-text-secondary">{t("synth.fullImage.pid")}</span>
                <input type="text" inputMode="numeric" className={inputClass} value={draft.pid}
                  onChange={(e) => set("pid", e.target.value)} data-testid="synth-full-image-pid" /></label>
              <label className="space-y-0.5"><span className="md-text-secondary">{t("synth.fullImage.secret")}</span>
                <input type="password" autoComplete="off" spellCheck={false} className={`${inputClass} font-mono`}
                  value={draft.fullImageSecretHex} onChange={(e) => set("fullImageSecretHex", e.target.value)}
                  data-testid="synth-full-image-secret" /></label>
            </div>
            <label className="block space-y-0.5"><span className="md-text-secondary">{t("synth.fullImage.sample")}</span>
              <input type="text" className={`${inputClass} font-mono`} value={draft.fullImageSample}
                onChange={(e) => set("fullImageSample", e.target.value)} data-testid="synth-full-image-sample" /></label>
            <label className="block space-y-0.5"><span className="md-text-secondary">{t("synth.fullImage.symbolDirs")}</span>
              <textarea rows={2} className={`${inputClass} font-mono`} value={draft.symbolDirs}
                onChange={(e) => set("symbolDirs", e.target.value)} data-testid="synth-symbol-dirs" /></label>
            <p className="md-text-muted">{t("synth.fullImage.slow")}</p>
          </div>
        </details>
        <details data-testid="synth-advanced">
          <summary className="cursor-pointer md-text-secondary">{t("synth.advanced.legend")}</summary>
          <div className="space-y-1 pt-1">
            <label className="block space-y-0.5"><span className="md-text-secondary">{t("synth.advanced.context")}</span>
              <input type="text" inputMode="numeric" className={inputClass} value={draft.context}
                onChange={(e) => set("context", e.target.value)} data-testid="synth-context" /></label>
            <label className="flex items-center gap-1">
              <input type="checkbox" checked={draft.verifyOnMsl} onChange={(e) => set("verifyOnMsl", e.target.checked)}
                data-testid="synth-verify-msl" />{t("synth.advanced.verifyMsl")}</label>
            <label className="flex items-center gap-1">
              <input type="checkbox" checked={draft.allowHighEntropy}
                onChange={(e) => set("allowHighEntropy", e.target.checked)} data-testid="synth-allow-high-entropy" />
              {t("synth.advanced.allowHighEntropy")}</label>
          </div>
        </details>
        {errors.length > 0 && (
          <ul role="alert" data-testid="synth-validation" style={{ color: "var(--md-accent-red)" }}>
            {errors.map((e) => <li key={e}>{t(e)}</li>)}
          </ul>
        )}
        {busy && <p role="status" data-testid="synth-busy">{t("synth.busyHint")}</p>}
        {job.phase && (
          <SynthJobStatus phase={job.phase} elapsedS={job.elapsedS} msg={job.msg} onCancel={() => void job.cancel()} />
        )}
        {job.cancelled && <p role="status" data-testid="synth-job-cancelled">{t("synth.job.cancelled")}</p>}
        {job.failure && (
          <>
            <p role="alert" data-testid="synth-error" style={{ color: "var(--md-accent-red)" }}>
              {job.failure.code && <span className="font-mono" data-testid="synth-error-code">{job.failure.code}: </span>}
              {job.failure.message}</p>
            <ApiErrorHint code={job.failure.code} />
          </>
        )}
        {job.result && <SynthesizeResult result={job.result} />}
      </div>
    </Modal>
  );
}

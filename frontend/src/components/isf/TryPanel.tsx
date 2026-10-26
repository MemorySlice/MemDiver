import { useEffect, useRef, useState } from "react";
import { useTranslation } from "react-i18next";

import { getIsfJobPayload, startIsfTryJob, type DraftRef, type TryResult, type TryVerdict } from "@/api/isf";
import { JobStatus } from "@/components/image/JobStatus";
import { useImageJob } from "@/components/image/useImageJob";
import { usePastTries } from "./usePastTries";
import { buttonClass, errorStyle, inputClass } from "./ui";

const VERDICT_STYLE: Record<TryVerdict, { icon: string; colour: string }> = {
  pass: { icon: "✓", colour: "var(--md-accent-green)" },
  partial: { icon: "~", colour: "var(--md-accent-yellow)" },
  fail: { icon: "✗", colour: "var(--md-accent-red)" },
  unverified: { icon: "?", colour: "var(--md-accent-orange)" },
  error: { icon: "!", colour: "var(--md-accent-red)" },
};

/** Verdict as icon + word + colour: colour is never the only cue. */
export function TryVerdictBadge({ verdict }: { verdict: TryVerdict }) {
  const { t } = useTranslation("isf");
  const { icon, colour } = VERDICT_STYLE[verdict] ?? VERDICT_STYLE.error;
  return (
    <span data-testid="try-verdict" data-verdict={verdict}
      className="inline-flex items-center gap-1 px-1.5 rounded border font-medium"
      style={{ color: colour, borderColor: colour }}>
      <span aria-hidden="true">{icon}</span>{t(`try.verdict.${verdict}`)}
    </span>
  );
}

const pct = (x: number) => `${(x * 100).toFixed(1)}%`;

function TryResultView({ result, onImplicated }: { result: TryResult; onImplicated: (item: string) => void }) {
  const { t } = useTranslation("isf");
  const cmp = result.comparison;
  const columns = cmp?.mismatches[0] ? Object.keys(cmp.mismatches[0]) : [];
  return (
    <div className="space-y-1" data-testid="try-result">
      <div className="flex items-center gap-2">
        <TryVerdictBadge verdict={result.verdict} />
        <span className="md-text-secondary">{t("try.stage", { stage: result.stage, plugin: result.plugin })}</span>
      </div>
      {result.error && <p data-testid="try-error" className="font-mono" style={{ color: "var(--md-accent-red)" }}>{result.error}</p>}
      {result.verdict === "unverified" && <p className="md-text-muted">{t("try.unverifiedHint")}</p>}
      {cmp && (
        <table data-testid="try-comparison" className="text-xs"><tbody>
          {(["expected", "returned", "matched"] as const).map((k) => (
            <tr key={k}><th className="text-left pr-2 font-normal md-text-secondary">{t(`try.cmp.${k}`)}</th>
              <td data-testid={`try-cmp-${k}`}>{cmp[k]}</td></tr>
          ))}
          <tr><th className="text-left pr-2 font-normal md-text-secondary">{t("try.cmp.recall")}</th>
            <td data-testid="try-cmp-recall">{pct(cmp.recall)}</td></tr>
          <tr><th className="text-left pr-2 font-normal md-text-secondary">{t("try.cmp.precision")}</th>
            <td data-testid="try-cmp-precision">{pct(cmp.precision)}</td></tr>
        </tbody></table>
      )}
      {cmp && (cmp.missing.length > 0 || cmp.extra.length > 0) && (
        <p data-testid="try-pids" className="md-text-secondary">
          {t("try.pids", { missing: cmp.missing.join(", ") || "-", extra: cmp.extra.join(", ") || "-" })}</p>
      )}
      {cmp && cmp.mismatch_count > 0 && (
        <div data-testid="try-mismatches">
          <p className="md-text-secondary">{t("try.mismatches", { count: cmp.mismatch_count })}
            {cmp.truncated ? ` ${t("try.truncated", { shown: cmp.mismatches.length })}` : ""}</p>
          <table className="text-xs"><thead><tr>
            {columns.map((c) => <th key={c} className="text-left pr-2">{c}</th>)}</tr></thead>
          <tbody>{cmp.mismatches.map((m, i) => (
            <tr key={i} data-testid="try-mismatch-row">
              {columns.map((c) => <td key={c} className="pr-2 font-mono">{String(m[c] ?? "")}</td>)}</tr>))}
          </tbody></table>
        </div>
      )}
      {result.implicated.length > 0 && (
        <div data-testid="try-implicated" className="flex flex-wrap items-center gap-1">
          <span className="md-text-secondary">{t("try.implicated")}</span>
          {result.implicated.map((i) => (
            <button key={i.item} type="button" data-testid="try-implicated-chip" title={i.reason}
              className={`${buttonClass} font-mono`} onClick={() => onImplicated(i.item)}>{i.item}</button>
          ))}
        </div>
      )}
    </div>
  );
}

/** Try the draft against the image with a Volatility plugin and a ground truth. */
export function TryPanel({ imagePath, draftRef, draft, rev, onImplicated }: {
  imagePath: string; draftRef: DraftRef; draft: string; rev: number; onImplicated: (item: string) => void;
}) {
  const { t } = useTranslation("isf");
  const [plugin, setPlugin] = useState("linux.pslist");
  const [truth, setTruth] = useState("");
  const [runs, setRuns] = useState(0);
  // The result of THIS session's run, per draft; earlier tries come from the record.
  // A result belongs to the draft/capture it was STARTED for, never to the current selection.
  const [last, setLast] = useState<{ origin: string; result: TryResult } | null>(null);
  const originRef = useRef("");
  const origin = [draftRef.caseDir, draftRef.captureId, draft].join("\u0000");
  const job = useImageJob<TryResult>((result) => {
    setLast({ origin: originRef.current, result });
    setRuns((n) => n + 1);
  }, getIsfJobPayload<TryResult>);
  const jobRef = useRef(job);
  useEffect(() => { jobRef.current = job; });
  // Switching draft/capture detaches the in-flight try.
  useEffect(() => {
    if (jobRef.current.state.status === "running") void jobRef.current.cancel();
  }, [origin]);
  const past = usePastTries(draftRef, draft, rev + runs);
  const current = last?.origin === origin ? last.result : null;
  const running = job.state.status === "running";

  const run = () => { originRef.current = origin; void job.start(() => startIsfTryJob({
    imagePath, caseDir: draftRef.caseDir, draft, plugin: plugin.trim() || "linux.pslist",
    groundTruth: truth.trim() || undefined,
  })); };
  return (
    <section className="space-y-1" data-testid="isf-try">
      <h4 className="font-semibold">{t("try.title")}</h4>
      <input type="text" value={plugin} className={inputClass} data-testid="try-plugin"
        aria-label={t("try.plugin")} onChange={(e) => setPlugin(e.target.value)} />
      <input type="text" value={truth} className={inputClass} data-testid="try-truth"
        aria-label={t("try.groundTruth")} placeholder={t("try.groundTruthPlaceholder")}
        onChange={(e) => setTruth(e.target.value)} />
      <button type="button" className={buttonClass} disabled={running || imagePath.trim() === ""}
        data-testid="try-run" onClick={run}>{t("try.run")}</button>
      <JobStatus state={job.state} label={t("try.running")} testId="try-job" onCancel={() => void job.cancel()} />
      {job.state.status === "cancelled" && <p data-testid="try-cancelled" className="md-text-muted">{t("job.cancelled")}</p>}
      {current && (
        <div data-testid="try-current">
          <h5 className="font-medium">{t("try.current")}</h5>
          <TryResultView result={current} onImplicated={onImplicated} />
        </div>
      )}
      <h5 className="font-medium">{t("try.past")}</h5>
      {past.error && <p role="alert" data-testid="try-past-error" style={errorStyle}>{t("try.pastError", { message: past.error })}</p>}
      {!past.error && !past.loading && past.entries.length === 0 && (
        <p className="md-text-muted" data-testid="try-past-empty">{t("try.pastEmpty")}</p>
      )}
      <ul data-testid="try-past" className="space-y-0.5">
        {past.entries.map((e) => (
          <li key={e.id} data-testid="try-past-item" data-verdict={e.payload?.verdict}>
            {t("try.pastItem", {
              created: e.created ?? "-", verdict: t(`try.verdict.${e.payload?.verdict ?? "error"}`, { defaultValue: e.payload?.verdict ?? "?" }),
              plugin: e.payload?.plugin ?? "-", version: e.payload?.version ?? "-",
              state: e.payload?.state_id ?? "-", implicated: e.payload?.implicated?.length ?? 0 })}
          </li>
        ))}
      </ul>
    </section>
  );
}

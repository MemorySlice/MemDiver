/**
 * 16-dot oracle smoke test.
 *
 * Before committing to a 9000-candidate run, let the user verify the
 * oracle loads and returns the right shape on a handful of samples.
 * Each dot is one sample from a list the caller provides (typically
 * 16 random byte strings from high-entropy regions of the first
 * dump). Green = oracle returned true, red = false, gray = error.
 *
 * UX intent: dry-run on random offsets SHOULD produce mostly red dots
 * — the whole pipeline exists because random candidates almost never
 * decrypt. A red bar is the normal pre-run state; the legend makes
 * that explicit so first-time users don't misinterpret it as a bug.
 *
 * A *failed* run is a different thing from an all-red run, and the dots
 * alone cannot express that: if the request is refused (misconfigured
 * oracle, execution disabled, oracle id gone) the server never grades a
 * single sample, so there is nothing for the dots to say. That silence
 * was the reported bug — an HTTP 400 with a perfectly readable message
 * left all 16 dots grey and the message only appeared on a sibling tab.
 * Hence the scoped failure line below: the bar states its own outcome
 * rather than relying on some other panel to state it.
 */

import { useState } from "react";
import { useTranslation } from "react-i18next";

import { useOracleStore } from "@/stores/oracle-store";

interface Props {
  /** Oracle id to test against; button is disabled when null. */
  oracleId: string | null;
  /** Base64-encoded byte strings to feed into the oracle. */
  samplesB64: string[];
}

type DotState = "idle" | "pass" | "fail" | "error";

function dotStyle(state: DotState): { background: string } {
  switch (state) {
    case "pass":
      return { background: "var(--md-accent-green)" };
    case "fail":
      return { background: "var(--md-accent-red)" };
    case "error":
      return { background: "var(--md-text-muted)" };
    default:
      return { background: "var(--md-bg-hover)" };
  }
}

export function OracleDryRunBar({ oracleId, samplesB64 }: Props) {
  const { t } = useTranslation("pipeline");
  const dryRun = useOracleStore((s) => s.dryRun);
  const runDry = useOracleStore((s) => s.runDry);
  const [submitting, setSubmitting] = useState(false);
  /**
   * Why THIS bar's last run failed — deliberately local, not a selector.
   *
   * ``useOracleStore.error`` is shared by every oracle action, and
   * StageOracle mounts OracleUpload / OracleExamplePicker alongside this
   * bar. A reactive selector would therefore paint a failed *upload*
   * under the dry-run dots. Reading the store imperatively at the moment
   * the run resolves keeps the message attributable to the run it came
   * from; OracleExamplePicker.storeFailure() uses the same idiom.
   */
  const [failure, setFailure] = useState<string | null>(null);

  async function handleRun(): Promise<void> {
    if (!oracleId || samplesB64.length === 0) return;
    setFailure(null);
    setSubmitting(true);
    try {
      const result = await runDry(oracleId, samplesB64);
      if (result === null) {
        // ``guarded`` already ran the body through ``readableFailure``, so this
        // is the server's own sentence and not a {"detail":…} envelope.
        //
        // NOTE (not a bug to fix here): on failure the store keeps the previous
        // ``dryRun``, so stale dots can sit above a fresh error. That is
        // acceptable — the error text is unambiguous about what happened — and
        // clearing a shared store field on behalf of one consumer would be the
        // worse trade.
        //
        // The empty string is treated as "no reason" alongside null: a
        // rejection with a blank message would otherwise set a falsy failure
        // and render nothing, which is the very silence this bar exists to end.
        const reason = useOracleStore.getState().error;
        setFailure(reason?.trim() ? reason : t("oracle.dryRun.unknownError"));
      }
    } finally {
      setSubmitting(false);
    }
  }

  const dots: DotState[] = Array.from({ length: samplesB64.length }, (_, i) => {
    if (!dryRun || dryRun.oracle_id !== oracleId) return "idle";
    const result = dryRun.results[i];
    if (!result) return "idle";
    if (result.error !== undefined) return "error";
    return result.ok ? "pass" : "fail";
  });

  const summary =
    dryRun && dryRun.oracle_id === oracleId
      ? t("oracle.dryRun.summary", {
          passes: dryRun.passes,
          fails: dryRun.fails,
          errors: dryRun.errors,
          avg: dryRun.per_call_us_avg.toFixed(1),
        })
      : null;

  return (
    <div className="space-y-2">
      <div className="flex items-center justify-between gap-2">
        <div className="text-xs md-text-muted">
          {t("oracle.dryRun.smokeTest", { count: samplesB64.length })}
        </div>
        <button
          type="button"
          disabled={!oracleId || submitting || samplesB64.length === 0}
          onClick={() => void handleRun()}
          className="text-xs px-2 py-1 rounded bg-[var(--md-accent-blue)] md-text-on-accent disabled:opacity-50"
          title={t("oracle.dryRun.testTitle")}
        >
          {submitting
            ? t("oracle.dryRun.testing")
            : t("oracle.dryRun.testButton", { count: samplesB64.length })}
        </button>
      </div>

      <div className="flex items-center gap-1.5">
        {dots.map((state, i) => (
          <span
            key={i}
            title={t("oracle.dryRun.dotTitle", { index: i, state })}
            className="inline-block w-3 h-3 rounded-full"
            style={dotStyle(state)}
          />
        ))}
      </div>

      {failure && (
        <p data-testid="oracle-dry-run-error" className="text-xs md-text-error">
          {t("oracle.dryRun.failedPrefix", { error: failure })}
        </p>
      )}

      <div className="flex items-center justify-between text-[10px] md-text-muted">
        <div className="flex items-center gap-2">
          <span className="inline-flex items-center gap-1">
            <span className="inline-block w-2 h-2 rounded-full bg-[var(--md-accent-green)]" /> {t("oracle.dryRun.legendPass")}
          </span>
          <span className="inline-flex items-center gap-1">
            <span className="inline-block w-2 h-2 rounded-full bg-[var(--md-accent-red)]" /> {t("oracle.dryRun.legendFail")}
          </span>
          <span className="inline-flex items-center gap-1">
            <span className="inline-block w-2 h-2 rounded-full bg-[var(--md-text-muted)]" /> {t("oracle.dryRun.legendError")}
          </span>
          <span>{t("oracle.dryRun.legendNote")}</span>
        </div>
        {summary && <div className="font-mono">{summary}</div>}
      </div>
    </div>
  );
}

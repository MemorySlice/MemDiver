/**
 * Oracle smoke test — one positive control plus a row of decoys.
 *
 * WHY THIS IS NOT THE OLD DRY-RUN BAR
 * ------------------------------------
 * The previous version built its own 16 samples in the browser as an
 * arithmetic ramp (``bytes[j] = (i * 31 + j) & 0xff``) and posted them to
 * ``/dry-run``. Those bytes are not key material and never touched a dump, so
 * a CORRECT oracle scored 0 pass / 16 fail — and so did a completely broken
 * one. The bar was decorative: no arrangement of its dots could tell the two
 * apart, which is the only question a smoke test exists to answer.
 *
 * ``/smoke-test`` composes the samples server-side instead:
 *
 *  - a **positive control** — the dataset's recorded answer key, which the
 *    oracle is supposed to ACCEPT. This is the half the old bar could never
 *    test, and it is what catches "this oracle always says no".
 *  - **negatives (decoys)** — real bytes read out of the user's own dump at
 *    random offsets, which the oracle is supposed to REJECT. This is what
 *    catches "this oracle always says yes".
 *
 * Only the pair is diagnostic, so the server returns a ``verdict`` and this bar
 * leads with it rather than making the user count dots.
 *
 * HONESTY CONSTRAINT
 * ------------------
 * The positive control uses ground truth from the dataset's ``meta.json``. It
 * is a SELF-TEST OF THE ORACLE, not a pipeline finding — nothing was searched
 * for and nothing was recovered. A green control dot sitting anonymously in a
 * row of decoys would read as "we found the key", so the control is rendered
 * first, separated by a gap, under its own label, with its provenance spelled
 * out beneath it. ``positive.ok === null`` means no control was RUN (no ground
 * truth available); it renders as a neutral marker and never as a failure.
 *
 * A *failed* run is a different thing from a bad verdict, and neither the dots
 * nor the banner can express it: if the request is refused (misconfigured
 * oracle, execution disabled, oracle id gone) the server never grades a single
 * sample. That silence was the original reported bug — an HTTP 400 with a
 * perfectly readable message left every dot grey and the message only appeared
 * on a sibling tab. Hence the scoped failure line below.
 */

import { useState } from "react";
import { useTranslation } from "react-i18next";

import type { SmokeTestResult, SmokeTestVerdict } from "@/api/oracles";
import { useOracleStore } from "@/stores/oracle-store";

interface Props {
  /** Oracle id to test against; the run button is disabled when null. */
  oracleId: string | null;
  /**
   * The dumps picked on the previous stage. ``sourcePaths[0]`` is the dump the
   * server reads the decoys out of and the run whose answer key becomes the
   * positive control, so an empty list means there is nothing to test against.
   */
  sourcePaths: string[];
  /** Candidate width to sample, in bytes. Matches the sweep's first key size. */
  keySize?: number;
  /** How many decoys to draw. The server's own default is the same number. */
  negativeCount?: number;
  /** Advance the wizard. Offered only once the verdict says the oracle works. */
  onContinue?: () => void;
}

/**
 * ``absent`` is deliberately its own state and not a flavour of ``error``:
 * "we did not run this" and "this run blew up" look the same in grey but mean
 * opposite things for whether the user should trust the bar.
 */
type DotState = "idle" | "pass" | "fail" | "error" | "absent";

function dotStyle(state: DotState): { background: string } {
  switch (state) {
    case "pass":
      return { background: "var(--md-accent-green)" };
    case "fail":
      return { background: "var(--md-accent-red)" };
    case "error":
      return { background: "var(--md-text-muted)" };
    case "absent":
      return { background: "var(--md-bg-hover)" };
    default:
      return { background: "var(--md-bg-hover)" };
  }
}

/**
 * Banner colour per verdict.
 *
 * Both failure verdicts are red because both mean the same thing operationally
 * — running the sweep with this oracle wastes the run. The two "we could not
 * tell" verdicts are amber rather than red: an untested oracle is not a broken
 * one, and colouring it as broken would train users to ignore the red.
 */
function verdictTone(verdict: SmokeTestVerdict): {
  bg: string;
  border: string;
  text: string;
} {
  switch (verdict) {
    case "discriminates":
      return {
        bg: "md-bg-success-subtle",
        border: "md-border-success",
        text: "md-text-success",
      };
    case "never_accepts":
    case "accepts_noise":
      return {
        bg: "md-bg-error-subtle",
        border: "md-border-error",
        text: "md-text-error",
      };
    default:
      return {
        bg: "md-bg-warning-subtle",
        border: "md-border-warning",
        text: "md-text-warning",
      };
  }
}

/** Last path segment, for a label that fits. The full path goes in `title`. */
function basename(path: string): string {
  const parts = path.split(/[/\\]/);
  return parts[parts.length - 1] || path;
}

export function OracleDryRunBar({
  oracleId,
  sourcePaths,
  keySize = 32,
  negativeCount = 15,
  onContinue,
}: Props) {
  const { t } = useTranslation("pipeline");
  const smokeTest = useOracleStore((s) => s.smokeTest);
  const runSmokeTest = useOracleStore((s) => s.runSmokeTest);
  const [submitting, setSubmitting] = useState(false);
  /**
   * Why THIS bar's last run failed — deliberately local, not a selector.
   *
   * ``useOracleStore.error`` is shared by every oracle action, and StageOracle
   * mounts OracleUpload / OracleExamplePicker alongside this bar. A reactive
   * selector would therefore paint a failed *upload* under the smoke-test dots.
   * Reading the store imperatively at the moment the run resolves keeps the
   * message attributable to the run it came from; OracleExamplePicker's
   * storeFailure() uses the same idiom.
   */
  const [failure, setFailure] = useState<string | null>(null);

  const hasDumps = sourcePaths.length > 0;

  async function handleRun(): Promise<void> {
    if (!oracleId || !hasDumps) return;
    setFailure(null);
    setSubmitting(true);
    try {
      const result = await runSmokeTest(oracleId, {
        source_paths: sourcePaths,
        key_size: keySize,
        negatives: negativeCount,
        include_positive_control: true,
      });
      if (result === null) {
        // ``guarded`` already ran the body through ``readableFailure``, so this
        // is the server's own sentence and not a {"detail":…} envelope.
        //
        // The store has already cleared ``smokeTest`` by now, so no stale
        // verdict survives beside this message — a banner asserting
        // "discriminates" above "the server refused the request" would be an
        // outright false claim about the oracle, not merely redundant.
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

  /*
    A result belonging to a DIFFERENT oracle must not colour this bar: the user
    can smoke-test one oracle, pick another, and the store still holds the first
    result until the second run resolves.
  */
  const active: SmokeTestResult | null =
    smokeTest && smokeTest.oracle_id === oracleId ? smokeTest : null;

  const positive = active?.positive ?? null;
  /*
    Tri-state, and the order matters. An oracle that crashed on the control has
    an `error`; an oracle that ran and said no has `ok === false`; `ok === null`
    means the control was never run at all and is NOT a failure.
  */
  const positiveState: DotState = !active
    ? "idle"
    : !positive?.present || positive.ok === null
      ? "absent"
      : positive.error
        ? "error"
        : positive.ok
          ? "pass"
          : "fail";

  /*
    The graded negatives, or a placeholder row before the first run so the bar
    has a shape to show. When a control was run it is ``results[0]``, so the
    decoys are everything after it.
  */
  const negativeResults = active
    ? active.results.slice(active.positive.present ? 1 : 0)
    : [];
  const negativeDots: Array<{ index: number; state: DotState; error?: string }> =
    active
      ? negativeResults.map((r) => ({
          index: r.index,
          // A per-sample `error` outranks `ok`: an oracle that threw did not
          // "reject" the candidate, it failed to judge it.
          state: r.error !== undefined ? "error" : r.ok ? "pass" : "fail",
          error: r.error,
        }))
      : Array.from({ length: negativeCount }, (_, i) => ({
          index: i + 1,
          state: "idle" as DotState,
        }));

  // Every sample that carried an error, control included — this list is the
  // error surface the old bar never had. It had the strings all along and used
  // them only as a boolean to pick a grey fill.
  const erroredSamples = active
    ? active.results.filter((r) => r.error !== undefined)
    : [];

  const summary = active
    ? t("oracle.dryRun.summary", {
        passes: active.passes,
        fails: active.fails,
        errors: active.errors,
        avg: active.per_call_us_avg.toFixed(1),
      })
    : null;

  const totalSamples = negativeCount + 1;
  const tone = active ? verdictTone(active.verdict) : null;

  return (
    <div className="space-y-2">
      <div className="flex items-center justify-between gap-2">
        <div className="text-xs md-text-muted">
          {t("oracle.dryRun.smokeTest", { count: totalSamples })}
        </div>
        <button
          type="button"
          disabled={!oracleId || submitting || !hasDumps}
          onClick={() => void handleRun()}
          className="text-xs px-2 py-1 rounded bg-[var(--md-accent-blue)] md-text-on-accent disabled:opacity-50"
          title={t("oracle.dryRun.testTitle")}
        >
          {submitting
            ? t("oracle.dryRun.testing")
            : t("oracle.dryRun.testButton", { count: totalSamples })}
        </button>
      </div>

      <p className="text-[10px] md-text-muted">
        {t("oracle.dryRun.composedNote")}
      </p>

      {!hasDumps && (
        <p data-testid="oracle-smoke-no-dumps" className="text-xs md-text-warning">
          {t("oracle.dryRun.noDumps")}
        </p>
      )}

      {active && tone && (
        <div
          data-testid="oracle-smoke-verdict"
          data-verdict={active.verdict}
          role="status"
          className={`text-xs px-2 py-1.5 rounded border ${tone.bg} ${tone.border} ${tone.text}`}
        >
          {t(`oracle.dryRun.verdict.${active.verdict}`)}
        </div>
      )}

      {/*
        The control sits in its own group with a gap before the decoys. The
        separation is not decoration: a green dot that means "the oracle
        recognises a key we already knew" must not be mistakable for one of the
        search results beside it.
      */}
      <div className="flex items-end gap-4">
        <div data-testid="oracle-smoke-positive" className="space-y-1">
          <div className="text-[10px] md-text-muted">
            {t("oracle.dryRun.positiveHeading")}
          </div>
          <span
            data-testid="oracle-smoke-positive-dot"
            data-state={positiveState}
            title={
              positive?.error
                ? t("oracle.dryRun.positiveDotTitleError", {
                    state: positiveState,
                    error: positive.error,
                  })
                : t("oracle.dryRun.positiveDotTitle", { state: positiveState })
            }
            className="inline-block w-3 h-3 rounded-full ring-1 ring-[var(--md-border)]"
            style={dotStyle(positiveState)}
          />
        </div>

        <div className="space-y-1">
          <div className="text-[10px] md-text-muted">
            {t("oracle.dryRun.negativesHeading", {
              count: negativeDots.length,
              keySize,
            })}
          </div>
          <div className="flex items-center gap-1.5 flex-wrap">
            {negativeDots.map((dot) => (
              <span
                key={dot.index}
                title={
                  dot.error
                    ? t("oracle.dryRun.dotTitleError", {
                        index: dot.index,
                        state: dot.state,
                        error: dot.error,
                      })
                    : t("oracle.dryRun.dotTitle", {
                        index: dot.index,
                        state: dot.state,
                      })
                }
                className="inline-block w-3 h-3 rounded-full"
                style={dotStyle(dot.state)}
              />
            ))}
          </div>
        </div>
      </div>

      {/*
        The provenance caption is required copy, not a nicety: without it a
        green control dot claims a discovery the pipeline did not make.
      */}
      <div className="text-[10px] md-text-muted space-y-0.5">
        <p>{t("oracle.dryRun.positiveSelfTestNote")}</p>
        {active && positive?.present && positive.provenance_label && (
          <p
            data-testid="oracle-smoke-positive-provenance"
            title={positive.source ?? undefined}
          >
            {t("oracle.dryRun.positiveProvenance", {
              provenance: positive.provenance_label,
            })}
          </p>
        )}
        {active && !positive?.present && (
          <p data-testid="oracle-smoke-positive-absent" className="md-text-warning">
            {t("oracle.dryRun.positiveAbsent")}{" "}
            {positive?.reason ?? t("oracle.dryRun.positiveAbsentNoReason")}
          </p>
        )}
      </div>

      {active && (
        <div className="text-[10px] md-text-muted space-y-0.5">
          {active.dump ? (
            <p data-testid="oracle-smoke-dump" title={active.dump.path}>
              {t("oracle.dryRun.negativesSource", {
                name: basename(active.dump.path),
                view: active.dump.view,
                keySize: active.negatives.key_size,
              })}
            </p>
          ) : (
            <p data-testid="oracle-smoke-dump-missing" className="md-text-warning">
              {t("oracle.dryRun.negativesSourceNone")}
            </p>
          )}
          {active.negatives.low_entropy_included > 0 && (
            <p data-testid="oracle-smoke-low-entropy" className="md-text-warning">
              {t("oracle.dryRun.lowEntropyNote", {
                count: active.negatives.low_entropy_included,
              })}
            </p>
          )}
        </div>
      )}

      {/*
        The missing error surface. The server has always returned a per-sample
        ``error`` string; the old bar consumed it as a boolean to choose a grey
        fill and threw the sentence away, so "the oracle raised TypeError on
        every sample" and "the oracle answered false" were indistinguishable.
      */}
      {erroredSamples.length > 0 && (
        <details data-testid="oracle-smoke-errors" className="text-[10px]">
          <summary className="cursor-pointer md-text-error">
            {t("oracle.dryRun.errorsHeading", { count: erroredSamples.length })}
          </summary>
          <ul className="mt-1 space-y-0.5 font-mono md-text-muted">
            {erroredSamples.map((r) => (
              <li key={r.index}>
                {t("oracle.dryRun.errorRow", {
                  index: r.index,
                  error: r.error,
                })}
              </li>
            ))}
          </ul>
        </details>
      )}

      {active && active.caveats.length > 0 && (
        <div data-testid="oracle-smoke-caveats" className="text-[10px] md-text-muted">
          <div className="font-semibold">{t("oracle.dryRun.caveatsHeading")}</div>
          <ul className="list-disc pl-4">
            {active.caveats.map((caveat) => (
              <li key={caveat}>{caveat}</li>
            ))}
          </ul>
        </div>
      )}

      {failure && (
        <p data-testid="oracle-dry-run-error" className="text-xs md-text-error">
          {t("oracle.dryRun.failedPrefix", { error: failure })}
        </p>
      )}

      {/*
        Offered only on ``discriminates``. Every other verdict means the next
        stage would be configured around an oracle that cannot answer the
        question the sweep is about to ask it.
      */}
      {active && active.verdict === "discriminates" && onContinue && (
        <button
          type="button"
          data-testid="oracle-smoke-continue"
          onClick={onContinue}
          className="text-xs px-3 py-1.5 rounded bg-[var(--md-accent-green)] md-text-on-accent"
        >
          {t("oracle.dryRun.continue")}
        </button>
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

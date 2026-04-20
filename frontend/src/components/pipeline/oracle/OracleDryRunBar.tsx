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
 */

import { useState } from "react";

import { useOracleStore } from "@/stores/oracle-store";

interface Props {
  /** Oracle id to test against; button is disabled when null. */
  oracleId: string | null;
  /** Base64-encoded byte strings to feed into the oracle. */
  samplesB64: string[];
}

type DotState = "idle" | "pass" | "fail" | "error";

function dotClass(state: DotState): string {
  switch (state) {
    case "pass":
      return "bg-green-600";
    case "fail":
      return "bg-red-600";
    case "error":
      return "bg-gray-500";
    default:
      return "bg-[var(--md-bg-hover)]";
  }
}

export function OracleDryRunBar({ oracleId, samplesB64 }: Props) {
  const dryRun = useOracleStore((s) => s.dryRun);
  const runDry = useOracleStore((s) => s.runDry);
  const [submitting, setSubmitting] = useState(false);

  async function handleRun(): Promise<void> {
    if (!oracleId || samplesB64.length === 0) return;
    setSubmitting(true);
    try {
      await runDry(oracleId, samplesB64);
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
      ? `${dryRun.passes} pass · ${dryRun.fails} fail · ${dryRun.errors} error · avg ${dryRun.per_call_us_avg.toFixed(1)}µs`
      : null;

  return (
    <div className="space-y-2">
      <div className="flex items-center justify-between gap-2">
        <div className="text-xs md-text-muted">
          Smoke test the oracle on {samplesB64.length} sample{samplesB64.length === 1 ? "" : "s"} before committing to a full sweep.
        </div>
        <button
          type="button"
          disabled={!oracleId || submitting || samplesB64.length === 0}
          onClick={() => void handleRun()}
          className="text-xs px-2 py-1 rounded bg-[var(--md-accent-blue)] text-white disabled:opacity-50"
          title="Verify the oracle loads and runs before committing to a full sweep"
        >
          {submitting ? "Testing…" : `Test on ${samplesB64.length} samples`}
        </button>
      </div>

      <div className="flex items-center gap-1.5">
        {dots.map((state, i) => (
          <span
            key={i}
            title={`sample ${i}: ${state}`}
            className={`inline-block w-3 h-3 rounded-full ${dotClass(state)}`}
          />
        ))}
      </div>

      <div className="flex items-center justify-between text-[10px] md-text-muted">
        <div className="flex items-center gap-2">
          <span className="inline-flex items-center gap-1">
            <span className="inline-block w-2 h-2 rounded-full bg-green-600" /> pass
          </span>
          <span className="inline-flex items-center gap-1">
            <span className="inline-block w-2 h-2 rounded-full bg-red-600" /> fail
          </span>
          <span className="inline-flex items-center gap-1">
            <span className="inline-block w-2 h-2 rounded-full bg-gray-500" /> error
          </span>
          <span>(random offsets expect mostly red)</span>
        </div>
        {summary && <div className="font-mono">{summary}</div>}
      </div>
    </div>
  );
}

import { useState } from "react";
import { useTranslation } from "react-i18next";

import { readableFailure } from "@/api/client";
import { runDetectorFixtures, type DetectorFixtureRun, type DetectorKind } from "@/api/detectors";
import { VerdictBadge } from "@/components/vol3/VerdictBadge";

const buttonClass =
  "px-2 py-1 text-xs rounded border border-[var(--md-border)] hover:bg-[var(--md-bg-hover)] disabled:opacity-40";

/**
 * Runs a detector's fixtures (D13) and shows the verdict as the vol3 `VerdictBadge`
 * (icon + word + colour). `artifact` is the YARA rule SOURCE for `yara`, a key-finder
 * name for `keyfinder`. A previous verdict is cleared when the artifact changes, so a
 * badge never describes text that is no longer in the editor. No fixtures renders as
 * indeterminate with an explanation, never as a pass.
 */
export function DetectorFixtureBadge({ artifactKind, artifact, caseDir, params }: {
  artifactKind: DetectorKind;
  artifact: string;
  caseDir?: string;
  params?: Record<string, unknown>;
}) {
  const { t } = useTranslation("detectors");
  // Outcomes are keyed by what they describe, so an edit makes the old one disappear
  // by derivation (no effect, no stale badge).
  const [outcome, setOutcome] = useState<{ key: string; run?: DetectorFixtureRun; error?: string } | null>(null);
  const [busy, setBusy] = useState(false);
  const empty = artifact.trim() === "";
  const key = JSON.stringify([artifactKind, artifact, caseDir ?? ""]);
  const current = outcome && outcome.key === key ? outcome : null;
  const run = current?.run ?? null;
  const error = current?.error ?? null;

  const execute = async () => {
    setBusy(true);
    try {
      const done = await runDetectorFixtures(artifactKind, artifact, { caseDir: caseDir?.trim() || undefined, params });
      setOutcome({ key, run: done });
    } catch (e) {
      setOutcome({ key, error: t("fixtures.error", { message: readableFailure(e) }) });
    }
    setBusy(false);
  };

  const noFixtures = run?.reason_code === "no_fixtures";
  return (
    <div className="flex flex-wrap items-center gap-2 text-xs" data-testid="detector-fixture-badge">
      <button type="button" className={buttonClass} disabled={empty || busy} onClick={execute}
        data-testid="detector-fixtures-run">
        {busy ? t("fixtures.running") : t("fixtures.run")}
      </button>
      {run ? <VerdictBadge verdict={run.verdict} />
        : <span className="md-text-muted" data-testid="detector-fixtures-not-run">
          {empty ? t("fixtures.needRule") : t("fixtures.notRun")}</span>}
      {run && !noFixtures && (
        <span className="md-text-muted" data-testid="detector-fixtures-summary">
          {t("fixtures.summary", { pass: run.counts.pass, total: run.counts.total })}</span>)}
      {noFixtures && (
        <span className="md-text-muted" data-testid="detector-fixtures-none">{t("fixtures.noFixtures")}</span>)}
      {run && run.verdict === "fail" && run.reason && (
        <span data-testid="detector-fixtures-reason" style={{ color: "var(--md-accent-red)" }}>{run.reason}</span>)}
      {error && <span role="alert" data-testid="detector-fixtures-error"
        style={{ color: "var(--md-accent-red)" }}>{error}</span>}
    </div>
  );
}

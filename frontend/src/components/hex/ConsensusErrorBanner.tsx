import { useTranslation } from "react-i18next";

import { useConsensusRun, useConsensusStore } from "@/stores/consensus-store";
import { useDumpStore } from "@/stores/dump-store";

/**
 * "The rebuild you asked for failed — these bytes are still the OLD build."
 *
 * ── Why the grid is not blanked instead ──────────────────────────────────────
 * `runConsensus`'s failure path deliberately leaves `consensusId` / `builtFrom`
 * / `builtNormalized` describing the previous build, because that build is not
 * wrong: it was computed over real dumps, and where `builtFrom` still covers
 * the selection it is still the correct answer for them. Dropping it would send
 * both multi-dump viewers back behind `NoConsensusPrompt` and throw away a
 * usable alignment because a LATER request 500'd — and where the selection HAS
 * moved on, `consensusCoversSelection` already fences the stale build off
 * without any help from the failure path.
 *
 * What was missing is the SAYING SO. The store has carried an `error` field all
 * along and the only thing rendering it was `DumpList`, in the sidebar: switch
 * to the overlay, hit "Align by delta-fit", watch it fail, and the grid went on
 * painting the previous alignment with nothing anywhere near the bytes to say
 * the coordinate the analyst just asked for was never applied. This banner is
 * that sentence, on the hex surface, with the re-run in it.
 *
 * Mounted PAST each viewer's `consensusUsable` fence, so "still showing the
 * previous build" is always a true statement where it renders. Shared by both
 * viewers for the same reason `WindowErrorBanner` is: one failure, one sentence.
 */
export interface ConsensusErrorBannerProps {
  /** `hex-overlay` or `multi-hex` — the viewer whose specs key on this. */
  testIdPrefix: string;
  /** The dumps a re-run must cover — the CURRENT selection, not the build's. */
  paths: string[];
}

export function ConsensusErrorBanner({ testIdPrefix, paths }: ConsensusErrorBannerProps) {
  const { t } = useTranslation("hex");
  const error = useConsensusStore((s) => s.error);
  const aslrNormalize = useDumpStore((s) => s.aslrNormalize);
  // The app's ONE in-flight flag, so this retry is disabled while a build
  // started from the chip, the align switch or the dump list is still running.
  const { running, run } = useConsensusRun();

  if (!error) return null;

  return (
    <div
      data-testid={`${testIdPrefix}-consensus-error`}
      role="status"
      className="px-3 py-1.5 text-xs md-bg-warning-subtle space-y-1"
    >
      <p className="font-medium">{t("consensusError.title")}</p>
      <p>{t("consensusError.body", { error })}</p>
      <button
        type="button"
        data-testid={`${testIdPrefix}-consensus-retry`}
        disabled={running}
        className="px-2 py-0.5 rounded border border-[var(--md-border)] hover:bg-[var(--md-bg-hover)] disabled:opacity-50"
        // The coordinate the LAST build was asked for, so a retry repeats the
        // request that failed rather than silently changing the question.
        onClick={() => run(paths, aslrNormalize)}
      >
        {running ? t("consensusError.retrying") : t("consensusError.retry")}
      </button>
    </div>
  );
}

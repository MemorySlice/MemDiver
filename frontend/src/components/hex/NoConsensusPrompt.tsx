import { useTranslation } from "react-i18next";

import { useConsensusRun } from "@/stores/consensus-store";
import { useDumpStore } from "@/stores/dump-store";

/**
 * Which fence the analyst has hit.
 *
 * `"missing"` — nothing has been built yet.
 * `"stale"`   — something HAS been built, but over a different set of dumps.
 *
 * They are two different facts and they need two different sentences: "run a
 * consensus" is confusing advice for someone who already ran one, and the
 * reason their result is being withheld ("it covers other dumps") is the only
 * thing that makes the re-run make sense.
 */
export type NoConsensusVariant = "missing" | "stale";

interface Props {
  /** The dumps a re-run must cover — the CURRENT selection, not the build's. */
  paths: string[];
  variant?: NoConsensusVariant;
}

/**
 * The multi-dump viewers' "there is no usable consensus here" empty state.
 *
 * Not a toast and not a blank grid. Without a consensus every byte is
 * unclassified, so an overlay would render a plain hex dump that silently reads
 * as "nothing varies" — the single most misleading thing these panes can show.
 * With a consensus built over OTHER dumps it is worse: the classes, the gaps
 * and the "Differs" rings are all confidently wrong, and nothing on screen says
 * so. An empty state carrying the action is the honest alternative.
 *
 * Shared by `HexOverlayPane` and `MultiHexViewer` so the fence cannot drift
 * into two different answers to the same question, and so the testids the E2E
 * specs key on (`hex-overlay-no-consensus` / `hex-overlay-run-consensus`)
 * describe one component rather than two copies of it.
 */
export function NoConsensusPrompt({ paths, variant = "missing" }: Props) {
  const { t } = useTranslation("hex");
  const aslrNormalize = useDumpStore((s) => s.aslrNormalize);
  // The app's ONE in-flight flag, so this prompt is disabled while a build
  // started from the chip, the banner or the align switch is still running.
  const { running, run } = useConsensusRun();

  const titleKey =
    variant === "stale" ? "overlayPane.staleConsensusTitle" : "overlayPane.noConsensusTitle";
  const bodyKey =
    variant === "stale" ? "overlayPane.staleConsensusBody" : "overlayPane.noConsensusBody";

  return (
    <div
      data-testid="hex-overlay-no-consensus"
      data-variant={variant}
      className="h-full flex items-center justify-center p-6"
    >
      <div className="text-center max-w-md space-y-2">
        <p className="text-sm font-medium">{t(titleKey)}</p>
        <p className="text-xs md-text-secondary">{t(bodyKey)}</p>
        <button
          type="button"
          data-testid="hex-overlay-run-consensus"
          disabled={running}
          className="px-3 py-1 rounded md-bg-accent md-text-on-accent text-xs disabled:opacity-50"
          onClick={() => run(paths, aslrNormalize)}
        >
          {running ? t("overlayPane.running") : t("overlayPane.runConsensus")}
        </button>
      </div>
    </div>
  );
}

import { useTranslation } from "react-i18next";

import { useVisibleWindowError } from "@/hooks/useVisibleWindowError";
import { useConsensusRun } from "@/stores/consensus-store";
import { useDumpStore } from "@/stores/dump-store";

/**
 * The backend answers 404 "No consensus computed yet" for a consensus id it no
 * longer holds (a server restart). Retrying the same request can never help;
 * only a rebuild can.
 */
const MISSING_CONSENSUS = /no consensus computed/i;

/**
 * "Some of the bytes on screen did not load" — with the way back.
 *
 * The two multi-dump viewers carried this markup verbatim, down to the
 * `role="status"`, the `title` and the five-line comment on the retry button;
 * only the testid prefix differed. The LOGIC was already one thing
 * (`useVisibleWindowError`), so leaving the markup duplicated meant the one
 * remaining way for the overlay and the side-by-side grid to report the same
 * failure differently.
 *
 * `firstRow` / `lastRow` are ABSOLUTE row indices and `lastRow` is inclusive,
 * exactly as the hook takes them; a negative `firstRow` means "nothing
 * rendered yet" and the banner stays out of the DOM.
 */
export interface WindowErrorBannerProps {
  /** `hex-overlay` or `multi-hex` — the viewer whose specs key on this. */
  testIdPrefix: string;
  firstRow: number;
  lastRow: number;
  /** The dumps a rebuild must cover (the current selection). Enables "Rebuild". */
  rebuildPaths?: string[];
}

export function WindowErrorBanner({ testIdPrefix, firstRow, lastRow, rebuildPaths }: WindowErrorBannerProps) {
  const { t } = useTranslation("hex");
  // Chunk-scoped, and covering EVERY chunk on screen rather than the first and
  // last row's — see `useVisibleWindowError`.
  const { error, retry } = useVisibleWindowError(firstRow, lastRow);
  const { running, run } = useConsensusRun();
  const aslrNormalize = useDumpStore((s) => s.aslrNormalize);

  if (!error) return null;

  return (
    <div
      data-testid={`${testIdPrefix}-window-error`}
      role="status"
      className="flex items-center gap-2 px-3 py-1 text-xs md-text-error"
      title={error}
    >
      <span>{error}</span>
      {/*
        The store auto-retries a failed chunk only twice, on a backoff — an
        unbounded retry is what turned one unreachable dump into a POST storm —
        so once that budget is spent this gesture is the way back, and it resets
        the budget.
      */}
      <button
        type="button"
        data-testid={`${testIdPrefix}-window-retry`}
        className="underline"
        onClick={retry}
      >
        {t("multiHex.windowErrorRetry")}
      </button>
      {rebuildPaths && MISSING_CONSENSUS.test(error) && (
        <button
          type="button"
          data-testid={`${testIdPrefix}-window-rebuild`}
          disabled={running}
          className="underline disabled:opacity-50"
          // The same request the workspace used: the current selection, in the
          // coordinate the analyst last chose.
          onClick={() => run(rebuildPaths, aslrNormalize)}
        >
          {running ? t("overlayPane.running") : t("multiHex.windowErrorRebuild")}
        </button>
      )}
    </div>
  );
}

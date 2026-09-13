import { useTranslation } from "react-i18next";

import type { DumpEntry } from "@/stores/dump-store";
import {
  DEFAULT_DUMP_WEIGHT,
  hasUnevenWeights,
  useDumpRailStore,
} from "@/stores/dump-rail-store";
import { useMultiHexStore } from "@/stores/multi-hex-store";
import { discardedFraction } from "./alignment-stats";

/**
 * The dump rail: WHOSE bytes the overlay is reading, and how much each counts.
 *
 * Until this existed the aligned overlay painted the ANCHOR's byte stream and
 * decorated it with what the other dumps contributed. That is a defensible
 * default and a bad one to be stuck with: the anchor is whichever dump happens
 * to be focused, so the bytes on screen were a fact about the UI's focus rather
 * than about the set. The rail replaces it with a stated, adjustable layer —
 * a weighted plurality of the dumps the analyst has included — and, crucially,
 * with the ability to step OUT of it onto one real dump at a time.
 *
 * ── The two states a chip can be in, and why they are not the same control ───
 * SOLO (clicking the chip) is a VIEW: it changes which bytes are painted and
 * nothing else. INCLUSION (the eye) is MEMBERSHIP: it changes what the
 * consensus is computed over, and therefore what the overlay says even while
 * you are looking at a different dump. Collapsing them into one click would
 * mean "let me look at dump 3 for a second" silently removed dump 3 from every
 * number on the screen.
 *
 * ── No per-dump delta ───────────────────────────────────────────────────────
 * The design's chip is `[id] [name] … [Δ delta]`. The delta is NOT rendered,
 * because the overlay genuinely does not have one: `multi-hex-store.alignment`
 * is the response's `alignment` block (method, bytes_compared, bytes_discarded,
 * sizes_differed, n_sources, warnings) and carries nothing per dump. The only
 * per-dump coordinates on the wire are `segments[].dumps[].va/offset`, which
 * the store does not keep and which invariant W1 forbids doing arithmetic on —
 * subtracting two of them to manufacture a "delta" is precisely the
 * client-side coordinate math that has already produced two real bugs here.
 * A placeholder would be worse than nothing: a dash in a column labelled Δ
 * reads as "no drift", which is a claim nobody has checked.
 */

export interface DumpRailProps {
  /** The dumps taking part in the alignment, in selection order. */
  dumps: DumpEntry[];
}

/** `1.5` → `"1.5"`, so the button always reads with one decimal place. */
function formatWeight(weight: number): string {
  return weight.toFixed(1);
}

export function DumpRail({ dumps }: DumpRailProps) {
  const { t } = useTranslation("hex");

  const weightByPath = useDumpRailStore((s) => s.weightByPath);
  const excludedPaths = useDumpRailStore((s) => s.excludedPaths);
  const soloPath = useDumpRailStore((s) => s.soloPath);
  const collapsed = useDumpRailStore((s) => s.collapsed);
  const cycleWeight = useDumpRailStore((s) => s.cycleWeight);
  const toggleIncluded = useDumpRailStore((s) => s.toggleIncluded);
  const setSolo = useDumpRailStore((s) => s.setSolo);
  const toggleCollapsed = useDumpRailStore((s) => s.toggleCollapsed);

  const alignment = useMultiHexStore((s) => s.alignment);

  const includedCount = dumps.filter((d) => !excludedPaths.has(d.path)).length;
  const weighted = hasUnevenWeights(weightByPath);

  if (collapsed) {
    // The collapsed strip follows `MultiHexViewer`'s collapsed-pane rail: the
    // control that folded something away leaves a control in its place, in the
    // same spot, so nothing the user hid becomes unreachable.
    return (
      <div
        data-testid="dump-rail-collapsed"
        className="shrink-0 flex flex-col items-center py-1 border-r border-[var(--md-border)] md-bg-secondary"
        style={{ width: "var(--md-rail-collapsed-width)" }}
      >
        <button
          type="button"
          data-testid="dump-rail-restore"
          aria-label={t("rail.restore")}
          title={t("rail.restore")}
          onClick={toggleCollapsed}
          className="px-1 rounded hover:bg-[var(--md-bg-hover)]"
        >
          {"▸"}
        </button>
      </div>
    );
  }

  return (
    <aside
      data-testid="dump-rail"
      role="group"
      aria-label={t("rail.label")}
      className="shrink-0 flex flex-col gap-1 overflow-y-auto px-2 py-1 text-xs border-r border-[var(--md-border)] md-bg-secondary"
      style={{ width: "var(--md-rail-width)" }}
    >
      <div className="flex items-center gap-1">
        {/*
          A styled label, NOT an `<h4>`. The rail is a `role="group"` with its
          own accessible name, so a heading here would add a level to the
          document outline that nothing below it actually nests under — and the
          axe heading-order rule is right to object to that.
        */}
        <div
          data-testid="dump-rail-head"
          className="flex-1 min-w-0 text-[10px] font-semibold uppercase tracking-wider md-text-muted"
        >
          {t("rail.sectionHead", { n: dumps.length })}
        </div>
        <button
          type="button"
          data-testid="dump-rail-collapse"
          aria-label={t("rail.collapse")}
          title={t("rail.collapse")}
          onClick={toggleCollapsed}
          className="shrink-0 px-1 rounded hover:bg-[var(--md-bg-hover)]"
        >
          {"◂"}
        </button>
      </div>

      {/*
        The overlay is a chip like the others because it is a peer of them: one
        of N+1 things the grid can be showing. Making it a heading instead would
        hide the fact that leaving solo is the same gesture as entering it.
      */}
      <button
        type="button"
        data-testid="dump-rail-overlay"
        aria-pressed={soloPath === null}
        aria-label={t("rail.overlayAction")}
        title={t("rail.overlayAction")}
        onClick={() => setSolo(null)}
        className={
          "flex flex-col items-start rounded border px-1.5 py-1 text-left " +
          (soloPath === null
            ? "md-bg-accent md-text-on-accent border-[var(--md-accent)]"
            : "border-[var(--md-border)] hover:bg-[var(--md-bg-hover)]")
        }
      >
        <span className="font-semibold">{t("rail.overlay")}</span>
        <span
          data-testid="dump-rail-overlay-mode"
          data-weighted={weighted ? "true" : "false"}
          className={soloPath === null ? undefined : "md-text-muted"}
        >
          {weighted ? t("rail.overlayWeighted") : t("rail.overlayEqual")}
        </span>
      </button>

      {/*
        The caveat in words, not only in a source comment. A plurality is not a
        byte anyone read out of a file: where the dumps disagree it can be a
        value that exists in none of them. The analyst has to know that before
        quoting it, and the sentence names the surface that does hold the true
        per-dump values.
      */}
      <p data-testid="dump-rail-plurality-note" className="md-text-muted text-[10px] leading-snug">
        {t("rail.pluralityNote")}
      </p>

      {dumps.map((dump, index) => {
        const included = !excludedPaths.has(dump.path);
        const soloed = soloPath === dump.path;
        const weight = weightByPath.get(dump.path) ?? DEFAULT_DUMP_WEIGHT;
        // The consensus must keep at least one voter: emptying it entirely
        // would not be a stricter reading, it would blank the grid and leave
        // no control on screen explaining why.
        const lastIncluded = included && includedCount <= 1;

        return (
          <div
            key={dump.id}
            data-testid={`dump-rail-chip-${dump.id}`}
            data-active={soloed ? "true" : "false"}
            data-included={included ? "true" : "false"}
            title={included ? dump.path : t("rail.excludedTitle")}
            className={
              "flex items-center gap-1 rounded border px-1 py-0.5 " +
              (soloed
                ? "md-bg-accent md-text-on-accent border-[var(--md-accent)]"
                : "border-[var(--md-border)]")
            }
            // Excluded dumps stay legible but visibly out of the reckoning.
            // Inline rather than a utility class so it cannot be confused with
            // the `disabled:opacity-50` the action buttons use for an
            // in-flight state.
            style={included ? undefined : { opacity: 0.5 }}
          >
            <button
              type="button"
              data-testid={`dump-rail-solo-${dump.id}`}
              aria-pressed={soloed}
              aria-label={t("rail.soloAction", { name: dump.name })}
              title={t("rail.soloAction", { name: dump.name })}
              onClick={() => setSolo(soloed ? null : dump.path)}
              className={
                "flex-1 min-w-0 flex items-center gap-1 text-left " +
                (soloed ? "" : "hover:underline")
              }
            >
              <span className="font-mono shrink-0 opacity-70">{index + 1}</span>
              <span className="truncate">{dump.name}</span>
            </button>

            <button
              type="button"
              data-testid={`dump-rail-include-${dump.id}`}
              aria-pressed={included}
              aria-label={
                included
                  ? t("rail.excludeAction", { name: dump.name })
                  : t("rail.includeAction", { name: dump.name })
              }
              title={
                lastIncluded
                  ? t("rail.lastIncludedTitle")
                  : included
                    ? t("rail.excludeAction", { name: dump.name })
                    : t("rail.includeAction", { name: dump.name })
              }
              disabled={lastIncluded}
              onClick={() => toggleIncluded(dump.path)}
              className="shrink-0 px-0.5 rounded disabled:cursor-not-allowed"
            >
              <span aria-hidden="true">{included ? "◉" : "◌"}</span>
            </button>

            <button
              type="button"
              data-testid={`dump-rail-weight-${dump.id}`}
              data-weight={weight}
              aria-label={t("rail.weightAction", {
                name: dump.name,
                weight: formatWeight(weight),
              })}
              title={t("rail.weightAction", {
                name: dump.name,
                weight: formatWeight(weight),
              })}
              onClick={() => cycleWeight(dump.path)}
              className="shrink-0 px-0.5 rounded font-mono tabular-nums"
            >
              {t("rail.weightValue", { weight: formatWeight(weight) })}
            </button>

            {/*
              The track is a redundant read of the number beside it — the
              button already SAYS `1.5×` — so it is hidden from assistive tech
              rather than repeating itself. `currentColor` for the fill is what
              lets it survive the accent chip, where a fixed accent fill would
              be invisible against the accent ground.
            */}
            <span
              aria-hidden="true"
              data-testid={`dump-rail-track-${dump.id}`}
              className="shrink-0 block h-1 w-5 rounded overflow-hidden"
              style={{ background: "var(--md-bg-tertiary)" }}
            >
              <span
                data-testid={`dump-rail-track-fill-${dump.id}`}
                className="block h-full"
                style={{ width: `${(weight / 1.5) * 100}%`, background: "currentColor" }}
              />
            </span>
          </div>
        );
      })}

      <div
        data-testid="dump-rail-stats"
        role="group"
        aria-label={t("rail.statsHead")}
        className="mt-1 pt-1 border-t border-[var(--md-border)] md-text-muted space-y-0.5"
      >
        <div className="text-[10px] font-semibold uppercase tracking-wider">
          {t("rail.statsHead")}
        </div>
        {alignment ? (
          <>
            <p data-testid="dump-rail-stats-compared">
              {t("rail.statsCompared", { bytes: alignment.bytes_compared })}
            </p>
            <p data-testid="dump-rail-stats-discarded">
              {t("rail.statsDiscarded", {
                bytes: alignment.bytes_discarded,
                percent: (discardedFraction(alignment) * 100).toFixed(1),
              })}
            </p>
          </>
        ) : (
          <p data-testid="dump-rail-stats-pending">{t("rail.statsPending")}</p>
        )}
      </div>
    </aside>
  );
}

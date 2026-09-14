import { useCallback } from "react";
import { useTranslation } from "react-i18next";

import {
  DEFAULT_REGION_MIN_LENGTH,
  NON_INVARIANT_UNION,
  NO_HONEST_ANSWER,
  anchorSpan,
  isJumpable,
} from "@/api/consensus-regions";
import type { ByteClassName } from "@/api/candidates";
import { useInfiniteScrollSentinel } from "@/hooks/useInfiniteScrollSentinel";
import { useVarianceRegionsLoader } from "@/hooks/useVarianceRegions";
import {
  useVarianceRegionsStore,
  type VarianceBrowseCategory,
  type VarianceRegion,
} from "@/stores/variance-regions-store";
import { offsetToHex } from "@/utils/hex-codec";
import { VARIANCE_META } from "@/utils/variance-classes";
import { RegionFilterBar } from "@/components/hex/RegionFilterBar";
import { VarianceSwatch } from "@/components/common/VarianceSwatch";

/**
 * EVERY occurrence of the selected class, as a list you can walk.
 *
 * The other half of the clickable legend: the chips answer "which class", this
 * answers "where, and what else is there". A row is clickable and focusable
 * exactly like `CandidateTable`'s — and for the same reason, exactly as inert
 * when there is nothing honest to jump to.
 *
 * ── Two coordinate rules, both of them load-bearing ─────────────────────────
 * 1. `region.anchor_offset` is handed to the store UNMODIFIED. The server did
 *    the slab -> VA -> navigable conversion (`_region_locator`) precisely so no
 *    client has to; every overlay coordinate bug this repo has shipped was
 *    client-side arithmetic, and each one looked like plausible bytes in the
 *    wrong place, which no type checker catches.
 * 2. The extent shown is `anchorSpan(region)` — `anchor_offset_end -
 *    anchor_offset` — and NEVER `length`. `length` is the SLAB length, and a
 *    region that crosses an `msl_layout` page boundary is one run in slab space
 *    and two disjoint runs in the anchor's, so rendering `length` as "48 bytes
 *    at 0x…" describes a range the viewer never selects.
 *
 * ── `-1` is "no honest answer", never an address ────────────────────────────
 * A raw/flat build queried in `"va"`, a locked anchor container, a slab offset
 * outside `msl_layout`: all three land as `-1`, and all three render as an em
 * dash. `anchor.jumpable` is the page-level form of the same statement, so the
 * jump affordance is hidden once for the page rather than inferred row by row
 * from a sea of dashes.
 */

/** `0x0004a118`, the spelling `HexToolbar`'s goto field and the minimap use. */
function formatOffset(offset: number): string {
  return `0x${offsetToHex(offset)}`;
}

/**
 * The browse vocabulary: the five variance classes, PLUS the union chip.
 *
 * Derived from `VARIANCE_META` rather than replacing it, and deliberately kept
 * module-local — widening `VARIANCE_META` itself would put a category into the
 * map `HexRow` reads for `byteClass`, and the union is a QUERY over three
 * bands, not a fourth colour the grid ever paints. Mirrors `VarianceClassChips`.
 */
const BROWSE_META: Record<VarianceBrowseCategory, { labelKey: string; swatchClass: string }> = {
  ...VARIANCE_META,
  [NON_INVARIANT_UNION]: {
    labelKey: "regions.category.changing",
    swatchClass: "variance-non-invariant",
  },
};

export function VarianceClassBrowser() {
  const { t } = useTranslation("hex");

  // Mounted here too: the Regions tab has to work when it is opened directly
  // (the chips only render in `class` mode). The loader is idempotent against
  // the store's own `requestKey`, so two mounts still make one request.
  useVarianceRegionsLoader();

  const category = useVarianceRegionsStore((s) => s.category);
  const regions = useVarianceRegionsStore((s) => s.regions);
  const total = useVarianceRegionsStore((s) => s.total);
  const nextAfter = useVarianceRegionsStore((s) => s.nextAfter);
  const activeIndex = useVarianceRegionsStore((s) => s.activeIndex);
  const loading = useVarianceRegionsStore((s) => s.loading);
  const error = useVarianceRegionsStore((s) => s.error);
  const windowScoped = useVarianceRegionsStore((s) => s.windowScoped);
  const minLength = useVarianceRegionsStore((s) => s.minLength);
  const maxLength = useVarianceRegionsStore((s) => s.maxLength);
  const anchorJumpable = useVarianceRegionsStore((s) => s.anchorJumpable);
  const jumpToIndex = useVarianceRegionsStore((s) => s.jumpToIndex);
  const loadMore = useVarianceRegionsStore((s) => s.loadMore);

  const hasMore = nextAfter !== NO_HONEST_ANSWER;

  /** Anything other than the server's own floor and no ceiling. */
  const sizeFiltered = minLength !== DEFAULT_REGION_MIN_LENGTH || maxLength !== 0;
  const singleClass =
    category !== null && category !== NON_INVARIANT_UNION && category !== "differs";
  /**
   * The empty state that has to explain itself.
   *
   * A length filter on ONE class is the harshest query this panel can ask, and
   * it is the one an analyst hunting a 48-byte secret types first. The secret
   * is ~27 key_candidate + 18 pointer + 3 structural bytes, so no single-class
   * run inside it is 48 bytes long and "Key Candidate, min 32" returns nothing
   * for a secret that is genuinely there. Saying "no regions" would let the
   * user conclude the dump is clean; this points at the union chip instead.
   */
  const emptyIsFilterArtifact = singleClass && sizeFiltered;

  /**
   * Jump, and STAY.
   *
   * Focus is put back on the row rather than moved into the grid: the user is
   * walking a list, and stealing focus would end that walk after one step and
   * strand a keyboard user in a 4 GiB byte grid. Only the viewer's CURSOR
   * moves — a different thing from the list cursor, which is exactly the
   * distinction `jumpToIndex` already draws.
   */
  const jump = useCallback(
    (index: number, row: HTMLElement | null) => {
      jumpToIndex(index);
      row?.focus();
    },
    [jumpToIndex],
  );

  // Auto-load the next page when the sentinel scrolls into view; the explicit
  // button below stays as the accessible, keyboard-triggerable fallback. The
  // observer itself is shared with `DatasetOverview`'s run pagination.
  const sentinelRef = useInfiniteScrollSentinel(hasMore, loading, loadMore);

  const active = activeIndex >= 0 ? regions[activeIndex] : undefined;

  return (
    <div
      className="h-full p-3 overflow-auto md-bg-secondary text-xs"
      data-testid="variance-class-browser"
    >
      <h3 className="text-xs font-semibold uppercase tracking-wider mb-2 md-text-muted">
        {category === null
          ? t("regions.title")
          : t("regions.titleFor", { label: t(BROWSE_META[category].labelKey) })}
      </h3>

      <RegionFilterBar />

      {/*
        The jump is silent without this: a scroll two panes away is invisible to
        a screen reader, so the announcement IS the feedback. Always mounted so
        the live region exists before the first update — a region added to the
        DOM already populated is not reliably announced.
      */}
      <p
        aria-live="polite"
        data-testid="variance-class-browser-status"
        className="md-text-muted mb-2 min-h-[1.25rem]"
      >
        {active
          ? t("regions.announce", {
              index: activeIndex + 1,
              total: regions.length,
              label: active.classification
                ? t(VARIANCE_META[active.classification].labelKey)
                : t("regions.unclassified"),
              bytes: anchorSpan(active) >= 0 ? anchorSpan(active) : active.length,
              offset: isJumpable(active) ? formatOffset(active.anchor_offset) : "—",
            })
          : ""}
      </p>

      {!anchorJumpable && regions.length > 0 && (
        <p
          data-testid="variance-class-browser-no-jump"
          role="status"
          className="mb-2 px-2 py-1 md-bg-warning-subtle"
        >
          {t("regions.noJump")}
        </p>
      )}

      {/*
        The caveat lands where it bites: a SINGLE-class query. `key_candidate`
        alone returned total 0 for a real planted secret, because the secret is
        27 key_candidate + 18 pointer + 3 structural bytes and every run of one
        class is shorter than `min_length`. The union does not have that
        problem, and `differs` is a different question entirely, so neither
        carries the note.
      */}
      {category !== null && category !== NON_INVARIANT_UNION && category !== "differs" && (
        <p className="mb-2 md-text-muted" data-testid="variance-class-browser-mixed-note">
          {t("regions.mixedClassNote")}
        </p>
      )}

      {windowScoped && (
        <p className="mb-2 md-text-muted" data-testid="variance-class-browser-window-scoped">
          {t("regions.differsWindowOnly")}
        </p>
      )}

      {error && (
        <p className="mb-2 md-text-error" role="alert" data-testid="variance-class-browser-error">
          {t("regions.error", { message: error })}
        </p>
      )}

      {!loading && !error && regions.length === 0 && (
        <p className="md-text-secondary" data-testid="variance-class-browser-empty">
          {emptyIsFilterArtifact && category !== null
            ? t("regions.emptySizeFiltered", { label: t(BROWSE_META[category].labelKey) })
            : t("regions.empty")}
        </p>
      )}

      {regions.length > 0 && (
        <>
          <p className="mb-1 md-text-muted" data-testid="variance-class-browser-count">
            {windowScoped
              ? t("regions.returnedInView", { returned: regions.length })
              : t("regions.returnedOfTotal", { returned: regions.length, total })}
          </p>
          <ul className="space-y-0.5" data-testid="variance-class-browser-list">
            {regions.map((region, index) => (
              <RegionRow
                key={`${region.slab_start}-${region.anchor_offset}-${index}`}
                region={region}
                index={index}
                selected={index === activeIndex}
                jumpable={anchorJumpable && isJumpable(region)}
                onJump={jump}
              />
            ))}
          </ul>
        </>
      )}

      {loading && (
        <p className="mt-2 md-text-muted" data-testid="variance-class-browser-loading">
          {t("regions.loading")}
        </p>
      )}

      {hasMore && (
        <>
          <div ref={sentinelRef} aria-hidden="true" data-testid="variance-class-browser-sentinel" />
          <button
            type="button"
            data-testid="variance-class-browser-load-more"
            disabled={loading}
            onClick={() => void loadMore()}
            className="mt-2 px-2 py-0.5 rounded border border-[var(--md-border)] hover:bg-[var(--md-bg-hover)] disabled:opacity-50"
          >
            {t("regions.loadMore")}
          </button>
        </>
      )}
    </div>
  );
}

interface RegionRowProps {
  region: VarianceRegion;
  index: number;
  selected: boolean;
  jumpable: boolean;
  onJump: (index: number, row: HTMLElement | null) => void;
}

/**
 * One occurrence.
 *
 * Clickable AND focusable, with Enter/Space, but only when the row has a real
 * anchor offset — the `CandidateTable` contract, kept identical so the two
 * jumpable lists in this app cannot teach two different interactions. An inert
 * row keeps its text and explains itself in `title` instead of pretending to be
 * a control that quietly does nothing.
 */
function RegionRow({ region, index, selected, jumpable, onJump }: RegionRowProps) {
  const { t } = useTranslation("hex");
  const span = anchorSpan(region);
  // `null` classification is a window-derived `differs` run: the byte cache
  // carries no class for it, and guessing one would be a fabricated finding.
  const meta = region.classification === null ? null : VARIANCE_META[region.classification];
  // A union page carries the per-class breakdown that makes the union
  // defensible: it shows a 48-byte row really is 27 key_candidate + 18 pointer
  // + 3 structural, rather than a pointer run that drifted in.
  const breakdown = Object.entries(region.class_counts) as [ByteClassName, number][];

  return (
    <li
      data-testid="variance-region-row"
      data-index={index}
      data-anchor-offset={region.anchor_offset}
      aria-current={selected ? "true" : undefined}
      tabIndex={jumpable ? 0 : undefined}
      title={jumpable ? t("regions.jumpTitle") : t("regions.jumpUnavailable")}
      onClick={jumpable ? (e) => onJump(index, e.currentTarget) : undefined}
      onKeyDown={
        jumpable
          ? (e) => {
              if (e.key === "Enter" || e.key === " ") {
                e.preventDefault();
                onJump(index, e.currentTarget);
              }
            }
          : undefined
      }
      className={
        "px-1 py-0.5 rounded border " +
        (selected ? "border-[var(--md-accent)] bg-[var(--md-bg-tertiary)] " : "border-transparent ") +
        (jumpable ? "cursor-pointer hover:bg-[var(--md-bg-hover)]" : "opacity-70")
      }
    >
      <span className="flex flex-wrap items-center gap-2">
        <span className="font-mono" data-testid="variance-region-offset">
          {jumpable ? formatOffset(region.anchor_offset) : "—"}
        </span>
        {/*
          The SPAN, not `length`. See the module doc's rule 2: `length` is the
          slab length and is not interchangeable with the range a jump selects.
        */}
        <span className="font-mono md-text-muted" data-testid="variance-region-span">
          {span >= 0 ? t("regions.bytes", { value: span }) : "—"}
        </span>
        {meta && (
          <VarianceSwatch swatchClass={meta.swatchClass} label={t(meta.labelKey)} />
        )}
        {!region.anchor_contiguous && (
          <span className="md-text-warning" data-testid="variance-region-approximate">
            {t("regions.approximate")}
          </span>
        )}
      </span>
      {breakdown.length > 0 && (
        <span
          className="flex flex-wrap items-center gap-1.5 md-text-muted"
          data-testid="variance-region-breakdown"
        >
          {breakdown.map(([name, n]) => (
            <VarianceSwatch
              key={name}
              swatchClass={VARIANCE_META[name].swatchClass}
              label={t("regions.breakdownEntry", {
                label: t(VARIANCE_META[name].labelKey),
                value: n,
              })}
            />
          ))}
        </span>
      )}
    </li>
  );
}

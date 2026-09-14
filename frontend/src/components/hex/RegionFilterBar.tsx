import { useTranslation } from "react-i18next";

import { DEFAULT_REGION_MIN_LENGTH, type RegionSort } from "@/api/consensus-regions";
import { useVarianceRegionsStore } from "@/stores/variance-regions-store";

/**
 * "I am hunting a 32-byte secret" — as two numbers and an order.
 *
 * The Regions list routinely holds five figures of rows, and scrolling 17,000
 * of them is not an analysis. An analyst hunting TLS key material already knows
 * the size they want (16 / 24 / 32 / 48 bytes are the ones that exist), so the
 * cheapest useful control is one that lets them SAY it.
 *
 * ── The honesty this bar owes the reader ────────────────────────────────────
 * 1. It filters the SLAB length. The rows render `anchorSpan()`, which is the
 *    range a jump actually selects, and the two differ for a region that
 *    crosses an `msl_layout` page boundary — one run in slab space, a wider
 *    range in the anchor's. Those rows already carry the "spans a page
 *    boundary" badge; `filter.lengthNote` is what connects the badge to the fact
 *    that such a row can render a size OUTSIDE the range that was typed.
 * 2. A preset sets BOTH bounds, because "32 B" means exactly 32, not "at least
 *    32". `Any` restores the server floor and an unbounded ceiling rather than
 *    `0`/`0`: a zero floor would ask for every one-byte run in the dump.
 * 3. Each control drops the loaded page through its store action. Nothing here
 *    re-sorts or re-filters rows client-side — page one of an offset-ordered
 *    list sorted by length is not "the longest regions", it is the longest 200
 *    of the first 200.
 *
 * Per-field selectors throughout (`lint:store-selectors`): an object-returning
 * selector without `useShallow` re-renders forever under zustand v5.
 */

/** The sizes real key material comes in. `null` is the "Any" chip. */
const SIZE_PRESETS: readonly (number | null)[] = [16, 24, 32, 48, null];

const SORT_OPTIONS: readonly { value: RegionSort; labelKey: string }[] = [
  { value: "offset", labelKey: "regions.filter.sortOffset" },
  { value: "length_desc", labelKey: "regions.filter.sortLongest" },
  { value: "length_asc", labelKey: "regions.filter.sortShortest" },
];

/** No ceiling, spelled the way the wire spells it. */
const NO_MAX_LENGTH = 0;

const CONTROL_CLASS =
  "px-1.5 py-0.5 rounded border border-[var(--md-border)] " +
  "bg-[var(--md-bg-primary)] text-xs";

export function RegionFilterBar() {
  const { t } = useTranslation("hex");

  const minLength = useVarianceRegionsStore((s) => s.minLength);
  const maxLength = useVarianceRegionsStore((s) => s.maxLength);
  const sort = useVarianceRegionsStore((s) => s.sort);
  const setMinLength = useVarianceRegionsStore((s) => s.setMinLength);
  const setMaxLength = useVarianceRegionsStore((s) => s.setMaxLength);
  const setSort = useVarianceRegionsStore((s) => s.setSort);

  /**
   * A preset is an EXACT-size query: both bounds, one gesture.
   *
   * The two setters are separate store actions on purpose — each is the same
   * "a different filter is a different list" drop the manual inputs use — and
   * React batches them, so the mounted loader still issues one request.
   */
  const applyPreset = (size: number | null) => {
    if (size === null) {
      setMinLength(DEFAULT_REGION_MIN_LENGTH);
      setMaxLength(NO_MAX_LENGTH);
      return;
    }
    setMinLength(size);
    setMaxLength(size);
  };

  const isPresetActive = (size: number | null): boolean =>
    size === null
      ? minLength === DEFAULT_REGION_MIN_LENGTH && maxLength === NO_MAX_LENGTH
      : minLength === size && maxLength === size;

  return (
    <div
      role="group"
      aria-label={t("regions.filter.label")}
      data-testid="region-filter-bar"
      className="mb-2 pb-2 border-b border-[var(--md-border)]"
    >
      <div className="flex flex-wrap items-center gap-1.5">
        <span
          role="group"
          aria-label={t("regions.filter.presetsLabel")}
          className="flex flex-wrap items-center gap-1"
        >
          {SIZE_PRESETS.map((size) => {
            const active = isPresetActive(size);
            return (
              <button
                key={size ?? "any"}
                type="button"
                aria-pressed={active}
                data-testid={`region-filter-preset-${size ?? "any"}`}
                title={
                  size === null
                    ? t("regions.filter.presetAnyTitle")
                    : t("regions.filter.presetTitle", { value: size })
                }
                onClick={() => applyPreset(size)}
                className={
                  "px-1.5 py-0.5 rounded border " +
                  (active
                    ? "border-[var(--md-accent)] bg-[var(--md-bg-tertiary)] font-medium"
                    : "border-transparent hover:bg-[var(--md-bg-hover)]")
                }
              >
                {size === null
                  ? t("regions.filter.presetAny")
                  : t("regions.filter.preset", { value: size })}
              </button>
            );
          })}
        </span>

        {/*
          `<label>` wrapping the control, the `StringsPanel` spelling: it is the
          accessible name without a generated id, and the axe suite counts
          unnamed inputs as debt this panel must not add to.
        */}
        <label className="flex items-center gap-1 md-text-secondary">
          {t("regions.filter.minLength")}
          <input
            type="number"
            min={1}
            value={minLength}
            data-testid="region-filter-min"
            onChange={(e) => setMinLength(Number(e.target.value) || 1)}
            className={`${CONTROL_CLASS} w-14 text-center`}
          />
        </label>

        <label className="flex items-center gap-1 md-text-secondary">
          {t("regions.filter.maxLength")}
          <input
            type="number"
            min={0}
            value={maxLength}
            title={t("regions.filter.maxLengthAny")}
            data-testid="region-filter-max"
            // `|| 0` and a `0` floor: an emptied field means "no ceiling", the
            // same thing `0` means on the wire, rather than NaN.
            onChange={(e) => setMaxLength(Number(e.target.value) || NO_MAX_LENGTH)}
            className={`${CONTROL_CLASS} w-14 text-center`}
          />
        </label>
        {/*
          The "0 = no limit" hint belongs to the MAX field, and in a wrapping
          row it ended up sitting flush against the next control's label
          ("0 = no limit Sort"), reading as one run-on phrase. `basis-full`
          ends the line after it, so the hint stays attached to the field it
          explains and the sort control starts clean.
        */}
        <span className="md-text-muted basis-full">
          {t("regions.filter.maxLengthAny")}
        </span>

        <label className="flex items-center gap-1 md-text-secondary">
          {t("regions.filter.sort")}
          <select
            value={sort}
            data-testid="region-filter-sort"
            onChange={(e) => setSort(e.target.value as RegionSort)}
            className={`${CONTROL_CLASS} bg-[var(--md-bg-secondary)] text-[var(--md-text-primary)]`}
          >
            {SORT_OPTIONS.map((option) => (
              <option key={option.value} value={option.value}>
                {t(option.labelKey)}
              </option>
            ))}
          </select>
        </label>
      </div>

      {/*
        Honesty 1. Always present, not conditional on a filter being active: the
        badge it explains is on the rows whether or not anything is filtered,
        and a note that appears only once the user is already confused is a note
        that arrived too late.
      */}
      <p className="mt-1 md-text-muted" data-testid="region-filter-length-note">
        {t("regions.filter.lengthNote")}
      </p>
    </div>
  );
}

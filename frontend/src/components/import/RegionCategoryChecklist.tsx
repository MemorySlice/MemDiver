import { useId } from "react";
import { useTranslation } from "react-i18next";
import type { ImportPreview, RegionCategory } from "@/api/types";
import { formatBytes } from "@/utils/format-bytes";
import {
  DEFAULT_REGION_CATEGORIES,
  REGION_CATEGORIES,
  isAllCategories,
  isDefaultCategories,
  orderCategories,
} from "./region-categories";

export interface RegionCategoryChecklistProps {
  selected: readonly RegionCategory[];
  onChange: (next: RegionCategory[]) => void;
  /** Per-category totals from a preview; omitted when nothing is on the server yet. */
  totals?: ImportPreview["totals"];
  /** Smaller layout without descriptions (the upload tab's batch selector). */
  compact?: boolean;
  disabled?: boolean;
}

/**
 * The category checklist with its "Defaults" / "All" quick buttons. Shared by
 * the wizard's Regions step (with preview totals) and the upload tab's batch
 * selector (without, since the files are not on the server yet).
 */
export function RegionCategoryChecklist({
  selected,
  onChange,
  totals,
  compact = false,
  disabled = false,
}: RegionCategoryChecklistProps) {
  const { t } = useTranslation("import");
  const legendId = useId();
  const chosen = new Set(selected);

  const toggle = (category: RegionCategory) => {
    const next = new Set(chosen);
    if (next.has(category)) next.delete(category);
    else next.add(category);
    onChange(orderCategories(next));
  };

  return (
    <fieldset
      className="space-y-2"
      aria-labelledby={legendId}
      disabled={disabled}
      data-testid="region-category-checklist"
    >
      <legend id={legendId} className="text-sm font-medium">
        {t("checklist.legend")}
      </legend>
      <div className="flex items-center gap-2 flex-wrap">
        <QuickButton
          label={t("checklist.defaults")}
          hint={t("checklist.defaultsHint")}
          active={isDefaultCategories(selected)}
          onClick={() => onChange([...DEFAULT_REGION_CATEGORIES])}
          testId="region-defaults"
        />
        <QuickButton
          label={t("checklist.all")}
          hint={t("checklist.allHint")}
          active={isAllCategories(selected)}
          onClick={() => onChange([...REGION_CATEGORIES])}
          testId="region-all"
        />
      </div>

      <ul className={compact ? "grid grid-cols-2 gap-1" : "space-y-1"}>
        {REGION_CATEGORIES.map((category) => (
          <li key={category}>
            <CategoryRow
              category={category}
              checked={chosen.has(category)}
              onToggle={() => toggle(category)}
              total={totals?.[category]}
              hasTotals={totals !== undefined}
              compact={compact}
            />
          </li>
        ))}
      </ul>

      {selected.length === 0 && (
        <p role="alert" className="text-xs" style={{ color: "var(--md-accent-red)" }}>
          {t("checklist.noneSelected")}
        </p>
      )}
    </fieldset>
  );
}

function QuickButton({
  label,
  hint,
  active,
  onClick,
  testId,
}: {
  label: string;
  hint: string;
  active: boolean;
  onClick: () => void;
  testId: string;
}) {
  return (
    <button
      type="button"
      onClick={onClick}
      title={hint}
      aria-pressed={active}
      data-testid={testId}
      className={`text-xs px-2 py-0.5 rounded border transition-colors ${
        active
          ? "border-[var(--md-accent-blue)] md-text-accent"
          : "border-[var(--md-border)] hover:bg-[var(--md-bg-hover)]"
      }`}
    >
      {label}
    </button>
  );
}

function CategoryRow({
  category,
  checked,
  onToggle,
  total,
  hasTotals,
  compact,
}: {
  category: RegionCategory;
  checked: boolean;
  onToggle: () => void;
  total?: { count: number; bytes: number };
  hasTotals: boolean;
  compact: boolean;
}) {
  const { t } = useTranslation("import");
  const descId = useId();
  const stats = total
    ? t("checklist.categoryStats", { count: total.count, bytes: formatBytes(total.bytes) })
    : hasTotals
      ? t("checklist.categoryAbsent")
      : null;

  return (
    <label
      className={`flex items-start gap-2 text-sm p-1 rounded cursor-pointer hover:bg-[var(--md-bg-hover)] ${
        hasTotals && !total ? "opacity-60" : ""
      }`}
      title={compact ? t(`category.${category}.desc`) : undefined}
    >
      <input
        type="checkbox"
        checked={checked}
        onChange={onToggle}
        aria-describedby={compact ? undefined : descId}
        data-testid={`region-category-${category}`}
        className="mt-0.5 accent-[var(--md-accent-blue)]"
      />
      <span className="min-w-0 flex-1">
        <span className="font-medium">{t(`category.${category}.label`)}</span>
        {stats && (
          <span className="ml-2 text-xs md-text-muted" data-testid={`region-stats-${category}`}>
            {stats}
          </span>
        )}
        {!compact && (
          <span id={descId} className="block text-xs md-text-secondary">
            {t(`category.${category}.desc`)}
          </span>
        )}
      </span>
    </label>
  );
}

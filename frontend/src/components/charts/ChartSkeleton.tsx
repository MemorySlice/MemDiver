/**
 * Chart-shaped loading placeholder.
 *
 * Used as the `<Suspense fallback>` for every lazy-loaded chart dispatcher
 * so the layout doesn't jump/blank out while the Plotly or SVG chunk is
 * being fetched. Purely decorative bars (`aria-hidden`) plus a screen
 * reader-only status message, consistent with the `animate-pulse` +
 * `aria-label` loading pattern already used elsewhere (see
 * `StringsPanel.tsx`).
 */
import { useTranslation } from "react-i18next";

const BAR_HEIGHTS = [45, 70, 55, 85, 60, 75, 50];

export function ChartSkeleton() {
  const { t } = useTranslation("charts");
  return (
    <div className="md-panel flex h-48 items-end gap-2 p-4" role="status">
      <span className="sr-only">{t("skeleton.loading")}</span>
      {BAR_HEIGHTS.map((height, i) => (
        <div
          key={i}
          aria-hidden="true"
          className="flex-1 animate-pulse rounded-t bg-[var(--md-border)]"
          style={{ height: `${height}%` }}
        />
      ))}
    </div>
  );
}

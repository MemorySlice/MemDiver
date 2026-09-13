import { useTranslation } from "react-i18next";
import { useDumpStore } from "@/stores/dump-store";

/**
 * The always-visible answer to "which dumps am I actually looking at?".
 *
 * One compact chip per loaded dump carrying the two INDEPENDENT affordances the
 * old sidebar row conflated:
 *
 *   - the checkbox is PARTICIPATION (`selectedDumpIds`) — which dumps the
 *     comparison, the consensus and the panes are computed over;
 *   - the radio is FOCUS (`activeDumpId`) — which dump the single-pane viewer
 *     shows and which one anchors the alignment.
 *
 * Focusing an unselected dump selects it (the store's one deliberate one-way
 * exception, see `reconcileSelection`), but ticking a box never moves focus.
 *
 * Deliberately ONE component mounted in two places — the main-area bar and the
 * Import tab — rather than two similar strips, so the entry points cannot drift
 * apart.
 */
export function DumpSelectionStrip() {
  const { t } = useTranslation("dumps");
  const dumps = useDumpStore((s) => s.dumps);
  const selectedDumpIds = useDumpStore((s) => s.selectedDumpIds);
  const activeDumpId = useDumpStore((s) => s.activeDumpId);
  const originDumpId = useDumpStore((s) => s.originDumpId);
  const toggleDumpSelected = useDumpStore((s) => s.toggleDumpSelected);
  const setActiveDump = useDumpStore((s) => s.setActiveDump);

  if (dumps.length === 0) return null;

  return (
    <div
      role="group"
      aria-label={t("selection.stripLabel")}
      data-testid="dump-selection-strip"
      className="flex items-center gap-1.5 overflow-x-auto min-w-0 text-xs"
    >
      {dumps.map((d) => {
        const selected = selectedDumpIds.includes(d.id);
        const focused = d.id === activeDumpId;
        return (
          <div
            key={d.id}
            data-testid="dump-chip"
            data-dump-id={d.id}
            onClick={() => setActiveDump(d.id)}
            className="flex items-center gap-1 shrink-0 px-1.5 py-0.5 rounded cursor-pointer hover:bg-[var(--md-bg-hover)]"
            style={{
              border: focused
                ? "1.5px solid var(--md-accent-blue)"
                : "1px solid var(--md-border)",
            }}
          >
            <input
              type="checkbox"
              checked={selected}
              aria-label={t("selection.participateLabel", { name: d.name })}
              data-testid={`dump-chip-select-${d.id}`}
              onClick={(e) => e.stopPropagation()}
              onChange={() => toggleDumpSelected(d.id)}
            />
            <input
              type="radio"
              // Scoped so the strip's radios never join the sidebar list's
              // group; two same-named groups in one document fight over the
              // browser's own checked bookkeeping.
              name="memdiver-dump-focus-strip"
              checked={focused}
              aria-label={t("selection.focusLabel", { name: d.name })}
              data-testid={`dump-chip-focus-${d.id}`}
              onClick={(e) => e.stopPropagation()}
              onChange={() => setActiveDump(d.id)}
            />
            <span className="font-mono truncate max-w-[12rem]" title={d.path}>
              {d.name}
            </span>
            {d.id === originDumpId && (
              <span
                data-testid={`dump-chip-origin-${d.id}`}
                title={t("selection.originTitle")}
                className="px-1 rounded text-[9px] font-semibold uppercase"
                style={{ background: "var(--md-bg-tertiary)" }}
              >
                {t("selection.originBadge")}
              </span>
            )}
          </div>
        );
      })}
    </div>
  );
}

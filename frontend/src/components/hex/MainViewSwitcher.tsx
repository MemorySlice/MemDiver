import { useTranslation } from "react-i18next";
import { useDumpStore, type MainView } from "@/stores/dump-store";

/**
 * The layout switch for the main analysis area: Single / Side by side / Overlay.
 *
 * The multi-dump modes are DISABLED below two selected dumps, never hidden. A
 * control that vanishes cannot be discovered, and "I loaded a second dump and
 * nothing changed" is exactly the complaint this switch exists to answer — a
 * greyed-out segment with an explanatory tooltip at least says what the missing
 * precondition is.
 *
 * Tab semantics mirror `HexToolbar`'s Raw/VAS/VA switch so both radio-style
 * groups in the hex area behave identically for a screen reader.
 */
export function MainViewSwitcher() {
  const { t } = useTranslation("hex");
  const mainView = useDumpStore((s) => s.mainView);
  const setMainView = useDumpStore((s) => s.setMainView);
  const selectedCount = useDumpStore((s) => s.selectedDumpIds.length);

  const enoughDumps = selectedCount >= 2;

  const segments: { view: MainView; label: string; title: string; needsTwo: boolean }[] = [
    { view: "single", label: t("mainView.single"), title: t("mainView.singleTitle"), needsTwo: false },
    {
      view: "sideBySide",
      label: t("mainView.sideBySide", { count: selectedCount }),
      title: t("mainView.sideBySideTitle"),
      needsTwo: true,
    },
    { view: "overlay", label: t("mainView.overlay"), title: t("mainView.overlayTitle"), needsTwo: true },
  ];

  return (
    <div
      role="tablist"
      aria-label={t("mainView.label")}
      data-testid="main-view-switcher"
      className="flex items-center shrink-0 rounded border border-[var(--md-border)] overflow-hidden text-xs"
    >
      {segments.map(({ view, label, title, needsTwo }, index) => {
        const disabled = needsTwo && !enoughDumps;
        return (
          <button
            key={view}
            role="tab"
            type="button"
            data-testid={`main-view-${view}`}
            aria-selected={mainView === view}
            aria-disabled={disabled || undefined}
            disabled={disabled}
            title={disabled ? t("mainView.needTwoTitle") : title}
            onClick={() => setMainView(view)}
            className={
              "px-2 py-0.5 " +
              (index > 0 ? "border-l border-[var(--md-border)] " : "") +
              (mainView === view ? "font-semibold " : "hover:bg-[var(--md-bg-hover)] ") +
              (disabled ? "opacity-40 cursor-not-allowed" : "")
            }
            style={
              mainView === view
                ? {
                    background: "var(--md-accent-blue)",
                    color: "var(--md-bg-primary)",
                  }
                : undefined
            }
          >
            {label}
          </button>
        );
      })}
    </div>
  );
}

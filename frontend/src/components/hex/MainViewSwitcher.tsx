import { useTranslation } from "react-i18next";
import { SegmentedControl } from "@/components/common/SegmentedControl";
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
 * Tab semantics come from the shared `SegmentedControl`, which is also what
 * `HexToolbar`'s Raw/VAS/VA group, the overlay's `Align` switch and its render
 * mode switch draw — so every radio-style group in the hex area behaves
 * identically for a screen reader. This one used to paint its selected segment
 * with an open-coded `{background: "var(--md-accent-blue)"}` where its three
 * siblings used the `md-bg-accent` / `md-text-on-accent` pair, which made it
 * the one group a re-theme of the accent would have left behind.
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
    <SegmentedControl
      aria-label={t("mainView.label")}
      testId="main-view-switcher"
      className="text-xs"
      selected={mainView}
      onSelect={(id) => setMainView(id as MainView)}
      options={segments.map(({ view, label, title, needsTwo }) => {
        const disabled = needsTwo && !enoughDumps;
        return {
          id: view,
          label,
          testId: `main-view-${view}`,
          disabled,
          title: disabled ? t("mainView.needTwoTitle") : title,
        };
      })}
    />
  );
}

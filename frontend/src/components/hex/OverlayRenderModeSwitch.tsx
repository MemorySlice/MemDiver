import { useTranslation } from "react-i18next";

import { SegmentedControl } from "@/components/common/SegmentedControl";

import {
  OVERLAY_RENDER_MODES,
  useOverlayRenderStore,
  type OverlayRenderMode,
} from "@/stores/overlay-render-store";

interface OverlayRenderModeSwitchProps {
  /**
   * Whether more than one dump is EFFECTIVELY in view.
   *
   * `false` dims the control rather than removing it. All three modes describe
   * a relationship BETWEEN dumps, so with one dump they are all the same
   * picture — but a control that disappears takes its own discoverability with
   * it, and worse, shifts every neighbour in the toolbar sideways the moment a
   * selection changes. Greyed out and still in place, it stays findable and the
   * row never jumps.
   */
  enabled: boolean;
}

/**
 * `Class │ Variants │ Glyph` — which reading of the aligned window the overlay
 * paints.
 *
 * Tab semantics and markup come from the shared `SegmentedControl`, which is
 * also what `MainViewSwitcher` and the `Raw file │ Memory (VAS) │ VA` group in
 * `HexToolbar` draw: the hex area has several radio-style segmented groups, and
 * one that looked or behaved differently would teach a screen-reader user that
 * it is a different kind of control.
 */
export function OverlayRenderModeSwitch({ enabled }: OverlayRenderModeSwitchProps) {
  const { t } = useTranslation("hex");
  const renderMode = useOverlayRenderStore((s) => s.renderMode);
  const setRenderMode = useOverlayRenderStore((s) => s.setRenderMode);

  const titleKey: Record<OverlayRenderMode, string> = {
    class: "renderMode.classTitle",
    variants: "renderMode.variantsTitle",
    glyph: "renderMode.glyphTitle",
  };

  return (
    <SegmentedControl
      aria-label={t("renderMode.label")}
      testId="hex-overlay-render-mode"
      data={{ "data-enabled": enabled ? "true" : "false" }}
      dimmed={!enabled}
      selected={renderMode}
      onSelect={(id) => setRenderMode(id as OverlayRenderMode)}
      options={OVERLAY_RENDER_MODES.map((mode) => ({
        id: mode,
        label: t(`renderMode.${mode}`),
        testId: `hex-overlay-render-mode-${mode}`,
        disabled: !enabled,
        title: enabled ? t(titleKey[mode]) : t("renderMode.needTwoTitle"),
      }))}
    />
  );
}

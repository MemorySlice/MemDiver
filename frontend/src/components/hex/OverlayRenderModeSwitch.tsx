import { useTranslation } from "react-i18next";

import { SegmentedControl } from "@/components/common/SegmentedControl";

import { useMultiHexStore } from "@/stores/multi-hex-store";
import {
  effectiveOverlayRenderMode,
  OVERLAY_RENDER_MODES,
  overlayRenderModeAvailable,
  useOverlayRenderStore,
  type OverlayRenderMode,
} from "@/stores/overlay-render-store";

/** The `heap:overlay.unavailable.*` reason for a non-`ok` heap status. */
function heapUnavailableKey(heapStatus: string | null): string {
  switch (heapStatus) {
    case "no_va_coordinate":
    case "empty_consensus":
    case "error":
      return `heap:overlay.unavailable.${heapStatus}`;
    default:
      return "heap:overlay.unavailable.missing";
  }
}

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
 * `Class │ Variants │ Glyph │ Heap` — which reading of the aligned window the
 * overlay paints. `Heap` is disabled, with the localized reason as its title,
 * whenever the window's `heap_status` is not `"ok"`.
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
  const heapStatus = useMultiHexStore((s) => s.heapStatus);

  const titleKey: Record<OverlayRenderMode, string> = {
    class: "renderMode.classTitle",
    variants: "renderMode.variantsTitle",
    glyph: "renderMode.glyphTitle",
    heap: "renderMode.heapTitle",
  };

  /** Why `mode` is unavailable right now, or `null` when it can be chosen. */
  const disabledReason = (mode: OverlayRenderMode): string | null => {
    if (!enabled) return t("renderMode.needTwoTitle");
    if (!overlayRenderModeAvailable(mode, heapStatus)) return t(heapUnavailableKey(heapStatus));
    return null;
  };

  return (
    <SegmentedControl
      aria-label={t("renderMode.label")}
      testId="hex-overlay-render-mode"
      data={{ "data-enabled": enabled ? "true" : "false" }}
      dimmed={!enabled}
      // What the grid actually paints, so an unavailable `heap` choice never
      // reads as selected over a grid painted in another mode.
      selected={effectiveOverlayRenderMode(renderMode, heapStatus)}
      onSelect={(id) => setRenderMode(id as OverlayRenderMode)}
      options={OVERLAY_RENDER_MODES.map((mode) => {
        const reason = disabledReason(mode);
        return {
          id: mode,
          label: t(`renderMode.${mode}`),
          testId: `hex-overlay-render-mode-${mode}`,
          disabled: reason !== null,
          title: reason ?? t(titleKey[mode]),
        };
      })}
    />
  );
}

import { useHexStore, type HexViewMode } from "@/stores/hex-store";
import { useMultiHexStore } from "@/stores/multi-hex-store";
import { addressDigitsFor, OFFSET_DIGITS_DEFAULT } from "@/utils/hex-codec";

/** How the offset gutter should be labelled: the base to add and the digit width. */
export interface GutterAddressing {
  /** Virtual address of offset 0, or `null` for the view-relative label. */
  offsetBase: number | null;
  addressDigits: number;
}

const RELATIVE: GutterAddressing = { offsetBase: null, addressDigits: OFFSET_DIGITS_DEFAULT };

/**
 * The gutter labelling for a given base. Only the "va" coordinate has an
 * absolute address to show; `vas` and `raw` stay view-relative.
 */
export function gutterAddressing(
  view: HexViewMode,
  base: number | null,
  span: number,
): GutterAddressing {
  if (view !== "va" || base === null || !Number.isFinite(base) || base < 0) return RELATIVE;
  return { offsetBase: base, addressDigits: addressDigitsFor(base + span) };
}

/**
 * Single-dump viewer: the base is `vaSpanStart`, valid only once the page
 * states have loaded (the same condition `InvestigationPanel` uses).
 */
export function useSingleGutterAddressing(): GutterAddressing {
  const view = useHexStore((s) => s.viewMode);
  const loaded = useHexStore((s) => s.pageStatesLoaded);
  const base = useHexStore((s) => s.vaSpanStart);
  const span = useHexStore((s) => s.fileSize);
  return gutterAddressing(view, loaded ? base : null, span);
}

/**
 * Aligned panes: the base is the server's `anchor.va_span_start`, kept by
 * `multi-hex-store` and honoured only while it belongs to the live request.
 */
export function useAlignedGutterAddressing(): GutterAddressing {
  const view = useHexStore((s) => s.viewMode);
  const span = useHexStore((s) => s.fileSize);
  const base = useMultiHexStore((s) =>
    s.anchorVaLabel !== null && s.anchorVaLabel.identity === s.identity
      ? s.anchorVaLabel.spanStart
      : null,
  );
  return gutterAddressing(view, base, span);
}

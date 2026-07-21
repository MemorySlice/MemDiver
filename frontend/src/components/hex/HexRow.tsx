import { memo, type ReactElement } from "react";
import { useTranslation } from "react-i18next";
import type { RegionIndex } from "./highlight-utils";
import { getRegionForOffset, highlightClass } from "./highlight-utils";
import { byteToHex, byteToAscii, offsetToHex } from "@/utils/hex-codec";
import type { HexViewMode } from "@/stores/hex-store";
import type { PageState } from "@/api/types";

/** Variance tiers for heatmap CSS classes (aligned with core/variance.py STRUCTURAL_MAX). */
const VAR_TIER_LOW = 50;
const VAR_TIER_HIGH = 200;

/** Backend ByteClass codes → CSS class; see hex.css:140-156. */
const CONSENSUS_CLASSES = [
  "consensus-invariant",
  "consensus-structural",
  "consensus-pointer",
  "consensus-key-candidate",
] as const;

interface HexRowProps {
  rowOffset: number;
  getByteAt: (offset: number) => number | undefined;
  getVarianceAt?: (offset: number) => number | undefined;
  cursorOffset: number | null;
  selectionStart: number | null;
  selectionEnd: number | null;
  focusColumn: "hex" | "ascii";
  regionIndex: RegionIndex;
  bytesPerRow?: number;
  activeFieldStart?: number | null;
  activeFieldEnd?: number | null;
  overlayEnabled?: boolean;
  getClassificationAt?: (offset: number) => number | undefined;
  view?: HexViewMode;
  getPageStateAt?: (offset: number) => PageState | undefined;
}

export const HexRow = memo(function HexRow({
  rowOffset,
  getByteAt,
  getVarianceAt,
  cursorOffset,
  selectionStart,
  selectionEnd,
  focusColumn: _focusColumn,
  regionIndex,
  bytesPerRow = 16,
  activeFieldStart = null,
  activeFieldEnd = null,
  overlayEnabled = false,
  getClassificationAt,
  view = "raw",
  getPageStateAt,
}: HexRowProps) {
  const { t } = useTranslation("hex");
  const isVaView = view === "va";
  const hexCells: ReactElement[] = [];
  const asciiCells: ReactElement[] = [];

  for (let i = 0; i < bytesPerRow; i++) {
    const byteOffset = rowOffset + i;
    const byteVal = getByteAt(byteOffset);
    const loaded = byteVal !== undefined;
    // "va"-view page state (CAPTURED/FAILED/UNMAPPED). undefined until
    // page-states resolve, or outside the "va" view.
    const pageState = isVaView ? getPageStateAt?.(byteOffset) : undefined;

    // Determine classes
    const classes: string[] = [];
    const isCursor = cursorOffset === byteOffset;
    const isSelected =
      selectionStart !== null &&
      selectionEnd !== null &&
      byteOffset >= selectionStart &&
      byteOffset <= selectionEnd;

    if (isCursor) classes.push("cursor");
    if (isSelected) classes.push("selected");

    const isActiveField =
      activeFieldStart !== null &&
      activeFieldEnd !== null &&
      byteOffset >= activeFieldStart &&
      byteOffset < activeFieldEnd;
    if (isActiveField) classes.push("active-field");

    // Highlight region
    const region = getRegionForOffset(regionIndex, byteOffset);
    if (region) {
      classes.push(highlightClass(region.type));
      if (region.colorIndex !== undefined) {
        classes.push(`field-color-${region.colorIndex % 8}`);
      }
      if (region.type === "neighborhood") {
        const lbl = region.label.toLowerCase();
        if (lbl.startsWith("key")) {
          classes.push("nb-key");
        } else if (lbl.startsWith("static")) {
          classes.push("nb-static");
        } else if (lbl.startsWith("dynamic")) {
          classes.push("nb-dynamic");
        }
      }
    }

    const varianceVal = getVarianceAt?.(byteOffset);
    if (varianceVal !== undefined) {
      if (varianceVal >= VAR_TIER_HIGH) classes.push("var-tier-3");
      else if (varianceVal >= VAR_TIER_LOW) classes.push("var-tier-2");
      else classes.push("var-tier-1");
    }

    if (overlayEnabled && getClassificationAt) {
      const code = getClassificationAt(byteOffset);
      if (code !== undefined && code >= 0 && code < CONSENSUS_CLASSES.length) {
        classes.push(CONSENSUS_CLASSES[code]);
      }
    }

    // "va"-view page-state tint. Composed AFTER the overlays above so a
    // non-captured page reads as failed/unmapped without clobbering
    // consensus/variance/search styling. CAPTURED bytes render normally.
    if (isVaView) {
      if (pageState === "FAILED") classes.push("page-failed");
      else if (pageState === "UNMAPPED") classes.push("page-unmapped");
    }

    // In the "va" view non-captured pages are zero-filled by the backend and
    // colored above, so the faint "loading" placeholder is reserved for
    // CAPTURED bytes whose chunk has not yet arrived (or before page-states
    // resolve, when the state is still unknown).
    const showLoading =
      !loaded &&
      (!isVaView || pageState === undefined || pageState === "CAPTURED");
    if (showLoading) classes.push("hex-loading");

    const classStr = classes.join(" ");
    let tooltip = region?.label ?? "";
    if (varianceVal !== undefined) {
      const varText = t("row.variance", { value: varianceVal.toFixed(1) });
      tooltip = tooltip ? `${tooltip} | ${varText}` : varText;
    }

    // Add gap after 8th byte for visual grouping
    const extraStyle = i === 8 ? { marginLeft: "6px" } : undefined;

    hexCells.push(
      <span
        key={`h${i}`}
        data-offset={byteOffset}
        data-col="hex"
        className={`hex-byte ${classStr}`}
        style={extraStyle}
        title={tooltip || undefined}
      >
        {loaded ? byteToHex(byteVal) : "--"}
      </span>
    );

    asciiCells.push(
      <span
        key={`a${i}`}
        data-offset={byteOffset}
        data-col="ascii"
        className={`hex-char ${classStr}`}
        title={tooltip || undefined}
      >
        {loaded ? byteToAscii(byteVal) : "."}
      </span>
    );
  }

  return (
    <div className="hex-row">
      <span className="hex-offset">{offsetToHex(rowOffset)}</span>
      <span className="hex-bytes">{hexCells}</span>
      <span className="hex-separator" />
      <span className="hex-ascii">{asciiCells}</span>
    </div>
  );
});

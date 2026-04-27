import { memo, type ReactElement } from "react";
import type { RegionIndex } from "./highlight-utils";
import { getRegionForOffset, highlightClass } from "./highlight-utils";
import { byteToHex, byteToAscii, offsetToHex } from "@/utils/hex-codec";

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
}: HexRowProps) {
  const hexCells: ReactElement[] = [];
  const asciiCells: ReactElement[] = [];

  for (let i = 0; i < bytesPerRow; i++) {
    const byteOffset = rowOffset + i;
    const byteVal = getByteAt(byteOffset);
    const loaded = byteVal !== undefined;

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

    if (!loaded) classes.push("hex-loading");

    const classStr = classes.join(" ");
    let tooltip = region?.label ?? "";
    if (varianceVal !== undefined) {
      tooltip = tooltip ? `${tooltip} | var: ${varianceVal.toFixed(1)}` : `var: ${varianceVal.toFixed(1)}`;
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

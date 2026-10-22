const BYTE_UNITS = ["B", "KiB", "MiB", "GiB", "TiB"] as const;

/**
 * Human-readable byte count with a binary unit, e.g. `1536` -> `"1.5 KiB"`.
 *
 * Whole bytes print without a decimal; everything larger keeps one, so a
 * 1.2 GiB dump never reads as a seven-digit KiB figure.
 */
export function formatBytes(bytes: number): string {
  if (!Number.isFinite(bytes) || bytes < 0) return "--";
  let value = bytes;
  let unit = 0;
  while (value >= 1024 && unit < BYTE_UNITS.length - 1) {
    value /= 1024;
    unit += 1;
  }
  return unit === 0 ? `${value} ${BYTE_UNITS[0]}` : `${value.toFixed(1)} ${BYTE_UNITS[unit]}`;
}

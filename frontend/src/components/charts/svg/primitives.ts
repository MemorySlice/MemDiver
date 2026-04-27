/**
 * Hand-rolled SVG chart primitives shared by svg/{Entropy,Variance,Vas,Survivor}.
 *
 * Inspired by the existing `ConvergenceChart.tsx` — keeps scales, ticks,
 * and formatting small and dependency-free (no d3-scale).
 */

/** Linear scale maps a value from [d0, d1] into [r0, r1]. */
export function scaleLinear(
  domain: [number, number],
  range: [number, number],
): (v: number) => number {
  const [d0, d1] = domain;
  const [r0, r1] = range;
  const span = d1 - d0 || 1;
  return (v) => r0 + ((v - d0) / span) * (r1 - r0);
}

/**
 * Log-10 scale. Values <= 0 clamp to a tiny positive min so Math.log10
 * stays finite; the domain's low end is likewise clamped.
 */
export function scaleLog(
  domain: [number, number],
  range: [number, number],
): (v: number) => number {
  const [d0, d1] = domain;
  const [r0, r1] = range;
  const safeMin = Math.max(d0, 1e-9);
  const logMin = Math.log10(safeMin);
  const logMax = Math.log10(Math.max(d1, safeMin * 10));
  const span = logMax - logMin || 1;
  return (v) => {
    const logV = Math.log10(Math.max(v, safeMin));
    return r0 + ((logV - logMin) / span) * (r1 - r0);
  };
}

/** "Nice" linear tick values within [min, max] (count is a target). */
export function niceLinearTicks(min: number, max: number, count = 5): number[] {
  if (min === max) return [min];
  if (min > max) [min, max] = [max, min];
  const span = max - min;
  const step0 = Math.pow(10, Math.floor(Math.log10(span / count)));
  const err = (count / span) * step0;
  let step = step0;
  if (err <= 0.15) step *= 10;
  else if (err <= 0.35) step *= 5;
  else if (err <= 0.75) step *= 2;
  const start = Math.ceil(min / step) * step;
  const ticks: number[] = [];
  for (let v = start; v <= max + step * 1e-6; v += step) {
    ticks.push(Number(v.toFixed(10)));
  }
  return ticks;
}

/** Powers-of-10 ticks in [min, max] for log-scale axes. */
export function niceLogTicks(min: number, max: number): number[] {
  const safeMin = Math.max(min, 1);
  const logMin = Math.floor(Math.log10(safeMin));
  const logMax = Math.ceil(Math.log10(Math.max(max, safeMin * 10)));
  const ticks: number[] = [];
  for (let n = logMin; n <= logMax; n++) ticks.push(Math.pow(10, n));
  return ticks;
}

/** Human-readable short-form number (1.2K, 3.4M, 0x100, etc). */
export function formatNumber(v: number): string {
  if (v === 0) return "0";
  const abs = Math.abs(v);
  if (abs >= 1e9) return (v / 1e9).toFixed(1) + "G";
  if (abs >= 1e6) return (v / 1e6).toFixed(1) + "M";
  if (abs >= 1e3) return (v / 1e3).toFixed(1) + "K";
  if (abs < 0.01 && abs > 0) return v.toExponential(1);
  return Number.isInteger(v) ? String(v) : v.toFixed(abs < 1 ? 2 : 1);
}

/** Hex-formatted byte offset with `0x` prefix. */
export function formatHexOffset(v: number): string {
  return "0x" + Math.round(v).toString(16);
}

/**
 * Build an SVG path `d` string for a polyline of [x, y] pairs.
 * Filtered nulls are skipped; gaps are preserved (new M after each gap).
 */
export function polylinePath(points: Array<[number, number] | null>): string {
  let d = "";
  let startNew = true;
  for (const p of points) {
    if (p === null || !Number.isFinite(p[0]) || !Number.isFinite(p[1])) {
      startNew = true;
      continue;
    }
    d += (startNew ? " M " : " L ") + p[0].toFixed(2) + " " + p[1].toFixed(2);
    startNew = false;
  }
  return d.trim();
}

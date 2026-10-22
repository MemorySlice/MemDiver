/**
 * Backend-agnostic view model for the entropy chart, shared by the Plotly and
 * SVG implementations so both draw the same thing from the same response.
 *
 * Geometry convention (both backends): every envelope bucket covers the
 * window starts `[starts[i], stops[i])` and is drawn as a flat step over that
 * span — two points, `(start, v)` and `(stop, v)`. Region markers use the
 * same window-start space (`[start, end)`), so they line up with the band.
 * The mean is a thin line through the bucket midpoints.
 */
import type { EntropyData } from "@/api/types";

/** Fraction of the achievable maximum used when the server names no threshold. */
const FALLBACK_THRESHOLD_FRACTION = 0.9;
/** Largest possible byte entropy (window >= 256). */
const BYTE_ENTROPY_CEILING = 8;
/** Headroom above the y-axis top, as a fraction of it. */
const Y_HEADROOM = 0.08;

export interface XY {
  x: number[];
  y: number[];
}

export interface EntropyEnvelopeSeries {
  /** Step points of the bucket minimum. */
  min: XY;
  /** Step points of the bucket maximum. */
  max: XY;
  /** Bucket midpoints of the mean. */
  mean: XY;
  bucketCount: number;
  /** Highest bucket max (where a single-window spike shows up). */
  peak: number;
}

export type EntropyResolution = "full" | "sampled";

export interface EntropyChartModel {
  envelope: EntropyEnvelopeSeries | null;
  /** Fallback line from `profile_sample` (used when there is no envelope). */
  profile: XY;
  xMin: number;
  xMax: number;
  threshold: number;
  maxEntropy: number;
  yTop: number;
  thresholdReachable: boolean;
  resolution: EntropyResolution | null;
  step: number | null;
  regions: EntropyData["high_entropy_regions"];
  regionTotal: number;
  regionsTruncated: boolean;
  isEmpty: boolean;
}

/** Compact bits/byte label: integers as-is, otherwise two decimals. */
export function formatBits(value: number): string {
  return Number.isInteger(value) ? String(value) : value.toFixed(2);
}

/** Achievable maximum entropy for a window: log2(min(window, 256)). */
export function maxEntropyForWindow(window?: number): number {
  if (!window || window < 2) return BYTE_ENTROPY_CEILING;
  return Math.log2(Math.min(window, 256));
}

/** Client-side threshold default: 90% of the achievable maximum (4.5 at window 32). */
export function fallbackThreshold(window?: number): number {
  return FALLBACK_THRESHOLD_FRACTION * maxEntropyForWindow(window);
}

function buildEnvelope(env: NonNullable<EntropyData["envelope"]>): EntropyEnvelopeSeries | null {
  const n = Math.min(env.starts.length, env.stops.length, env.min.length, env.max.length);
  if (n === 0) return null;
  const min: XY = { x: [], y: [] };
  const max: XY = { x: [], y: [] };
  const mean: XY = { x: [], y: [] };
  let peak = -Infinity;
  for (let i = 0; i < n; i++) {
    const start = env.starts[i];
    const stop = Math.max(env.stops[i], start);
    min.x.push(start, stop);
    min.y.push(env.min[i], env.min[i]);
    max.x.push(start, stop);
    max.y.push(env.max[i], env.max[i]);
    if (env.mean?.[i] !== undefined) {
      mean.x.push((start + stop) / 2);
      mean.y.push(env.mean[i]);
    }
    if (env.max[i] > peak) peak = env.max[i];
  }
  return { min, max, mean, bucketCount: n, peak };
}

function resolveResolution(data: EntropyData): EntropyResolution | null {
  if (data.resolution) return data.resolution;
  if (data.step === undefined) return null;
  return data.step === 1 ? "full" : "sampled";
}

function xExtent(envelope: EntropyEnvelopeSeries | null, profile: XY): [number, number] {
  const xs = envelope ? envelope.max.x : profile.x;
  if (xs.length === 0) return [0, 1];
  const lo = xs[0];
  const hi = xs[xs.length - 1];
  return hi > lo ? [lo, hi] : [lo, lo + 1];
}

/** Derive everything both chart backends draw from one entropy response. */
export function buildEntropyChartModel(data: EntropyData, thresholdProp?: number): EntropyChartModel {
  const envelope = data.envelope ? buildEnvelope(data.envelope) : null;
  const samples = data.profile_sample ?? [];
  const profile: XY = { x: samples.map((p) => p.offset), y: samples.map((p) => p.entropy) };
  const [xMin, xMax] = xExtent(envelope, profile);
  const threshold = data.threshold ?? thresholdProp ?? fallbackThreshold(data.window);
  const maxEntropy = data.max_entropy ?? maxEntropyForWindow(data.window);
  const regions = data.high_entropy_regions ?? [];
  return {
    envelope,
    profile,
    xMin,
    xMax,
    threshold,
    maxEntropy,
    yTop: Math.max(maxEntropy, threshold) * (1 + Y_HEADROOM),
    thresholdReachable: data.threshold_reachable ?? threshold <= maxEntropy,
    resolution: resolveResolution(data),
    step: data.step ?? null,
    regions,
    regionTotal: data.region_count ?? regions.length,
    regionsTruncated: data.regions_truncated ?? false,
    isEmpty: !envelope && samples.length === 0,
  };
}

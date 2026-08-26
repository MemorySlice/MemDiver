/**
 * Duration splitting for human-readable elapsed/remaining readouts.
 *
 * Deliberately UNIT-FREE: this module returns numbers only and never a
 * string like "2h 30m". The words belong to the i18n layer -- a caller
 * feeds the parts into `t("...etaHours", { h, m })` so the phrasing (and
 * any future locale) lives in `locales/<lng>/*.json`, not in this file.
 */

/** Whole hours / minutes / seconds a duration decomposes into. */
export interface DurationParts {
  h: number;
  m: number;
  s: number;
}

const SECONDS_PER_MINUTE = 60;
const SECONDS_PER_HOUR = 3600;

/**
 * Split a duration in seconds into whole hours, minutes and seconds.
 *
 * Fractional input is floored (an ETA of 2736.4s is "45m 36s", not
 * "45m 36.4s"). Negative and non-finite inputs -- a NaN from a degenerate
 * rate, an `Infinity` from a zero-second sample window -- collapse to all
 * zeros rather than propagating into the DOM.
 */
export function splitDuration(seconds: number): DurationParts {
  if (!Number.isFinite(seconds) || seconds <= 0) {
    return { h: 0, m: 0, s: 0 };
  }
  const whole = Math.floor(seconds);
  return {
    h: Math.floor(whole / SECONDS_PER_HOUR),
    m: Math.floor((whole % SECONDS_PER_HOUR) / SECONDS_PER_MINUTE),
    s: whole % SECONDS_PER_MINUTE,
  };
}

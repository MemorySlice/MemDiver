import type { RuleStyle } from "./highlight-rules";

/** Colour AND a glyph: a rule hit is never signalled by colour alone. */
export const RULE_MARKERS: Record<RuleStyle, { glyph: string; token: string }> = {
  danger: { glyph: "✖", token: "--md-accent-red" },
  warn: { glyph: "▲", token: "--md-accent-orange" },
  info: { glyph: "ℹ", token: "--md-accent-blue" },
  ok: { glyph: "✔", token: "--md-accent-green" },
};

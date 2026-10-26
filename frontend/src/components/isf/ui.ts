/** Shared class strings of the ISF builder (same look as the YARA / Image panels). */
export const inputClass =
  "w-full px-2 py-1 text-xs rounded border border-[var(--md-border)] bg-[var(--md-bg-secondary)]";
export const buttonClass =
  "px-2 py-1 text-xs rounded border border-[var(--md-border)] hover:bg-[var(--md-bg-hover)] disabled:opacity-40";
export const errorStyle = { color: "var(--md-accent-red)" } as const;
/** Icon-size action button (square, never shrinks, so row actions stay inline). */
export const iconButtonClass =
  "shrink-0 w-6 h-6 inline-flex items-center justify-center text-xs rounded border border-[var(--md-border)] hover:bg-[var(--md-bg-hover)] disabled:opacity-40";

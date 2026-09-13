import type { ReactNode } from "react";

/**
 * The one segmented radio-style group this app draws.
 *
 * Four copies of this markup had grown side by side — the overlay's `Align`
 * switch, its `Class | Variants | Glyph` switch, the `Single | Side by side |
 * Overlay` layout switch and the toolbar's `Raw file | Memory (VAS) | VA`
 * group — with a BYTE-IDENTICAL container class string, the same
 * `tablist`/`tab`/`aria-selected` semantics, the same `px-2 py-0.5` and the
 * same divider-on-all-but-first rule. Four copies is four chances for one of
 * them to teach a screen-reader user that it is a different kind of control,
 * which is exactly what each of their doc comments says must not happen.
 *
 * ── What is deliberately NOT here ───────────────────────────────────────────
 * Arrow-key roving tabindex. None of the four had it, adding it would change
 * how every one of them behaves, and that is a separate, deliberate change
 * rather than a side effect of removing duplication. It is the obvious next
 * improvement to make HERE, once, instead of four times.
 */
export interface SegmentedOption {
  /** Stable identity; also what `onSelect` receives. */
  id: string;
  label: ReactNode;
  title?: string;
  disabled?: boolean;
  /** `data-testid` for this segment. Omitted leaves the button unlabelled. */
  testId?: string;
}

export interface SegmentedControlProps {
  options: readonly SegmentedOption[];
  /**
   * The live selection, or `null` for "none of these".
   *
   * `null` is a real state, not a missing value: the overlay's `Align` switch
   * reflects the BUILD on screen, and before the first aligned window there is
   * no coordinate to point at.
   */
  selected: string | null;
  onSelect: (id: string) => void;
  /** Name the group by a string ... */
  "aria-label"?: string;
  /** ... or by the id of a visible label already on screen. */
  "aria-labelledby"?: string;
  /** `data-testid` for the group. */
  testId?: string;
  /** Extra `data-*` attributes on the container, e.g. `data-method`. */
  data?: Record<string, string>;
  /** A `title` on the container, for a group-wide explanation. */
  title?: string;
  /**
   * Dim the WHOLE group — "this control has nothing to say right now".
   *
   * An inline opacity rather than a utility class, so it cannot be confused
   * with the `disabled:opacity-50` a segment carries for a transient in-flight
   * state.
   */
  dimmed?: boolean;
  /** Appended to the container's classes (e.g. a font size). */
  className?: string;
}

const CONTAINER =
  "flex items-center shrink-0 rounded border border-[var(--md-border)] overflow-hidden";

export function SegmentedControl({
  options,
  selected,
  onSelect,
  testId,
  data,
  title,
  dimmed = false,
  className,
  ...aria
}: SegmentedControlProps) {
  return (
    <div
      role="tablist"
      aria-label={aria["aria-label"]}
      aria-labelledby={aria["aria-labelledby"]}
      data-testid={testId}
      title={title}
      className={className ? `${CONTAINER} ${className}` : CONTAINER}
      style={dimmed ? { opacity: 0.45 } : undefined}
      {...data}
    >
      {options.map((option, index) => {
        const isSelected = selected === option.id;
        const disabled = option.disabled === true;
        return (
          <button
            key={option.id}
            role="tab"
            type="button"
            data-testid={option.testId}
            aria-selected={isSelected}
            aria-disabled={disabled || undefined}
            disabled={disabled}
            title={option.title}
            onClick={() => onSelect(option.id)}
            className={
              "px-2 py-0.5 disabled:opacity-50 " +
              (index > 0 ? "border-l border-[var(--md-border)] " : "") +
              (isSelected
                ? "md-bg-accent md-text-on-accent font-semibold "
                : "hover:bg-[var(--md-bg-hover)] ") +
              (disabled ? "cursor-not-allowed" : "")
            }
          >
            {option.label}
          </button>
        );
      })}
    </div>
  );
}

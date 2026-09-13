import type { ReactNode } from "react";

/**
 * One legend entry: a decorative colour chip, and the word it stands for.
 *
 * The chip is ALWAYS `aria-hidden`. It carries no information the label does
 * not already carry, so announcing it gives a screen-reader user a bare,
 * nameless element between every two words of the legend. That was true at
 * eight of this app's eleven swatch sites and silently untrue at the other
 * three — which is the whole argument for the attribute living in one place
 * rather than in eleven `<span>`s that each have to remember it.
 *
 * `inline-flex items-center gap-1` is the shared spacing idiom; the minimap's
 * older `mr-1` spelling folds into it here.
 */
export interface VarianceSwatchProps {
  /** The `.md-variance-swatch` modifier, e.g. `variance-pointer`. */
  swatchClass: string;
  /** The visible word. Always rendered, since it is the accessible name. */
  label: ReactNode;
  /** `data-testid` for the chip itself, where a spec keys on it. */
  swatchTestId?: string;
  /** `data-testid` for the wrapper. */
  testId?: string;
  /** Extra classes on the wrapper (e.g. `md-text-muted`). */
  className?: string;
  /** Extra classes on the chip (e.g. `mt-0.5 shrink-0` for a list row). */
  swatchExtraClass?: string;
}

export function VarianceSwatch({
  swatchClass,
  label,
  swatchTestId,
  testId,
  className,
  swatchExtraClass,
}: VarianceSwatchProps) {
  const wrapper = "inline-flex items-center gap-1";
  const chip = `md-variance-swatch ${swatchClass}${swatchExtraClass ? ` ${swatchExtraClass}` : ""}`;
  return (
    <span data-testid={testId} className={className ? `${wrapper} ${className}` : wrapper}>
      <span aria-hidden="true" data-testid={swatchTestId} className={chip} />
      {label}
    </span>
  );
}

/**
 * FTUE (First-Time UX) type definitions.
 *
 * A Tour is a sequence of TourSteps, each optionally anchored to a DOM element
 * via a data-tour-id attribute. Tours may be gated on predicates (trigger) and
 * steps may block until a user action is performed (requireAction).
 */

export type TourPlacement =
  | "top"
  | "bottom"
  | "left"
  | "right"
  | "center"
  | "over";

export interface TourRequireAction {
  /** Hint shown to the user while the predicate is not yet satisfied. */
  description: string;
  /** When this returns true, the step auto-proceeds to its popover. */
  predicate: () => boolean;
}

export interface TourStep {
  id: string;
  /** Value of data-tour-id attribute (preferred) or a CSS selector. */
  target?: string;
  title: string;
  body: string;
  placement?: TourPlacement;
  requireAction?: TourRequireAction;
}

export type TourTrigger =
  | { kind: "immediate" }
  | { kind: "on-condition"; predicate: () => boolean };

export interface Tour {
  id: string;
  version: number;
  trigger: TourTrigger;
  steps: TourStep[];
  /** Lower number = shown first. Defaults to Infinity (runs last). */
  priority?: number;
}

export interface SeenTour {
  id: string;
  version: number;
  seenAt: number;
  completed: boolean;
}

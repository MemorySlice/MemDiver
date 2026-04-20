import { useEffect, useRef } from "react";
import { driver, type Driver, type DriveStep } from "driver.js";
import "driver.js/dist/driver.css";
import { useTourController } from "./useTourController";
import type { TourStep } from "./types";

const POPOVER_CLASS = "memdiver-tour-popover";
const STYLE_ELEMENT_ID = "memdiver-tour-style";
const WAIT_POLL_MS = 200;

/**
 * Injects theme-aware overrides for Driver.js's popover + overlay so the tour
 * matches MemDiver's light/dark theme variables. Idempotent: safe to call
 * multiple times.
 */
function ensureThemeStyle(): void {
  if (document.getElementById(STYLE_ELEMENT_ID)) return;
  const style = document.createElement("style");
  style.id = STYLE_ELEMENT_ID;
  style.textContent = `
  .${POPOVER_CLASS} {
    background-color: var(--md-bg-secondary) !important;
    color: var(--md-text-primary) !important;
    border: 1px solid var(--md-border) !important;
    box-shadow: 0 4px 20px rgba(0, 0, 0, 0.35) !important;
  }
  .${POPOVER_CLASS} .driver-popover-title {
    color: var(--md-text-bright) !important;
  }
  .${POPOVER_CLASS} .driver-popover-description {
    color: var(--md-text-primary) !important;
  }
  .${POPOVER_CLASS} .driver-popover-progress-text {
    color: var(--md-text-muted) !important;
  }
  .${POPOVER_CLASS} .driver-popover-close-btn {
    color: var(--md-text-muted) !important;
  }
  .${POPOVER_CLASS} .driver-popover-close-btn:hover {
    color: var(--md-text-bright) !important;
  }
  .${POPOVER_CLASS} .driver-popover-footer button {
    background-color: var(--md-bg-tertiary) !important;
    color: var(--md-text-primary) !important;
    border: 1px solid var(--md-border) !important;
    text-shadow: none !important;
  }
  .${POPOVER_CLASS} .driver-popover-footer button:hover {
    background-color: var(--md-bg-hover) !important;
  }
  .${POPOVER_CLASS} .driver-popover-arrow-side-left {
    border-left-color: var(--md-bg-secondary) !important;
  }
  .${POPOVER_CLASS} .driver-popover-arrow-side-right {
    border-right-color: var(--md-bg-secondary) !important;
  }
  .${POPOVER_CLASS} .driver-popover-arrow-side-top {
    border-top-color: var(--md-bg-secondary) !important;
  }
  .${POPOVER_CLASS} .driver-popover-arrow-side-bottom {
    border-bottom-color: var(--md-bg-secondary) !important;
  }
  `;
  document.head.appendChild(style);
}

function prefersReducedMotion(): boolean {
  if (typeof window === "undefined" || !window.matchMedia) return false;
  return window.matchMedia("(prefers-reduced-motion: reduce)").matches;
}

function resolveTarget(step: TourStep): Element | null {
  if (!step.target) return null;
  // Prefer data-tour-id lookup; fall back to CSS selector.
  const byAttr = document.querySelector(`[data-tour-id="${step.target}"]`);
  if (byAttr) return byAttr;
  try {
    return document.querySelector(step.target);
  } catch {
    return null;
  }
}

type Side = "top" | "right" | "bottom" | "left" | "over";

function placementToSide(step: TourStep): Side {
  const p = step.placement;
  if (!p || p === "center") return "over";
  return p;
}

export function TourRenderer() {
  const {
    activeTour,
    currentStep,
    activeStepIndex,
    advance,
    complete,
    dismiss,
    markSeen,
  } = useTourController();

  const driverRef = useRef<Driver | null>(null);
  const waitTimerRef = useRef<number | null>(null);
  // Synced from the effect body and read by the render-step effect. Holds the
  // "tearing down" flag so onDestroyed can distinguish self-initiated destroy
  // (our cleanup) from external destroy (overlay/Esc click).
  const tearingDownRef = useRef(false);

  const tourId = activeTour?.id ?? null;

  // Instance lifecycle: create once per tour, destroy on tour end. Keyed only
  // on the tour id (primitive) so step advances don't recreate the instance.
  // Zustand actions are stable — intentionally omitted from deps so unrelated
  // re-renders never run this effect.
  useEffect(() => {
    if (!tourId || !activeTour) return;
    ensureThemeStyle();
    tearingDownRef.current = false;

    const version = activeTour.version;
    const instance = driver({
      animate: !prefersReducedMotion(),
      allowClose: true,
      overlayOpacity: 0.55,
      popoverClass: POPOVER_CLASS,
      showButtons: ["next", "close"],
      smoothScroll: true,
      onDestroyed: () => {
        if (tearingDownRef.current) return;
        markSeen(tourId, version, false);
        dismiss();
      },
    });
    driverRef.current = instance;

    return () => {
      tearingDownRef.current = true;
      if (waitTimerRef.current !== null) {
        window.clearInterval(waitTimerRef.current);
        waitTimerRef.current = null;
      }
      instance.destroy();
      driverRef.current = null;
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [tourId]);

  // Step rendering: call highlight() on the live instance whenever the step
  // changes. Does NOT recreate the driver instance.
  useEffect(() => {
    const instance = driverRef.current;
    if (!instance || !activeTour || !currentStep) return;

    if (waitTimerRef.current !== null) {
      window.clearInterval(waitTimerRef.current);
      waitTimerRef.current = null;
    }

    const isLast = activeStepIndex === activeTour.steps.length - 1;
    const tId = activeTour.id;
    const tVersion = activeTour.version;

    const showStep = (): void => {
      const element = resolveTarget(currentStep);
      const side = placementToSide(currentStep);
      const step: DriveStep = {
        element: element ?? undefined,
        popover: {
          title: currentStep.title,
          description: currentStep.body,
          side: element ? side : "over",
          align: "center",
          showButtons: ["next", "close"],
          nextBtnText: isLast ? "Done" : "Next",
          doneBtnText: "Done",
          onNextClick: () => {
            if (isLast) {
              markSeen(tId, tVersion, true);
              complete();
            } else {
              advance();
            }
          },
          onCloseClick: () => {
            markSeen(tId, tVersion, false);
            dismiss();
          },
        },
      };
      instance.highlight(step);
    };

    const requireAction = currentStep.requireAction;
    if (requireAction && !requireAction.predicate()) {
      const hintStep: DriveStep = {
        element: resolveTarget(currentStep) ?? undefined,
        popover: {
          title: currentStep.title,
          description: `${currentStep.body}\n\n${requireAction.description}`,
          side: "over",
          align: "center",
          showButtons: ["close"],
          onCloseClick: () => {
            markSeen(tId, tVersion, false);
            dismiss();
          },
        },
      };
      instance.highlight(hintStep);
      waitTimerRef.current = window.setInterval(() => {
        if (requireAction.predicate()) {
          if (waitTimerRef.current !== null) {
            window.clearInterval(waitTimerRef.current);
            waitTimerRef.current = null;
          }
          showStep();
        }
      }, WAIT_POLL_MS);
    } else {
      showStep();
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [tourId, activeStepIndex]);

  return null;
}

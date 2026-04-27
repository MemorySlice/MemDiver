/**
 * Track the pixel width of a DOM element via ResizeObserver so SVG
 * charts can size themselves responsively. Returns a ref to attach to
 * the container plus the observed width (clamped to a minimum floor).
 *
 * Each hand-rolled SVG chart (EntropyChart, VarianceMap, VasChart,
 * SurvivorCurve) uses this to avoid duplicating the observer plumbing.
 */
import { useEffect, useRef, useState, type RefObject } from "react";

export interface UseContainerWidthOptions {
  /** Initial width returned before the first observer callback. */
  initialWidth?: number;
  /** Floor for the reported width; narrower content stays usable. */
  minWidth?: number;
}

export function useContainerWidth<T extends HTMLElement = HTMLDivElement>(
  options: UseContainerWidthOptions = {},
): [RefObject<T | null>, number] {
  const { initialWidth = 600, minWidth = 280 } = options;
  const ref = useRef<T | null>(null);
  const [width, setWidth] = useState<number>(initialWidth);

  useEffect(() => {
    if (typeof ResizeObserver === "undefined") return;
    const el = ref.current;
    if (!el) return;
    const ro = new ResizeObserver((entries) => {
      for (const entry of entries) {
        const w = entry.contentRect.width;
        if (w > 0) setWidth(Math.max(minWidth, Math.floor(w)));
      }
    });
    ro.observe(el);
    return () => ro.disconnect();
  }, [minWidth]);

  return [ref, width];
}

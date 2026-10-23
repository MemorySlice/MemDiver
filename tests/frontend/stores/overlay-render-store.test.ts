import { beforeEach, describe, expect, it } from "vitest";

import {
  DEFAULT_OVERLAY_RENDER_MODE,
  effectiveOverlayRenderMode,
  OVERLAY_RENDER_MODES,
  overlayRenderModeAvailable,
  useOverlayRenderStore,
} from "@/stores/overlay-render-store";

/**
 * The mode is a view preference, so the things worth pinning are the boring
 * ones: what a fresh viewer opens on, that a choice actually sticks, and that
 * tearing the workspace down does not leave the next selection painted in a
 * mode nobody chose for it.
 */

beforeEach(() => {
  useOverlayRenderStore.getState().reset();
});

describe("overlay render store", () => {
  /**
   * `class` is the reading the BACKEND consensus computed; the other two are
   * client-side re-descriptions of the same window. Opening on one of those
   * would show a colour the consensus never produced.
   */
  it("defaults to the consensus-class reading", () => {
    expect(useOverlayRenderStore.getState().renderMode).toBe("class");
    expect(DEFAULT_OVERLAY_RENDER_MODE).toBe("class");
  });

  it("keeps whichever mode was chosen", () => {
    for (const mode of OVERLAY_RENDER_MODES) {
      useOverlayRenderStore.getState().setRenderMode(mode);
      expect(useOverlayRenderStore.getState().renderMode).toBe(mode);
    }
  });

  it("returns to the default on reset", () => {
    useOverlayRenderStore.getState().setRenderMode("glyph");
    expect(useOverlayRenderStore.getState().renderMode).toBe("glyph");

    useOverlayRenderStore.getState().reset();

    expect(useOverlayRenderStore.getState().renderMode).toBe("class");
  });

  it("names exactly the four modes the switch offers", () => {
    expect([...OVERLAY_RENDER_MODES]).toEqual(["class", "variants", "glyph", "heap"]);
  });
});

describe("heap render mode availability", () => {
  it("is available only when the window's heap status is ok", () => {
    expect(overlayRenderModeAvailable("heap", "ok")).toBe(true);
    for (const status of [null, "no_va_coordinate", "empty_consensus", "error"]) {
      expect(overlayRenderModeAvailable("heap", status)).toBe(false);
    }
  });

  it("never gates the three heap-independent modes", () => {
    for (const mode of ["class", "variants", "glyph"] as const) {
      expect(overlayRenderModeAvailable(mode, null)).toBe(true);
      expect(effectiveOverlayRenderMode(mode, "error")).toBe(mode);
    }
  });

  it("falls back to the default while heap roles are unusable, without forgetting the choice", () => {
    useOverlayRenderStore.getState().setRenderMode("heap");
    expect(effectiveOverlayRenderMode("heap", "no_va_coordinate")).toBe("class");
    expect(effectiveOverlayRenderMode("heap", "ok")).toBe("heap");
    expect(useOverlayRenderStore.getState().renderMode).toBe("heap");
  });
});

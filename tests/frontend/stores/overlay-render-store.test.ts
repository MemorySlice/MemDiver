import { beforeEach, describe, expect, it } from "vitest";

import {
  DEFAULT_OVERLAY_RENDER_MODE,
  OVERLAY_RENDER_MODES,
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

  it("names exactly the three modes the switch offers", () => {
    expect([...OVERLAY_RENDER_MODES]).toEqual(["class", "variants", "glyph"]);
  });
});

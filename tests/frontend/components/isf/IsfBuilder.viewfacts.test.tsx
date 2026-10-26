import { beforeEach, describe, expect, it, vi } from "vitest";
import { render, screen, waitFor } from "@testing-library/react";
import "@testing-library/jest-dom/vitest";
import "@/i18n";

import { useImageStore } from "@/stores/image-store";

const active = vi.hoisted(() => ({ path: "" }));
vi.mock("@/hooks/useActiveDump", () => ({ useActiveDump: () => ({ path: active.path, name: "v" }) }));
const SHA = "cd".repeat(32);
// The `view` of `useViewContext` is the preview's `view_block`, as the backend sends it.
vi.mock("@/components/vol3/useViewContext", () => ({
  useViewContext: () => ({
    ctx: {}, loadIntervals: async () => null,
    view: active.path ? {
      kind: "kernel", pid: null, capture_id: SHA, view_path: active.path, has_profile: true,
      profile: { origin: "explicit", sha256: null, isf_name: "p.json" }, paging: null,
      image_path: "/cases/a/img.lime", image_sha256: SHA,
    } : null,
  }),
}));
const api = vi.hoisted(() => ({ listIsfDrafts: vi.fn() }));
vi.mock("@/api/isf", async (orig) => ({ ...(await orig<typeof import("@/api/isf")>()), ...api }));
vi.mock("@/api/annotations", async (orig) => ({ ...(await orig<typeof import("@/api/annotations")>()),
  listIsfTries: vi.fn(async () => ({ entries: [], count: 0 })) }));
vi.mock("@/components/isf/ProbeRunner", () => ({
  ProbeRunner: ({ imagePath }: { imagePath: string }) => <div data-testid="probe-image">{imagePath}</div>,
}));

const { IsfBuilder } = await import("@/components/isf/IsfBuilder");

beforeEach(() => {
  localStorage.clear();
  useImageStore.getState().reset();
  api.listIsfDrafts.mockResolvedValue({ capture_id: SHA, drafts: [], count: 0 });
});

describe("IsfBuilder takes the image from the active view's facts", () => {
  it("prefers the view's image path and capture id over the image store", async () => {
    active.path = "/cases/a/views/kernel.mdview";
    useImageStore.setState({ imagePath: "/elsewhere/other.lime", caseDir: "/cases/a" });
    render(<IsfBuilder />);
    expect(screen.getByTestId("probe-image")).toHaveTextContent("/cases/a/img.lime");
    expect(screen.queryByTestId("isf-image-path")).toBeNull();
    await waitFor(() => expect(api.listIsfDrafts).toHaveBeenCalledWith({ caseDir: "/cases/a", captureId: SHA }));
  });

  it("falls back to the image store when the active dump is not an image view", () => {
    active.path = "";
    useImageStore.setState({ imagePath: "/store/img.lime" });
    render(<IsfBuilder />);
    expect(screen.getByTestId("probe-image")).toHaveTextContent("/store/img.lime");
  });
});

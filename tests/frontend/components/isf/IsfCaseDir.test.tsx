import { beforeEach, describe, expect, it, vi } from "vitest";
import { render, screen, fireEvent } from "@testing-library/react";
import "@testing-library/jest-dom/vitest";
import "@/i18n";

import { caseDirOfView } from "@/components/isf/case-dir";
import { useImageStore } from "@/stores/image-store";

const active = vi.hoisted(() => ({ path: "" }));
vi.mock("@/hooks/useActiveDump", () => ({ useActiveDump: () => ({ path: active.path, name: "v" }) }));
vi.mock("@/components/vol3/useViewContext", () => ({ useViewContext: () => ({ view: { capture_id: "cap1" } }) }));
const api = vi.hoisted(() => ({ listIsfDrafts: vi.fn() }));
vi.mock("@/api/isf", async (orig) => ({ ...(await orig<typeof import("@/api/isf")>()), ...api }));
vi.mock("@/api/annotations", async (orig) => ({ ...(await orig<typeof import("@/api/annotations")>()),
  listIsfTries: vi.fn(async () => ({ entries: [], count: 0 })) }));

const { IsfBuilder } = await import("@/components/isf/IsfBuilder");

beforeEach(() => {
  localStorage.clear();
  active.path = "";
  useImageStore.getState().reset();
  useImageStore.setState({ imagePath: "/img.lime" });
  api.listIsfDrafts.mockResolvedValue({ capture_id: "cap1", drafts: [], count: 0 });
});

describe("ISF case directory prefill", () => {
  it("derives the case from <case>/views/<name>.mdview only", () => {
    expect(caseDirOfView("/cases/a/views/kernel.mdview")).toBe("/cases/a");
    expect(caseDirOfView("/elsewhere/kernel.mdview")).toBe("");
  });

  it("prefills from the open view's case", () => {
    active.path = "/cases/a/views/kernel.mdview";
    render(<IsfBuilder />);
    expect(screen.getByTestId("isf-case-dir")).toHaveValue("/cases/a");
  });

  it("leaves it empty for a view outside a case layout", () => {
    active.path = "/tmp/kernel.mdview";
    render(<IsfBuilder />);
    expect(screen.getByTestId("isf-case-dir")).toHaveValue("");
  });

  it("remembers the last edit per capture and restores it", () => {
    const first = render(<IsfBuilder />);
    fireEvent.change(screen.getByTestId("isf-case-dir"), { target: { value: "/my/case" } });
    expect(api.listIsfDrafts).not.toHaveBeenCalledWith({ caseDir: "/my/case", captureId: "cap1" });
    fireEvent.blur(screen.getByTestId("isf-case-dir"));
    expect(localStorage.getItem("memdiver.isf.caseDir.cap1")).toBe("/my/case");
    first.unmount();
    useImageStore.setState({ caseDir: "" });
    render(<IsfBuilder />);
    expect(screen.getByTestId("isf-case-dir")).toHaveValue("/my/case");
  });

  it("lists on commit only, and shows case.not_found inline rather than as an error", async () => {
    const { ApiError } = await import("@/api/client");
    api.listIsfDrafts.mockRejectedValue(new ApiError(404, JSON.stringify({ error: "x", code: "case.not_found" })));
    render(<IsfBuilder />);
    api.listIsfDrafts.mockClear();
    fireEvent.change(screen.getByTestId("isf-case-dir"), { target: { value: "/new" } });
    expect(api.listIsfDrafts).not.toHaveBeenCalled();
    fireEvent.keyDown(screen.getByTestId("isf-case-dir"), { key: "Enter" });
    expect(await screen.findByTestId("isf-drafts-nocase")).toBeInTheDocument();
    expect(screen.queryByTestId("isf-drafts-error")).toBeNull();
  });
});

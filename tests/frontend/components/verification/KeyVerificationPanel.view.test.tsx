import { describe, it, expect, vi, beforeEach } from "vitest";
import { act, render, screen, fireEvent, waitFor } from "@testing-library/react";
import "@testing-library/jest-dom/vitest";
import "@/i18n";

/**
 * The Verify-Key panel pre-fills the hex cursor, an offset in the viewer's
 * CURRENT view, so it must send that view; otherwise the backend reads the
 * candidate at the same number in its default view (another byte on a gcore).
 * A typed offset follows the viewer too whenever the dump has several distinct
 * views; a single-view (raw-only) dump sends no view at all.
 */

const verifyKey = vi.fn();
vi.mock("@/api/client", () => ({
  verifyKey: (...a: unknown[]) => verifyKey(...a),
  exportKeylog: vi.fn(),
  getPageStates: vi.fn(() => new Promise(() => {})),
}));
vi.mock("@/hooks/useActiveDump", () => ({
  useActiveDump: () => ({ path: "/core", name: "planted.core" }),
}));

import { KeyVerificationPanel } from "@/components/verification/KeyVerificationPanel";
import { useHexStore } from "@/stores/hex-store";
import { useVerificationStore } from "@/stores/verification-store";

beforeEach(() => {
  verifyKey.mockReset();
  localStorage.clear();
  useVerificationStore.getState().reset();
  useHexStore.getState().reset();
  useHexStore.setState({ viewMode: "raw" });
  useHexStore.getState().setDumpPath("/core", 8320, "raw");
  useHexStore.getState().setAvailableViews(["raw", "vas"], "gcore");
});

async function verifyAtCursor(): Promise<void> {
  fireEvent.change(screen.getByTestId("verify-ciphertext-input"), { target: { value: "00".repeat(16) } });
  fireEvent.click(screen.getByTestId("verify-submit-btn"));
  await waitFor(() => expect(verifyKey).toHaveBeenCalled());
}

describe("KeyVerificationPanel view", () => {
  it("sends the cursor offset with the viewer's current (data-driven) view", async () => {
    verifyKey.mockResolvedValue({ verified: true, offset: 0x1100, cipher: "AES-128-CBC", key_hex: "73" });
    act(() => {
      useHexStore.getState().showView("vas");
      useHexStore.getState().setCursor(0x1100);
    });
    render(<KeyVerificationPanel />);
    await verifyAtCursor();
    expect(verifyKey.mock.calls[0][0]).toMatchObject({ dump_path: "/core", offset: 0x1100, view: "vas" });
  });

  it("sends raw when the viewer shows raw", async () => {
    verifyKey.mockResolvedValue({ verified: false, offset: 0x1b0, cipher: "AES-128-CBC", key_hex: null });
    act(() => useHexStore.getState().setCursor(0x1b0));
    render(<KeyVerificationPanel />);
    await verifyAtCursor();
    expect(verifyKey.mock.calls[0][0]).toMatchObject({ offset: 0x1b0, view: "raw" });
  });

  it("bookmarks a verified key in the view it was verified in", async () => {
    verifyKey.mockResolvedValue({ verified: true, offset: 0x1100, cipher: "AES-128-CBC", key_hex: "73" });
    act(() => {
      useHexStore.getState().showView("vas");
      useHexStore.getState().setCursor(0x1100);
    });
    render(<KeyVerificationPanel />);
    await verifyAtCursor();
    act(() => useHexStore.getState().showView("raw")); // the viewer moved on
    fireEvent.click(await screen.findByText("Bookmark offset"));
    expect(useHexStore.getState().bookmarks).toEqual([
      expect.objectContaining({ offset: 0x1100, view: "vas" }),
    ]);
  });

  it("sends the viewer's current view for a typed offset on a multi-view dump", async () => {
    verifyKey.mockResolvedValue({ verified: true, offset: 0, cipher: "AES-128-CBC", key_hex: "73" });
    act(() => {
      useHexStore.getState().showView("vas");
      useHexStore.getState().setCursor(0x1100);
    });
    render(<KeyVerificationPanel />);
    fireEvent.change(screen.getByTestId("verify-offset-input"), { target: { value: "0" } });
    await verifyAtCursor();
    expect(verifyKey.mock.calls[0][0]).toMatchObject({ offset: 0, view: "vas" });
  });

  it("bookmarks a typed-offset key in the view that was sent", async () => {
    verifyKey.mockResolvedValue({ verified: true, offset: 0, cipher: "AES-128-CBC", key_hex: "73" });
    act(() => useHexStore.getState().showView("vas"));
    render(<KeyVerificationPanel />);
    fireEvent.change(screen.getByTestId("verify-offset-input"), { target: { value: "0" } });
    await verifyAtCursor();
    act(() => useHexStore.getState().showView("raw"));
    fireEvent.click(await screen.findByText("Bookmark offset"));
    expect(useHexStore.getState().bookmarks).toEqual([
      expect.objectContaining({ offset: 0, view: "vas" }),
    ]);
  });

  it("labels the offset input with the viewer's current view", () => {
    act(() => useHexStore.getState().showView("vas"));
    render(<KeyVerificationPanel />);
    expect(screen.getByTestId("verify-offset-view")).toHaveTextContent("in VAS view");
    act(() => useHexStore.getState().showView("raw"));
    expect(screen.getByTestId("verify-offset-view")).toHaveTextContent("in raw view");
  });

  it("sends no view and shows no label for a typed offset on a raw-only dump", async () => {
    act(() => {
      useHexStore.getState().reset();
      useHexStore.getState().setDumpPath("/core", 8320, "raw");
      useHexStore.getState().setAvailableViews(["raw"], "raw");
    });
    verifyKey.mockResolvedValue({ verified: false, offset: 0, cipher: "AES-128-CBC", key_hex: null });
    render(<KeyVerificationPanel />);
    expect(screen.queryByTestId("verify-offset-view")).toBeNull();
    fireEvent.change(screen.getByTestId("verify-offset-input"), { target: { value: "0" } });
    await verifyAtCursor();
    expect(verifyKey.mock.calls[0][0]).toMatchObject({ offset: 0 });
    expect(verifyKey.mock.calls[0][0].view).toBeUndefined();
  });
});

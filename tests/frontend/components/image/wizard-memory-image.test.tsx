import { beforeEach, describe, expect, it, vi } from "vitest";
import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import "@testing-library/jest-dom/vitest";
import "@/i18n";

const getPathInfo = vi.hoisted(() => vi.fn());
vi.mock("@/api/client", async (orig) => ({
  ...(await orig<typeof import("@/api/client")>()),
  getPathInfo,
}));
vi.mock("@/api/algorithms", () => ({
  getAlgorithmAvailability: vi.fn(async () => ({ availability: {} })),
}));
vi.mock("@/components/wizard/FileBrowser", () => ({ FileBrowser: () => null }));

const { ThemeProvider } = await import("@/providers/ThemeProvider");
const { Wizard } = await import("@/components/wizard/Wizard");
const { useAppStore } = await import("@/stores/app-store");
const { useImageStore } = await import("@/stores/image-store");
const { useDumpStore } = await import("@/stores/dump-store");

const renderWizard = () => render(<ThemeProvider><Wizard /></ThemeProvider>);

beforeEach(() => {
  getPathInfo.mockReset();
  useImageStore.getState().reset();
  useDumpStore.getState().clearAll();
  useAppStore.setState({ inputPath: "/img.lime", analysisApproach: "auto", wizardStep: 0, appView: "wizard", wizardComplete: false });
});

describe("wizard Memory image choice", () => {
  it("routes an image file to the Image panel without the dump flow", async () => {
    getPathInfo.mockResolvedValue({ exists: true, is_file: true, is_directory: false });
    renderWizard();
    fireEvent.click(screen.getByTestId("wizard-memory-image"));
    fireEvent.click(screen.getByRole("button", { name: "Open Image panel" }));
    await waitFor(() => expect(useAppStore.getState().appView).toBe("workspace"));
    expect(useImageStore.getState().imagePath).toBe("/img.lime");
    expect(useDumpStore.getState().dumps).toHaveLength(0);
    // Regression: the image path must not become a dataset root (that fired
    // /api/dataset/runs?root=<image> → 404 and "Failed to load runs").
    expect(useAppStore.getState().inputMode).toBe("file");
    expect(useAppStore.getState().inputPath).toBe("");
    // ...and the first view opened must not trigger the wizard's auto analysis run.
    expect(useAppStore.getState().analysisApproach).toBe("inspect");
  });

  it("rejects a directory and stays in the wizard", async () => {
    getPathInfo.mockResolvedValue({ exists: true, is_file: false, is_directory: true });
    renderWizard();
    fireEvent.click(screen.getByTestId("wizard-memory-image"));
    fireEvent.click(screen.getByRole("button", { name: "Open Image panel" }));
    expect(await screen.findByText("This path is not a file.")).toBeInTheDocument();
    expect(useImageStore.getState().imagePath).toBe("");
  });

  it("keeps the normal flow when the choice is off", async () => {
    getPathInfo.mockResolvedValue({ exists: true, is_file: true, is_directory: false, dump_count: 1 });
    renderWizard();
    fireEvent.click(screen.getByRole("button", { name: "Next" }));
    await waitFor(() => expect(useAppStore.getState().wizardStep).toBe(1));
    expect(useImageStore.getState().imagePath).toBe("");
  });
});

import { beforeEach, describe, expect, it, vi } from "vitest";
import { fireEvent, render, screen } from "@testing-library/react";
import "@testing-library/jest-dom/vitest";
import "@/i18n";

import { useConsensusStore } from "@/stores/consensus-store";
import { useDumpStore } from "@/stores/dump-store";

const hook = vi.hoisted(() => ({ error: null as string | null, retry: vi.fn() }));
vi.mock("@/hooks/useVisibleWindowError", () => ({
  useVisibleWindowError: () => ({ error: hook.error, failedChunkCount: 1, retry: hook.retry }),
}));

const { WindowErrorBanner } = await import("@/components/hex/WindowErrorBanner");

const PATHS = ["/a.msl", "/b.msl"];
const runConsensus = vi.fn(async () => {});

beforeEach(() => {
  runConsensus.mockClear();
  hook.retry.mockClear();
  useConsensusStore.setState({ runConsensus, runInFlight: false });
});

describe("WindowErrorBanner rebuild", () => {
  it("offers Rebuild for a vanished consensus and re-runs the same request", () => {
    hook.error = "Some bytes in this window could not be loaded: No consensus computed yet";
    render(<WindowErrorBanner testIdPrefix="multi-hex" firstRow={0} lastRow={3} rebuildPaths={PATHS} />);
    fireEvent.click(screen.getByTestId("multi-hex-window-rebuild"));
    expect(runConsensus).toHaveBeenCalledWith(PATHS, useDumpStore.getState().aslrNormalize);
  });

  it("offers no Rebuild for other failures or without paths", () => {
    hook.error = "Internal Server Error";
    const { rerender } = render(
      <WindowErrorBanner testIdPrefix="multi-hex" firstRow={0} lastRow={3} rebuildPaths={PATHS} />,
    );
    expect(screen.queryByTestId("multi-hex-window-rebuild")).toBeNull();
    hook.error = "No consensus computed yet";
    rerender(<WindowErrorBanner testIdPrefix="multi-hex" firstRow={0} lastRow={3} />);
    expect(screen.queryByTestId("multi-hex-window-rebuild")).toBeNull();
    expect(screen.getByTestId("multi-hex-window-retry")).toBeInTheDocument();
  });
});

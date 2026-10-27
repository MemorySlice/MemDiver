import { render, screen, waitFor } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import "@/i18n";
import { HexOverlay } from "@/components/hex/HexOverlay";

afterEach(() => vi.unstubAllGlobals());

describe("HexOverlay file-offset label", () => {
  it("labels the gutter as a file offset with an explanatory tooltip", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async () => ({
        ok: true,
        json: async () => ({ bytes: "AAECAw==", file_size: 4 }),
      })),
    );
    render(<HexOverlay pathA="/d/a.raw" pathB="/d/b.raw" />);
    const label = await screen.findByTestId("overlay-file-offset-label");
    await waitFor(() => expect(label.textContent).toContain("File offset"));
    expect(label.getAttribute("title")).toMatch(/not a memory address/);
  });
});

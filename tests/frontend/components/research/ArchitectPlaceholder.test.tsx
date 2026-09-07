import { afterEach, beforeEach, describe, it, expect, vi } from "vitest";
import { fireEvent, render, screen, waitFor } from "@testing-library/react";
// See ErrorBoundary.test.tsx: needed so `tsc -b` sees jest-dom's augmentation.
import "@testing-library/jest-dom/vitest";
import "@/i18n";

import type { CheckStaticResult } from "@/api/client";
import type { DumpEntry } from "@/stores/dump-store";
import { useDumpStore } from "@/stores/dump-store";
import { useHexStore } from "@/stores/hex-store";

/**
 * Only the network call is mocked. The store lookup that feeds the request
 * body stays REAL, so an encrypted `.msl` reaching `/api/architect/check-static`
 * without its key would fail here — a mock of the whole flow would not.
 */
const { checkStaticMock } = vi.hoisted(() => ({ checkStaticMock: vi.fn() }));

vi.mock("@/api/client", async (importOriginal) => ({
  ...(await importOriginal<typeof import("@/api/client")>()),
  checkStatic: checkStaticMock,
}));

const { ArchitectPlaceholder } = await import(
  "@/components/research/ArchitectPlaceholder"
);

const RESULT: CheckStaticResult = {
  static_mask: [true, false],
  reference_hex: "4142",
  static_ratio: 0.5,
  anchors: [{ start: 0, length: 1 }],
};

function dump(id: string, path: string, over: Partial<DumpEntry> = {}): DumpEntry {
  return {
    id,
    path,
    name: path,
    size: 4096,
    format: "msl",
    sameProcess: true,
    ...over,
  };
}

/** Two dumps + a 2-byte selection — the minimum Step 1 accepts. */
function seedWorkspace(dumps: DumpEntry[]) {
  useDumpStore.setState({ dumps });
  useHexStore.setState({ selection: { anchor: 0, active: 1 } });
}

beforeEach(() => {
  checkStaticMock.mockReset();
  checkStaticMock.mockResolvedValue(RESULT);
  useDumpStore.setState({ dumps: [] });
  useHexStore.setState({ selection: null, highlightedRegions: [] });
});

afterEach(() => {
  useDumpStore.setState({ dumps: [] });
  useHexStore.setState({ selection: null, highlightedRegions: [] });
});

async function clickCheckStatic() {
  render(<ArchitectPlaceholder />);
  fireEvent.click(screen.getByRole("button", { name: "Check Static" }));
  await waitFor(() => expect(checkStaticMock).toHaveBeenCalledTimes(1));
  return checkStaticMock.mock.calls[0][0] as Record<string, unknown>;
}

describe("ArchitectPlaceholder static check — key material", () => {
  it("carries the first dump's key material so an encrypted .msl is reachable", async () => {
    seedWorkspace([
      dump("a", "/d/a.msl", { keyMaterial: { passphrase: "hunter2" } }),
      dump("b", "/d/b.msl"),
    ]);

    const body = await clickCheckStatic();

    expect(body).toEqual({
      dump_paths: ["/d/a.msl", "/d/b.msl"],
      offset: 0,
      length: 2,
      passphrase: "hunter2",
    });
  });

  it("forwards key_hex and kem_key_hex the same way", async () => {
    seedWorkspace([
      dump("a", "/d/a.msl", {
        keyMaterial: { key_hex: "00ff", kem_key_hex: "beef" },
      }),
      dump("b", "/d/b.msl"),
    ]);

    const body = await clickCheckStatic();

    expect(body).toMatchObject({ key_hex: "00ff", kem_key_hex: "beef" });
  });

  it("sends an unchanged body when no dump carries key material", async () => {
    seedWorkspace([dump("a", "/d/a.raw", { format: "raw" }), dump("b", "/d/b.raw", { format: "raw" })]);

    const body = await clickCheckStatic();

    // Byte-identical to what shipped before the key-material widening: no
    // `passphrase: undefined` keys that would alter the serialized JSON.
    expect(body).toEqual({
      dump_paths: ["/d/a.raw", "/d/b.raw"],
      offset: 0,
      length: 2,
    });
    expect(JSON.stringify(body)).toBe(
      '{"dump_paths":["/d/a.raw","/d/b.raw"],"offset":0,"length":2}',
    );
  });
});

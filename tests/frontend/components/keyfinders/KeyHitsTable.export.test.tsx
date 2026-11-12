import { beforeEach, describe, expect, it, vi } from "vitest";
import { fireEvent, render, screen, within } from "@testing-library/react";
import "@testing-library/jest-dom/vitest";
import "@/i18n";

import type { KeyHitRow } from "@/api/keyfinders";

vi.mock("@/api/vol3", async (orig) => ({
  ...(await orig<typeof import("@/api/vol3")>()), getVol3PluginDir: vi.fn(async () => ({ path: "/r" })),
}));
const { KeyHitsTable } = await import("@/components/keyfinders/KeyHitsTable");

const KEY = "00112233445566778899aabbccddeeff";
const hit = (key: string | null): KeyHitRow => ({
  finder: "aes_schedule", label: "aes128_schedule", addr: 4096, space: "va", length: 176, confidence: 1,
  metadata: key ? { key_hex: key } : {}, va: 4096, vas_offset: 0, heap: null, region: null,
});
const onRowClick = vi.fn();

beforeEach(() => onRowClick.mockReset());

describe("KeyHitsTable export", () => {
  it("offers the export on a hit carrying its key, prefilled with the scanned dump and that key", () => {
    render(<KeyHitsTable rows={[hit(KEY), hit(null)]} active={null} onRowClick={onRowClick} onVerify={vi.fn()}
      dumpPath="/d/a.msl" />);
    const rows = screen.getAllByTestId("keyfinders-row");
    expect(within(rows[1]).queryByTestId("keyfinders-export")).toBeNull();
    fireEvent.click(within(rows[0]).getByTestId("keyfinders-export"));
    expect(onRowClick).not.toHaveBeenCalled();
    const dialog = screen.getByRole("dialog");
    expect((within(dialog).getByTestId("synth-dump-path") as HTMLInputElement).value).toBe("/d/a.msl");
    expect((within(dialog).getByTestId("synth-dump-secret") as HTMLInputElement).value).toBe(KEY);
    fireEvent.click(within(dialog).getByTestId("synth-dump-add"));
    expect(onRowClick).not.toHaveBeenCalled();
  });

  it("offers no export without a dump path", () => {
    render(<KeyHitsTable rows={[hit(KEY)]} active={null} onRowClick={onRowClick} onVerify={vi.fn()} />);
    expect(screen.queryByTestId("keyfinders-export")).toBeNull();
  });
});

import { beforeEach, describe, expect, it, vi } from "vitest";
import { fireEvent, render, screen, within } from "@testing-library/react";
import "@testing-library/jest-dom/vitest";
import "@/i18n";

import type { DumpKeyLocation, LocateKeyResponse } from "@/api/locate-key";
import { useDumpStore } from "@/stores/dump-store";
import { useImageStore } from "@/stores/image-store";

const locate = vi.hoisted(() => ({ locateKey: vi.fn() }));
vi.mock("@/api/locate-key", async (orig) => ({ ...(await orig<typeof import("@/api/locate-key")>()), ...locate }));
const vol3 = vi.hoisted(() => ({ synthesizeVol3Plugin: vi.fn(), getVol3PluginDir: vi.fn() }));
vi.mock("@/api/vol3", async (orig) => ({ ...(await orig<typeof import("@/api/vol3")>()), ...vol3 }));

const { LocatedKeysSection } = await import("@/components/research/LocatedKeysSection");
const { ArchitectPlaceholder } = await import("@/components/research/ArchitectPlaceholder");

const KEY = "ee2813d66e00112233445566778899aabbccddeeff00112233445566778899aa";
const A = "/data/run_0001/memslicer.msl";
const B = "/data/run_0001/gdb_raw.bin";
const C = "/data/run_0001/other.bin";

const row = (dump_path: string, present: boolean | null, first: number | null): DumpKeyLocation => ({
  dump_path, name: dump_path.split("/").pop()!, format_name: "msl", size_for_view: 1, status: "searched",
  present, first_offset: first, hit_count: present ? 2 : 0, offsets: first === null ? [] : [first],
  offsets_truncated: false, detail: "",
});
const RESPONSE = {
  verdict: "found", dumps_present: 2, dumps_searched: 3,
  dumps: [row(A, true, 0x8020), row(B, false, null), row(C, true, 0x10)],
} as unknown as LocateKeyResponse;

beforeEach(() => {
  locate.locateKey.mockReset();
  vol3.getVol3PluginDir.mockResolvedValue({ path: "/repo/vol3plugins" });
  useDumpStore.setState({ dumps: [] });
  useImageStore.getState().setCaseDir("my-case");
});

describe("LocatedKeysSection", () => {
  it("locates a typed key (masked) and lists where it is", async () => {
    locate.locateKey.mockResolvedValue(RESPONSE);
    render(<LocatedKeysSection dumpPaths={[A, B, C]} />);
    const input = screen.getByTestId("locate-secret") as HTMLInputElement;
    expect(input.type).toBe("password");
    expect(screen.getByTestId("locate-run")).toBeDisabled();
    fireEvent.change(input, { target: { value: KEY } });
    expect(screen.getByTestId("locate-secret-mask")).toHaveTextContent("•••• (32 B)");
    fireEvent.click(screen.getByTestId("locate-run"));
    expect(await screen.findByTestId("locate-summary")).toHaveTextContent("Found in 2 of 3 searched dump(s).");
    expect(locate.locateKey).toHaveBeenCalledWith({ dump_paths: [A, B, C], secret_hex: KEY, allocator: "off" });
    const rows = screen.getAllByTestId("locate-row");
    expect(within(rows[0]).getByText("0x8020")).toBeInTheDocument();
    expect(within(rows[1]).queryByTestId("locate-export")).toBeNull();
    expect(document.body.textContent).not.toContain(KEY);
  });

  it("exports from a hit row: that dump first, the other holders after, the key prefilled", async () => {
    locate.locateKey.mockResolvedValue(RESPONSE);
    render(<LocatedKeysSection dumpPaths={[A, B, C]} />);
    fireEvent.change(screen.getByTestId("locate-secret"), { target: { value: KEY } });
    fireEvent.click(screen.getByTestId("locate-run"));
    const rows = await screen.findAllByTestId("locate-row");
    const exportButton = within(rows[2]).getByTestId("locate-export");
    expect(exportButton).toHaveTextContent("Export as Volatility 3 plugin");
    fireEvent.click(exportButton);
    const dialog = await screen.findByRole("dialog");
    const paths = within(dialog).getAllByTestId("synth-dump-path").map((i) => (i as HTMLInputElement).value);
    expect(paths).toEqual([C, A]);
    const secrets = within(dialog).getAllByTestId("synth-dump-secret").map((i) => (i as HTMLInputElement).value);
    expect(secrets).toEqual([KEY, ""]);
    expect((within(dialog).getByTestId("synth-case") as HTMLInputElement).value).toBe("my-case");
    expect(document.body.textContent).not.toContain(KEY);
  });

  it("shows a refused locate with its code", async () => {
    const { ApiError } = await import("@/api/client");
    locate.locateKey.mockRejectedValue(new ApiError(404, JSON.stringify({ error: "gone", code: "file.not_found" })));
    render(<LocatedKeysSection dumpPaths={[A]} />);
    fireEvent.change(screen.getByTestId("locate-secret"), { target: { value: KEY } });
    fireEvent.click(screen.getByTestId("locate-run"));
    expect(await screen.findByTestId("locate-error")).toHaveTextContent("file.not_found: gone");
  });

  it("is offered by the Architect even with a single dump", () => {
    useDumpStore.setState({ dumps: [{ id: "d", path: A, name: "m", size: 1, format: "msl", sameProcess: true }] });
    render(<ArchitectPlaceholder />);
    expect(screen.getByTestId("architect-empty")).toBeInTheDocument();
    expect(screen.getByTestId("located-keys")).toBeInTheDocument();
  });
});

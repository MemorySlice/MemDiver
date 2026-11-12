import { beforeEach, describe, expect, it, vi } from "vitest";
import { fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import "@testing-library/jest-dom/vitest";
import "@/i18n";

import { useDumpStore } from "@/stores/dump-store";
import { SYNTH } from "./synth-fixtures";

const api = vi.hoisted(() => ({
  listVol3Sources: vi.fn(), listVol3Fixtures: vi.fn(), synthesizeVol3Plugin: vi.fn(), getVol3PluginDir: vi.fn(),
}));
vi.mock("@/api/vol3", async (orig) => ({ ...(await orig<typeof import("@/api/vol3")>()), ...api }));
const { PluginEditor } = await import("@/components/vol3/PluginEditor");

beforeEach(() => {
  Object.values(api).forEach((m) => m.mockReset());
  api.listVol3Sources.mockResolvedValue({ sources: [], count: 0 });
  api.listVol3Fixtures.mockResolvedValue({ fixtures: [], count: 0 });
  api.getVol3PluginDir.mockResolvedValue({ path: "/r" });
  useDumpStore.setState({ dumps: [], activeDumpId: null });
});

describe("PluginEditor export", () => {
  it("opens the dialog on the context's dumps with the editor's case and refreshes the list after a stored plugin", async () => {
    useDumpStore.setState({ dumps: [
      { id: "a", path: "/d/a.msl", name: "a", size: 1, format: "msl", sameProcess: true },
      { id: "b", path: "/d/b.msl", name: "b", size: 1, format: "msl", sameProcess: true },
    ], activeDumpId: null });
    api.synthesizeVol3Plugin.mockResolvedValue(SYNTH);
    render(<PluginEditor viewPath="" caseDir="/case" running={false} onRun={vi.fn()} />);
    await waitFor(() => expect(api.listVol3Sources).toHaveBeenCalledTimes(1));
    fireEvent.click(screen.getByTestId("editor-export-plugin"));
    const dialog = screen.getByRole("dialog");
    expect(within(dialog).getAllByTestId("synth-dump-path").map((i) => (i as HTMLInputElement).value))
      .toEqual(["/d/a.msl", "/d/b.msl"]);
    expect((within(dialog).getByTestId("synth-case") as HTMLInputElement).value).toBe("/case");
    const secrets = within(dialog).getAllByTestId("synth-dump-secret");
    fireEvent.change(secrets[0], { target: { value: "aa" } });
    fireEvent.change(secrets[1], { target: { value: "bb" } });
    fireEvent.click(within(dialog).getByTestId("synth-submit"));
    await screen.findByTestId("synth-result");
    await waitFor(() => expect(api.listVol3Sources).toHaveBeenCalledTimes(2));
  });
});

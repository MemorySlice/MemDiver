import { beforeEach, describe, expect, it, vi } from "vitest";
import { fireEvent, render, screen } from "@testing-library/react";
import "@testing-library/jest-dom/vitest";
import "@/i18n";

import { useAppStore } from "@/stores/app-store";
import { useDumpStore } from "@/stores/dump-store";
import { EXEC, PLUGIN, RUN2 } from "./synth-fixtures";

const api = vi.hoisted(() => ({
  execVol3Plugin: vi.fn(), listVol3Plugins: vi.fn(), getVol3PluginDir: vi.fn(),
}));
vi.mock("@/api/vol3", async (orig) => ({ ...(await orig<typeof import("@/api/vol3")>()), ...api }));

const { Vol3ExecForm } = await import("@/components/vol3/Vol3ExecForm");
const { Vol3Panel } = await import("@/components/vol3/Vol3Panel");

beforeEach(() => {
  Object.values(api).forEach((m) => m.mockReset());
  api.listVol3Plugins.mockResolvedValue({ os_family: "linux", plugins: [], count: 0 });
  useDumpStore.setState({ dumps: [], activeDumpId: null });
});

describe("Vol3ExecForm", () => {
  it("runs a plugin by name under vol with dirs and shell-split args", async () => {
    api.execVol3Plugin.mockResolvedValue(EXEC);
    render(<Vol3ExecForm imagePath={RUN2} caseDir="" />);
    fireEvent.change(screen.getByTestId("vol3-exec-plugin"), { target: { value: PLUGIN } });
    fireEvent.change(screen.getByTestId("vol3-exec-plugin-dirs"), { target: { value: "/c/vol3/plugins\n" } });
    fireEvent.change(screen.getByTestId("vol3-exec-args"), { target: { value: "--oracle-sample '/d/run 2/cipher'" } });
    fireEvent.click(screen.getByTestId("vol3-exec-run"));
    await screen.findByTestId("synth-exec-result");
    expect(api.execVol3Plugin).toHaveBeenCalledWith({
      plugin: PLUGIN, image_path: RUN2, plugin_dirs: ["/c/vol3/plugins"], args: ["--oracle-sample", "/d/run 2/cipher"],
    });
    expect(screen.getAllByTestId("synth-exec-proven")).toHaveLength(2);
  });
});

describe("Vol3Panel with an .msl", () => {
  it("offers stock-vol exec and the export button instead of the .mdview hint", async () => {
    useAppStore.setState({ inputMode: "file" });
    const id = useDumpStore.getState().addDump({ path: RUN2, name: "memslicer.msl", size: 10, format: "msl" });
    useDumpStore.getState().setActiveDump(id);
    render(<Vol3Panel />);
    expect(await screen.findByTestId("vol3-exec-form")).toBeInTheDocument();
    expect(screen.getByTestId("vol3-exec-image")).toHaveTextContent(RUN2);
    expect(screen.getByTestId("vol3-export-plugin")).toBeInTheDocument();
    expect(screen.queryByTestId("needs-view")).toBeNull();
    expect(screen.queryByTestId("vol3-run")).toBeNull();
  });
});

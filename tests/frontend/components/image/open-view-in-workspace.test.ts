import { beforeEach, describe, expect, it, vi } from "vitest";

const getPathInfo = vi.hoisted(() => vi.fn(async () => ({ file_size: 123 })));
vi.mock("@/api/client", async (orig) => ({
  ...(await orig<typeof import("@/api/client")>()),
  getPathInfo,
}));

const { openViewInWorkspace } = await import("@/components/image/open-view-in-workspace");
const { useAppStore } = await import("@/stores/app-store");
const { useDumpStore } = await import("@/stores/dump-store");

beforeEach(() => {
  useDumpStore.getState().clearAll();
});

describe("openViewInWorkspace", () => {
  it("turns an empty image workspace into a file workspace on the opened view", async () => {
    useAppStore.setState({ inputMode: "file", inputPath: "" });
    await openViewInWorkspace("/cases/a/kernel.mdview");
    expect(useAppStore.getState().inputMode).toBe("file");
    expect(useAppStore.getState().inputPath).toBe("/cases/a/kernel.mdview");
    expect(useDumpStore.getState().dumps.map((d) => d.path)).toEqual(["/cases/a/kernel.mdview"]);
  });

  it("leaves an existing file workspace's input path alone", async () => {
    useAppStore.setState({ inputMode: "file", inputPath: "/dumps/x.msl" });
    await openViewInWorkspace("/cases/a/process.mdview");
    expect(useAppStore.getState().inputPath).toBe("/dumps/x.msl");
    expect(useDumpStore.getState().activeDumpId).toBe(useDumpStore.getState().dumps[0].id);
  });
});

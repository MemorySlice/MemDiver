import { beforeEach, describe, expect, it, vi } from "vitest";
import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import "@testing-library/jest-dom/vitest";
import "@/i18n";

import { useDumpStore } from "@/stores/dump-store";
import { KEY1, RUN1 } from "./synth-fixtures";

const api = vi.hoisted(() => ({
  listFormatOracles: vi.fn(), suggestFormatOracle: vi.fn(), getVol3PluginDir: vi.fn(),
}));
vi.mock("@/api/vol3", async (orig) => ({ ...(await orig<typeof import("@/api/vol3")>()), ...api }));

const { SynthesizeDialog } = await import("@/components/vol3/SynthesizeDialog");

const mount = () => render(
  <SynthesizeDialog initialDumps={[RUN1]} initialSecretHex={KEY1} onClose={vi.fn()} />);
const select = () => screen.getByTestId("synth-oracle") as HTMLSelectElement;
const optionValues = () => Array.from(select().options).map((o) => o.value);
const suggestion = (over = {}) => ({
  dump_path: RUN1, reason: "r",
  suggestion: { kind: "luks", sample_path: "/vault", params: {}, reason: "LUKS header found",
    confidence: "high", signal: "vault", sample_needed: null, ...over },
});

beforeEach(() => {
  Object.values(api).forEach((m) => m.mockReset());
  api.getVol3PluginDir.mockResolvedValue({ path: "/p" });
  api.suggestFormatOracle.mockResolvedValue({ dump_path: RUN1, suggestion: null, reason: "none" });
  useDumpStore.setState({ dumps: [] });
});

describe("SynthesizeDialog oracle listing and suggestion", () => {
  it("loads the oracle kinds from the listing", async () => {
    api.listFormatOracles.mockResolvedValue({ formats: [{ kind: "alpha" }, { kind: "luks" }], count: 2 });
    mount();
    await waitFor(() => expect(optionValues()).toEqual(["gocryptfs-gcm", "alpha", "luks"]));
    expect(optionValues()).not.toContain("xts-fsmagic");
  });

  it("falls back to the known kinds when the listing fails", async () => {
    api.listFormatOracles.mockRejectedValue(new Error("down"));
    mount();
    await waitFor(() => expect(api.listFormatOracles).toHaveBeenCalled());
    expect(optionValues()).toContain("xts-fsmagic");
    expect(optionValues()).toContain("gocryptfs-gcm");
  });

  it("pre-fills kind, name and sample from a suggestion and shows the reason", async () => {
    api.listFormatOracles.mockResolvedValue({ formats: [{ kind: "gocryptfs-gcm" }, { kind: "luks" }], count: 2 });
    api.suggestFormatOracle.mockResolvedValue(suggestion());
    mount();
    await waitFor(() => expect(select().value).toBe("luks"));
    expect(api.suggestFormatOracle).toHaveBeenCalledWith(RUN1);
    expect((screen.getByTestId("synth-name") as HTMLInputElement).value).toBe("memdiver_luks");
    expect((screen.getByTestId("synth-dump-sample") as HTMLInputElement).value).toBe("/vault");
    expect(screen.getByTestId("synth-oracle-suggestion")).toHaveTextContent("LUKS header found");
    expect(screen.getByTestId("synth-oracle-suggestion")).toHaveTextContent("high");
  });

  it("does not override a kind or sample the user already set", async () => {
    api.listFormatOracles.mockResolvedValue({ formats: [{ kind: "gocryptfs-gcm" }, { kind: "luks" }, { kind: "xts-fsmagic" }], count: 3 });
    let resolve!: (v: unknown) => void;
    api.suggestFormatOracle.mockReturnValue(new Promise((r) => { resolve = r; }));
    mount();
    await waitFor(() => expect(optionValues()).toContain("luks"));
    fireEvent.change(select(), { target: { value: "xts-fsmagic" } });
    fireEvent.change(screen.getByTestId("synth-dump-sample"), { target: { value: "/mine" } });
    await waitFor(() => expect(api.suggestFormatOracle).toHaveBeenCalled());
    resolve(suggestion());
    await waitFor(() => expect(screen.getByTestId("synth-oracle-suggestion")).toBeInTheDocument());
    expect(select().value).toBe("xts-fsmagic");
    expect((screen.getByTestId("synth-dump-sample") as HTMLInputElement).value).toBe("/mine");
  });

  it("replaces a suggested sample when the first dump changes, never a typed one", async () => {
    api.listFormatOracles.mockResolvedValue({ formats: [{ kind: "gocryptfs-gcm" }], count: 1 });
    api.suggestFormatOracle.mockResolvedValueOnce(suggestion({ kind: "gocryptfs-gcm", sample_path: "/run1/cipher" }));
    mount();
    const sample = () => (screen.getByTestId("synth-dump-sample") as HTMLInputElement).value;
    await waitFor(() => expect(sample()).toBe("/run1/cipher"));
    api.suggestFormatOracle.mockResolvedValueOnce(suggestion({ kind: "gocryptfs-gcm", sample_path: "/run2/cipher" }));
    fireEvent.change(screen.getAllByTestId("synth-dump-path")[0], { target: { value: "/run2/mem.msl" } });
    await waitFor(() => expect(sample()).toBe("/run2/cipher"));
    api.suggestFormatOracle.mockResolvedValueOnce(suggestion({ kind: "gocryptfs-gcm", sample_path: null }));
    fireEvent.change(screen.getAllByTestId("synth-dump-path")[0], { target: { value: "/run3/mem.msl" } });
    await waitFor(() => expect(sample()).toBe(""));
    fireEvent.change(screen.getByTestId("synth-dump-sample"), { target: { value: "/typed" } });
    api.suggestFormatOracle.mockResolvedValueOnce(suggestion({ kind: "gocryptfs-gcm", sample_path: "/run4/cipher" }));
    fireEvent.change(screen.getAllByTestId("synth-dump-path")[0], { target: { value: "/run4/mem.msl" } });
    await waitFor(() => expect(api.suggestFormatOracle).toHaveBeenLastCalledWith("/run4/mem.msl"));
    await new Promise((r) => setTimeout(r, 50));
    expect(sample()).toBe("/typed");
  });

  it("shows nothing when there is no suggestion", async () => {
    api.listFormatOracles.mockRejectedValue(new Error("down"));
    mount();
    await waitFor(() => expect(api.suggestFormatOracle).toHaveBeenCalled());
    expect(screen.queryByTestId("synth-oracle-suggestion")).not.toBeInTheDocument();
  });
});

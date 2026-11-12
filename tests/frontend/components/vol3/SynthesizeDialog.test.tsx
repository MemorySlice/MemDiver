import { beforeEach, describe, expect, it, vi } from "vitest";
import { fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import "@testing-library/jest-dom/vitest";
import "@/i18n";

import { ApiError } from "@/api/client";
import { useDumpStore } from "@/stores/dump-store";
import {
  CASE_PLUGINS, CIPHER2, EXEC, KEY1, KEY2, PLUGIN, REPO_PLUGINS, RUN1, RUN2, SYNTH,
} from "./synth-fixtures";

const api = vi.hoisted(() => ({
  synthesizeVol3Plugin: vi.fn(), execVol3Plugin: vi.fn(), getVol3PluginDir: vi.fn(),
}));
vi.mock("@/api/vol3", async (orig) => ({ ...(await orig<typeof import("@/api/vol3")>()), ...api }));

const { SynthesizeDialog } = await import("@/components/vol3/SynthesizeDialog");

const onClose = vi.fn();
const onSynthesized = vi.fn();
const mount = (dumps: string[] = [RUN1], secret: string | undefined = KEY1) => render(
  <SynthesizeDialog initialDumps={dumps} initialSecretHex={secret} initialCaseDir="my-case"
    onClose={onClose} onSynthesized={onSynthesized} />);

const dumpRows = () => screen.getAllByTestId("synth-dump");
const field = (row: HTMLElement, id: string) => within(row).getByTestId(id) as HTMLInputElement;

/** The full key must never be rendered as text, nor sit in an attribute other than a password input's value. */
function expectKeyNotShown(key: string) {
  expect(document.body.textContent ?? "").not.toContain(key);
  for (const el of Array.from(document.body.querySelectorAll("*"))) {
    for (const attr of Array.from(el.attributes)) {
      if (attr.name === "value" && (el as HTMLInputElement).type === "password") continue;
      expect(attr.value).not.toContain(key);
    }
  }
}

beforeEach(() => {
  Object.values(api).forEach((m) => m.mockReset());
  onClose.mockReset();
  onSynthesized.mockReset();
  api.getVol3PluginDir.mockResolvedValue({ path: REPO_PLUGINS });
  useDumpStore.setState({ dumps: [] });
});

describe("SynthesizeDialog form", () => {
  it("is a labelled modal dialog prefilled from the hit, the key masked in a password field", () => {
    mount();
    const dialog = screen.getByRole("dialog");
    expect(dialog).toHaveAccessibleName("Export as Volatility 3 plugin");
    const row = dumpRows()[0];
    expect(field(row, "synth-dump-path").value).toBe(RUN1);
    expect(field(row, "synth-dump-secret").type).toBe("password");
    expect(field(row, "synth-dump-secret")).toHaveAccessibleName("Dump 1 key (hex)");
    expect(within(row).getByTestId("synth-dump-secret-mask")).toHaveTextContent("•••• (32 B)");
    expect((screen.getByTestId("synth-name") as HTMLInputElement).value).toBe("memdiver_gocryptfs");
    expect((screen.getByTestId("synth-oracle") as HTMLSelectElement).value).toBe("gocryptfs-gcm");
    expect((screen.getByTestId("synth-case") as HTMLInputElement).value).toBe("my-case");
    expect(screen.getByTestId("synth-single-dump-hint")).toBeInTheDocument();
    expectKeyNotShown(KEY1);
  });

  it("focuses the plugin name and closes on Escape", () => {
    mount();
    expect(screen.getByTestId("synth-name")).toHaveFocus();
    fireEvent.keyDown(document, { key: "Escape" });
    expect(onClose).toHaveBeenCalled();
  });

  it("shows validation errors and sends nothing", () => {
    mount([RUN1], "abc");
    fireEvent.click(screen.getByTestId("synth-submit"));
    expect(screen.getByTestId("synth-validation")).toHaveTextContent("even number of hex digits");
    expect(api.synthesizeVol3Plugin).not.toHaveBeenCalled();
  });

  it("sends one key and one sample per added dump, and the container key of an encrypted .msl", async () => {
    useDumpStore.setState({ dumps: [{ id: "d1", path: RUN1, name: "m", size: 1, format: "msl", sameProcess: true,
      keyMaterial: { passphrase: "pw" } }] });
    api.synthesizeVol3Plugin.mockResolvedValue(SYNTH);
    mount();
    fireEvent.change(field(dumpRows()[0], "synth-dump-sample"), { target: { value: "/data/run_0001/cipher" } });
    fireEvent.click(screen.getByTestId("synth-dump-add"));
    const second = dumpRows()[1];
    fireEvent.change(field(second, "synth-dump-path"), { target: { value: RUN2 } });
    fireEvent.change(field(second, "synth-dump-secret"), { target: { value: KEY2 } });
    fireEvent.change(field(second, "synth-dump-sample"), { target: { value: CIPHER2 } });
    fireEvent.click(screen.getByTestId("synth-submit"));
    await screen.findByTestId("synth-result");
    expect(api.synthesizeVol3Plugin).toHaveBeenCalledWith({
      passphrase: "pw", dump_paths: [RUN1, RUN2], name: "memdiver_gocryptfs", oracle_kind: "gocryptfs-gcm",
      secret_hex: [KEY1, KEY2], oracle_sample_path: ["/data/run_0001/cipher", CIPHER2], context: 64,
      case_dir: "my-case", verify_on: ["msl"], allow_high_entropy_context: undefined, async: true,
    });
    expect(onSynthesized).toHaveBeenCalledWith(SYNTH);
    expectKeyNotShown(KEY1);
    expectKeyNotShown(KEY2);
  });

  it("shows the error code of a refused request", async () => {
    api.synthesizeVol3Plugin.mockRejectedValue(new ApiError(400, JSON.stringify({
      error: "not a MemDiver case: /tmp/x", code: "case.not_a_case", category: "INVALID_INPUT" })));
    mount();
    fireEvent.click(screen.getByTestId("synth-submit"));
    const alert = await screen.findByTestId("synth-error");
    expect(within(alert).getByTestId("synth-error-code")).toHaveTextContent("case.not_a_case");
    expect(alert).toHaveTextContent("not a MemDiver case: /tmp/x");
  });
});

describe("SynthesizeResult", () => {
  async function synthesized() {
    api.synthesizeVol3Plugin.mockResolvedValue(SYNTH);
    mount([RUN1, RUN2]);
    fireEvent.click(screen.getByTestId("synth-submit"));
    return screen.findByTestId("synth-result");
  }

  it("shows a badge per target, the Proven count, diagnostics and the source", async () => {
    await synthesized();
    const verdicts = screen.getAllByTestId("synth-verdict");
    expect(verdicts).toHaveLength(2);
    expect(verdicts.map((v) => v.getAttribute("data-status"))).toEqual(["proven", "proven"]);
    expect(within(verdicts[0]).getByTestId("verdict-badge")).toHaveTextContent("proven");
    expect(screen.getByTestId("synth-proven-count")).toHaveTextContent("Proven hits: 4");
    expect(screen.getByTestId("synth-diagnostic")).toHaveTextContent("vol3_recipe.high_entropy_constant");
    expect(screen.getByTestId("synth-source")).toHaveTextContent("class MemDiverSynthGocryptfs");
    expect(screen.getByTestId("synth-stored")).toHaveTextContent(`${CASE_PLUGINS}/memdiver_gocryptfs.py`);
  });

  it("copies the vol command", async () => {
    const writeText = vi.fn(async () => {});
    Object.assign(navigator, { clipboard: { writeText } });
    await synthesized();
    fireEvent.click(screen.getByTestId("synth-copy-command"));
    await screen.findByTestId("synth-copied");
    expect(writeText).toHaveBeenCalledWith(SYNTH.vol_command);
  });

  it("downloads the source as <name>.py", async () => {
    const createObjectURL = vi.fn(() => "blob:x");
    Object.assign(URL, { createObjectURL, revokeObjectURL: vi.fn() });
    const click = vi.spyOn(HTMLAnchorElement.prototype, "click").mockImplementation(() => {});
    await synthesized();
    fireEvent.click(screen.getByTestId("synth-download"));
    expect(createObjectURL).toHaveBeenCalled();
    expect(click).toHaveBeenCalled();
    click.mockRestore();
  });

  it("runs a later dump under vol with its own oracle sample, rows masked, Proven first", async () => {
    api.execVol3Plugin.mockResolvedValue(EXEC);
    await synthesized();
    const run = within(screen.getAllByTestId("synth-verdict")[1]).getByTestId("synth-run-under-vol");
    await waitFor(() => expect(run).toBeEnabled());
    fireEvent.click(run);
    await screen.findByTestId("synth-exec-result");
    expect(api.execVol3Plugin).toHaveBeenCalledWith({
      plugin: PLUGIN, image_path: RUN2, plugin_dirs: [CASE_PLUGINS], symbol_dirs: [],
      args: ["--oracle-sample", CIPHER2],
    });
    expect(screen.getByTestId("synth-exec-summary")).toHaveTextContent("2 row(s), 2 proven");
    const proven = screen.getAllByTestId("synth-exec-proven");
    expect(proven.map((c) => c.textContent)).toEqual(["oracle:gocryptfs-gcm", "oracle:gocryptfs-gcm"]);
    const headers = within(screen.getByTestId("synth-exec-table")).getAllByRole("columnheader");
    expect(headers[0]).toHaveTextContent("Proven");
    expectKeyNotShown(KEY2);
  });

  it("shows the code of a refused exec", async () => {
    api.execVol3Plugin.mockRejectedValue(new ApiError(400, JSON.stringify({
      error: "vol timed out", code: "vol3.exec.timeout", category: "TIMEOUT" })));
    await synthesized();
    const run = screen.getAllByTestId("synth-run-under-vol")[0];
    await waitFor(() => expect(run).toBeEnabled());
    fireEvent.click(run);
    expect(await screen.findByTestId("synth-exec-error")).toHaveTextContent("vol3.exec.timeout: vol timed out");
  });
});

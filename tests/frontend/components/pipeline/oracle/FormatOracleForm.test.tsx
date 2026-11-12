import { beforeEach, describe, expect, it, vi } from "vitest";
import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import "@testing-library/jest-dom/vitest";
import "@/i18n";

const refresh = vi.fn();
const addFormatOracle = vi.fn();
vi.mock("@/api/oracles", () => ({ addFormatOracle: (...a: unknown[]) => addFormatOracle(...a) }));
vi.mock("@/api/vol3", async (orig) => ({
  ...(await orig<typeof import("@/api/vol3")>()),
  listFormatOracles: vi.fn().mockResolvedValue({ formats: [{ kind: "luks" }, { kind: "aead-generic" }], count: 2 }),
}));
vi.mock("@/stores/oracle-store", () => ({
  useOracleStore: (sel: (s: { refresh: typeof refresh }) => unknown) => sel({ refresh }),
}));

const { FormatOracleForm } = await import("@/components/pipeline/oracle/FormatOracleForm");

beforeEach(() => { refresh.mockReset(); addFormatOracle.mockReset(); });

describe("FormatOracleForm", () => {
  it("registers the chosen kind with the sample path, then refreshes the list", async () => {
    addFormatOracle.mockResolvedValue({ id: "x" });
    render(<FormatOracleForm />);
    await waitFor(() => expect((screen.getByTestId("format-oracle-kind") as HTMLSelectElement).options).toHaveLength(2));
    fireEvent.change(screen.getByTestId("format-oracle-kind"), { target: { value: "aead-generic" } });
    fireEvent.change(screen.getByTestId("format-oracle-sample"), { target: { value: " /s " } });
    fireEvent.click(screen.getByTestId("format-oracle-add"));
    await waitFor(() => expect(refresh).toHaveBeenCalled());
    expect(addFormatOracle).toHaveBeenCalledWith("aead-generic", "/s");
  });

  it("shows the server's refusal and does not refresh", async () => {
    addFormatOracle.mockRejectedValue(new Error("bad sample"));
    render(<FormatOracleForm />);
    fireEvent.click(screen.getByTestId("format-oracle-add"));
    await waitFor(() => expect(screen.getByTestId("format-oracle-error")).toHaveTextContent("bad sample"));
    expect(refresh).not.toHaveBeenCalled();
  });
});

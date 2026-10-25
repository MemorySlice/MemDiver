import { beforeEach, describe, expect, it, vi } from "vitest";
import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import "@testing-library/jest-dom/vitest";
import "@/i18n";

const api = vi.hoisted(() => ({ listVol3SavedQueries: vi.fn(), runVol3Query: vi.fn() }));
vi.mock("@/api/vol3", () => api);
vi.mock("@/api/client", () => ({ readableFailure: (e: unknown) => String(e) }));

const { QueryBox } = await import("@/components/vol3/QueryBox");

const RESULT = {
  columns: ["pid"], rows: [[1]], truncated: false, row_count: 1, limit: 500, elapsed_s: 0,
};

beforeEach(() => {
  api.listVol3SavedQueries.mockReset().mockResolvedValue({
    saved_queries: [{ name: "hidden_processes", description: "d", sql: "SELECT pid FROM t" }], count: 1,
  });
  api.runVol3Query.mockReset().mockResolvedValue(RESULT);
});

async function pick() {
  render(<QueryBox caseDir="/case" onSendToHighlights={() => {}} note={null} />);
  await waitFor(() => expect(screen.getByRole("option", { name: "hidden_processes" })).toBeInTheDocument());
  fireEvent.change(screen.getByTestId("query-saved"), { target: { value: "hidden_processes" } });
}

describe("QueryBox saved queries", () => {
  it("sends the saved NAME while the text is unchanged", async () => {
    await pick();
    fireEvent.click(screen.getByTestId("query-run"));
    await waitFor(() => expect(api.runVol3Query).toHaveBeenCalledWith("/case", { saved: "hidden_processes" }));
  });

  it("sends raw sql once the text is edited", async () => {
    await pick();
    fireEvent.change(screen.getByTestId("query-sql"), { target: { value: "SELECT pid FROM t LIMIT 1" } });
    fireEvent.click(screen.getByTestId("query-run"));
    await waitFor(() =>
      expect(api.runVol3Query).toHaveBeenCalledWith("/case", { sql: "SELECT pid FROM t LIMIT 1" }));
  });

  it("shows backend warnings", async () => {
    api.runVol3Query.mockResolvedValue({ ...RESULT, warnings: ["input table was truncated"] });
    await pick();
    fireEvent.click(screen.getByTestId("query-run"));
    expect(await screen.findByTestId("query-warning")).toHaveTextContent("input table was truncated");
  });
});

import { describe, it, expect, beforeEach } from "vitest";
import { act, fireEvent, render, screen } from "@testing-library/react";
import "@testing-library/jest-dom/vitest";
import "@/i18n";

import { MemoryBudgetDialog } from "@/components/common/MemoryBudgetDialog";
import { useMemoryBudgetStore } from "@/stores/memory-budget-store";

const INFO = {
  message: "estimate exceeds budget",
  estimateBytes: 2 * 1024 ** 3,
  budgetBytes: 1024 ** 3,
};

function ask(): Promise<boolean> {
  let answer!: Promise<boolean>;
  act(() => {
    answer = useMemoryBudgetStore.getState().ask(INFO);
  });
  return answer;
}

beforeEach(() => {
  useMemoryBudgetStore.setState({ pending: null });
});

describe("MemoryBudgetDialog", () => {
  it("renders nothing without a pending question", () => {
    render(<MemoryBudgetDialog />);
    expect(screen.queryByTestId("memory-budget-dialog")).not.toBeInTheDocument();
  });

  it("shows the message and estimate vs budget", () => {
    render(<MemoryBudgetDialog />);
    void ask();
    expect(screen.getByRole("dialog")).toHaveAccessibleName("Memory budget exceeded");
    expect(screen.getByTestId("memory-budget-message")).toHaveTextContent(INFO.message);
    expect(screen.getByTestId("memory-budget-estimate")).toHaveTextContent("2.0 GiB");
    expect(screen.getByTestId("memory-budget-budget")).toHaveTextContent("1.0 GiB");
    expect(screen.getByText(/heap,stack/)).toBeInTheDocument();
    expect(screen.getByTestId("memory-budget-cancel")).toHaveFocus();
  });

  it("resolves true on Run anyway", async () => {
    render(<MemoryBudgetDialog />);
    const answer = ask();
    fireEvent.click(screen.getByRole("button", { name: "Run anyway" }));
    await expect(answer).resolves.toBe(true);
    expect(screen.queryByTestId("memory-budget-dialog")).not.toBeInTheDocument();
  });

  it("resolves false on Cancel", async () => {
    render(<MemoryBudgetDialog />);
    const answer = ask();
    fireEvent.click(screen.getByRole("button", { name: "Cancel" }));
    await expect(answer).resolves.toBe(false);
  });
});

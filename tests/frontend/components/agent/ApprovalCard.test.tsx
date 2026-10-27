import { describe, expect, it, vi } from "vitest";
import { fireEvent, render, screen } from "@testing-library/react";
import "@/i18n";

import { ApprovalCard } from "@/components/agent/ApprovalCard";

const item = { kind: "approval" as const, id: "p1", tool: "export_keylog", input: { a: 1 }, access: "write",
  scopes: ["once", "chat"], resolved: null };

describe("ApprovalCard", () => {
  it("sends the right decision for each button and focuses itself", () => {
    const onDecide = vi.fn();
    render(<ApprovalCard item={item} onDecide={onDecide} />);
    expect(screen.getByTestId("approval-card")).toHaveFocus();
    fireEvent.change(screen.getByLabelText("Optional note to the assistant"), { target: { value: " careful " } });
    fireEvent.click(screen.getByText("Allow once"));
    fireEvent.click(screen.getByText("Allow for this chat"));
    fireEvent.click(screen.getByText("Deny"));
    expect(onDecide.mock.calls).toEqual([
      ["p1", true, "once", "careful"], ["p1", true, "chat", "careful"], ["p1", false, "once", "careful"],
    ]);
  });

  it("omits the chat scope when the server did not offer it, and shows the resolved state", () => {
    const { rerender } = render(<ApprovalCard item={{ ...item, scopes: ["once"] }} onDecide={vi.fn()} />);
    expect(screen.queryByText("Allow for this chat")).toBeNull();
    rerender(<ApprovalCard item={{ ...item, resolved: { allowed: true, message: "ok" } }} onDecide={vi.fn()} />);
    expect(screen.getByTestId("approval-resolved")).toHaveTextContent("Allowed: ok");
    expect(screen.queryByText("Deny")).toBeNull();
  });
});

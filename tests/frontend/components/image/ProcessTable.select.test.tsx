import { describe, expect, it, vi } from "vitest";
import { fireEvent, render, screen } from "@testing-library/react";
import "@testing-library/jest-dom/vitest";
import "@/i18n";

import { stubVirtualizerLayout } from "../../helpers/virtualizer";
import type { ProcessRow } from "@/api/image";
import { ProcessTable } from "@/components/image/ProcessTable";

const row = (pid: number, comm: string): ProcessRow => ({
  pid, ppid: 1, comm, uid: 0, has_mm: true, task_offset: 0,
  location: { space: "kernel_va", value: 0 } as ProcessRow["location"],
});

describe("ProcessTable selection (D14)", () => {
  it("selecting a pid reports the row and marks the selected one without relying on colour", () => {
    stubVirtualizerLayout(600, 240);
    const onSelect = vi.fn();
    render(<ProcessTable rows={[row(1, "init"), row(2, "sshd")]} busy={false}
      onOpen={vi.fn()} onExtract={vi.fn()} selectedPid={2} onSelect={onSelect} />);
    const [first, second] = screen.getAllByTestId("process-select");
    expect(second).toHaveAttribute("aria-pressed", "true");
    expect(second).toHaveTextContent("● 2");
    expect(first).toHaveAttribute("aria-pressed", "false");
    fireEvent.click(first);
    expect(onSelect).toHaveBeenCalledWith(expect.objectContaining({ pid: 1 }));
  });

  it("stays a plain table when no onSelect is given", () => {
    stubVirtualizerLayout(600, 240);
    render(<ProcessTable rows={[row(1, "init")]} busy={false} onOpen={vi.fn()} onExtract={vi.fn()} />);
    expect(screen.queryByTestId("process-select")).toBeNull();
  });
});

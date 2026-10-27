import { describe, expect, it, vi } from "vitest";
import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import "@/i18n";

import { AgentSettingsForm } from "@/components/agent/AgentSettingsForm";
import type { AgentSettingsBundle } from "@/api/agent";

const bundle: AgentSettingsBundle = {
  settings: { model: "m1", effort: "low", max_turns: 12, max_budget_usd: 1, result_budget_bytes: 20000 },
  defaults: { model: "m1", effort: "low", max_turns: 8, max_budget_usd: 0.5, result_budget_bytes: 20000 },
  limits: { max_turns: [1, 200], max_budget_usd: [0.05, 50], result_budget_bytes: [2000, 500000] },
  choices: { model: ["m1", "m2"], effort: ["low", "high"] }, warning: false,
};

describe("AgentSettingsForm", () => {
  it("shows limits and defaults and blocks saving an out-of-range value", () => {
    const onSave = vi.fn(async () => {});
    render(<AgentSettingsForm bundle={bundle} onSave={onSave} />);
    expect(screen.getByText("Allowed 1 to 200, default 8")).toBeInTheDocument();
    fireEvent.change(screen.getByLabelText("Max turns"), { target: { value: "500" } });
    expect(screen.getByText("Enter a number between 1 and 200.")).toBeInTheDocument();
    expect(screen.getByLabelText("Max turns")).toHaveAttribute("aria-invalid", "true");
    expect(screen.getByText("Save settings")).toBeDisabled();
    fireEvent.change(screen.getByLabelText("Max turns"), { target: { value: "2.5" } });
    expect(screen.getByText("Save settings")).toBeDisabled();
  });

  it("saves valid values and resets to the defaults", async () => {
    const onSave = vi.fn(async () => {});
    render(<AgentSettingsForm bundle={bundle} onSave={onSave} />);
    fireEvent.change(screen.getByLabelText("Max turns"), { target: { value: "20" } });
    fireEvent.click(screen.getByText("Save settings"));
    await waitFor(() => expect(onSave).toHaveBeenCalledWith(expect.objectContaining({ max_turns: 20, model: "m1" })));
    fireEvent.click(screen.getByText("Reset to defaults"));
    await waitFor(() => expect(onSave).toHaveBeenLastCalledWith(bundle.defaults));
  });

  it("surfaces a server rejection", async () => {
    const onSave = vi.fn(async () => { throw new Error('{"detail":"max_turns must be between 1 and 200"}'); });
    render(<AgentSettingsForm bundle={bundle} onSave={onSave} />);
    fireEvent.click(screen.getByText("Save settings"));
    expect(await screen.findByText(/max_turns must be between 1 and 200/)).toBeInTheDocument();
  });
});

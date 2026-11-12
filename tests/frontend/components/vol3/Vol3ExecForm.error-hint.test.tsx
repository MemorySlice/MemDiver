import { beforeEach, describe, expect, it, vi } from "vitest";
import { fireEvent, render, screen } from "@testing-library/react";
import "@testing-library/jest-dom/vitest";
import "@/i18n";

import { ApiError } from "@/api/client";
import { RUN2 } from "./synth-fixtures";

const api = vi.hoisted(() => ({ execVol3Plugin: vi.fn() }));
vi.mock("@/api/vol3", async (orig) => ({ ...(await orig<typeof import("@/api/vol3")>()), ...api }));

const { Vol3ExecForm } = await import("@/components/vol3/Vol3ExecForm");

const DENIAL_MESSAGE = "read path '/etc/x.lime' is outside the read sandbox (MEMDIVER_ALLOWED_ROOTS is set).";

/** What the server answers for a path the sandbox excludes. */
const denial = () => new ApiError(403, JSON.stringify({
  detail: DENIAL_MESSAGE, error: DENIAL_MESSAGE,
  code: "path.outside_sandbox", category: "PRECONDITION",
}));

// Braces matter: a beforeEach that RETURNS the mock would run it as a teardown.
beforeEach(() => {
  api.execVol3Plugin.mockReset();
});

describe("Vol3ExecForm request failures", () => {
  it("explains a sandbox denial with the localized hint next to the server message", async () => {
    api.execVol3Plugin.mockRejectedValue(denial());
    render(<Vol3ExecForm imagePath="/etc/x.lime" caseDir="" />);
    fireEvent.click(screen.getByTestId("vol3-exec-run"));

    const error = await screen.findByTestId("vol3-exec-error");
    expect(error).toHaveTextContent(`path.outside_sandbox: ${DENIAL_MESSAGE}`);
    const hint = screen.getByTestId("api-error-hint");
    expect(hint).toHaveTextContent(/outside the folders this server is allowed to use/);
    expect(hint).toHaveTextContent("MEMDIVER_ALLOWED_ROOTS");
  });

  it("shows no hint for a failure without a known code", async () => {
    api.execVol3Plugin.mockRejectedValue(new ApiError(400, JSON.stringify({
      error: "plugin not found", code: "vol3.unknown_plugin", category: "INVALID_INPUT" })));
    render(<Vol3ExecForm imagePath={RUN2} caseDir="" />);
    fireEvent.click(screen.getByTestId("vol3-exec-run"));

    expect(await screen.findByTestId("vol3-exec-error")).toHaveTextContent("plugin not found");
    expect(screen.queryByTestId("api-error-hint")).toBeNull();
  });

  it("clears the hint when the next run starts", async () => {
    api.execVol3Plugin.mockRejectedValueOnce(denial()).mockReturnValueOnce(new Promise(() => {}));
    render(<Vol3ExecForm imagePath="/etc/x.lime" caseDir="" />);
    fireEvent.click(screen.getByTestId("vol3-exec-run"));
    await screen.findByTestId("api-error-hint");

    fireEvent.click(screen.getByTestId("vol3-exec-run"));
    await vi.waitFor(() => expect(screen.queryByTestId("api-error-hint")).toBeNull());
  });
});

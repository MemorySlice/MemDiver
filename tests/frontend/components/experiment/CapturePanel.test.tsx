import { afterEach, describe, it, expect, vi } from "vitest";
import { fireEvent, render, screen } from "@testing-library/react";

import "@/i18n";
import { CapturePanel } from "@/components/experiment/CapturePanel";
import type { CaptureReport } from "@/api/capture";

const REPORT: CaptureReport = {
  ok: true,
  tool: "fridump",
  output_path: "/artifacts/captures/app.dump",
  target: { pid: 4242, name: "com.example.app", device: "usb:emulator-5554" },
  maps_path: null,
  regions_captured: 12,
  bytes_captured: 2048,
  names: "none",
  skipped: [
    { base: 4096, base_hex: "0x1000", size: 1024, reason: "size_cap" },
    { base: 8192, base_hex: "0x2000", size: 512, reason: "mystery_reason" },
  ],
  skipped_bytes: 1536,
  warnings: ["low-level detail"],
  summary_warnings: ["3 regions were truncated"],
  error: null,
};

afterEach(() => {
  vi.unstubAllGlobals();
});

function fillAndSubmit() {
  fireEvent.change(screen.getByTestId("capture-target"), { target: { value: "com.example.app" } });
  fireEvent.change(screen.getByTestId("capture-tool"), { target: { value: "fridump" } });
  fireEvent.change(screen.getByTestId("capture-device-kind"), { target: { value: "usb" } });
  fireEvent.change(screen.getByTestId("capture-device-detail"), { target: { value: "emulator-5554" } });
  fireEvent.click(screen.getByTestId("capture-submit"));
}

describe("CapturePanel", () => {
  it("submits the composed body and renders the report", async () => {
    const fetchMock = vi.fn().mockResolvedValue(new Response(JSON.stringify(REPORT)));
    vi.stubGlobal("fetch", fetchMock);
    render(<CapturePanel />);
    fillAndSubmit();

    expect(await screen.findByText("Capture succeeded")).toBeInTheDocument();
    const [url, init] = fetchMock.mock.calls[0];
    expect(url).toBe("/api/experiment/capture");
    expect(JSON.parse(init.body)).toEqual({
      target: "com.example.app",
      tool: "fridump",
      device: "usb:emulator-5554",
      output: null,
      max_region_size: null,
    });
    expect(screen.getByText("Output: /artifacts/captures/app.dump")).toBeInTheDocument();
    expect(screen.getByText("Captured 12 regions (2.0 KiB)")).toBeInTheDocument();
    expect(screen.getByText("Region names from: none")).toBeInTheDocument();
    expect(screen.getByText(/classified as anonymous/)).toBeInTheDocument();
    expect(screen.getByText("3 regions were truncated")).toBeInTheDocument();
    expect(screen.getByText("2 regions skipped (1.5 KiB)")).toBeInTheDocument();
    expect(screen.getByText("over size cap")).toBeInTheDocument();
    expect(screen.getByText("mystery_reason")).toBeInTheDocument();
    expect(screen.getByText("0x1000")).toBeInTheDocument();
  });

  it("refuses a remote device without a host and does not fetch", () => {
    const fetchMock = vi.fn();
    vi.stubGlobal("fetch", fetchMock);
    render(<CapturePanel />);
    fireEvent.change(screen.getByTestId("capture-target"), { target: { value: "1234" } });
    fireEvent.change(screen.getByTestId("capture-device-kind"), { target: { value: "remote" } });
    fireEvent.click(screen.getByTestId("capture-submit"));
    expect(screen.getByTestId("capture-error")).toHaveTextContent("Enter the remote host");
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("shows the capability error message from a 412", async () => {
    const body = JSON.stringify({ error: "frida is not installed", category: "capability" });
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue(new Response(body, { status: 412 })));
    render(<CapturePanel />);
    fillAndSubmit();
    expect(await screen.findByTestId("capture-error")).toHaveTextContent(
      "Capture failed: frida is not installed",
    );
  });

  it("enables the large read-only checkbox only for lldb", () => {
    render(<CapturePanel />);
    const checkbox = screen.getByTestId("capture-include-large-readonly");
    expect(checkbox).toBeDisabled();
    fireEvent.change(screen.getByTestId("capture-tool"), { target: { value: "lldb" } });
    expect(checkbox).toBeEnabled();
  });
});

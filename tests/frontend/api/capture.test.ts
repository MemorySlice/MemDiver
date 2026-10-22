import { afterEach, describe, it, expect, vi } from "vitest";

import {
  INITIAL_CAPTURE_FORM,
  buildCaptureRequest,
  captureProcess,
  composeDeviceString,
  parseMaxRegionSize,
} from "@/api/capture";

afterEach(() => {
  vi.unstubAllGlobals();
});

describe("composeDeviceString", () => {
  it("returns local regardless of detail", () => {
    expect(composeDeviceString("local", "ignored")).toBe("local");
  });

  it("returns bare usb without a device id", () => {
    expect(composeDeviceString("usb", "  ")).toBe("usb");
  });

  it("appends a trimmed usb device id", () => {
    expect(composeDeviceString("usb", " emulator-5554 ")).toBe("usb:emulator-5554");
  });

  it("composes remote host and optional port", () => {
    expect(composeDeviceString("remote", "10.0.0.2")).toBe("remote:10.0.0.2");
    expect(composeDeviceString("remote", "10.0.0.2:27042")).toBe("remote:10.0.0.2:27042");
  });

  it("refuses remote without a host", () => {
    expect(composeDeviceString("remote", "")).toBeNull();
  });
});

describe("parseMaxRegionSize", () => {
  it("treats empty as no cap", () => {
    expect(parseMaxRegionSize(" ")).toBeNull();
  });

  it("accepts positive integers", () => {
    expect(parseMaxRegionSize("4096")).toBe(4096);
  });

  it("rejects zero, negatives and non-integers", () => {
    expect(parseMaxRegionSize("0")).toBeUndefined();
    expect(parseMaxRegionSize("-5")).toBeUndefined();
    expect(parseMaxRegionSize("1.5")).toBeUndefined();
    expect(parseMaxRegionSize("abc")).toBeUndefined();
  });
});

describe("buildCaptureRequest", () => {
  it("requires a target", () => {
    expect(buildCaptureRequest(INITIAL_CAPTURE_FORM)).toEqual({ invalid: "capture.errTargetRequired" });
  });

  it("requires a remote host", () => {
    const form = { ...INITIAL_CAPTURE_FORM, target: "1234", deviceKind: "remote" as const };
    expect(buildCaptureRequest(form)).toEqual({ invalid: "capture.errRemoteHostRequired" });
  });

  it("rejects an invalid max region size", () => {
    const form = { ...INITIAL_CAPTURE_FORM, target: "1234", maxRegionSize: "0" };
    expect(buildCaptureRequest(form)).toEqual({ invalid: "capture.errMaxRegionSize" });
  });

  it("builds a memslicer body without include_large_readonly", () => {
    const form = { ...INITIAL_CAPTURE_FORM, target: " 1234 ", includeLargeReadonly: true };
    expect(buildCaptureRequest(form)).toEqual({
      target: "1234",
      tool: "memslicer",
      device: "local",
      output: null,
      max_region_size: null,
    });
  });

  it("sends include_large_readonly only for lldb", () => {
    const form = {
      ...INITIAL_CAPTURE_FORM,
      target: "com.example.app",
      tool: "lldb" as const,
      deviceKind: "usb" as const,
      deviceDetail: "emulator-5554",
      output: "/tmp/out.core",
      maxRegionSize: "1048576",
      includeLargeReadonly: true,
    };
    expect(buildCaptureRequest(form)).toEqual({
      target: "com.example.app",
      tool: "lldb",
      device: "usb:emulator-5554",
      output: "/tmp/out.core",
      max_region_size: 1048576,
      include_large_readonly: true,
    });
  });
});

describe("captureProcess", () => {
  it("POSTs the body to /api/experiment/capture", async () => {
    const fetchMock = vi.fn().mockResolvedValue(new Response(JSON.stringify({ ok: true })));
    vi.stubGlobal("fetch", fetchMock);
    await captureProcess({ target: "1", tool: "memslicer", device: "local" });
    const [url, init] = fetchMock.mock.calls[0];
    expect(url).toBe("/api/experiment/capture");
    expect(init.method).toBe("POST");
    expect(JSON.parse(init.body)).toEqual({ target: "1", tool: "memslicer", device: "local" });
  });
});

/**
 * Typed client for `POST /api/experiment/capture` -- dump ONE running process
 * (by pid or process / Android package name) with memslicer, lldb or fridump.
 *
 * The route is synchronous: the response IS the capture report. Request and
 * response shapes live here (the `./locate-key` precedent) so a backend change
 * lands in one file rather than in every component that fetches.
 */

import { request } from "./client";

/** Exported as const tuples with the unions DERIVED, so a rename breaks `tsc`. */
export const CAPTURE_TOOLS = ["memslicer", "lldb", "fridump"] as const;
export type CaptureTool = (typeof CAPTURE_TOOLS)[number];

export const DEVICE_KINDS = ["local", "usb", "remote"] as const;
export type DeviceKind = (typeof DEVICE_KINDS)[number];

/** Where the region names in the dump came from; `"none"` = all anonymous. */
export const CAPTURE_NAME_SOURCES = ["proc_maps", "frida_ranges", "lldb", "none"] as const;
export type CaptureNameSource = (typeof CAPTURE_NAME_SOURCES)[number];

/** Reasons the backend gives for skipping a region (open-ended: render raw otherwise). */
export const KNOWN_SKIP_REASONS = [
  "unreadable",
  "read_failed",
  "short_read",
  "size_cap",
  "large_readonly",
  "timeout",
] as const;
export type KnownSkipReason = (typeof KNOWN_SKIP_REASONS)[number];

export interface CaptureRequest {
  target: string;
  tool: CaptureTool;
  device: string;
  output?: string | null;
  max_region_size?: number | null;
  include_large_readonly?: boolean;
  timeout?: number | null;
}

export interface CaptureSkippedRegion {
  base: number;
  base_hex: string;
  size: number;
  reason: string;
}

export interface CaptureReport {
  ok: boolean;
  tool: string;
  output_path: string;
  target: { pid: number | null; name: string | null; device: string };
  maps_path: string | null;
  regions_captured: number;
  bytes_captured: number;
  names: CaptureNameSource | null;
  skipped: CaptureSkippedRegion[];
  skipped_bytes: number;
  warnings: string[];
  summary_warnings: string[];
  error: string | null;
}

/**
 * Compose the backend's `device` string from the UI's kind + detail fields:
 * `local`, `usb`, `usb:<frida-device-id>`, `remote:<host>[:<port>]`.
 *
 * Returns `null` when the combination is incomplete (Remote without a host),
 * so the caller can refuse to submit instead of sending a malformed device.
 */
export function composeDeviceString(kind: DeviceKind, detail: string): string | null {
  const trimmed = detail.trim();
  if (kind === "local") return "local";
  if (kind === "usb") return trimmed === "" ? "usb" : `usb:${trimmed}`;
  return trimmed === "" ? null : `remote:${trimmed}`;
}

/**
 * Parse the optional max-region-size field. Empty -> `null` (no cap);
 * a positive integer -> that number; anything else -> `undefined` (invalid).
 */
export function parseMaxRegionSize(raw: string): number | null | undefined {
  const trimmed = raw.trim();
  if (trimmed === "") return null;
  if (!/^\d+$/.test(trimmed)) return undefined;
  const value = Number(trimmed);
  return Number.isSafeInteger(value) && value >= 1 ? value : undefined;
}

/** The capture form's raw field values, as the UI holds them. */
export interface CaptureForm {
  target: string;
  tool: CaptureTool;
  deviceKind: DeviceKind;
  deviceDetail: string;
  output: string;
  maxRegionSize: string;
  includeLargeReadonly: boolean;
}

export const INITIAL_CAPTURE_FORM: CaptureForm = {
  target: "",
  tool: "memslicer",
  deviceKind: "local",
  deviceDetail: "",
  output: "",
  maxRegionSize: "",
  includeLargeReadonly: false,
};

/**
 * Build the request body from the form, or return `{ invalid }` carrying the
 * i18n key (namespace `misc`) of the first validation problem.
 * `include_large_readonly` is sent only for lldb, the one tool that honours it.
 */
export function buildCaptureRequest(form: CaptureForm): CaptureRequest | { invalid: string } {
  const target = form.target.trim();
  if (target === "") return { invalid: "capture.errTargetRequired" };
  const device = composeDeviceString(form.deviceKind, form.deviceDetail);
  if (device === null) return { invalid: "capture.errRemoteHostRequired" };
  const maxRegionSize = parseMaxRegionSize(form.maxRegionSize);
  if (maxRegionSize === undefined) return { invalid: "capture.errMaxRegionSize" };
  const output = form.output.trim();
  return {
    target,
    tool: form.tool,
    device,
    output: output === "" ? null : output,
    max_region_size: maxRegionSize,
    ...(form.tool === "lldb" ? { include_large_readonly: form.includeLargeReadonly } : {}),
  };
}

export const captureProcess = (body: CaptureRequest) =>
  request<CaptureReport>("/api/experiment/capture", {
    method: "POST",
    body: JSON.stringify(body),
  });

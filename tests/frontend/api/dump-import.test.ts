import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";

import { previewImport } from "@/api/client";
import { importDumpFile, importDumpPath, uploadDump } from "@/api/dump-import";
import { useDumpStore } from "@/stores/dump-store";

/** Build a minimal Response-like stub for the mocked fetch. */
function jsonResponse(body: unknown, ok = true, status = 200): Response {
  return {
    ok,
    status,
    json: async () => body,
    text: async () => (typeof body === "string" ? body : JSON.stringify(body)),
  } as unknown as Response;
}

const IMPORT_RESULT = {
  source: "/tmp/in.core",
  output: "/srv/imports/gcore-1a2b3c4d.msl",
  regions_written: 10,
  key_hints_written: 0,
  total_bytes: 40960,
};

const fetchMock = vi.fn();

beforeEach(() => {
  fetchMock.mockReset();
  vi.stubGlobal("fetch", fetchMock);
  useDumpStore.setState({ dumps: [] });
});

afterEach(() => {
  vi.unstubAllGlobals();
});

function sentForm(): FormData {
  return fetchMock.mock.calls[0][1].body as FormData;
}

function sentJson(): Record<string, unknown> {
  return JSON.parse(fetchMock.mock.calls[0][1].body as string) as Record<string, unknown>;
}

describe("previewImport", () => {
  it("posts the path only when no selection is given", async () => {
    fetchMock.mockResolvedValueOnce(jsonResponse({ format: "raw", regions: [] }));
    await previewImport("/data/a.dump");

    const [url, init] = fetchMock.mock.calls[0];
    expect(url).toBe("/api/dumps/preview");
    expect(init.method).toBe("POST");
    expect(sentJson()).toEqual({ path: "/data/a.dump" });
  });

  it("forwards a memory map as maps_path", async () => {
    fetchMock.mockResolvedValueOnce(jsonResponse({}));
    await previewImport("/data/a.dump", undefined, undefined, undefined, { mapsPath: "/data/a.layout" });
    expect(sentJson()).toEqual({ path: "/data/a.dump", maps_path: "/data/a.layout" });
  });

  it("forwards regions and exclude_regions", async () => {
    fetchMock.mockResolvedValueOnce(jsonResponse({}));
    await previewImport("/data/a.core", "heap,stack", "image");
    expect(sentJson()).toEqual({
      path: "/data/a.core",
      regions: "heap,stack",
      exclude_regions: "image",
    });
  });
});

describe("uploadDump / importDumpFile", () => {
  const file = new File([new Uint8Array(16)], "gcore.core");

  it("sends only the file when no options are given (back-compat)", async () => {
    fetchMock.mockResolvedValueOnce(jsonResponse(IMPORT_RESULT));
    await uploadDump(file);
    const keys = [...sentForm().keys()];
    expect(keys).toEqual(["file"]);
  });

  it("appends the selection form fields that were set", async () => {
    fetchMock.mockResolvedValueOnce(jsonResponse(IMPORT_RESULT));
    await uploadDump(file, { regions: "heap", excludeRegions: "stack", materialize: true });
    const form = sentForm();
    expect(form.get("regions")).toBe("heap");
    expect(form.get("exclude_regions")).toBe("stack");
    expect(form.get("materialize")).toBe("true");
  });

  it("surfaces the server detail on failure", async () => {
    fetchMock.mockResolvedValueOnce(
      jsonResponse({ detail: "unknown region category 'x'; valid names: heap" }, false, 422),
    );
    await expect(uploadDump(file, { regions: "x" })).rejects.toThrow(
      /Upload failed: 422 .*valid names: heap/,
    );
  });

  it("registers the import and carries selection outcome fields", async () => {
    fetchMock.mockResolvedValueOnce(
      jsonResponse({ ...IMPORT_RESULT, excluded_region_count: 2, warnings: ["w"] }),
    );
    const dump = await importDumpFile(file, { regions: "heap" });
    expect(dump.name).toBe("gcore-1a2b3c4d.msl");
    expect(dump.excludedRegionCount).toBe(2);
    expect(dump.warnings).toEqual(["w"]);
    expect(useDumpStore.getState().dumps.map((d) => d.path)).toContain(IMPORT_RESULT.output);
  });

  it("omits selection outcome fields when the server did not send them", async () => {
    fetchMock.mockResolvedValueOnce(jsonResponse(IMPORT_RESULT));
    const dump = await importDumpFile(file);
    expect(dump).not.toHaveProperty("excludedRegionCount");
    expect(dump).not.toHaveProperty("warnings");
  });
});

describe("importDumpPath", () => {
  it("posts the server path with mapped option names and registers the result", async () => {
    fetchMock.mockResolvedValueOnce(jsonResponse(IMPORT_RESULT));
    const dump = await importDumpPath("/data/gcore.core", {
      outputDir: "/srv/uploads/corpus",
      regions: "heap",
      excludeRegions: "image",
      materialize: true,
    });

    expect(fetchMock.mock.calls[0][0]).toBe("/api/dumps/import-path");
    expect(sentJson()).toEqual({
      path: "/data/gcore.core",
      output_dir: "/srv/uploads/corpus",
      regions: "heap",
      exclude_regions: "image",
      materialize: true,
    });
    expect(dump.path).toBe(IMPORT_RESULT.output);
    expect(useDumpStore.getState().dumps).toHaveLength(1);
  });

  it("sends just the path without options", async () => {
    fetchMock.mockResolvedValueOnce(jsonResponse(IMPORT_RESULT));
    await importDumpPath("/data/a.dump");
    expect(sentJson()).toEqual({ path: "/data/a.dump" });
  });

  it("forwards a memory map as maps_path", async () => {
    fetchMock.mockResolvedValueOnce(jsonResponse(IMPORT_RESULT));
    await importDumpPath("/data/a.dump", { regions: "heap", mapsPath: "/data/a.layout" });
    expect(sentJson()).toEqual({ path: "/data/a.dump", regions: "heap", maps_path: "/data/a.layout" });
  });
});

describe("encrypted .msl key material", () => {
  const km = { passphrase: "pw", key_hex: " 00ff ", kem_key_hex: "" };

  it("previewImport sends key material in the POST body, not the URL", async () => {
    fetchMock.mockResolvedValueOnce(jsonResponse({}));
    await previewImport("/data/e.msl", undefined, undefined, km);
    const [url] = fetchMock.mock.calls[0];
    expect(url).toBe("/api/dumps/preview");
    expect(sentJson()).toEqual({ path: "/data/e.msl", passphrase: "pw", key_hex: "00ff" });
  });

  it("uploadDump appends key fields and decrypt_output", async () => {
    fetchMock.mockResolvedValueOnce(jsonResponse(IMPORT_RESULT));
    await uploadDump(new File([new Uint8Array(4)], "e.msl"), {
      materialize: true,
      keyMaterial: km,
      decryptOutput: true,
    });
    const form = sentForm();
    expect(form.get("passphrase")).toBe("pw");
    expect(form.get("key_hex")).toBe("00ff");
    expect(form.has("kem_key_hex")).toBe(false);
    expect(form.get("decrypt_output")).toBe("true");
    expect(fetchMock.mock.calls[0][0]).toBe("/api/dumps/upload");
  });

  it("importDumpPath sends key fields and maps re-encryption outcome", async () => {
    fetchMock.mockResolvedValueOnce(
      jsonResponse({ ...IMPORT_RESULT, materialized: true, reencrypted: true, decrypted_output: false }),
    );
    const dump = await importDumpPath("/data/e.msl", { materialize: true, keyMaterial: { passphrase: "pw" } });
    expect(sentJson()).toEqual({ path: "/data/e.msl", materialize: true, passphrase: "pw" });
    expect(dump.reencrypted).toBe(true);
    expect(dump.decryptedOutput).toBe(false);
  });
});

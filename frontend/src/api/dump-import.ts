import { request } from "@/api/client";
import { keyMaterialWire } from "@/api/key-material-wire";
import type { ImportSelectionOptions, ImportSelectionResult } from "@/api/types";
import { useDumpStore } from "@/stores/dump-store";

/**
 * Shape returned by `POST /api/dumps/upload` and `POST /api/dumps/import-path`.
 * The selection fields are present only when a region selection was applied
 * (or a warning raised), so an import without options keeps the old shape.
 */
export interface DumpUploadResult extends ImportSelectionResult {
  source: string;
  output: string;
  regions_written: number;
  key_hints_written?: number;
  total_bytes: number;
}

/** A dump that now exists server-side and is registered in the dump store. */
export interface ImportedDump {
  id: string;
  path: string;
  name: string;
  /** Bytes written to the converted container (`total_bytes`). */
  size: number;
  /** Regions the converter wrote, surfaced by the Import tab's queue. */
  regionsWritten: number;
  /** Regions the selection dropped; absent when no selection was applied. */
  excludedRegionCount?: number;
  /** Captured bytes the selection dropped; absent when no selection was applied. */
  excludedBytes?: number;
  /** Known secrets that only occurred in excluded regions (selection only). */
  secretsOnlyInExcluded?: number;
  /** True when an `.msl` input was rewritten as a filtered copy. */
  materialized?: boolean;
  /** Encrypted source: the filtered copy was re-encrypted with the same key. */
  reencrypted?: boolean;
  /** Encrypted source: the filtered copy was written as plaintext (opt-in). */
  decryptedOutput?: boolean;
  /** Import warnings (e.g. secrets found only in excluded regions). */
  warnings?: string[];
}

/** Append only the selection options the caller actually set. */
function appendSelectionFields(form: FormData, opts?: ImportSelectionOptions): void {
  if (opts?.regions) form.append("regions", opts.regions);
  if (opts?.excludeRegions) form.append("exclude_regions", opts.excludeRegions);
  if (opts?.materialize) form.append("materialize", "true");
  for (const [name, value] of Object.entries(keyMaterialWire(opts?.keyMaterial))) {
    form.append(name, value);
  }
  if (opts?.decryptOutput) form.append("decrypt_output", "true");
}

/** FastAPI's `{"detail": "..."}` message, or `""` for a non-JSON body. */
async function failureDetail(res: Response): Promise<string> {
  try {
    const parsed = JSON.parse(await res.text()) as { detail?: unknown };
    return typeof parsed.detail === "string" ? parsed.detail : "";
  } catch {
    return "";
  }
}

/**
 * Upload one capture. The server converts it to `.msl` and answers with the
 * SERVER-SIDE path of the result — which is what every analysis endpoint
 * consumes. A browser `File` is not addressable by the backend, so this
 * round-trip is what turns a dropped file into something the session can
 * actually reason about.
 *
 * `opts` restricts the import to some region categories; omitted, everything
 * is imported (and an `.msl` upload is staged verbatim).
 */
export async function uploadDump(
  file: File,
  opts?: ImportSelectionOptions,
): Promise<DumpUploadResult> {
  const form = new FormData();
  form.append("file", file);
  appendSelectionFields(form, opts);
  const res = await fetch("/api/dumps/upload", { method: "POST", body: form });
  if (!res.ok) {
    const detail = await failureDetail(res);
    throw new Error(`Upload failed: ${res.status}${detail ? ` — ${detail}` : ""}`);
  }
  return (await res.json()) as DumpUploadResult;
}

/** Register a converted `.msl` in the dump store and describe it. */
function registerImported(data: DumpUploadResult): ImportedDump {
  // The label comes from the server-side name, which is now
  // `<dropped stem>-<uuid8>.msl` — recognisable AND unique. Using `file.name`
  // instead was tried and reverted: importing run_0001 and run_0002 of the same
  // tool (both literally named `memslicer.msl`) then produced two panes with
  // identical labels. The old bug was the opposite extreme — an unrecognisable
  // `tmpvqb05sie.msl` — and the server-side rename is what fixed that.
  const name = data.output.split(/[\\/]/).pop() || data.output;
  const id = useDumpStore.getState().addDump({
    path: data.output,
    name,
    size: data.total_bytes,
    format: "msl",
  });
  return {
    id,
    path: data.output,
    name,
    size: data.total_bytes,
    regionsWritten: data.regions_written,
    ...(data.excluded_region_count !== undefined
      ? { excludedRegionCount: data.excluded_region_count }
      : {}),
    ...(data.excluded_bytes !== undefined ? { excludedBytes: data.excluded_bytes } : {}),
    ...(data.secrets_only_in_excluded !== undefined
      ? { secretsOnlyInExcluded: data.secrets_only_in_excluded }
      : {}),
    ...(data.materialized !== undefined ? { materialized: data.materialized } : {}),
    ...(data.reencrypted !== undefined ? { reencrypted: data.reencrypted } : {}),
    ...(data.decrypted_output !== undefined
      ? { decryptedOutput: data.decrypted_output }
      : {}),
    ...(data.warnings ? { warnings: data.warnings } : {}),
  };
}

/**
 * Upload a capture AND register the converted `.msl` in the dump store.
 *
 * Every dropzone in the app must end here, so that a dump dropped anywhere
 * joins the ONE dump set the rest of the session works from. `addDump` also
 * puts the new dump into `selectedDumpIds`, so it immediately participates in
 * the analysis rather than living in a private, unrelated inbox.
 */
export async function importDumpFile(
  file: File,
  opts?: ImportSelectionOptions,
): Promise<ImportedDump> {
  return registerImported(await uploadDump(file, opts));
}

/** Options for importing a dump that already lives on the server. */
export interface ImportDumpPathOptions extends ImportSelectionOptions {
  /** Output directory; must lie inside the configured upload directory. */
  outputDir?: string;
  pid?: number;
  /** Raw input: `/proc/<pid>/maps`-style memory map (default: auto-detected sidecar). */
  mapsPath?: string;
}

/**
 * Convert a SERVER-SIDE dump (no upload round-trip) and register the result.
 * Same output-directory rules as an upload; the source file is left untouched.
 */
export async function importDumpPath(
  path: string,
  opts?: ImportDumpPathOptions,
): Promise<ImportedDump> {
  const data = await request<DumpUploadResult>("/api/dumps/import-path", {
    method: "POST",
    body: JSON.stringify({
      path,
      ...(opts?.outputDir ? { output_dir: opts.outputDir } : {}),
      ...(opts?.pid ? { pid: opts.pid } : {}),
      ...(opts?.regions ? { regions: opts.regions } : {}),
      ...(opts?.excludeRegions ? { exclude_regions: opts.excludeRegions } : {}),
      ...(opts?.materialize ? { materialize: true } : {}),
      ...keyMaterialWire(opts?.keyMaterial),
      ...(opts?.decryptOutput ? { decrypt_output: true } : {}),
      ...(opts?.mapsPath ? { maps_path: opts.mapsPath } : {}),
    }),
  });
  return registerImported(data);
}

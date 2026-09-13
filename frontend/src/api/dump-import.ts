import { useDumpStore } from "@/stores/dump-store";

/** Shape returned by `POST /api/dumps/upload`. */
export interface DumpUploadResult {
  source: string;
  output: string;
  regions_written: number;
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
}

/**
 * Upload one capture. The server converts it to `.msl` and answers with the
 * SERVER-SIDE path of the result — which is what every analysis endpoint
 * consumes. A browser `File` is not addressable by the backend, so this
 * round-trip is what turns a dropped file into something the session can
 * actually reason about.
 */
export async function uploadDump(file: File): Promise<DumpUploadResult> {
  const form = new FormData();
  form.append("file", file);
  const res = await fetch("/api/dumps/upload", { method: "POST", body: form });
  if (!res.ok) throw new Error(`Upload failed: ${res.status}`);
  return (await res.json()) as DumpUploadResult;
}

/**
 * Upload a capture AND register the converted `.msl` in the dump store.
 *
 * Every dropzone in the app must end here, so that a dump dropped anywhere
 * joins the ONE dump set the rest of the session works from. `addDump` also
 * puts the new dump into `selectedDumpIds`, so it immediately participates in
 * the analysis rather than living in a private, unrelated inbox.
 */
export async function importDumpFile(file: File): Promise<ImportedDump> {
  const data = await uploadDump(file);
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
  };
}

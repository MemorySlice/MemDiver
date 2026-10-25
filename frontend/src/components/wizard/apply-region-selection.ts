import { importDumpPath, type ImportedDump } from "@/api/dump-import";
import { keyMaterialWire } from "@/api/key-material-wire";
import type { ImportPreview, KeyMaterial, RegionCategory } from "@/api/types";
import {
  categoriesToSpec,
  isMslPath,
  selectionCounts,
} from "@/components/import/region-categories";

export interface RegionSelectionInput {
  inputMode: "file" | "directory" | "dataset";
  inputPath: string;
  categories: readonly RegionCategory[];
  /** `.msl` opt-in: write a filtered copy instead of filtering at analysis time. */
  materialize: boolean;
  /** Preview of the (first) input, when one was obtained. */
  preview: ImportPreview | null;
  /** Encrypted `.msl` + materialize: opens the source (request-scoped secret). */
  keyMaterial?: KeyMaterial;
  /** Encrypted `.msl` + materialize: write the copy as plaintext (opt-in). */
  decryptOutput?: boolean;
}

export interface RegionSelectionOutcome {
  /** Session `region_filter` to persist (`null` = every region). */
  regionFilter: string | null;
  /** Converted / filtered `.msl` the session should open instead of `inputPath`. */
  imported: ImportedDump | null;
}

/**
 * Turn the wizard's region choice into what the session actually runs on.
 *
 * - Directory / dataset input: dumps are opened in place, so the choice
 *   becomes the session `region_filter` (honoured for `.msl` dumps).
 * - A single `.msl`: non-destructive by default (session `region_filter`);
 *   with `materialize`, a filtered copy is imported and opened instead.
 * - A single raw / ELF-core / minidump: those sources ignore a view filter,
 *   so a selection that drops anything converts the file with `regions`
 *   (excluded regions keep their VAS_MAP entry, no bytes). A raw dump split
 *   by a memory map (`layout: "maps"`) converts with that same map.
 *
 * A selection that excludes nothing per the preview changes nothing, so the
 * historical "analyse the file as it is" path stays untouched.
 */
export async function applyRegionSelection(
  input: RegionSelectionInput,
): Promise<RegionSelectionOutcome> {
  const spec = categoriesToSpec(input.categories);
  if (input.inputMode !== "file") return { regionFilter: spec, imported: null };
  // A memory-image view (.mdview) is opened in place. "Importing" it as a raw
  // dump would convert the small descriptor FILE into an .msl and show its text
  // as memory; turning a process view into an .msl is extraction, not import.
  if (isImageView(input)) return { regionFilter: null, imported: null };

  const excludesSomething =
    spec !== null &&
    (input.preview === null ||
      selectionCounts(input.preview.totals, input.categories).excluded_count > 0);
  if (!excludesSomething || spec === null) return { regionFilter: null, imported: null };

  const isMsl = input.preview?.is_msl ?? isMslPath(input.inputPath);
  if (isMsl && !input.materialize) return { regionFilter: spec, imported: null };

  const mapsPath = layoutMapsPath(input.preview);
  const imported = await importDumpPath(input.inputPath, {
    regions: spec,
    ...(mapsPath ? { mapsPath } : {}),
    ...(isMsl ? { materialize: true } : {}),
    ...(isMsl && hasKeyMaterial(input.keyMaterial) ? { keyMaterial: input.keyMaterial } : {}),
    ...(isMsl && input.decryptOutput ? { decryptOutput: true } : {}),
  });
  // The written file already holds only the selected regions.
  return { regionFilter: null, imported };
}

/**
 * The memory map a raw preview was split by, so the conversion uses the same
 * regions the user selected from (also a map that is not an auto-detected
 * sidecar). `undefined` for layouts that need none.
 */
function layoutMapsPath(preview: ImportPreview | null): string | undefined {
  if (preview?.layout !== "maps") return undefined;
  return preview.maps_path ?? undefined;
}

/** True when at least one key field is non-blank (blank inputs send nothing). */
function hasKeyMaterial(km?: KeyMaterial): km is KeyMaterial {
  return Object.keys(keyMaterialWire(km)).length > 0;
}


/** True for a `.mdview` memory-image view (by preview, or by extension before one arrives). */
function isImageView(input: RegionSelectionInput): boolean {
  return Boolean(input.preview?.view_kind) || /\.mdview$/i.test(input.inputPath);
}

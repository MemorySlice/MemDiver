import type { SessionSnapshot } from "@/api/types";
import { useAppStore } from "@/stores/app-store";
import { useAnalysisStore } from "@/stores/analysis-store";
import { useHexStore } from "@/stores/hex-store";
import { useDumpStore } from "@/stores/dump-store";
import { useDumpRailStore } from "@/stores/dump-rail-store";
import { uiToApiInputMode, type UiInputMode } from "@/utils/input-mode";

/**
 * Build the saveSession() payload from the live stores. Single source of
 * truth shared by Workspace autosave (Ctrl+S) and SessionManager manual save
 * so the field set can't drift between the two sites.
 *
 * Two rules this file exists to enforce:
 *
 *  1. **Persist by PATH, never by id.** Dump ids are per-session
 *     `crypto.randomUUID()` values, so an id written to disk names nothing on
 *     the next load. Every id-keyed collection is translated here.
 *  2. **The explicit destructure IS the redaction.** `DumpEntry` carries
 *     `keyMaterial` (plaintext recovered secrets: passphrase, key_hex,
 *     kem_key_hex) and `tagStatus`, and sessions are unprotected gzipped JSON
 *     under `~/.memdiver/sessions/`. Writing `dumps: dumpState.dumps` would
 *     put secrets on disk; the four-field destructure below is what stops it,
 *     so it must never be replaced by a spread. `tagStatus` is dropped too —
 *     a stored `"valid"` without its key would make `TagStatusBadge` claim
 *     "unlocked" when the key is gone.
 */
export function buildSessionSnapshot(
  sessionName: string,
): Partial<SessionSnapshot> {
  const state = useAppStore.getState();
  const result = useAnalysisStore.getState().result;
  const bookmarks = useHexStore.getState().bookmarks;
  const dumpState = useDumpStore.getState();
  const railState = useDumpRailStore.getState();

  // Fields the React UI does not model. Forwarded from the last loaded
  // snapshot so that opening a Marimo-authored session and re-saving it
  // from the React workspace does not silently drop values.
  const preserved = state.lastLoadedSnapshot;

  const pathById = new Map(dumpState.dumps.map((d) => [d.id, d.path]));
  const toPath = (id: string | null): string | null =>
    id === null ? null : (pathById.get(id) ?? null);
  const toPaths = (ids: Iterable<string>): string[] => {
    const out: string[] = [];
    for (const id of ids) {
      const path = pathById.get(id);
      if (path !== undefined) out.push(path);
    }
    return out;
  };

  // Rail state is already path-keyed, but it outlives the dumps it describes:
  // prune entries for paths that are no longer loaded, or stale keys
  // accumulate forever across save/load cycles.
  const loadedPaths = new Set(pathById.values());
  const dumpWeights: Record<string, number> = {};
  // `weightByPath` is a Map and `visibleDumps`/`excludedPaths` are Sets, and
  // `JSON.stringify` turns ALL of them into `{}`. Every one is converted
  // explicitly below; none may be handed to the payload as-is.
  for (const [path, weight] of railState.weightByPath) {
    if (loadedPaths.has(path)) dumpWeights[path] = weight;
  }
  const excludedDumpPaths = [...railState.excludedPaths].filter((p) =>
    loadedPaths.has(p),
  );
  // "" rather than null: the wire contract declares `solo_dump_path` a plain
  // string, and sending null is rejected with a 422 that only surfaces against
  // a real backend -- never in tests that mock the API.
  const soloDumpPath =
    railState.soloPath !== null && loadedPaths.has(railState.soloPath)
      ? railState.soloPath
      : "";

  const originDumpPath = toPath(dumpState.originDumpId);

  return {
    session_name: sessionName,
    input_mode: uiToApiInputMode(state.inputMode as UiInputMode),
    // `input_path` stays the single-dump legacy field SessionLanding renders.
    // Fall back to the origin dump so a workspace assembled entirely through
    // AddDumpButton (which never touches `inputPath`) still shows something.
    input_path: state.inputPath || (originDumpPath ?? ""),
    dataset_root: state.datasetRoot,
    keylog_filename: state.keylogFilename,
    template_name: state.templateName,
    protocol_name: state.protocolName,
    protocol_version: state.protocolVersion,
    scenario: state.scenario,
    selected_libraries: state.selectedLibraries,
    selected_phase: state.selectedPhase,
    mode: state.mode,
    selected_algorithms: [...state.selectedAlgorithms],
    algorithm: preserved?.algorithm ?? "",
    max_runs: preserved?.max_runs ?? 10,
    normalize_phases: preserved?.normalize_phases ?? false,
    single_file_format: preserved?.single_file_format ?? "",
    ground_truth_mode: preserved?.ground_truth_mode ?? "auto",
    analysis_result: result
      ? (result as unknown as Record<string, unknown>)
      : null,
    bookmarks,
    investigation_offset: null,

    // --- Multi-dump workspace ---------------------------------------------
    // The destructure below is the redaction. Never `dumps: dumpState.dumps`.
    dumps: dumpState.dumps.map(({ path, name, size, format }) => ({
      path,
      name,
      size,
      format,
    })),
    active_dump_path: toPath(dumpState.activeDumpId),
    selected_dump_paths: toPaths(dumpState.selectedDumpIds),
    // `visibleDumps` is a COLLAPSED set despite its name; the misnomer stops
    // at this boundary rather than reaching disk.
    collapsed_dump_paths: toPaths(dumpState.visibleDumps),
    origin_dump_path: originDumpPath,
    main_view: dumpState.mainView,
    aslr_normalize: dumpState.aslrNormalize,

    dump_weights: dumpWeights,
    excluded_dump_paths: excludedDumpPaths,
    solo_dump_path: soloDumpPath,
    rail_collapsed: railState.collapsed,
  } as Partial<SessionSnapshot>;
}

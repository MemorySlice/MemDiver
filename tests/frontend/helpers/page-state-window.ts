import { vi } from "vitest";

import type {
  AlignedWindowPageStateRun,
  AlignedWindowRequest,
  AlignedWindowResponse,
} from "@/api/aligned-window";
import type { DumpEntry } from "@/stores/dump-store";

/**
 * A realistic aligned window for the page-state tests: the anchor's first
 * three rows sit in FAILED / UNMAPPED / NOT_RESIDENT pages, which the aligned
 * layout never captured, so they are gaps for EVERY dump (`classes = -1`,
 * outside `bytes_valid`) and only the anchor carries `page_states` for them —
 * exactly what the backend sends.
 */
export const TINTED_ROWS = 3;
const ROW = 16;
const TINTED = TINTED_ROWS * ROW;

export const ANCHOR_RUNS: AlignedWindowPageStateRun[] = [
  [0, ROW, "FAILED"],
  [ROW, ROW, "UNMAPPED"],
  [2 * ROW, ROW, "NOT_RESIDENT"],
];

export function mslEntry(i: number): DumpEntry {
  return {
    id: `d${i}`,
    path: `/dumps/d${i}.msl`,
    name: `d${i}.msl`,
    size: 64 * 1024,
    format: "msl",
    sameProcess: true,
  };
}

/** The window the backend answers `req` with: runs only on `req.anchor_path`. */
export function pageStateWindow(req: AlignedWindowRequest): AlignedWindowResponse {
  const length = req.length ?? 8192;
  const paths = req.dumps ?? [];
  const classes = new Array<number>(length).fill(0);
  for (let i = 0; i < TINTED; i++) classes[i] = -1;
  const bytes = new Array<number>(length).fill(0).map((_, i) => (i < TINTED ? 0 : 0x41));
  return {
    consensus_id: req.consensus_id ?? null,
    classified: true,
    alignment: {
      method: "virtual_address",
      bytes_compared: length - TINTED,
      bytes_discarded: 0,
      sizes_differed: false,
      n_sources: paths.length,
      warnings: [],
    },
    anchor: {
      kind: "dump",
      dump_path: req.anchor_path ?? null,
      dump_index: Math.max(0, paths.indexOf(req.anchor_path ?? "")),
      view: req.view ?? "va",
      offset: req.offset ?? 0,
      va: 0,
      va_span_start: 0,
      slab_offset: 0,
    },
    requested_length: length,
    length,
    truncated: false,
    classes,
    variants: classes.map((c) => (c === -1 ? 0 : 1)),
    gaps: [[0, TINTED]],
    segments: [],
    dumps: paths.map((path, index) => ({
      dump_index: index,
      dump_path: path,
      format: "msl",
      view: req.view ?? "va",
      bytes: btoa(String.fromCharCode(...bytes)),
      bytes_valid: [[TINTED, length - TINTED]],
      page_states: path === req.anchor_path && req.offset === 0 ? ANCHOR_RUNS : [],
      key_status: { decrypted: true, hint: null, tag_status: "not_encrypted" as const },
    })),
  };
}

/**
 * Answers the `.msl` view-size probe (`useMslViewSizes`) so the window loader
 * is allowed to fire; every other `fetch` never settles.
 */
export function stubViewSizeProbe(size = 64 * 1024): void {
  vi.stubGlobal(
    "fetch",
    vi.fn((url: string) => {
      if (!String(url).includes("/api/inspect/hex-raw")) return new Promise(() => {});
      return Promise.resolve({
        ok: true,
        json: async () => ({ file_size: size, format: "msl", distinct_views: ["raw", "vas", "va"] }),
      });
    }),
  );
}

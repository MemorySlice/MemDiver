/**
 * Typed client for the aligned-window surface:
 *   `POST /api/analysis/consensus/aligned-window`
 *
 * One request returns, for a single window of the ANCHOR dump's coordinate
 * space, the corresponding bytes of every other dump in the consensus build —
 * already re-indexed into window space. It is what backs the N-pane hex
 * viewer: N panes, one round trip, one alignment.
 *
 * ── Invariant W1 (the whole point of this endpoint) ───────────────────────────
 * For every dump `d` and every `i` in `[0, length)`, `dumps[d].bytes[i]` is the
 * byte dump `d` holds at the address the consensus put in correspondence with
 * the anchor's byte at `offset + i`. EVERYTHING IS ALREADY IN WINDOW INDEX
 * SPACE.
 *
 * The client must therefore NEVER do coordinate arithmetic on `va` / `offset`
 * to place bytes. `segments[].dumps[].va` and `.offset` are provenance for
 * display only ("this run of the window came from 0x7f…12340 in dump 3"), never
 * an input to an index computation. Two real bugs in this repo came from
 * client-side coordinate math — the consensus overlay painted in slab
 * coordinates onto a `.msl` VA view, and the `vaSpanStart` rebasing raced the
 * chunk fetch — and in both cases the symptom was *plausible bytes in the wrong
 * place*, which no type checker and no smoke test catches. Index with `i`.
 *
 * Where no correspondence exists, all four of these hold together: `i` is
 * inside a `gaps` run, `classes[i] === -1`, `bytes[i] === 0`, and `i` is
 * OUTSIDE every `bytes_valid` run. `bytes_valid` is the ONLY way to tell a real
 * `0x00` apart from an absent byte.
 */

import { request } from "./client";

/** Which coordinate space the caller is navigating in. */
export type AlignedWindowView = "raw" | "vas" | "va";

/**
 * The coordinate the RESPONSE reports the anchor in.
 *
 * Strictly wider than `AlignedWindowView`: when `anchor.kind === "slab"` the
 * window was addressed in the consensus's own aligned-slab coordinate, which is
 * not a navigable dump view at all and which the backend reports as `"slab"`.
 * Kept as a separate alias — rather than widening `AlignedWindowView` — so that
 * the REQUEST field stays a real view the hex viewer can navigate, and so a
 * `switch` over a `HexViewMode` can never silently receive `"slab"`.
 */
export type AlignedWindowAnchorView = AlignedWindowView | "slab";

/** Per-dump key material, mirroring the `KeyMaterial` query fields elsewhere. */
export interface AlignedWindowKey {
  dump_path: string;
  passphrase?: string;
  key_hex?: string;
  kem_key_hex?: string;
}

export interface AlignedWindowRequest {
  /** Exactly one of `consensus_id` / `dump_paths`. */
  consensus_id?: string;
  /** The no-consensus fallback: align these dumps ad hoc. */
  dump_paths?: string[];
  anchor: "dump" | "slab";
  /** Required when `anchor === "dump"`. */
  anchor_path?: string;
  /** The anchor's OWN navigable offset. */
  offset?: number;
  /** The anchor's coordinate. */
  view?: AlignedWindowView;
  /** Required when `anchor === "slab"`. */
  slab_offset?: number;
  length?: number;
  /** Subset of the build; default = the whole build. */
  dumps?: string[];
  include_bytes?: boolean;
  keys?: AlignedWindowKey[];
}

export interface AlignedWindowAlignment {
  method: "module_offset" | "virtual_address" | "file_offset";
  bytes_compared: number;
  bytes_discarded: number;
  sizes_differed: boolean;
  n_sources: number;
  warnings: string[];
}

export interface AlignedWindowAnchor {
  kind: "dump" | "slab";
  /** `null` when `kind === "slab"` — a slab window belongs to no one dump. */
  dump_path: string | null;
  /** `-1` when `kind === "slab"`. */
  dump_index: number;
  /**
   * `"slab"` whenever `kind === "slab"`; otherwise the anchor dump's own view.
   *
   * NOT an `AlignedWindowView`. Anything that feeds this to a viewer — a
   * `HexViewMode` prop, a coordinate switch — must narrow it first; treating
   * `"slab"` as a navigable view is how a slab-coordinate window ends up
   * painted onto a dump's byte stream.
   */
  view: AlignedWindowAnchorView;
  offset: number;
  /** `-1` when `kind === "slab"` (no virtual address). */
  va: number;
  /** `-1` when `kind === "slab"`. */
  va_span_start: number;
  /** `-1` when the window covers no segment at all. */
  slab_offset: number;
}

/** Provenance for one run of the window. Display only — never index math. */
export interface AlignedWindowSegment {
  window_offset: number;
  length: number;
  slab_offset: number;
  dumps: {
    dump_index: number;
    /**
     * `-1` on the `file_offset` and unclassified alignment paths: those runs
     * have NO virtual address, and `-1` is the sentinel that says so. Render it
     * as "—", never as an address, and never subtract it from anything.
     */
    va: number;
    /** A real stream offset on every path, including where `va === -1`. */
    offset: number;
  }[];
}

export interface AlignedWindowDump {
  dump_index: number;
  dump_path: string;
  format: string;
  view: string;
  /** base64, decoding to EXACTLY `length` bytes; `null` = locked. */
  bytes: string | null;
  /** Present-byte runs as `[start, runLength]`. THE presence mask. */
  bytes_valid: [number, number][];
  key_status: {
    decrypted: boolean;
    hint: string | null;
    /**
     * Why the dump is (or is not) readable, independent of `decrypted`:
     * `"not_encrypted"` needs no key at all, `"missing_key"` is awaiting one,
     * `"corrupted"` will never decrypt with any key.
     */
    tag_status: "not_encrypted" | "missing_key" | "corrupted";
  };
}

export interface AlignedWindowResponse {
  consensus_id: string | null;
  /** `false` => every entry of `classes` is `-1`. */
  classified: boolean;
  alignment: AlignedWindowAlignment;
  anchor: AlignedWindowAnchor;
  requested_length: number;
  /** AFTER clamping — this, not `requested_length`, is the array length. */
  length: number;
  truncated: boolean;
  /** `length` entries; `-1` = gap / unclassified. */
  classes: number[];
  /** `[window_offset, run_length]` runs with no correspondence. */
  gaps: [number, number][];
  segments: AlignedWindowSegment[];
  dumps: AlignedWindowDump[];
}

/**
 * Fetch one aligned window. Errors surface as `ApiError` from `./client`, the
 * same as every other typed client in this directory.
 */
export function fetchAlignedWindow(
  req: AlignedWindowRequest,
): Promise<AlignedWindowResponse> {
  return request<AlignedWindowResponse>("/api/analysis/consensus/aligned-window", {
    method: "POST",
    body: JSON.stringify(req),
  });
}

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
import { useDumpStore } from "@/stores/dump-store";

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

/**
 * Key material for the paths a request may need to OPEN, secret-less dumps left out.
 *
 * The `consensus_id` branch only ever opens the anchor, but the `dump_paths`
 * branch resolves key material across the whole set, so both are offered and
 * the backend picks. Deduplicates `paths` -- a repeated path would otherwise
 * emit a repeated `keys` entry.
 */
export function keysForPaths(paths: readonly string[]): AlignedWindowKey[] {
  const lookup = useDumpStore.getState().getKeyMaterialByPath;
  const keys: AlignedWindowKey[] = [];
  for (const dump_path of new Set(paths)) {
    const material = lookup(dump_path);
    if (!material) continue;
    if (!material.passphrase && !material.key_hex && !material.kem_key_hex) continue;
    keys.push({
      dump_path,
      ...(material.passphrase ? { passphrase: material.passphrase } : {}),
      ...(material.key_hex ? { key_hex: material.key_hex } : {}),
      ...(material.kem_key_hex ? { kem_key_hex: material.kem_key_hex } : {}),
    });
  }
  return keys;
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

/**
 * Provenance for one run of the window. Display only — never index math.
 *
 * ── TODO (backend): explicit RE-ANCHOR SEAM markers ─────────────────────────
 * The design asks for a dashed rule between hex rows wherever a dump's delta is
 * re-anchored partway through the span (`re-anchor · dump 03 · Δ +0x40 from
 * here`), carrying the caution that *a stable run that ends at a seam is a
 * mapping artefact, not a finding*. The client CANNOT honestly compute that, and
 * this note records why rather than leaving the next reader to re-derive it:
 *
 *   1. A seam is, by definition, a place where the mapping from the anchor's
 *      coordinate to a PEER's coordinate changes slope. Detecting it means
 *      differencing `dumps[].va` (or `.offset`) across two segments — exactly
 *      the peer-coordinate arithmetic invariant W1 forbids, and exactly what
 *      `DumpRail` already refused to do for the per-dump Δ column.
 *   2. `segments[].window_offset` boundaries are computable here and require no
 *      such arithmetic — but they are a strict SUPERSET of the seams. A new
 *      segment is emitted at every mapping/page boundary and at every gap,
 *      almost all of which carry the SAME delta. Drawing those as "re-anchor"
 *      would manufacture the mapping-artefact confusion the caution exists to
 *      warn about, which is worse than drawing nothing.
 *   3. `alignment` carries nothing per dump (method, bytes_compared,
 *      bytes_discarded, sizes_differed, n_sources, warnings), and the store
 *      keeps no segments at all, so there is no third source to appeal to.
 *
 * What would make it honest, in the one place the arithmetic is legitimate —
 * `app/tools_consensus.py`, which holds every dump's `msl_layout` and computes
 * the correspondence in the first place:
 *
 *   - Add `seams: { window_offset: number; dump_index: number; delta: number }[]`
 *     to `AlignedWindowResponse`, emitted ONLY where the producer observes the
 *     anchor→peer delta actually change between two adjacent correspondence
 *     runs — never merely where a new `msl_layout` row starts.
 *   - `window_offset` must be in window index space, like every other offset in
 *     this response, so the client can place the rule with `i` alone.
 *   - `delta` is the signed change (peer coordinate minus the previous run's),
 *     already differenced server-side; the client renders it and never
 *     recomputes it.
 *   - Emit nothing on the `file_offset` path: a flat build has no mapping to
 *     re-anchor, so an empty array there is the correct answer, not a gap.
 *
 * Until that field exists, `HexOverlayPane` renders no seam rules, and its
 * virtualizer keeps its fixed 20px row geometry.
 */
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
  /**
   * `length` entries, one per window index like `classes`: how many DISTINCT
   * byte values the dumps present at that index hold. `0` = nobody is present
   * there, `1` = every present dump agrees. Locked dumps (`bytes === null`)
   * contribute nothing, so they never add a variant.
   *
   * THE cross-dump disagreement answer as well, and the only one on the wire:
   * an index is a DIFFER iff `variants[i] >= 2`. That is exactly "at least TWO
   * dumps are PRESENT there (inside their `bytes_valid`) and at least two of
   * those present values differ" — one present dump counts `1` and an empty
   * index counts `0`, so `>= 2` is unreachable without two present dumps
   * holding two values. A byte only one dump holds is NOT a difference:
   * absence is a separate finding, and counting it would flag every unmapped
   * hole in every dump. The response used to carry a redundant boolean
   * `differs` run list saying precisely this; it was removed rather than kept
   * as a second field that must always agree with this one.
   *
   * Computed over exactly the dumps this request asked for, which is why it is
   * server-side: a client reducer over a byte cache also sees dumps that have
   * since left the selection.
   *
   * Weight-independent by design — it counts values, not a plurality. The
   * weighted "consensus byte" stays a client computation because it must
   * answer live to the user's per-dump weights.
   */
  variants: number[];
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

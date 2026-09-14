/**
 * Typed client for the consensus-regions surface:
 *   `POST /api/analysis/consensus/regions`
 *
 * One request returns ONE PAGE of "every occurrence of a consensus class",
 * offset-ordered and JUMPABLE — the list behind "show me every key candidate",
 * where clicking a row scrolls the hex viewer to that byte.
 *
 * ── Fact 1: `anchor_offset` IS `hex-store.scrollToOffset`'s argument ─────────
 * Unmodified. Verbatim. The server performed the slab -> VA -> navigable-offset
 * conversion (`app.tools_consensus._region_locator`) precisely so that no
 * client ever has to, because the overlay navigates in `"vas"` while the single
 * viewer navigates in `"va"` and a VA alone would force every caller to
 * re-implement `_translate_va`.
 *
 * ANY client-side adjustment of this number is a bug. Not "risky" — a bug. The
 * two overlay defects this repo already shipped were both client-side
 * coordinate math (the consensus overlay painting in slab coordinates onto a
 * `.msl` VA view; the `vaSpanStart` rebasing racing the chunk fetch), and in
 * both cases the symptom was *plausible bytes in the wrong place*, which no
 * type checker and no smoke test catches. Pass the number through.
 *
 * ── Fact 2: `-1` means "no honest answer", NEVER 0 ──────────────────────────
 * The convention `ConsensusVector.slab_to_va` set, carried through every
 * anchor-derived field here. `anchor_offset === -1` is produced by, at least:
 * a raw/flat build queried in `"va"`, a LOCKED anchor container (reported, not
 * raised — a page of regions is still useful without a key), and a slab offset
 * outside `msl_layout`. `anchor.jumpable === false` is the page-level form of
 * exactly the same statement, sent once so a caller can hide the jump
 * affordance instead of inferring a refusal from a sea of `-1`s. Render `-1` as
 * "—", never as an address or an offset, and never subtract it from anything.
 *
 * ── Fact 3: a region is contiguous in SLAB space, not in the anchor's ───────
 * `msl_layout` rows are PER PAGE and `slab_to_va` is linear only WITHIN a row,
 * so a region spanning a row boundary is one run in slab space and two disjoint
 * runs in the anchor's own coordinate. That is why `anchor_offset_end` is
 * resolved from the region's LAST byte rather than from
 * `anchor_offset + length`, and why `anchor_contiguous` exists.
 *
 * NEVER render `length` as though it were a VA span. `length` is the SLAB
 * length. When describing the jump target — a highlight, a "48 bytes at
 * 0x…" label, a selection extent — use `anchorSpan(region)`
 * (`anchor_offset_end - anchor_offset`), which is the range that actually gets
 * selected, and consult `anchor_contiguous` to know whether that range IS the
 * region or merely CONTAINS it.
 *
 * ── `classes: null` is the NON-INVARIANT UNION, deliberately ────────────────
 * Not "every class", and emphatically not "key_candidate". Real key material is
 * class-MIXED. Measured on real data: a planted 48-byte TLS secret classifies
 * as 27 key_candidate + 18 pointer + 3 structural bytes, and the naive query
 * `classes=["key_candidate"], min_length=8` returns **total 0** — the secret is
 * shattered into shards shorter than any sane `min_length` and is lost
 * entirely. The union over STRUCTURAL/POINTER/KEY_CANDIDATE keeps it whole, so
 * it is the default, and `"non_invariant"` names it explicitly for a caller
 * that passes `classes` at all.
 */

import { request } from "./client";
import type {
  AlignedWindowAlignment,
  AlignedWindowKey,
  AlignedWindowView,
} from "./aligned-window";
import type { ByteClassName } from "./candidates";

/**
 * The anchor's navigable coordinate.
 *
 * The same three values as `AlignedWindowView` and `HexViewMode`, aliased
 * rather than redeclared so a `HexViewMode` can be handed straight to
 * `anchor_view` and a widening of one can never drift from the other. Unlike
 * `AlignedWindowAnchorView` this never carries `"slab"`: this route takes no
 * slab anchor, because a slab offset is not a coordinate a viewer can scroll.
 */
export type RegionAnchorView = AlignedWindowView;

/** What coordinate the CONSENSUS itself was built in (`_coordinate_of`). */
export type RegionCoordinate = "aligned" | "flat" | "raw_file";

/** The union alias that names "every non-invariant class" on the wire. */
export const NON_INVARIANT_UNION = "non_invariant" as const;

/** A class filter entry: a class name, or the union alias. */
export type RegionClassSpec = ByteClassName | typeof NON_INVARIANT_UNION;

/**
 * The order one page of regions comes back in.
 *
 * `"offset"` is the historical order and the server default. The two length
 * orders exist for the question this route is actually asked — "show me the
 * 32-byte runs first" — and they change what the CURSOR counts in: under
 * `"offset"` `next_after` is a slab offset, under either length sort it is a
 * rank index. Neither is a number a client may interpret; see
 * {@link NO_HONEST_ANSWER}.
 */
export type RegionSort = "offset" | "length_desc" | "length_asc";

/** Server default (`api.models.ConsensusRegionsRequest.sort`). */
export const DEFAULT_REGION_SORT: RegionSort = "offset";

/** Server default (`api.models.ConsensusRegionsRequest.min_length`). */
export const DEFAULT_REGION_MIN_LENGTH = 8;

/** Server default page size (`app.tools_consensus.DEFAULT_REGIONS_PER_PAGE`). */
export const DEFAULT_REGIONS_PER_PAGE = 200;

/** Hard server cap (`app.tools_consensus.MAX_REGIONS_PER_PAGE`); 501 is a 422. */
export const MAX_REGIONS_PER_PAGE = 500;

/**
 * The `-1` sentinel, spelled once.
 *
 * It means three different things in three places and the SAME thing in all of
 * them — "there is no honest answer here":
 *   - `after: -1`        -> start from the beginning (no cursor yet)
 *   - `next_after: -1`   -> end of list (no further page)
 *   - `anchor_*: -1`     -> this anchor coordinate could not be resolved
 * It is never a plausible value, which is the whole point: a `0` would be.
 *
 * `-1` is also the ONLY value of a cursor a client may reason about. Since
 * {@link RegionSort}, the cursor's UNIT follows `sort`: a slab offset under
 * `"offset"`, a RANK INDEX into the sorted list under either length sort. Treat
 * it as OPAQUE — hand `next_after` straight back as the next `after`, compare
 * it to `-1`, and never do arithmetic on it or render it as an address.
 */
export const NO_HONEST_ANSWER = -1;

/** `after` for the FIRST page. Alias of {@link NO_HONEST_ANSWER}, for reading. */
export const REGION_CURSOR_START = NO_HONEST_ANSWER;

export interface ConsensusRegionsRequest {
  /**
   * Exactly one of `consensus_id` / `dump_paths`.
   *
   * Enforced at the boundary with a 400, for the reason the aligned-window
   * route gives: "which correspondence are these regions in" has to have
   * exactly one answer. Use {@link buildConsensusRegionsRequest} and the
   * either/or becomes unrepresentable rather than merely documented.
   */
  consensus_id?: string;
  /** The no-consensus fallback: build over these dumps ad hoc. */
  dump_paths?: string[];
  /**
   * `null` / omitted = the NON-INVARIANT UNION. See the module doc: a
   * `["key_candidate"]` query returns total 0 for a real, planted secret.
   */
  classes?: RegionClassSpec[] | null;
  /** Shortest region to report, in SLAB bytes. Server default 8. */
  min_length?: number;
  /** Longest region to report; `0` is unbounded (backend contract). */
  max_length?: number;
  /** Page order. Server default `"offset"`; see {@link RegionSort}. */
  sort?: RegionSort;
  /**
   * Exclusive cursor — the previous page's `next_after` verbatim. `-1` starts.
   *
   * OPAQUE. Its unit follows {@link ConsensusRegionsRequest.sort}: a slab
   * offset under `"offset"`, a rank index into the sorted list under
   * `"length_desc"` / `"length_asc"`. A client hands it back and compares it to
   * `-1`; it never adds to it, and never shows it as an offset.
   */
  after?: number;
  /** Rows per page. `1..500`; outside that the route answers 422, not a clamp. */
  limit?: number;
  /** The dump whose coordinate the jump offsets are expressed in. */
  anchor_path?: string;
  /** That dump's navigable view. Server default `"va"`. */
  anchor_view?: RegionAnchorView;
  /**
   * `false` skips OPENING the anchor entirely: no offsets, `jumpable: false`.
   * The cheap path for a caller that only wants `total` and `counts`.
   */
  include_anchor_offsets?: boolean;
  normalize?: boolean;
  /**
   * Load-bearing, not decoration: resolving a `"vas"` anchor offset means
   * OPENING — and therefore decrypting — the anchor container. Which is also
   * why this route is POST: key material must stay out of access logs, shell
   * history and `Referer`.
   */
  keys?: AlignedWindowKey[];
}

/** Which dump the page's jump offsets are expressed in, and whether they exist. */
export interface ConsensusRegionsAnchor {
  /** `null` when the request named no anchor. */
  dump_path: string | null;
  /** Index within the build; `-1` when there is no anchor. */
  dump_index: number;
  /** The requested view, echoed. */
  view: RegionAnchorView;
  /**
   * The page-level form of Fact 2: `false` means EVERY row's `anchor_offset` is
   * `-1` and the jump affordance should be hidden, not attempted. A locked
   * anchor lands here rather than raising, because the regions themselves come
   * from the consensus and are unaffected by the missing key.
   */
  jumpable: boolean;
}

/** One region, with the coordinates a viewer can actually be scrolled to. */
export interface ClassRegion {
  /** Inclusive start in SLAB space — the pagination cursor's coordinate. */
  slab_start: number;
  /** Exclusive end in SLAB space. */
  slab_end: number;
  /**
   * `slab_end - slab_start`. The SLAB length.
   *
   * NOT a VA span and NOT a selection extent. See Fact 3: use
   * {@link anchorSpan} whenever describing the jump target.
   */
  length: number;
  /** The region's own class label — never inferred from `mean_variance`. */
  classification: ByteClassName;
  mean_variance: number;
  /**
   * Per-class byte counts INSIDE this region. `{}` for a single-class query,
   * where it would be a tautology (`length` already says it).
   *
   * For a union it is the fact that makes the union defensible: it shows that a
   * 48-byte row really is 27 key_candidate + 18 pointer + 3 structural and not
   * a pointer run that drifted in.
   */
  class_counts: Partial<Record<ByteClassName, number>>;
  /** The anchor's virtual address of the FIRST byte. `-1` = no honest answer. */
  anchor_va: number;
  /**
   * `hex-store.scrollToOffset`'s argument, verbatim. `-1` = not jumpable.
   * See Fact 1 — do not adjust this number for any reason.
   */
  anchor_offset: number;
  /**
   * One past the anchor offset of the region's LAST byte. `-1` = unresolved.
   *
   * Resolved from the last byte, NOT from `anchor_offset + length`, because of
   * Fact 3. `extendSelection` therefore takes `anchor_offset_end - 1`.
   */
  anchor_offset_end: number;
  /**
   * Does `[anchor_offset, anchor_offset_end)` EQUAL the region, or merely
   * contain it? `false` means the slab run crossed an `msl_layout` page
   * boundary and the anchor-space range is a superset — highlight it as an
   * approximation, and say so.
   */
  anchor_contiguous: boolean;
}

export interface ConsensusRegionsResponse {
  /** `null` on the `dump_paths` branch: no session was registered to name. */
  consensus_id: string | null;
  coordinate: RegionCoordinate;
  alignment: AlignedWindowAlignment;
  anchor: ConsensusRegionsAnchor;
  /** The RESOLVED class list the page was computed over, always explicit. */
  classes: ByteClassName[];
  /** `true` when `classes` holds more than one — i.e. this page is a union. */
  union: boolean;
  min_length: number;
  max_length: number;
  /** The order this page was computed in, echoed. See {@link RegionSort}. */
  sort: RegionSort;
  /** The cursor this page was asked for, echoed. `-1` = this was page one. */
  after: number;
  /**
   * The cursor for the NEXT page, or `-1` for END OF LIST.
   *
   * `-1` here is not "offset zero" and not "unknown": the server sets it only
   * when it actually saw one region past the page. Use {@link hasNextPage}.
   *
   * OPAQUE, and its unit follows `sort` — a slab offset under `"offset"`, a
   * rank index under either length sort. Hand it back as the next `after`;
   * `-1` is the only comparison a client is entitled to make on it.
   */
  next_after: number;
  /** Size of the WHOLE result set, not of this page. Stated against `returned`. */
  total: number;
  returned: number;
  truncated: boolean;
  /**
   * The WHOLE-BUILD class histogram, shipped with every page so the chip counts
   * beside the list ("key_candidate 1.2M") cost no second round trip.
   */
  counts: Partial<Record<ByteClassName, number>>;
  regions: ClassRegion[];
}

/**
 * The either/or, as a type.
 *
 * A discriminated source makes "neither or both" — the route's two 400s —
 * unrepresentable at the call site instead of merely documented on two optional
 * fields.
 */
export type ConsensusRegionsSource =
  | { consensusId: string }
  | { dumpPaths: readonly string[] };

/** Everything about the QUERY, as opposed to the correspondence it runs over. */
export interface ConsensusRegionsQuery {
  /** `null` (or omitted) = the non-invariant union. See the module doc. */
  classes?: RegionClassSpec[] | null;
  minLength?: number;
  maxLength?: number;
  sort?: RegionSort;
  after?: number;
  limit?: number;
  anchorPath?: string | null;
  anchorView?: RegionAnchorView;
  includeAnchorOffsets?: boolean;
  normalize?: boolean;
  keys?: AlignedWindowKey[];
}

/**
 * Compose one request body.
 *
 * Every field the query cares about is sent EXPLICITLY, even where it equals
 * the server default, so the body reads as the query that actually ran — the
 * `buildCandidatesRequest` precedent. The one field that is conditionally
 * omitted is `keys`, which is empty far more often than not and whose presence
 * in a log line is the thing this route exists to avoid.
 *
 * `classes` is passed through UNCHANGED, `null` included: `null` is a real,
 * load-bearing value here (the non-invariant union) and defaulting it to
 * anything else would reintroduce the shattered-key bug the module doc
 * measures.
 */
export function buildConsensusRegionsRequest(
  source: ConsensusRegionsSource,
  query: ConsensusRegionsQuery = {},
): ConsensusRegionsRequest {
  const body: ConsensusRegionsRequest = {
    ...("consensusId" in source
      ? { consensus_id: source.consensusId }
      : { dump_paths: [...source.dumpPaths] }),
    classes: query.classes ?? null,
    min_length: query.minLength ?? DEFAULT_REGION_MIN_LENGTH,
    max_length: query.maxLength ?? 0,
    sort: query.sort ?? DEFAULT_REGION_SORT,
    after: query.after ?? REGION_CURSOR_START,
    limit: query.limit ?? DEFAULT_REGIONS_PER_PAGE,
    anchor_view: query.anchorView ?? "va",
    include_anchor_offsets: query.includeAnchorOffsets ?? true,
    normalize: query.normalize ?? false,
  };
  // `anchor_path` is omitted rather than sent as null: its ABSENCE is what
  // tells the producer not to open any container at all, and Pydantic's
  // `str | None` accepts both spellings, so the cheaper one wins.
  if (query.anchorPath) body.anchor_path = query.anchorPath;
  if (query.keys && query.keys.length > 0) body.keys = query.keys;
  return body;
}

/** Is there a further page? `next_after === -1` is END, not offset zero. */
export function hasNextPage(response: ConsensusRegionsResponse): boolean {
  return response.next_after !== NO_HONEST_ANSWER;
}

/**
 * Can this row be jumped to at all?
 *
 * The per-row form of `anchor.jumpable`. Checked against `< 0` rather than
 * `=== -1` so that any future sentinel in the same family still reads as a
 * refusal instead of as a wild offset.
 */
export function isJumpable(region: Pick<ClassRegion, "anchor_offset">): boolean {
  return region.anchor_offset >= 0;
}

/**
 * The region's extent IN THE ANCHOR'S COORDINATE, or `-1` if unresolved.
 *
 * THE function to reach for when describing a jump target. `length` is the
 * SLAB length and is NOT interchangeable with this (Fact 3): where a region
 * crosses an `msl_layout` page boundary the two differ, and rendering `length`
 * as the highlighted span paints a range the viewer never selected.
 */
export function anchorSpan(
  region: Pick<ClassRegion, "anchor_offset" | "anchor_offset_end">,
): number {
  if (region.anchor_offset < 0 || region.anchor_offset_end < 0) {
    return NO_HONEST_ANSWER;
  }
  return region.anchor_offset_end - region.anchor_offset;
}

/**
 * Fetch one page of regions. Errors surface as `ApiError` from `./client`, the
 * same as every other typed client in this directory.
 */
export function fetchConsensusRegions(
  req: ConsensusRegionsRequest,
): Promise<ConsensusRegionsResponse> {
  return request<ConsensusRegionsResponse>("/api/analysis/consensus/regions", {
    method: "POST",
    body: JSON.stringify(req),
  });
}

/**
 * Typed client for the key-location spine:
 *   `POST /api/analysis/locate-key`   — where does a KNOWN secret live?
 *   `POST /api/analysis/key-pattern`  — turn that location into a signature.
 *
 * Mirrors the Pydantic `LocateKeyRequest` / `KeyPatternRequest` (api/models.py)
 * and the payloads of `app.tools_pipeline.locate_key` /
 * `export_key_pattern` 1:1, following the `./candidates` precedent: request and
 * response shapes live here so a backend change lands in one file rather than in
 * every component that fetches.
 *
 * Unlike every other analysis route, `locateKey` accepts a SINGLE dump: locating
 * a key in one dump is a complete answer. `exportKeyPattern` needs two, because
 * a static mask is a comparison.
 */

import { request } from "./client";

// ---- the three-valued per-dump status (engine/key_location.py) ----

/**
 * Exported as a const TUPLE, with the union type DERIVED from it, so a backend
 * rename breaks `npx tsc -b` here instead of silently producing a `status` no
 * branch matches. Same reason the verdicts below are spelled the same way.
 */
export const KEY_LOCATION_STATUSES = [
  "searched",
  "unreadable",
  "too_small",
] as const;

export type KeyLocationStatus = (typeof KEY_LOCATION_STATUSES)[number];

/**
 * The cross-dump verdict. `"not_searched"` claims NOTHING — it is neither a
 * presence nor an absence, and a consumer MUST render it as "unknown". Painting
 * it red beside `"absent"` is the exact silent zero the backend's three-valued
 * model exists to prevent.
 */
export const KEY_LOCATION_VERDICTS = [
  "found",
  "absent",
  "not_searched",
] as const;

export type KeyLocationVerdict = (typeof KEY_LOCATION_VERDICTS)[number];

/** Context bytes per side of the key; matches `DEFAULT_KEY_CONTEXT` server-side. */
export const DEFAULT_KEY_CONTEXT = 64;

/** Offsets RETURNED per dump; `hit_count` stays the true total either way. */
export const DEFAULT_MAX_KEY_OFFSETS = 64;

// ---- per-dump census row ----

export interface DumpKeyLocation {
  dump_path: string;
  name: string;
  format_name: string;
  size_for_view: number;
  status: KeyLocationStatus;
  /**
   * `null` — NOT `false` — on any row whose `status` is not `"searched"`.
   * Branch on `=== true` / `=== false` and treat `null` as unknown; a falsy
   * check would report an unreadable dump as a proven absence.
   */
  present: boolean | null;
  first_offset: number | null;
  /** The TRUE occurrence total, even when `offsets` was truncated. */
  hit_count: number;
  offsets: number[];
  offsets_truncated: boolean;
  /** Why the dump could not be searched; empty on a searched row. */
  detail: string;
}

/** Structured note qualifying a result (core.service_result.Diagnostic). */
export interface KeyDiagnostic {
  code: string;
  message: string;
  severity: string;
  details?: Record<string, unknown>;
}

// ---- locate-key ----

/** Which of the three input forms the answer was computed from. */
export type KeyInputForm = "key_hex" | "keylog_line" | "secret";

export interface LocateKeyRequest {
  dump_paths: string[];
  /**
   * The SECRET to search for, as hex. Named `secret_hex`, not `key_hex`:
   * `key_hex` on this wire is the CONTAINER DECRYPTION key (inherited from
   * `KeyMaterialFields`), and one request can legitimately carry both.
   */
  secret_hex?: string;
  /** One NSS key-log row: `<LABEL> <client_random_hex> <secret_hex>`. */
  keylog_line?: string;
  secret?: { secret_type: string; client_random: string; secret: string } | null;
  view?: string | null;
  max_offsets?: number;
  // container decryption (KeyMaterialFields)
  passphrase?: string | null;
  key_hex?: string | null;
  kem_key_hex?: string | null;
}

export interface LocateKeyResponse {
  verdict: KeyLocationVerdict;
  input_form: KeyInputForm;
  /** NSS label, or `""` for the bare-hex input form. */
  secret_type: string;
  /** Public handshake material, or `""` for the bare-hex input form. */
  client_random: string;
  needle_length: number;
  /** Correlates two results without disclosing the secret, which is never echoed. */
  needle_sha256: string;
  view: string | null;
  dumps_total: number;
  /** THE denominator. Every count below is over this, not over `dumps_total`. */
  dumps_searched: number;
  dumps_present: number;
  dumps_absent: number;
  dumps_unreadable: number;
  dumps_too_small: number;
  /** False for a mixed result AND false when nothing was searched. */
  unanimous: boolean;
  first_offset: number | null;
  offsets_agree: boolean;
  common_offset: number | null;
  /** In the SUPPLIED order, so it can be zipped against `dump_paths`. */
  dumps: DumpKeyLocation[];
  elapsed_s: number;
  diagnostics: KeyDiagnostic[];
}

// ---- export-key-pattern ----

export interface KeyPatternRequest {
  dump_paths: string[];
  secret_hex?: string;
  keylog_line?: string;
  secret?: { secret_type: string; client_random: string; secret: string } | null;
  context?: number;
  format?: string;
  name?: string;
  min_static_ratio?: number;
  view?: string | null;
  output_dir?: string | null;
  /** TRUE by default on this route alone — the hex panels below need the bytes. */
  include_window_hex?: boolean;
  max_offsets?: number;
  passphrase?: string | null;
  key_hex?: string | null;
  kem_key_hex?: string | null;
}

/** The generated pattern (architect/pattern_generator.py `generate`). */
export interface KeyPattern {
  name: string;
  length: number;
  hex_pattern: string;
  /** The ONLY rendering every exporter emits — `??` marks the wildcards. */
  wildcard_pattern: string;
  static_ratio: number;
  static_count: number;
  volatile_count: number;
}

export interface KeyPatternRegion {
  /**
   * The REFERENCE dump's window start. Meaningful as a dump offset only when
   * the top-level `offsets_agree` is true; under drift it generalises to
   * nothing and must not be used to seed a hex-view jump.
   */
  offset: number;
  length: number;
  key_start: number;
  key_end: number;
  /** Where the key begins INSIDE the pattern (== `context_before`). */
  key_offset_in_pattern: number;
  context_requested: number;
  /** What was actually feasible for EVERY dump in the mask set. */
  context_before: number;
  context_after: number;
}

/** One dump's window, ready for a `CrossLibraryHex` panel. */
export interface KeyPatternWindow {
  dump_path: string;
  name: string;
  window_start: number;
  key_start: number;
  /** False for a dump that does NOT hold the key — those are the wildcarders. */
  present: boolean;
  /** The dump `hex_pattern` was read from. Exactly one window has this. */
  reference: boolean;
  /** Present only when `include_window_hex` was set. */
  hex?: string;
}

export interface KeyPatternResponse {
  format: string;
  content: string;
  pattern: KeyPattern;
  region: KeyPatternRegion;
  /** Server-side path, present only when `output_dir` was set. */
  pattern_path?: string;
  /** Hoisted from `location` because it qualifies `region.offset`. */
  offsets_agree: boolean;
  /** Key bytes that came out static. Non-zero is a warning sign, not a win. */
  key_static_count: number;
  /** Key bytes wildcarded. ZERO means the rule embeds the secret verbatim. */
  key_wildcard_count: number;
  mask_regions: number;
  mask_dumps_present: number;
  mask_dumps_absent: number;
  excluded_dumps: string[];
  windows: KeyPatternWindow[];
  location: LocateKeyResponse;
  /** The location diagnostics AND the export-quality ones, in that order. */
  diagnostics: KeyDiagnostic[];
}

// ---- window panels for CrossLibraryHex ----

/** The panel shape `CrossLibraryHex` takes (one per dump). */
export interface LibraryPanel {
  name: string;
  data: Uint8Array;
}

/**
 * Map the per-dump windows onto `CrossLibraryHex`'s `libraries` prop.
 *
 * Windows without `hex` are DROPPED rather than rendered as an empty panel: an
 * all-zero panel beside real bytes reads as "this dump is zeroed here", which
 * is a claim about memory the response never made. Request the pattern with
 * `include_window_hex` (the default on the HTTP route) to get them all.
 *
 * `keyOffset` for the component is `region.key_offset_in_pattern`, and
 * `keyLength` is `location.needle_length` — every window is positional, so both
 * are the same for all panels.
 */
export function windowPanels(resp: KeyPatternResponse): LibraryPanel[] {
  const panels: LibraryPanel[] = [];
  for (const window of resp.windows) {
    if (!window.hex) continue;
    const bytes = new Uint8Array(window.hex.length / 2);
    for (let i = 0; i < bytes.length; i++) {
      bytes[i] = parseInt(window.hex.slice(i * 2, i * 2 + 2), 16);
    }
    panels.push({ name: window.name, data: bytes });
  }
  return panels;
}

export const locateKey = (body: LocateKeyRequest) =>
  request<LocateKeyResponse>("/api/analysis/locate-key", {
    method: "POST",
    body: JSON.stringify(body),
  });

export const exportKeyPattern = (body: KeyPatternRequest) =>
  request<KeyPatternResponse>("/api/analysis/key-pattern", {
    method: "POST",
    body: JSON.stringify(body),
  });

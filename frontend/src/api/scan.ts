/**
 * Typed client for the rule-scanning surface:
 *   `POST /api/scan/yara`  — run a MemDiver-emitted YARA rule over N dumps.
 *   `POST /api/scan/score` — score those firings against known-true intervals.
 *   `POST /api/scan/verify-plugin` — RUN a MemDiver-emitted Volatility3 plugin
 *     over N dumps, in-process and/or through the operator's own `vol`, and
 *     report which runtime and which resolved framework version answered.
 *
 * Mirrors the Pydantic `ScanYaraRequest` (api/routers/scan.py) and the payload
 * of `app.tools_pipeline.scan_yara_rule` 1:1, following the `./locate-key`
 * precedent: request and response shapes live here so a backend change lands in
 * one file rather than in every component that fetches.
 *
 * This is the other half of `exportKeyPattern` in `./locate-key`, which only
 * ever WROTE a signature. There is deliberately no component yet — the same
 * posture `locateFieldPairs` and `/api/inspect/region` landed with: the typed
 * seam is what a UI is built against, and shipping it separately keeps the
 * capability honest on all four surfaces from the start.
 */

import { request } from "./client";

// ---- the per-dump status (app/tools_pipeline.py YARA_SCAN_STATUSES) ----

/**
 * Exported as a const TUPLE, with the union type DERIVED from it, so a backend
 * rename breaks `npx tsc -b` here instead of silently producing a `status` no
 * branch matches. Same reason `KEY_LOCATION_STATUSES` is spelled this way.
 */
export const YARA_SCAN_STATUSES = ["scanned", "unreadable"] as const;

export type YaraScanStatus = (typeof YARA_SCAN_STATUSES)[number];

/**
 * The cross-dump verdict. FOUR-valued, and only ONE of the four is an absence:
 *
 * - `"matched"` — at least one dump matched.
 * - `"clean"` — at least one dump was scanned end to end with no match, and no
 *   scanned dump was degraded. The only value that may be rendered as "the rule
 *   does not fire here".
 * - `"inconclusive"` — nothing matched, but every zero came from a scan that
 *   timed out or hit a read error, so the zeros are UNPROVEN.
 * - `"not_scanned"` — no dump was readable.
 *
 * Painting `"inconclusive"` or `"not_scanned"` beside `"clean"` is the exact
 * silent all-clear the backend's four-valued model exists to prevent.
 */
export const YARA_SCAN_VERDICTS = [
  "matched",
  "clean",
  "inconclusive",
  "not_scanned",
] as const;

export type YaraScanVerdict = (typeof YARA_SCAN_VERDICTS)[number];

/** How the rule set was supplied; echoed on the response as `intake`. */
export const YARA_INTAKES = ["source", "paths"] as const;

export type YaraIntake = (typeof YARA_INTAKES)[number];

/** Matches KEPT per dump; matches `DEFAULT_MAX_MATCHES` server-side. */
export const DEFAULT_MAX_MATCHES = 10000;

/** libyara budget in seconds; matches `DEFAULT_TIMEOUT_S` server-side. */
export const DEFAULT_TIMEOUT_S = 60;

/**
 * Whether a response carries its per-match LISTS; matches
 * `DEFAULT_INCLUDE_MATCHES` in `app/tools_pipeline.py`. `true` is the only
 * shape this client has ever received, so nothing about an existing call
 * changes.
 */
export const DEFAULT_INCLUDE_MATCHES = true;

// ---- one string instance of one rule ----

export interface RuleMatch {
  rule: string;
  tags: string[];
  string_id: string;
  /**
   * Absolute start of the matched WINDOW — not of the key — in `ScanPayload.view`
   * coordinates. The key is expected at `offset + key_offset`.
   */
  offset: number;
  /** The TRUE match width. `matched_hex` may be shorter (libyara caps it). */
  length: number;
  matched_hex: string;
  /** Where the key sits inside the window; `null` for a rule with no such meta. */
  key_offset: number | null;
  key_length: number | null;
}

// ---- one dump's scan ----

export interface ScanPayload {
  dump_path: string;
  /** The view actually scanned, resolved from the format when none was asked for. */
  view: string;
  scanned_bytes: number;
  rule_names: string[];
  /**
   * ABSENT — not `[]` — on a count-only response (`include_matches: false`).
   * That is why it is optional here rather than typed as an always-present
   * array: an empty list would make a row with 825,779 hits indistinguishable
   * from a proven-clean one to `scan.matches.length`, which is the same silent
   * false absence `scan: null` on an unreadable row exists to prevent. Read
   * `matches_omitted` (or `match_count`) before descending into this, and let
   * `strictNullChecks` do the rest.
   */
  matches?: RuleMatch[];
  /**
   * `true` ONLY on a count-only response, and absent from every full one, so
   * `matches === undefined` never has to be attributed to an old backend.
   * A count-only row cannot be fed to `scoreDetector`, which consumes
   * `dumps[].scan.matches`.
   */
  matches_omitted?: boolean;
  /** Derived server-side; the TRUE total only while `truncated` is false. */
  match_count: number;
  /** The match list stops at `max_matches` and is not the whole truth. */
  truncated: boolean;
  /** At least one chunk hit the libyara budget; ITS BYTES ARE UNSCANNED. */
  timed_out: boolean;
  chunks: number;
  strategy: string;
  /** Per-chunk failures, including an overlap too narrow for the widest pattern. */
  errors: string[];
}

export interface YaraScanDump {
  dump_path: string;
  name: string;
  status: YaraScanStatus;
  /** Why the dump could not be scanned; empty on a scanned row. */
  detail: string;
  /**
   * `null` — NOT a zeroed payload — on any row whose `status` is not
   * `"scanned"`. That is the point of nesting it: there is no `match_count: 0`
   * on an unreadable row for a falsy check to misread as a proven absence.
   */
  scan: ScanPayload | null;
}

/** Structured note qualifying a result (core.service_result.Diagnostic). */
export interface YaraScanDiagnostic {
  code: string;
  message: string;
  severity: string;
  details?: Record<string, unknown>;
}

// ---- request / response ----

export interface ScanYaraRequest {
  dump_paths: string[];
  /**
   * Inline YARA rule text — e.g. the `content` an `exportKeyPattern({format:
   * "yara"})` call just returned. Supply exactly ONE of this and `rule_paths`;
   * the backend refuses both (and neither) with INVALID_INPUT and no
   * precedence, so do not "helpfully" send both.
   */
  rule_source?: string | null;
  /** Server-side paths to `.yar` files, each compiled in its own namespace. */
  rule_paths?: string[] | null;
  view?: string | null;
  /**
   * Matches kept per dump. `null` means NO CAP; `0` is refused rather than read
   * as unlimited, because a cap arithmetic'd down to 0 means "stop".
   */
  max_matches?: number | null;
  timeout_s?: number;
  /** `0` sizes the chunk overlap from the rules' own `pattern_length` meta. */
  overlap_bytes?: number;
  /**
   * `false` asks for the COUNT-ONLY census: every count and flag, none of the
   * per-match lists. Ask for it whenever the question is "how selective is
   * this rule?" rather than "where exactly did it fire?" — an unselective rule
   * fires hundreds of thousands of times per dump and each firing carries up
   * to 512 bytes of `matched_hex`, so the full response can reach gigabytes
   * while its counts are a few hundred bytes.
   *
   * It bounds the RESPONSE, not the scan: libyara still finds every match, so
   * the request is no faster. And it is orthogonal to `max_matches` — neither
   * implies the other, so a count-only response taken under a cap reports a
   * FLOOR. Send `max_matches: null` with it for the honest total; the
   * `analysis.yara_scan.count_only` diagnostic says which one you got.
   */
  include_matches?: boolean;
}

export interface YaraScanCounts {
  dumps_total: number;
  /** THE denominator. Every rate below is over this, not over `dumps_total`. */
  dumps_scanned: number;
  dumps_unreadable: number;
  dumps_matched: number;
  /** Scanned end to end, zero matches. The only proven-absence count. */
  dumps_clean: number;
  /** Zero matches, but timed out or errored — the zeros are unproven. */
  dumps_inconclusive: number;
  dumps_truncated: number;
  dumps_timed_out: number;
  dumps_with_errors: number;
  /**
   * Opened, handed to the scanner, and `scanned_bytes: 0` — the view sized to
   * nothing. The QUIETEST degraded channel (no error, no timeout), counted on
   * its own because it cannot be inferred from the other two. Such rows are
   * `dumps_inconclusive`, never `dumps_clean`.
   */
  dumps_zero_bytes: number;
  /** A FLOOR whenever `dumps_truncated` is non-zero. */
  matches_total: number;
  scanned_bytes: number;
}

export interface YaraRuleSet {
  /** Compiled rule identifiers, in declaration order. */
  names: string[];
  count: number;
  /** Echoed as SUPPLIED; empty for the inline-source intake. */
  paths: string[];
  /**
   * The widest pattern the rules declare — exactly the width a chunk overlap
   * must cover. `null` means the rules carry no `pattern_length` meta, which is
   * itself the signal that the automatic overlap had nothing to size itself from.
   */
  max_pattern_length: number | null;
}

export interface YaraScanResponse {
  verdict: YaraScanVerdict;
  intake: YaraIntake;
  view: string | null;
  rules: YaraRuleSet;
  caps: {
    max_matches: number | null;
    timeout_s: number;
    overlap_bytes: number;
  };
  counts: YaraScanCounts;
  /** In the SUPPLIED order, so it can be zipped against `dump_paths`. */
  dumps: YaraScanDump[];
  elapsed_s: number;
  diagnostics: YaraScanDiagnostic[];
}

export const scanYara = (body: ScanYaraRequest) =>
  request<YaraScanResponse>("/api/scan/yara", {
    method: "POST",
    body: JSON.stringify(body),
  });

// ---- scoring what the scan found (POST /api/scan/score) ----

/**
 * What could be established about ONE (detector, dump) row. The split is the
 * recall DENOMINATOR: an `"unscorable"` row carried zero truth intervals, so
 * there was nothing to measure it against and `metrics` is `null` rather than
 * a block of zeros.
 *
 * A const TUPLE with the union DERIVED from it, for the same reason
 * `YARA_SCAN_STATUSES` is spelled this way.
 */
export const SCORE_ROW_STATUSES = ["scored", "unscorable"] as const;

export type ScoreRowStatus = (typeof SCORE_ROW_STATUSES)[number];

/**
 * The cross-row verdict. THREE-valued, and only ONE of the three is a
 * measurement:
 *
 * - `"scored"` — rows carried both keys and firings, so the rates in `report`
 *   mean something.
 * - `"no_matches"` — there were keys to find and the detector fired on none of
 *   them. This zero is REAL and is the one that should hurt.
 * - `"no_truths"` — no row carried a truth interval, so nothing was scorable,
 *   `report` is `null`, and the result says nothing about the firings — least
 *   of all that they were wrong.
 *
 * Painting `"no_truths"` as a bad score is the mirror image of the silent
 * all-clear `YaraScanVerdict` guards against: a vacuous zero rendered as a
 * measured failure.
 */
export const SCORE_DETECTOR_VERDICTS = [
  "scored",
  "no_matches",
  "no_truths",
] as const;

export type ScoreDetectorVerdict = (typeof SCORE_DETECTOR_VERDICTS)[number];

/** How the work was supplied; echoed on the response as `intake`. */
export const SCORE_DETECTOR_INTAKES = ["pair", "rows"] as const;

export type ScoreDetectorIntake = (typeof SCORE_DETECTOR_INTAKES)[number];

/**
 * The three criteria, ALWAYS returned together — this is one designed report
 * shape, not a hedge between candidate metrics. `containment` says the firing's
 * window enclosed the key (what a wildcarded-window rule actually claims),
 * `key_offset` says the predicted key position was right to within alignment
 * slack, and `exact` says it was right to the byte. Reading them together is
 * what distinguishes "found the neighbourhood" from "found the key", so a UI
 * must never render one alone.
 */
export const SCORE_CRITERIA = ["containment", "key_offset", "exact"] as const;

export type ScoreCriterion = (typeof SCORE_CRITERIA)[number];

/**
 * Default slack for the `key_offset` criterion; matches
 * `DEFAULT_TOLERANCE_BYTES` server-side. 16 is the `alignment=16` boundary
 * candidates are blocked on, so a detected region may sit up to 15 bytes below
 * the true key start and still be the same finding.
 */
export const DEFAULT_TOLERANCE_BYTES = 16;

/** One firing handed to the scorer. `offset`/`length` are REQUIRED: the backend
 * refuses a row without them rather than defaulting to 0, because the metrics
 * engine reads its inputs by attribute and would score a missing position as a
 * firing at the very start of the dump. */
export interface ScoreMatchInput {
  /** Absolute start of the matched WINDOW, in the view the scan ran in. */
  offset: number;
  length: number;
  /**
   * Where the rule predicts the key sits inside its window. Omit (or `null`)
   * for a rule carrying no such meta: that firing then makes NO positional
   * claim and is excluded from the `key_offset`/`exact` precision denominators
   * rather than charged as a false positive.
   */
  key_offset?: number | null;
  key_length?: number | null;
}

/** One known-true key interval: `[start, start + length)`. */
export interface ScoreTruthInput {
  /** `offset` is accepted as an alias, the way the backend accepts it. */
  start?: number;
  offset?: number;
  length: number;
  /**
   * `"keylog"` (the complete truth set) or `"ledger"` (corroboration only).
   * Carry it: it is what keeps sparse ledger corroboration from being laundered
   * into a key-log recall denominator.
   */
  source?: string;
}

/** One pre-grouped (detector, dump) row for the `rows` intake. */
export interface ScoreRowInput {
  matches?: ScoreMatchInput[];
  truths?: ScoreTruthInput[];
  detector?: string;
  dump?: string;
  truth_sources?: string[];
}

/**
 * Precision/recall for ONE criterion over one match set and truth set.
 *
 * `precision` is match-indexed (`tp_matches / matches`) and `recall`
 * truth-indexed (`covered_truths / truths`), so they are NOT two views of one
 * confusion matrix and cannot be recombined into a single `tp`. Both are
 * bounded by 1.0 by construction.
 *
 * Every rate is `0.0` when its denominator is zero, so ALWAYS check the counts
 * before rendering a zero as a failure: `recall === 0 && truths === 0` means
 * there was nothing to find, while `recall === 0 && truths > 0` means the
 * detector genuinely missed every key.
 */
export interface IntervalDetectionMetrics {
  criterion: ScoreCriterion;
  /** Always `0` for the `exact` criterion, whatever tolerance was requested. */
  tolerance_bytes: number;
  /** The precision denominator. Criterion-dependent: under `key_offset`/`exact`
   * a firing with no `key_offset` is unscorable and excluded from it. */
  matches: number;
  /** The recall denominator. */
  truths: number;
  tp_matches: number;
  fp_matches: number;
  covered_truths: number;
  missed_truths: number;
  precision: number;
  recall: number;
  f1: number;
  /**
   * Fan-in: the most firings any single key attracted. Published rather than
   * deduplicated because `> 1` flatters a rule set whose members overlap.
   */
  max_matches_per_truth: number;
  /**
   * Fan-out: the most distinct keys any single firing's window contained.
   * READ THIS BEFORE recall: a recall of 1.0 reached by one enormous window
   * that swallowed every key shows up here as `=== truths`, and rendering the
   * recall without it launders that into a flattering score.
   */
  max_truths_per_match: number;
  /**
   * Every related `[match_idx, truth_idx, delta]` triple, indexed into the
   * ORIGINAL input arrays. `delta` is signed. Present on a row's own metrics
   * and always EMPTY in the roll-up, whose indices would be meaningless across
   * rows.
   */
  pairs: number[][];
}

/** One criterion's metrics, keyed by criterion. All three keys are present. */
export type ScoreMetricsByCriterion = Record<
  ScoreCriterion,
  IntervalDetectionMetrics
>;

export interface ScoreDetectorRow {
  detector: string;
  /** The label supplied for provenance; `""` when none was. Nothing is opened. */
  dump: string;
  status: ScoreRowStatus;
  /** Firing count — readable without descending into `metrics`, which is
   * `null` exactly when the question is sharpest. */
  matches: number;
  /** The recall denominator for this row. `0` on an `"unscorable"` row. */
  truths: number;
  truth_sources: string[];
  /**
   * `null` — NOT a zeroed block — on any row whose `status` is not `"scored"`.
   * That is the point of nesting it: there is no `recall: 0` on a row with no
   * truth set for a falsy check to misread as "the detector missed everything".
   */
  metrics: ScoreMetricsByCriterion | null;
}

/** Micro-averaged metrics plus provenance for a group of scored rows. */
export interface ScoreGroupSummary {
  rows: number;
  truth_sources: string[];
  metrics: ScoreMetricsByCriterion;
}

export interface ScoreDetectorSummary extends ScoreGroupSummary {
  detector: string;
  /** The labels of the rows that fed this summary; unlabelled rows are omitted. */
  dumps: string[];
}

/**
 * The roll-up. Counts are additive and the rates are recomputed from the summed
 * counts (a micro-average, so a row with many firings weighs more).
 */
export interface ScoreDetectorReport {
  tolerance_bytes: number;
  criteria: ScoreCriterion[];
  /** How many rows were SCORED — never how many were supplied. */
  rows: number;
  /** Sorted by detector name. */
  detectors: ScoreDetectorSummary[];
  overall: ScoreGroupSummary;
}

export interface ScoreDetectorCounts {
  rows_total: number;
  /** Rows that carried at least one truth interval — THE scored denominator. */
  rows_scored: number;
  /** Rows with no truth interval. Excluded from `report` entirely. */
  rows_unscorable: number;
  /** Scored rows where the detector fired nowhere: a real per-row total miss. */
  rows_without_matches: number;
  matches_total: number;
  /** Firings on scorable rows only — the precision denominator. */
  matches_scored: number;
  /** Firings on unscorable rows. Published so a caller who KNOWS those dumps
   * hold no key can compute the stricter precision themselves. */
  matches_unscorable: number;
  truths_total: number;
  detectors: number;
  dumps: number;
}

export interface ScoreDetectorRequest {
  /** The single-pair intake. Supply exactly ONE of this (with `truths`) and
   * `rows`; the backend refuses both — and neither — with INVALID_INPUT and no
   * precedence, so do not "helpfully" send both. */
  matches?: ScoreMatchInput[] | null;
  truths?: ScoreTruthInput[] | null;
  detector?: string | null;
  /** A LABEL for provenance only — no path is opened and no bytes are read. */
  dump?: string | null;
  truth_sources?: string[] | null;
  /** The N-row intake. Rows are scored INDEPENDENTLY and only the counts are
   * summed, so a firing from one dump can never pair with a truth from
   * another whose offsets happen to line up. */
  rows?: ScoreRowInput[] | null;
  tolerance_bytes?: number;
}

export interface ScoreDetectorResponse {
  verdict: ScoreDetectorVerdict;
  intake: ScoreDetectorIntake;
  tolerance_bytes: number;
  criteria: ScoreCriterion[];
  counts: ScoreDetectorCounts;
  /** One row per supplied row, in the SUPPLIED order. */
  rows: ScoreDetectorRow[];
  /** `null` — NOT a block of zeros — when no row was scorable. */
  report: ScoreDetectorReport | null;
  elapsed_s: number;
  /** Same `core.service_result.Diagnostic` shape both routes emit, so the type
   * is shared rather than duplicated. READ THESE: the fan-out warning is the
   * only thing that says a precision of 1.000 came from one window that
   * swallowed every key. */
  diagnostics: YaraScanDiagnostic[];
}

export const scoreDetector = (body: ScoreDetectorRequest) =>
  request<ScoreDetectorResponse>("/api/scan/score", {
    method: "POST",
    body: JSON.stringify(body),
  });

// ---- verifying the vol3 plugin we emit (POST /api/scan/verify-plugin) ----

/**
 * Which runtime ran the plugin. `app/tools_pipeline.py` `VOL3_MODES`.
 *
 * - `"auto"` (the default) prefers IN-PROCESS — the PyPI `volatility3` in
 *   MemDiver's own environment — and falls back to an external launcher.
 * - `"in_process"` execs the plugin against the framework the backend imports
 *   and scans a PROJECTED view, so it is the only mode that can address an
 *   `.msl`.
 * - `"subprocess"` runs `vol -p <dir> -f <dump> <module>.<Class>` against the
 *   operator's own launcher — the way a plugin is actually used, and frequently
 *   a different framework version.
 *
 * A const TUPLE with the union DERIVED from it, for the same reason
 * `YARA_SCAN_STATUSES` is spelled this way.
 */
export const VOL3_MODES = ["auto", "in_process", "subprocess"] as const;

export type Vol3Mode = (typeof VOL3_MODES)[number];

/**
 * What happened to ONE dump. THREE-valued, and the third value is the point:
 *
 * - `"verified"` — the plugin ran over this dump's bytes; `run` is present.
 * - `"unreadable"` — the dump could not be opened; `run` is `null`.
 * - `"unsupported"` — the requested MODE cannot address these bytes at all;
 *   `run` is `null`. Measured, not theoretical: `vol` takes a bare file path
 *   and never goes through the container layer, so on an `.msl` it scans the
 *   CONTAINER FILE and reports the key skewed by the container's header size
 *   (1080 bytes on the ground-truth import). A confident wrong offset
 *   is worse than no answer, so such a row is refused rather than reported.
 */
export const VERIFY_PLUGIN_STATUSES = [
  "verified",
  "unreadable",
  "unsupported",
] as const;

export type VerifyPluginStatus = (typeof VERIFY_PLUGIN_STATUSES)[number];

/**
 * The cross-dump verdict. FOUR-valued, and only ONE of the four is an absence:
 *
 * - `"hit"` — the plugin fired on at least one dump.
 * - `"no_hit"` — it ran end to end and fired on nothing, and no zero was
 *   degraded. The only value that may be rendered as "this plugin does not fire
 *   here".
 * - `"inconclusive"` — nothing fired, but every zero came off a run that
 *   covered 0 bytes, so the zeros are UNPROVEN.
 * - `"not_run"` — nothing ran at all. Claims NOTHING, and is what
 *   `mode: "subprocess"` returns for an `.msl`.
 *
 * Painting `"inconclusive"` or `"not_run"` beside `"no_hit"` is the exact
 * silent all-clear the backend's four-valued model exists to prevent.
 */
export const VERIFY_PLUGIN_VERDICTS = [
  "hit",
  "no_hit",
  "inconclusive",
  "not_run",
] as const;

export type VerifyPluginVerdict = (typeof VERIFY_PLUGIN_VERDICTS)[number];

/** How the plugin was supplied; echoed on the response as `intake`. */
export const VERIFY_PLUGIN_INTAKES = ["path", "source"] as const;

export type VerifyPluginIntake = (typeof VERIFY_PLUGIN_INTAKES)[number];

/** Hits RETAINED per dump; matches `VOL3_MAX_HITS` server-side. */
export const VOL3_MAX_HITS = 50000;

/** Wall-clock ceiling for one subprocess run; matches `VOL3_SUBPROC_TIMEOUT_S`. */
export const VOL3_SUBPROC_TIMEOUT_S = 900;

/**
 * Whether a response carries its per-hit LISTS; matches `DEFAULT_INCLUDE_HITS`
 * in `app/tools_pipeline.py`.
 */
export const DEFAULT_INCLUDE_HITS = true;

/**
 * A `[major, minor, patch]` framework version. A TUPLE, not a string: the whole
 * reason this field exists is that three Volatility3 trees commonly coexist on
 * one machine and disagree (measured here: 2.27.0 in-process vs 2.27.1 through
 * the operator's `vol.py`), so it has to be comparable rather than merely
 * printable.
 */
export type FrameworkVersion = [number, number, number];

/** One row of the emitted plugin's TreeGrid, in MemDiver coordinates. */
export interface Vol3Hit {
  /** Absolute start of the matched WINDOW — not of the key. */
  offset: number;
  /** The window's width, from the plugin's own `PATTERN_LENGTH`. */
  length: number;
  /** Where the key sits inside the window, RELATIVE to `offset`. */
  key_offset: number;
  /** `offset + key_offset`, precomputed so a UI cannot get the addition wrong. */
  key_absolute_offset: number;
  key_length: number;
  key_hex: string;
  key_entropy: number;
  static_ratio: number;
}

/** One dump's run of the plugin. */
export interface Vol3RunPayload {
  plugin_class_name: string;
  layer_scanned: string;
  layer_bytes: number;
  window_length: number;
  /** The honest total, never capped by `max_hits`. */
  match_count: number;
  hits_retained: number;
  /**
   * `hits` stopped at `max_hits`. When true, `key_recovered` and
   * `expected_offset_reported` may be FALSE NEGATIVES — they are computed over
   * the retained hits.
   */
  hits_capped: boolean;
  expected_offset: number | null;
  /** EXACT membership, no tolerance: a hit 64 bytes off is a miss, not a near miss. */
  expected_offset_reported: boolean;
  /**
   * Did the plugin hand the supplied key's exact bytes back? `null` — NOT
   * `false` — when no `key_hex` was sent.
   *
   * READ THIS BESIDE `match_count`, never instead of it. An emitted pattern
   * WILDCARDS the key, so its window still matches a dump the key was wiped
   * from: measured on the 8-dump ground-truth run, a pad-256 plugin fires on
   * 8 of 8 and `key_recovered` is true on exactly the 2 that still hold the
   * secret.
   */
  key_recovered: boolean | null;
  anchor_bytes: number;
  /**
   * Distinct byte VALUES among the anchor's static bytes — the single most
   * predictive number for selectivity. An anchor of 128 zero bytes has `1` and
   * fires anywhere a long zero run exists, however high its static ratio looks.
   */
  anchor_distinct_bytes: number;
  matches_per_mib: number;
  /**
   * ABSENT — not `[]` — on a count-only response (`include_hits: false`), for
   * the reason `ScanPayload.matches` is optional: an empty list would make a
   * row with thousands of firings indistinguishable from a proven-clean one.
   */
  hits?: Vol3Hit[];
  /** `true` ONLY on a count-only response, and absent from every full one. */
  hits_omitted?: boolean;
}

export interface VerifyPluginDump {
  dump_path: string;
  name: string;
  status: VerifyPluginStatus;
  /** Why this dump was not verified; `""` on a verified row. */
  detail: string;
  /**
   * Which runtime answered THIS row. Per-row rather than per-request because
   * `mode: "auto"`'s fallback can legitimately differ per dump.
   */
  mode_used: Vol3Mode | null;
  /**
   * The RESOLVED framework version for this row. Render it: a hit at 370672
   * that does not say which framework found it cannot be reproduced.
   */
  framework_version: FrameworkVersion | null;
  /**
   * The view the bytes came from. `null` in subprocess mode, where `vol` mapped
   * the FILE rather than a MemDiver view — which is exactly why a container
   * never reaches that runtime.
   */
  view: string | null;
  /**
   * `null` — NOT a zeroed payload — on any row whose `status` is not
   * `"verified"`. That is the point of nesting it: there is no `match_count: 0`
   * on an unsupported row for a falsy check to misread as a proven absence.
   */
  run: Vol3RunPayload | null;
}

/** One runtime's availability and the version it actually resolves. */
export interface Vol3RuntimeInProcess {
  available: boolean;
  framework_version: FrameworkVersion | null;
}

/**
 * The external launcher, in full. `cwd` and `python` are as load-bearing as the
 * path: a checkout's `vol.py` loads a different framework depending on the
 * directory it runs from, so all three belong in any report of what answered.
 */
export interface Vol3RuntimeSubprocess extends Vol3RuntimeInProcess {
  /** One-line description, ready to print. */
  launcher: string | null;
  argv: string[] | null;
  cwd: string | null;
  python: string | null;
  /** Which resolution rule produced it (`"MEMDIVER_VOL3_BIN"`, `"vol_bin="`, …). */
  source: string | null;
}

export interface Vol3Runtime {
  mode_requested: Vol3Mode;
  in_process: Vol3RuntimeInProcess;
  subprocess: Vol3RuntimeSubprocess;
  /**
   * `null` — NOT `true` — when either side's version is unknown. "We could not
   * tell" and "they match" are different facts.
   */
  versions_agree: boolean | null;
  /** The launcher line, or the not-found message naming both remedies. */
  launcher: string;
}

export interface VerifyPluginRequest {
  dump_paths: string[];
  /**
   * The plugin's Python TEXT — e.g. the `content` an
   * `exportKeyPattern({format: "vol3"})` call just returned. Supply exactly ONE
   * of this and `plugin_path`; the backend refuses both (and neither) with
   * INVALID_INPUT and no precedence.
   */
  plugin_source?: string | null;
  /** Server-side path to an emitted `.py` plugin. */
  plugin_path?: string | null;
  mode?: Vol3Mode;
  view?: string | null;
  /** A byte position the key is known to occupy. Matched EXACTLY. */
  expected_offset?: number | null;
  /** The secret's bytes, to assert the plugin handed the KEY back. */
  key_hex?: string | null;
  /**
   * Passed through to the plugin's `--pid`, and EXPLICITLY UNPROVEN: narrowing
   * needs a kernel image plus a matching ISF, which a flat process dump has
   * neither of. Do not render the rows as restricted to that process.
   */
  pid?: number | null;
  /**
   * The `vol`/`vol.py` launcher to use, BEATING the `MEMDIVER_VOL3_BIN` env
   * var. This is the only way to select a launcher from a browser — an
   * environment variable is not something an HTTP body can set.
   */
  vol_bin?: string | null;
  /** The interpreter that owns that launcher's volatility3; beats `MEMDIVER_VOL3_PYTHON`. */
  vol_python?: string | null;
  timeout_s?: number;
  max_hits?: number;
  /** `false` asks for the COUNT-ONLY census: every count and flag, no hit lists. */
  include_hits?: boolean;
}

export interface VerifyPluginCounts {
  dumps_total: number;
  /** THE denominator. Every rate below is over this, not over `dumps_total`. */
  dumps_verified: number;
  dumps_unreadable: number;
  /** Refused by the requested runtime. NEVER folded into a zero. */
  dumps_unsupported: number;
  dumps_hit: number;
  /** Ran end to end, fired nowhere. The only proven-absence count. */
  dumps_no_hit: number;
  /** Fired nowhere over 0 bytes — the zeros are unproven. */
  dumps_inconclusive: number;
  dumps_zero_bytes: number;
  dumps_hits_capped: number;
  /** A true census: each row's `match_count` is honest even when its list capped. */
  hits_total: number;
  hits_retained: number;
  bytes_scanned: number;
  /** `null` when no `key_hex` was sent; otherwise how many dumps returned it. */
  dumps_key_recovered: number | null;
  /** `null` when no `expected_offset` was sent. */
  dumps_expected_offset_reported: number | null;
}

export interface VerifyPluginIdentity {
  class_name: string;
  /** `null` for the inline-source intake. */
  path: string | null;
  window_length: number;
  anchor_bytes: number;
  anchor_distinct_bytes: number;
}

export interface VerifyPluginResponse {
  verdict: VerifyPluginVerdict;
  intake: VerifyPluginIntake;
  plugin: VerifyPluginIdentity;
  /** Which runtimes exist and which framework each resolves. Render it. */
  runtime: Vol3Runtime;
  caps: {
    mode: Vol3Mode;
    view: string | null;
    max_hits: number;
    timeout_s: number;
    pid: number | null;
  };
  counts: VerifyPluginCounts;
  /** In the SUPPLIED order, so it can be zipped against `dump_paths`. */
  dumps: VerifyPluginDump[];
  elapsed_s: number;
  /** Same `core.service_result.Diagnostic` shape the other two routes emit. */
  diagnostics: YaraScanDiagnostic[];
}

export const verifyPlugin = (body: VerifyPluginRequest) =>
  request<VerifyPluginResponse>("/api/scan/verify-plugin", {
    method: "POST",
    body: JSON.stringify(body),
  });

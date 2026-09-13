import { afterEach, describe, it, expect, vi } from "vitest";

import {
  DEFAULT_INCLUDE_MATCHES,
  DEFAULT_MAX_MATCHES,
  DEFAULT_TIMEOUT_S,
  DEFAULT_TOLERANCE_BYTES,
  SCORE_CRITERIA,
  SCORE_DETECTOR_INTAKES,
  SCORE_DETECTOR_VERDICTS,
  SCORE_ROW_STATUSES,
  YARA_INTAKES,
  YARA_SCAN_STATUSES,
  YARA_SCAN_VERDICTS,
  scanYara,
  scoreDetector,
  type ScanYaraRequest,
  type ScoreCriterion,
  type ScoreDetectorIntake,
  type ScoreDetectorRequest,
  type ScoreDetectorRow,
  type ScoreDetectorVerdict,
  type ScoreRowStatus,
  type YaraIntake,
  type ScanPayload,
  type YaraScanDump,
  type YaraScanStatus,
  type YaraScanVerdict,
  DEFAULT_INCLUDE_HITS,
  VERIFY_PLUGIN_INTAKES,
  VERIFY_PLUGIN_STATUSES,
  VERIFY_PLUGIN_VERDICTS,
  VOL3_MAX_HITS,
  VOL3_MODES,
  VOL3_SUBPROC_TIMEOUT_S,
  verifyPlugin,
  type Vol3Mode,
  type Vol3RunPayload,
  type Vol3Runtime,
  type VerifyPluginDump,
  type VerifyPluginIntake,
  type VerifyPluginRequest,
  type VerifyPluginStatus,
  type VerifyPluginVerdict,
} from "@/api/scan";

afterEach(() => {
  vi.restoreAllMocks();
});

/**
 * The vocabularies are exported as const TUPLES with the union types DERIVED
 * from them, so a backend rename breaks `tsc` here instead of silently
 * producing a `status`/`verdict` no branch matches. A wrong literal in a closed
 * union is worse than no union at all: it type-checks and then never matches a
 * real response. These tests pin the exact members against
 * `app/tools_pipeline.py`'s `YARA_SCAN_STATUSES` / `YARA_SCAN_VERDICTS`.
 */
describe("the scan vocabularies", () => {
  it("matches YARA_SCAN_STATUSES server-side", () => {
    expect(YARA_SCAN_STATUSES).toEqual(["scanned", "unreadable"]);
  });

  it("matches YARA_SCAN_VERDICTS server-side, all four of them", () => {
    expect(YARA_SCAN_VERDICTS).toEqual([
      "matched",
      "clean",
      "inconclusive",
      "not_scanned",
    ]);
    // The distinction that carries the whole capability: exactly ONE of the
    // four is an absence. A zero-match scan that timed out is `inconclusive`,
    // and rendering it beside `clean` is the silent all-clear the backend's
    // four-valued verdict exists to prevent.
    expect(YARA_SCAN_VERDICTS).toContain("inconclusive");
    expect(YARA_SCAN_VERDICTS).toContain("not_scanned");
  });

  it("matches the two rule intakes, and offers no third", () => {
    // There is no `.yarc` intake and there must never be one: a compiled rule
    // file is executable libyara bytecode.
    expect(YARA_INTAKES).toEqual(["source", "paths"]);
  });

  it("derives the union types from the tuples", () => {
    const status: YaraScanStatus = "unreadable";
    const verdict: YaraScanVerdict = "inconclusive";
    const intake: YaraIntake = "paths";
    // @ts-expect-error — "missing" is not one of the two statuses.
    const bogusStatus: YaraScanStatus = "missing";
    // @ts-expect-error — "found" is locate-key's verdict, not this one's.
    const bogusVerdict: YaraScanVerdict = "found";
    // @ts-expect-error — a precompiled rule blob is not an accepted intake.
    const bogusIntake: YaraIntake = "compiled";
    expect([
      status,
      verdict,
      intake,
      bogusStatus,
      bogusVerdict,
      bogusIntake,
    ]).toHaveLength(6);
  });

  it("carries the engine's defaults, not re-guessed literals", () => {
    expect(DEFAULT_MAX_MATCHES).toBe(10000);
    expect(DEFAULT_TIMEOUT_S).toBe(60);
  });
});

/**
 * `scan` is `null` — NOT a zeroed payload — on any row that was not scanned.
 * That is why it is nested rather than flattened: there is no `match_count: 0`
 * on an unreadable row for a falsy check to misread as a proven absence.
 */
describe("the per-dump row contract", () => {
  const rows: YaraScanDump[] = [
    {
      dump_path: "/dumps/pre_abort.dump",
      name: "pre_abort.dump",
      status: "scanned",
      detail: "",
      scan: {
        dump_path: "/dumps/pre_abort.dump",
        view: "raw",
        scanned_bytes: 11223040,
        rule_names: ["memdiver_key_pattern"],
        matches: [
          {
            rule: "memdiver_key_pattern",
            tags: ["memdiver"],
            string_id: "$pattern",
            offset: 370608,
            length: 160,
            matched_hex: "00ff",
            key_offset: 64,
            key_length: 32,
          },
        ],
        match_count: 1,
        truncated: false,
        timed_out: false,
        chunks: 1,
        strategy: "filepath",
        errors: [],
      },
    },
    {
      dump_path: "/dumps/locked.msl",
      name: "locked.msl",
      status: "unreadable",
      detail: "cannot read region table",
      scan: null,
    },
  ];

  it("keeps an unreadable dump as a ROW with no scan payload", () => {
    const unreadable = rows[1];
    expect(unreadable.status).toBe("unreadable");
    expect(unreadable.scan).toBeNull();
    // Not an omission: dropping it would shrink the denominator every rate in
    // `counts` is computed over.
    expect(unreadable.detail).not.toBe("");
  });

  it("puts the key at offset + key_offset, not at offset", () => {
    // `matches!` because the field is optional on `ScanPayload`: a count-only
    // response (`include_matches: false`) omits it entirely rather than
    // sending `[]`. This row is a FULL one, so it is there.
    const match = rows[0].scan!.matches![0];
    // `offset` is the matched WINDOW's start. Treating it as the key's start is
    // the mistake the two meta fields exist to prevent.
    expect(match.offset + (match.key_offset ?? 0)).toBe(370672);
    expect(match.key_length).toBe(32);
  });

  it("reports the degraded channels alongside the matches", () => {
    const scan = rows[0].scan!;
    // All three are always present on a scanned row, so "not degraded" is
    // distinguishable from "this response predates the fields".
    expect(scan.truncated).toBe(false);
    expect(scan.timed_out).toBe(false);
    expect(scan.errors).toEqual([]);
  });
});

describe("scanYara", () => {
  it("POSTs to /api/scan/yara with the inline rule intake", async () => {
    const fetchMock = vi.fn().mockResolvedValue({
      ok: true,
      status: 200,
      text: async () => JSON.stringify({ verdict: "matched" }),
    });
    vi.stubGlobal("fetch", fetchMock);

    const body: ScanYaraRequest = {
      dump_paths: ["/a.dump", "/b.dump"],
      rule_source: "rule r { strings: $a = { de ad } condition: $a }",
    };
    await scanYara(body);

    const [url, init] = fetchMock.mock.calls[0] as [string, RequestInit];
    expect(url).toBe("/api/scan/yara");
    expect(init.method).toBe("POST");
    const sent = JSON.parse(init.body as string);
    expect(sent.dump_paths).toHaveLength(2);
    expect(sent.rule_source).toContain("rule r");
    // The other intake is NOT sent alongside it: the backend refuses both with
    // no precedence, so a client that sends both gets a 400 rather than a
    // census produced by rules it did not intend.
    expect(sent.rule_paths).toBeUndefined();

    vi.unstubAllGlobals();
  });

  it("sends max_matches: null as the way to ask for no cap", async () => {
    const fetchMock = vi.fn().mockResolvedValue({
      ok: true,
      status: 200,
      text: async () => JSON.stringify({ verdict: "clean" }),
    });
    vi.stubGlobal("fetch", fetchMock);

    await scanYara({
      dump_paths: ["/a.dump"],
      rule_paths: ["/rules/key.yar"],
      max_matches: null,
    });

    const [, init] = fetchMock.mock.calls[0] as [string, RequestInit];
    const sent = JSON.parse(init.body as string);
    // `null`, not `0`: the backend refuses a non-positive cap rather than
    // reading it as "unlimited", because a cap arithmetic'd down to 0 means
    // "stop" and being handed the whole match list is the opposite.
    expect(sent.max_matches).toBeNull();
    expect("max_matches" in sent).toBe(true);

    vi.unstubAllGlobals();
  });
});

/**
 * The COUNT-ONLY response shape (`include_matches: false`).
 *
 * The measurement behind it: the reference corpus's 8 dumps scanned with the
 * default 64-byte pad rule and no match cap produced 6,621,373 matches and a
 * 4.0 GB payload, because each match carries up to 512 bytes of `matched_hex`.
 * `max_matches` bounds how many matches are HELD server-side and never bounded
 * the response, and a selectivity question wants a number anyway.
 *
 * The type-level point pinned here is that `matches` is OPTIONAL and absent
 * rather than `[]`: an empty array would make a row with 825,779 hits
 * indistinguishable from a proven-clean one to `scan.matches.length`, which is
 * the same silent false absence `scan: null` guards against on an unreadable
 * row.
 */
describe("the count-only response shape", () => {
  it("matches DEFAULT_INCLUDE_MATCHES server-side", () => {
    expect(DEFAULT_INCLUDE_MATCHES).toBe(true);
  });

  it("types a count-only row with no matches array at all", () => {
    const counted: ScanPayload = {
      dump_path: "/dumps/pre_abort.dump",
      view: "raw",
      scanned_bytes: 11223040,
      rule_names: ["memdiver_key_pattern"],
      // No `matches` key: this compiles precisely because the field is
      // optional, which is the contract the backend's omission needs.
      matches_omitted: true,
      match_count: 825779,
      truncated: false,
      timed_out: false,
      chunks: 1,
      strategy: "filepath",
      errors: [],
    };

    expect(counted.matches).toBeUndefined();
    // NOT an empty array. A `.length` check on this throws instead of quietly
    // reporting a proven absence, which is the intended failure mode.
    expect(counted.matches).not.toEqual([]);
    // Every count and flag survives, which is the whole point.
    expect(counted.match_count).toBe(825779);
    expect(counted.truncated).toBe(false);
    expect(counted.scanned_bytes).toBe(11223040);
  });

  it("leaves matches_omitted off a full row", () => {
    const full: ScanPayload = {
      dump_path: "/dumps/pre_abort.dump",
      view: "raw",
      scanned_bytes: 1024,
      rule_names: ["memdiver_key_pattern"],
      matches: [],
      match_count: 0,
      truncated: false,
      timed_out: false,
      chunks: 1,
      strategy: "filepath",
      errors: [],
    };

    // `matches: []` on a FULL row is a real, proven zero — the value the
    // count-only form must never be confused with.
    expect(full.matches).toEqual([]);
    expect(full.matches_omitted).toBeUndefined();
  });

  it("sends include_matches: false to ask for counts without lists", async () => {
    const fetchMock = vi.fn().mockResolvedValue({
      ok: true,
      status: 200,
      text: async () => JSON.stringify({ verdict: "matched" }),
    });
    vi.stubGlobal("fetch", fetchMock);

    await scanYara({
      dump_paths: ["/a.dump"],
      rule_paths: ["/rules/pad64.yar"],
      // The pairing that makes the census honest: count-only is ORTHOGONAL to
      // `max_matches`, so under a cap the counts are a floor.
      max_matches: null,
      include_matches: false,
    });

    const [, init] = fetchMock.mock.calls[0] as [string, RequestInit];
    const sent = JSON.parse(init.body as string);
    expect(sent.include_matches).toBe(false);
    expect(sent.max_matches).toBeNull();

    vi.unstubAllGlobals();
  });

  it("omits include_matches when the full payload is wanted", async () => {
    const fetchMock = vi.fn().mockResolvedValue({
      ok: true,
      status: 200,
      text: async () => JSON.stringify({ verdict: "clean" }),
    });
    vi.stubGlobal("fetch", fetchMock);

    await scanYara({ dump_paths: ["/a.dump"], rule_source: "rule r {}" });

    const [, init] = fetchMock.mock.calls[0] as [string, RequestInit];
    const sent = JSON.parse(init.body as string);
    // Absent, so the backend's own default decides — the client never
    // re-literals it.
    expect("include_matches" in sent).toBe(false);

    vi.unstubAllGlobals();
  });
});

/**
 * The scoring vocabularies, pinned the same way and for the same reason: a
 * wrong literal in a closed union type-checks and then never matches a real
 * response. These are the exact members of `app/tools_pipeline.py`'s
 * `SCORE_ROW_STATUSES` / `SCORE_DETECTOR_VERDICTS` /
 * `SCORE_DETECTOR_INTAKES` and `engine/detector_metrics.py`'s `CRITERIA`.
 */
describe("the detector-scoring vocabularies", () => {
  it("matches SCORE_ROW_STATUSES server-side", () => {
    expect(SCORE_ROW_STATUSES).toEqual(["scored", "unscorable"]);
  });

  it("matches SCORE_DETECTOR_VERDICTS server-side, all three of them", () => {
    expect(SCORE_DETECTOR_VERDICTS).toEqual([
      "scored",
      "no_matches",
      "no_truths",
    ]);
    // The distinction that carries this capability, and it is the MIRROR of
    // the scan verdict's: `no_truths` is a vacuous zero (nothing was scorable,
    // `report` is null) while `no_matches` is a measured total miss. Rendering
    // the first as a bad score is as wrong as rendering an unproven zero as an
    // all-clear.
    expect(SCORE_DETECTOR_VERDICTS).toContain("no_truths");
    expect(SCORE_DETECTOR_VERDICTS).toContain("no_matches");
  });

  it("matches the two intakes, and offers no third", () => {
    expect(SCORE_DETECTOR_INTAKES).toEqual(["pair", "rows"]);
  });

  it("keeps all THREE criteria, in the engine's headline-first order", () => {
    // Always returned together: one designed report shape, not a hedge between
    // candidate metrics. A UI that renders `containment` alone cannot tell
    // "found the neighbourhood" from "found the key".
    expect(SCORE_CRITERIA).toEqual(["containment", "key_offset", "exact"]);
  });

  it("derives the union types from the tuples", () => {
    const status: ScoreRowStatus = "unscorable";
    const verdict: ScoreDetectorVerdict = "no_truths";
    const intake: ScoreDetectorIntake = "rows";
    const criterion: ScoreCriterion = "key_offset";
    // @ts-expect-error — "missing" is not one of the two row statuses.
    const bogusStatus: ScoreRowStatus = "missing";
    // @ts-expect-error — "clean" is the SCAN verdict, not the score verdict.
    const bogusVerdict: ScoreDetectorVerdict = "clean";
    // @ts-expect-error — there is no third intake.
    const bogusIntake: ScoreDetectorIntake = "source";
    // @ts-expect-error — byte-set intersection is precisely NOT a criterion here.
    const bogusCriterion: ScoreCriterion = "offsets";
    expect([
      status,
      verdict,
      intake,
      criterion,
      bogusStatus,
      bogusVerdict,
      bogusIntake,
      bogusCriterion,
    ]).toHaveLength(8);
  });

  it("carries the engine's tolerance default, not a re-guessed literal", () => {
    // 16 == the `alignment=16` candidates are blocked on, so a detected region
    // may start up to 15 bytes below the true key and still be one finding.
    expect(DEFAULT_TOLERANCE_BYTES).toBe(16);
  });
});

/**
 * `metrics` is `null` — NOT a zeroed block — on an unscorable row, and that is
 * the whole reason it is nested: there is no `recall: 0` on a row with no truth
 * set for a falsy check to misread as "the detector missed everything".
 */
describe("the per-row scoring contract", () => {
  const rows: ScoreDetectorRow[] = [
    {
      detector: "memdiver_key_pattern",
      dump: "/dumps/pre_abort.dump",
      status: "scored",
      matches: 2,
      truths: 1,
      truth_sources: ["keylog"],
      metrics: {
        containment: {
          criterion: "containment",
          tolerance_bytes: 16,
          matches: 2,
          truths: 1,
          tp_matches: 1,
          fp_matches: 1,
          covered_truths: 1,
          missed_truths: 0,
          precision: 0.5,
          recall: 1,
          f1: 0.6666666666666666,
          max_matches_per_truth: 1,
          max_truths_per_match: 1,
          pairs: [[0, 0, 64]],
        },
        key_offset: {
          criterion: "key_offset",
          tolerance_bytes: 16,
          matches: 1,
          truths: 1,
          tp_matches: 1,
          fp_matches: 0,
          covered_truths: 1,
          missed_truths: 0,
          precision: 1,
          recall: 1,
          f1: 1,
          max_matches_per_truth: 1,
          max_truths_per_match: 1,
          pairs: [[0, 0, 0]],
        },
        exact: {
          criterion: "exact",
          tolerance_bytes: 0,
          matches: 1,
          truths: 1,
          tp_matches: 1,
          fp_matches: 0,
          covered_truths: 1,
          missed_truths: 0,
          precision: 1,
          recall: 1,
          f1: 1,
          max_matches_per_truth: 1,
          max_truths_per_match: 1,
          pairs: [[0, 0, 0]],
        },
      },
    },
    {
      detector: "memdiver_key_pattern",
      dump: "/dumps/no_ground_truth.dump",
      status: "unscorable",
      matches: 7,
      truths: 0,
      truth_sources: [],
      metrics: null,
    },
  ];

  it("keeps a row with no truth set as a ROW with no metrics block", () => {
    const unscorable = rows[1];
    expect(unscorable.status).toBe("unscorable");
    expect(unscorable.metrics).toBeNull();
    // Its firings are still published, so a caller who KNOWS that dump holds no
    // key can compute the stricter precision themselves.
    expect(unscorable.matches).toBe(7);
    expect(unscorable.truths).toBe(0);
  });

  it("keeps the key_offset denominator SMALLER than containment's", () => {
    const metrics = rows[0].metrics!;
    // A firing with no `key_offset` makes no positional claim, so it is
    // excluded from the key_offset/exact precision denominator rather than
    // charged as a false positive. The two denominators differing is the
    // designed behaviour, not a drift.
    expect(metrics.containment.matches).toBe(2);
    expect(metrics.key_offset.matches).toBe(1);
    expect(metrics.exact.tolerance_bytes).toBe(0);
  });

  it("exposes the fan-in/fan-out structure beside the rates", () => {
    const containment = rows[0].metrics!.containment;
    // Published precisely so a recall of 1.0 reached by one window that
    // swallowed every key cannot be laundered into a flattering score.
    expect(containment.max_truths_per_match).toBe(1);
    expect(containment.max_matches_per_truth).toBe(1);
    // `pairs` carries the signed delta, so "off by 64 bytes" is readable.
    expect(containment.pairs[0]).toEqual([0, 0, 64]);
  });
});

describe("scoreDetector", () => {
  it("POSTs to /api/scan/score with the single-pair intake", async () => {
    const fetchMock = vi.fn().mockResolvedValue({
      ok: true,
      status: 200,
      text: async () => JSON.stringify({ verdict: "scored" }),
    });
    vi.stubGlobal("fetch", fetchMock);

    const body: ScoreDetectorRequest = {
      matches: [{ offset: 370608, length: 160, key_offset: 64 }],
      truths: [{ start: 370672, length: 32, source: "keylog" }],
      detector: "memdiver_key_pattern",
      dump: "/dumps/pre_abort.dump",
    };
    await scoreDetector(body);

    const [url, init] = fetchMock.mock.calls[0] as [string, RequestInit];
    expect(url).toBe("/api/scan/score");
    expect(init.method).toBe("POST");
    const sent = JSON.parse(init.body as string);
    expect(sent.matches[0].offset).toBe(370608);
    expect(sent.truths[0].start).toBe(370672);
    // The other intake is NOT sent alongside it: the backend refuses both with
    // no precedence, so a client that sends both gets a 400 rather than a
    // report scored over data it did not mean.
    expect(sent.rows).toBeUndefined();

    vi.unstubAllGlobals();
  });

  it("sends the rows intake without the pair-only labels", async () => {
    const fetchMock = vi.fn().mockResolvedValue({
      ok: true,
      status: 200,
      text: async () => JSON.stringify({ verdict: "no_truths" }),
    });
    vi.stubGlobal("fetch", fetchMock);

    await scoreDetector({
      rows: [
        {
          matches: [{ offset: 4096, length: 48 }],
          truths: [{ offset: 4112, length: 16 }],
          detector: "r",
          dump: "/a.dump",
        },
      ],
      tolerance_bytes: 0,
    });

    const [, init] = fetchMock.mock.calls[0] as [string, RequestInit];
    const sent = JSON.parse(init.body as string);
    expect(sent.rows).toHaveLength(1);
    // `detector` / `dump` decorate the PAIR form only; the backend refuses
    // them beside `rows` rather than ignoring them, because each row carries
    // its own.
    expect(sent.detector).toBeUndefined();
    expect(sent.dump).toBeUndefined();
    // 0 must survive the wire as 0: it is the exact-match tolerance, not a
    // falsy "unset" that should fall back to 16.
    expect(sent.tolerance_bytes).toBe(0);

    vi.unstubAllGlobals();
  });
});

/**
 * The plugin-verification vocabularies, pinned against `app/tools_pipeline.py`'s
 * `VOL3_MODES` / `VERIFY_PLUGIN_STATUSES` / `VERIFY_PLUGIN_VERDICTS`, for the
 * reason the YARA ones are pinned above: a wrong literal in a closed union
 * type-checks and then never matches a real response.
 */
describe("the plugin-verification vocabularies", () => {
  it("matches VOL3_MODES server-side, auto FIRST", () => {
    expect(VOL3_MODES).toEqual(["auto", "in_process", "subprocess"]);
    // The order encodes the user-facing contract: `auto` is the default and it
    // PREFERS in-process (the PyPI volatility3), falling back to the external
    // launcher. Reversing that would silently change which framework a default
    // request is answered by.
    expect(VOL3_MODES[0]).toBe("auto");
  });

  it("matches VERIFY_PLUGIN_STATUSES server-side, all THREE of them", () => {
    expect(VERIFY_PLUGIN_STATUSES).toEqual([
      "verified",
      "unreadable",
      "unsupported",
    ]);
    // `unsupported` is the member that carries the capability: a container
    // handed to `mode: "subprocess"` is REFUSED, because `vol` would scan the
    // container file and report the key skewed by the container header (1080
    // bytes on the ground-truth import). A wrong offset is
    // worse than no answer, so there is no fourth "scanned anyway" state.
    expect(VERIFY_PLUGIN_STATUSES).toContain("unsupported");
  });

  it("matches VERIFY_PLUGIN_VERDICTS server-side, all four of them", () => {
    expect(VERIFY_PLUGIN_VERDICTS).toEqual([
      "hit",
      "no_hit",
      "inconclusive",
      "not_run",
    ]);
    // Exactly ONE of the four is an absence. `not_run` is what a forced
    // subprocess run over an `.msl` returns, and rendering it beside `no_hit`
    // would report "the plugin does not fire here" about a run that never
    // happened.
    expect(VERIFY_PLUGIN_VERDICTS).toContain("not_run");
    expect(VERIFY_PLUGIN_VERDICTS).toContain("inconclusive");
  });

  it("matches the two plugin intakes, and offers no third", () => {
    expect(VERIFY_PLUGIN_INTAKES).toEqual(["path", "source"]);
  });

  it("derives the union types from the tuples", () => {
    const mode: Vol3Mode = VOL3_MODES[1];
    const status: VerifyPluginStatus = VERIFY_PLUGIN_STATUSES[2];
    const verdict: VerifyPluginVerdict = VERIFY_PLUGIN_VERDICTS[3];
    const intake: VerifyPluginIntake = VERIFY_PLUGIN_INTAKES[0];
    expect([mode, status, verdict, intake]).toEqual([
      "in_process",
      "unsupported",
      "not_run",
      "path",
    ]);
  });

  it("carries the producer's defaults, not re-guessed literals", () => {
    expect(VOL3_MAX_HITS).toBe(50000);
    expect(VOL3_SUBPROC_TIMEOUT_S).toBe(900);
    expect(DEFAULT_INCLUDE_HITS).toBe(true);
  });
});

describe("the per-dump verification row contract", () => {
  it("keeps mode_used and framework_version ON THE ROW", () => {
    // Not on the request, and not only in `runtime`: under `mode: "auto"` the
    // fallback can differ per dump, and a hit that does not say which of the
    // machine's Volatility3 trees found it cannot be reproduced.
    const row: VerifyPluginDump = {
      dump_path: "/a.dump",
      name: "a.dump",
      status: "verified",
      detail: "",
      mode_used: "in_process",
      framework_version: [2, 27, 0],
      view: "raw",
      run: {
        plugin_class_name: "MemDiverScanPad256",
        layer_scanned: "flat",
        layer_bytes: 11223040,
        window_length: 560,
        match_count: 1,
        hits_retained: 1,
        hits_capped: false,
        expected_offset: 370672,
        expected_offset_reported: true,
        key_recovered: true,
        anchor_bytes: 498,
        anchor_distinct_bytes: 38,
        matches_per_mib: 0.0934,
        hits: [
          {
            offset: 370416,
            length: 560,
            key_offset: 256,
            key_absolute_offset: 370672,
            key_length: 48,
            key_hex: "aba1",
            key_entropy: 5.4183,
            static_ratio: 0.8893,
          },
        ],
      },
    };
    expect(row.framework_version).toEqual([2, 27, 0]);
    // The key is at `key_absolute_offset`, which is `offset + key_offset` —
    // published rather than left to the caller's arithmetic.
    const hit = row.run!.hits![0];
    expect(hit.offset + hit.key_offset).toBe(hit.key_absolute_offset);
  });

  it("keeps an unsupported dump as a ROW with no run payload", () => {
    const row: VerifyPluginDump = {
      dump_path: "/a.msl",
      name: "a.msl",
      status: "unsupported",
      detail: "mode='subprocess' hands `vol` the file path",
      mode_used: null,
      framework_version: null,
      view: null,
      run: null,
    };
    // NOT a zeroed run block: there is no `match_count: 0` here for a falsy
    // check to misread as "the plugin does not fire on this dump".
    expect(row.run).toBeNull();
    expect(row.detail).not.toBe("");
  });

  it("types a count-only run with no hits array at all", () => {
    const run: Vol3RunPayload = {
      plugin_class_name: "P",
      layer_scanned: "file",
      layer_bytes: 11223040,
      window_length: 560,
      match_count: 825779,
      hits_retained: 0,
      hits_capped: true,
      expected_offset: null,
      expected_offset_reported: false,
      key_recovered: null,
      anchor_bytes: 128,
      anchor_distinct_bytes: 1,
      matches_per_mib: 77133.0,
      hits_omitted: true,
    };
    expect(run.hits).toBeUndefined();
    expect(run.hits_omitted).toBe(true);
    // `key_recovered: null` is "you asked nothing", never "the key was absent".
    expect(run.key_recovered).toBeNull();
    // anchor_distinct_bytes === 1 is the 64-byte-pad non-detector's signature.
    expect(run.anchor_distinct_bytes).toBe(1);
  });

  it("keeps versions_agree three-valued", () => {
    const runtime: Vol3Runtime = {
      mode_requested: "auto",
      in_process: { available: true, framework_version: [2, 27, 0] },
      subprocess: {
        available: true,
        framework_version: [2, 27, 1],
        launcher: "python vol.py (cwd=/checkout, via MEMDIVER_VOL3_BIN)",
        argv: ["/checkout/env/bin/python", "/checkout/vol.py"],
        cwd: "/checkout",
        python: "/checkout/env/bin/python",
        source: "MEMDIVER_VOL3_BIN",
      },
      versions_agree: false,
      launcher: "…-> 2.27.1",
    };
    // Measured on the author's machine, and the reason this field is not a
    // boolean-with-a-default: `null` is "we could not tell", which is a
    // different fact from "they match".
    expect(runtime.versions_agree).toBe(false);
    const unknown: Vol3Runtime["versions_agree"] = null;
    expect(unknown).toBeNull();
    // cwd and python are as load-bearing as the path: a checkout's vol.py
    // resolves a different framework depending on the directory it runs from.
    expect(runtime.subprocess.cwd).toBe("/checkout");
    expect(runtime.subprocess.python).toContain("python");
  });
});

describe("verifyPlugin", () => {
  it("POSTs to /api/scan/verify-plugin with the inline source intake", async () => {
    const fetchMock = vi.fn().mockResolvedValue({
      ok: true,
      status: 200,
      text: async () => JSON.stringify({ verdict: "hit" }),
    });
    vi.stubGlobal("fetch", fetchMock);

    const body: VerifyPluginRequest = {
      dump_paths: ["/a.dump", "/b.dump"],
      plugin_source: "class MemDiverScanP(object):\n    pass\n",
      mode: "in_process",
      expected_offset: 370672,
      key_hex: "aba1",
    };
    const result = await verifyPlugin(body);
    expect(result.verdict).toBe("hit");

    const [url, init] = fetchMock.mock.calls[0] as [string, RequestInit];
    expect(url).toBe("/api/scan/verify-plugin");
    expect(init.method).toBe("POST");
    const sent = JSON.parse(init.body as string);
    expect(sent.plugin_source).toContain("class MemDiverScanP");
    // Never both: the backend refuses that with no precedence.
    expect(sent.plugin_path).toBeUndefined();
    expect(sent.expected_offset).toBe(370672);

    vi.unstubAllGlobals();
  });

  it("sends vol_bin/vol_python, the only launcher channel a browser has", async () => {
    const fetchMock = vi.fn().mockResolvedValue({
      ok: true,
      status: 200,
      text: async () => JSON.stringify({ verdict: "hit" }),
    });
    vi.stubGlobal("fetch", fetchMock);

    await verifyPlugin({
      dump_paths: ["/a.dump"],
      plugin_path: "/plugins/Pad256.py",
      mode: "subprocess",
      vol_bin: "/checkout/vol.py",
      vol_python: "/checkout/env/bin/python",
    });

    const [, init] = fetchMock.mock.calls[0] as [string, RequestInit];
    const sent = JSON.parse(init.body as string);
    // An environment variable is not something an HTTP body can set, so these
    // two fields are what makes "point me at my own vol.py" reachable from the
    // web surface at all. They BEAT MEMDIVER_VOL3_BIN / MEMDIVER_VOL3_PYTHON.
    expect(sent.vol_bin).toBe("/checkout/vol.py");
    expect(sent.vol_python).toBe("/checkout/env/bin/python");
    expect(sent.mode).toBe("subprocess");

    vi.unstubAllGlobals();
  });

  it("sends include_hits: false to ask for counts without hit lists", async () => {
    const fetchMock = vi.fn().mockResolvedValue({
      ok: true,
      status: 200,
      text: async () => JSON.stringify({ verdict: "hit" }),
    });
    vi.stubGlobal("fetch", fetchMock);

    await verifyPlugin({
      dump_paths: ["/a.dump"],
      plugin_path: "/p.py",
      include_hits: false,
    });

    const [, init] = fetchMock.mock.calls[0] as [string, RequestInit];
    expect(JSON.parse(init.body as string).include_hits).toBe(false);

    vi.unstubAllGlobals();
  });
});

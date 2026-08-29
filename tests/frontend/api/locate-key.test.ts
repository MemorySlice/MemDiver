import { afterEach, describe, it, expect, vi } from "vitest";

import {
  DEFAULT_KEY_CONTEXT,
  DEFAULT_MAX_KEY_OFFSETS,
  KEY_LOCATION_STATUSES,
  KEY_LOCATION_VERDICTS,
  exportKeyPattern,
  locateKey,
  windowPanels,
  type DumpKeyLocation,
  type KeyLocationStatus,
  type KeyLocationVerdict,
  type KeyPatternResponse,
  type LocateKeyRequest,
} from "@/api/locate-key";

afterEach(() => {
  vi.restoreAllMocks();
});

/**
 * The vocabularies are exported as const TUPLES with the union types DERIVED
 * from them, so a backend rename breaks `tsc` here instead of silently
 * producing a `status`/`verdict` no branch matches. These tests pin the exact
 * members against `engine/key_location.py`.
 */
describe("the three-valued vocabularies", () => {
  it("matches KEY_LOCATION_STATUSES server-side", () => {
    expect(KEY_LOCATION_STATUSES).toEqual([
      "searched",
      "unreadable",
      "too_small",
    ]);
  });

  it("matches KEY_LOCATION_VERDICTS server-side, including not_searched", () => {
    expect(KEY_LOCATION_VERDICTS).toEqual(["found", "absent", "not_searched"]);
    // The third verdict is the whole point: an all-unreadable dump set must
    // never be renderable as an absence.
    expect(KEY_LOCATION_VERDICTS).toContain("not_searched");
  });

  it("derives the union types from the tuples", () => {
    const status: KeyLocationStatus = "too_small";
    const verdict: KeyLocationVerdict = "not_searched";
    // @ts-expect-error — "missing" is not one of the three statuses.
    const bogusStatus: KeyLocationStatus = "missing";
    // @ts-expect-error — "unknown" is not one of the three verdicts.
    const bogusVerdict: KeyLocationVerdict = "unknown";
    expect([status, verdict, bogusStatus, bogusVerdict]).toHaveLength(4);
  });

  it("carries the engine's defaults, not re-guessed literals", () => {
    expect(DEFAULT_KEY_CONTEXT).toBe(64);
    expect(DEFAULT_MAX_KEY_OFFSETS).toBe(64);
  });
});

/**
 * `present` is `null` — NOT `false` — on any row that was never searched. A
 * falsy check would paint an unreadable dump as a proven absence, which is the
 * exact silent zero the backend's row invariants exist to prevent.
 */
describe("the per-dump row contract", () => {
  const rows: DumpKeyLocation[] = [
    {
      dump_path: "/dumps/pre_abort.dump",
      name: "pre_abort.dump",
      format_name: "raw",
      size_for_view: 11223040,
      status: "searched",
      present: true,
      first_offset: 370672,
      hit_count: 1,
      offsets: [370672],
      offsets_truncated: false,
      detail: "",
    },
    {
      dump_path: "/dumps/post_cleanup.dump",
      name: "post_cleanup.dump",
      format_name: "raw",
      size_for_view: 11223040,
      status: "searched",
      present: false,
      first_offset: null,
      hit_count: 0,
      offsets: [],
      offsets_truncated: false,
      detail: "",
    },
    {
      dump_path: "/dumps/broken.dump",
      name: "broken.dump",
      format_name: "",
      size_for_view: 0,
      status: "unreadable",
      present: null,
      first_offset: null,
      hit_count: 0,
      offsets: [],
      offsets_truncated: false,
      detail: "Permission denied",
    },
  ];

  it("distinguishes searched-and-absent from never-searched", () => {
    expect(rows.filter((r) => r.present === true)).toHaveLength(1);
    expect(rows.filter((r) => r.present === false)).toHaveLength(1);
    expect(rows.filter((r) => r.present === null)).toHaveLength(1);
    // The trap: a falsy test folds the unreadable row into the absent ones.
    expect(rows.filter((r) => !r.present)).toHaveLength(2);
  });

  it("keeps hit_count as the true total even when offsets were truncated", () => {
    const truncated: DumpKeyLocation = {
      ...rows[0],
      hit_count: 5311,
      offsets: [370672, 370720],
      offsets_truncated: true,
    };
    expect(truncated.offsets.length).toBeLessThan(truncated.hit_count);
  });
});

describe("windowPanels", () => {
  function response(
    windows: KeyPatternResponse["windows"],
  ): KeyPatternResponse {
    return {
      format: "yara",
      content: "rule x {}",
      pattern: {
        name: "x",
        length: 176,
        hex_pattern: "",
        wildcard_pattern: "",
        static_ratio: 0.7273,
        static_count: 128,
        volatile_count: 48,
      },
      region: {
        offset: 370608,
        length: 176,
        key_start: 370672,
        key_end: 370720,
        key_offset_in_pattern: 64,
        context_requested: 64,
        context_before: 64,
        context_after: 64,
      },
      offsets_agree: true,
      key_static_count: 0,
      key_wildcard_count: 48,
      mask_regions: 8,
      mask_dumps_present: 2,
      mask_dumps_absent: 6,
      excluded_dumps: [],
      windows,
      location: {} as KeyPatternResponse["location"],
      diagnostics: [],
    };
  }

  it("decodes each window's hex into a CrossLibraryHex panel", () => {
    const panels = windowPanels(
      response([
        {
          dump_path: "/dumps/a.dump",
          name: "a.dump",
          window_start: 370608,
          key_start: 370672,
          present: true,
          reference: true,
          hex: "00ff10",
        },
        {
          dump_path: "/dumps/b.dump",
          name: "b.dump",
          window_start: 370608,
          key_start: 370672,
          present: false,
          reference: false,
          hex: "0102ab",
        },
      ]),
    );

    expect(panels).toHaveLength(2);
    expect(panels[0].name).toBe("a.dump");
    expect([...panels[0].data]).toEqual([0x00, 0xff, 0x10]);
    expect([...panels[1].data]).toEqual([0x01, 0x02, 0xab]);
  });

  it("DROPS a window with no hex rather than rendering an empty panel", () => {
    // An all-zero panel beside real bytes reads as "this dump is zeroed here",
    // which is a claim about memory the response never made.
    const panels = windowPanels(
      response([
        {
          dump_path: "/dumps/a.dump",
          name: "a.dump",
          window_start: 0,
          key_start: 64,
          present: true,
          reference: true,
          hex: "abcd",
        },
        {
          dump_path: "/dumps/b.dump",
          name: "b.dump",
          window_start: 0,
          key_start: 64,
          present: false,
          reference: false,
        },
      ]),
    );

    expect(panels).toHaveLength(1);
    expect(panels[0].name).toBe("a.dump");
  });

  it("returns an empty list when no window carries bytes", () => {
    expect(windowPanels(response([]))).toEqual([]);
  });
});

describe("locateKey", () => {
  it("POSTs to /api/analysis/locate-key with secret_hex, not key_hex", async () => {
    const fetchMock = vi.fn().mockResolvedValue({
      ok: true,
      status: 200,
      text: async () => JSON.stringify({ verdict: "found" }),
    });
    vi.stubGlobal("fetch", fetchMock);

    // THE wire collision: `key_hex` decrypts the container, `secret_hex` is the
    // needle. One request may legitimately carry both.
    const body: LocateKeyRequest = {
      dump_paths: ["/a.dump"],
      secret_hex: "aabb",
      key_hex: "00".repeat(32),
    };
    await locateKey(body);

    const [url, init] = fetchMock.mock.calls[0] as [string, RequestInit];
    expect(url).toBe("/api/analysis/locate-key");
    expect(init.method).toBe("POST");
    const sent = JSON.parse(init.body as string);
    expect(sent.secret_hex).toBe("aabb");
    expect(sent.key_hex).toBe("00".repeat(32));

    vi.unstubAllGlobals();
  });
});

describe("exportKeyPattern", () => {
  it("POSTs to /api/analysis/key-pattern", async () => {
    const fetchMock = vi.fn().mockResolvedValue({
      ok: true,
      status: 200,
      text: async () => JSON.stringify({ format: "yara" }),
    });
    vi.stubGlobal("fetch", fetchMock);

    await exportKeyPattern({ dump_paths: ["/a", "/b"], secret_hex: "aabb" });

    const [url, init] = fetchMock.mock.calls[0] as [string, RequestInit];
    expect(url).toBe("/api/analysis/key-pattern");
    expect(init.method).toBe("POST");

    vi.unstubAllGlobals();
  });
});

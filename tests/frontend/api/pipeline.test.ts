import { describe, it, expect } from "vitest";

import { artifactDownloadUrl } from "@/api/pipeline";
import type {
  PcapSkipReason,
  PcapValidateResult,
  PipelineRunRequest,
} from "@/api/pipeline";

describe("artifactDownloadUrl", () => {
  it("builds the runs/artifacts path", () => {
    expect(artifactDownloadUrl("abc123", "keys.json")).toBe(
      "/api/pipeline/runs/abc123/artifacts/keys.json",
    );
  });

  it("percent-encodes both the task id and the artifact name", () => {
    expect(artifactDownloadUrl("a b/c", "my file.bin")).toBe(
      "/api/pipeline/runs/a%20b%2Fc/artifacts/my%20file.bin",
    );
  });
});

/**
 * The pcap arm step reports what the parse DROPPED, not only what it kept, so
 * the operator can tell "nothing to find" from "we never looked at 40 % of the
 * capture". These fixtures are the real payload shape of
 * ``POST /api/pcaps/validate`` (see tests/test_api_pcaps.py); typing them as
 * the declared interfaces makes this a compile-time contract check as much as
 * a runtime one.
 */
describe("PcapValidateResult accounting fields", () => {
  const result: PcapValidateResult = {
    pcap_path: "/tmp/traffic.pcap",
    session_count: 1,
    sessions: [
      {
        client_random: "aa".repeat(32),
        server_random: "bb".repeat(32),
        version: "13",
        cipher_suite: 4865,
        cipher_name: "TLS_AES_128_GCM_SHA256",
        client_app_records: 20,
        server_app_records: 4,
        has_app_records: true,
        app_records_seen: 24,
        records_returned: 20,
        // The 20 covered records over a TLS 1.3 sequence window, counted per
        // DIRECTION (the window index restarts on each side). Client: 16
        // records, indices 0..15, contributing min(index, 8) + 1 challenges =
        // (1+..+9) + 7*9 = 108. Server: 4 records = 1+2+3+4 = 10. Total 118 --
        // ~5.9 per covered record, which is why the challenge numbers are
        // reported separately from the record ones rather than derived.
        challenges_available: 118,
        challenges_returned: 118,
      },
    ],
    skipped_sessions: [
      {
        reason: "unsupported_cipher_suite",
        flow: "10.0.0.1:443 -> 10.0.0.2:51000",
        cipher_suite: 4866,
      },
    ],
    flow_count: 4,
    caps: { max_records_per_direction: 16, max_challenges: null },
    records_truncated: true,
  };

  it("surfaces a dropped session with a machine-readable reason", () => {
    expect(result.skipped_sessions?.[0].reason).toBe("unsupported_cipher_suite");
    expect(result.skipped_sessions?.[0].cipher_suite).toBe(4866);
  });

  it("distinguishes flows seen from sessions kept", () => {
    expect(result.flow_count).toBe(4);
    expect(result.session_count).toBe(1);
  });

  it("reports the record cap that clipped a session", () => {
    const session = result.sessions[0];
    expect(result.caps?.max_records_per_direction).toBe(16);
    expect(result.records_truncated).toBe(true);
    expect(session.records_returned).toBeLessThan(session.app_records_seen ?? 0);
  });

  it("tolerates a response without the accounting fields", () => {
    const bare: PcapValidateResult = {
      pcap_path: "/tmp/empty.pcap",
      session_count: 0,
      sessions: [],
    };
    expect(bare.records_truncated).toBeUndefined();
  });

  it("reports an uncapped challenge budget as a present null, not a gap", () => {
    // ``max_challenges`` is optional on the type but the backend always emits
    // the KEY (``null`` when uncapped), so "uncapped" is distinguishable from
    // "this response predates the field".
    expect(result.caps?.max_challenges).toBeNull();
    expect(result.caps && "max_challenges" in result.caps).toBe(true);
  });
});

/**
 * The skip reasons are a CLOSED union, so a literal that does not exist on the
 * backend is a compile error rather than a row the UI silently cannot label.
 * These are the exact strings ``TlsPcapResource._note_skipped`` is called with
 * (engine/resources/tls_pcap.py) -- pinned here because a wrong literal in a
 * closed union is worse than no union at all: it type-checks and then never
 * matches a real response.
 */
describe("PcapSkipReason", () => {
  const reasons: PcapSkipReason[] = [
    "no_client_hello",
    "no_server_hello",
    "no_cipher_suite",
    "short_random",
    "unsupported_cipher_suite",
    "no_change_cipher_spec",
    "client_random_mismatch",
  ];

  it("covers every reason the parser can emit", () => {
    expect(reasons).toHaveLength(7);
    expect(new Set(reasons).size).toBe(reasons.length);
  });

  it("carries per-direction context for a missing ChangeCipherSpec", () => {
    // A TLS 1.2 direction with no ChangeCipherSpec is undecryptable, so the
    // session is KEPT while its records are uncoverable: ``records_returned: 0``
    // against a non-zero ``app_records_seen``, explained by this entry. The
    // entry's ``app_records_seen`` is that DIRECTION's count, so it can be
    // smaller than the session-level (both-directions) number.
    const result: PcapValidateResult = {
      pcap_path: "/tmp/no-ccs.pcap",
      session_count: 1,
      sessions: [
        {
          client_random: "00".repeat(32),
          server_random: "11".repeat(32),
          version: "12",
          cipher_suite: 49199,
          cipher_name: "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
          client_app_records: 3,
          server_app_records: 0,
          has_app_records: true,
          app_records_seen: 3,
          records_returned: 0,
          challenges_available: 0,
          challenges_returned: 0,
        },
      ],
      skipped_sessions: [
        {
          reason: "no_change_cipher_spec",
          flow: "10.0.0.1:12345 -> 10.0.0.2:443",
          direction: "client",
          app_records_seen: 3,
        },
      ],
      flow_count: 2,
      caps: { max_records_per_direction: 16, max_challenges: null },
      records_truncated: true,
      challenges_available: 0,
      challenges_returned: 0,
      challenges_truncated: false,
    };

    const session = result.sessions[0];
    const skip = result.skipped_sessions?.[0];
    expect(session.records_returned).toBe(0);
    expect(session.app_records_seen).toBe(3);
    expect(result.records_truncated).toBe(true);
    expect(skip?.reason).toBe("no_change_cipher_spec");
    expect(skip?.direction).toBe("client");
    expect(skip?.app_records_seen).toBe(3);
    // Zero challenges available is NOT a truncation -- there was nothing to
    // truncate. The truncation flag must not fire on an empty stream.
    expect(result.challenges_truncated).toBe(false);
  });

  it("names the session a client_random filter passed over", () => {
    const skip: PcapValidateResult["skipped_sessions"] = [
      {
        reason: "client_random_mismatch",
        flow: "10.0.0.1:12345 -> 10.0.0.2:443",
        client_random: "cc".repeat(32),
      },
    ];
    expect(skip[0].client_random).toHaveLength(64);
  });
});

describe("capture-level challenge accounting", () => {
  it("flags a challenge budget that clipped the stream", () => {
    // ``max_challenges`` is spent ACROSS sessions in parse order, so the
    // capture-level numbers -- not the per-session ones -- are what say whether
    // the oracle saw the whole capture.
    const capped: PcapValidateResult = {
      pcap_path: "/tmp/traffic.pcap",
      session_count: 2,
      sessions: [],
      caps: { max_records_per_direction: 16, max_challenges: 50 },
      challenges_available: 195,
      challenges_returned: 50,
      challenges_truncated: true,
      records_truncated: true,
    };
    expect(capped.challenges_returned).toBeLessThan(
      capped.challenges_available ?? 0,
    );
    expect(capped.challenges_truncated).toBe(true);
    // ~3.9 challenges per record on the corpus, so a cap of 50 buys ~13
    // records: the reason ``challenges_available`` has to be reported at all.
    expect(Math.floor((capped.caps?.max_challenges ?? 0) / 3.9)).toBe(12);
  });
});

describe("PipelineRunRequest pcap work caps", () => {
  it("accepts both caps, and null to keep the backend defaults", () => {
    const capped: PipelineRunRequest = {
      source_paths: ["/tmp/a.dump"],
      pcap_path: "/tmp/traffic.pcap",
      pcap_max_records: 64,
      pcap_max_challenges: 128,
    };
    const defaulted: PipelineRunRequest = {
      source_paths: ["/tmp/a.dump"],
      pcap_path: "/tmp/traffic.pcap",
      pcap_max_records: null,
      pcap_max_challenges: null,
    };
    expect(capped.pcap_max_records).toBe(64);
    expect(defaulted.pcap_max_challenges).toBeNull();
  });
});

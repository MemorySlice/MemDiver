import { describe, it, expect } from "vitest";

import type { PcapField, PcapSession } from "@/api/pipeline";
import {
  pcapFieldPreview,
  pcapSessionSummary,
  pcapVersionLabel,
  sessionHasAppRecords,
  shortClientRandom,
} from "@/components/pipeline/oracle/pcap-session";

function makeSession(overrides: Partial<PcapSession> = {}): PcapSession {
  return {
    client_random: "a".repeat(64),
    server_random: "b".repeat(64),
    version: "13",
    cipher_suite: 0x1301,
    cipher_name: "TLS_AES_128_GCM_SHA256",
    client_app_records: 3,
    server_app_records: 5,
    has_app_records: true,
    ...overrides,
  };
}

describe("pcapVersionLabel", () => {
  it("maps 13 to 1.3", () => {
    expect(pcapVersionLabel("13")).toBe("1.3");
  });
  it("maps 12 to 1.2", () => {
    expect(pcapVersionLabel("12")).toBe("1.2");
  });
});

describe("shortClientRandom", () => {
  it("truncates long randoms with an ellipsis", () => {
    expect(shortClientRandom("a".repeat(64))).toBe(`${"a".repeat(16)}…`);
  });
  it("leaves short values untouched", () => {
    expect(shortClientRandom("deadbeef")).toBe("deadbeef");
  });
});

describe("pcapSessionSummary", () => {
  it("projects the interpolation fields", () => {
    expect(pcapSessionSummary(makeSession())).toEqual({
      version: "1.3",
      cipher: "TLS_AES_128_GCM_SHA256",
      clientRecords: 3,
      serverRecords: 5,
    });
  });

  it("reflects a TLS 1.2 session", () => {
    const summary = pcapSessionSummary(
      makeSession({ version: "12", cipher_name: "TLS_RSA_WITH_AES_128_CBC_SHA" }),
    );
    expect(summary.version).toBe("1.2");
    expect(summary.cipher).toBe("TLS_RSA_WITH_AES_128_CBC_SHA");
  });
});

describe("sessionHasAppRecords", () => {
  it("returns the backend-emitted flag verbatim", () => {
    expect(
      sessionHasAppRecords(
        makeSession({ has_app_records: false, client_app_records: 9, server_app_records: 9 }),
      ),
    ).toBe(false);
    expect(
      sessionHasAppRecords(
        makeSession({ has_app_records: true, client_app_records: 0, server_app_records: 0 }),
      ),
    ).toBe(true);
  });
});

function makeField(overrides: Partial<PcapField> = {}): PcapField {
  return {
    field_id: "client_random",
    label: "ClientHello.random",
    type: "bytes",
    value_hex: "aa".repeat(32),
    value: null,
    length: 32,
    source: "client_hello",
    provenance: null,
    searchable: true,
    ...overrides,
  };
}

/**
 * ``pcapFieldPreview`` decides what a reader sees for one field. The rule is
 * "the decoded form when there is a more useful one than hex", because the two
 * audiences differ: a dump search wants ``value_hex``, a human reading the
 * browser wants the hostname.
 */
describe("pcapFieldPreview", () => {
  it("prefers a decoded string over its hex", () => {
    expect(
      pcapFieldPreview(
        makeField({ type: "string", value: "example.com", value_hex: "6578" }),
      ),
    ).toBe("example.com");
  });

  it("renders a uint and a uint[] from the decoded value", () => {
    expect(pcapFieldPreview(makeField({ type: "uint", value: 4865 }))).toBe("4865");
    expect(
      pcapFieldPreview(makeField({ type: "uint[]", value: [4865, 4866] })),
    ).toBe("4865, 4866");
  });

  it("elides a long hex run but keeps a short one whole", () => {
    // 32 bytes of random is 64 hex characters; the full run stays in the row's
    // ``title``, so eliding here hides nothing.
    expect(pcapFieldPreview(makeField())).toBe(`${"aa".repeat(16)}…`);
    expect(pcapFieldPreview(makeField({ value_hex: "aabbccdd" }))).toBe("aabbccdd");
  });

  it("renders a field with no byte form as empty", () => {
    // The record-sequence lists: no wire bytes at all (TLS never transmits the
    // sequence number), so there is nothing to preview when ``value`` is null.
    expect(pcapFieldPreview(makeField({ value_hex: "", value: null }))).toBe("");
  });
});

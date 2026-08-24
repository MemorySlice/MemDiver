import { describe, it, expect } from "vitest";

import {
  buildSecrets,
  countValidEntries,
  entryFromVerifiedKey,
  makeEntry,
  updateEntry,
  validateEntry,
  type KeylogEntry,
} from "./keylog-composer";
import { DEFAULT_SECRET_TYPE } from "@/api/keylog-labels";

// A valid 32-byte (64 hex char) client random and an even-length secret.
const CLIENT_RANDOM = "aa".repeat(32);
const SECRET = "bb".repeat(32);

function entry(overrides: Partial<KeylogEntry> = {}): KeylogEntry {
  return {
    id: overrides.id ?? "id-1",
    secretType: overrides.secretType ?? "CLIENT_TRAFFIC_SECRET_0",
    clientRandom: overrides.clientRandom ?? CLIENT_RANDOM,
    secret: overrides.secret ?? SECRET,
  };
}

describe("validateEntry", () => {
  it("accepts a fully-formed entry", () => {
    expect(validateEntry(entry()).valid).toBe(true);
  });

  it("rejects an empty secret type", () => {
    const v = validateEntry(entry({ secretType: "  " }));
    expect(v.secretTypeValid).toBe(false);
    expect(v.valid).toBe(false);
  });

  it("rejects a client random that is not 64 hex chars", () => {
    const v = validateEntry(entry({ clientRandom: "abcd" }));
    expect(v.clientRandomValid).toBe(false);
    expect(v.valid).toBe(false);
  });

  it("rejects non-hex or odd-length secrets", () => {
    expect(validateEntry(entry({ secret: "zz" })).secretValid).toBe(false);
    expect(validateEntry(entry({ secret: "abc" })).secretValid).toBe(false);
    expect(validateEntry(entry({ secret: "" })).secretValid).toBe(false);
  });

  it("normalises whitespace and 0x prefix before validating", () => {
    const v = validateEntry(
      entry({ clientRandom: `0x${CLIENT_RANDOM}`, secret: `  ${SECRET}  ` }),
    );
    expect(v.valid).toBe(true);
  });
});

describe("buildSecrets", () => {
  it("assembles snake_case secrets from valid entries with normalised hex", () => {
    const secrets = buildSecrets([
      entry({ id: "a", clientRandom: `0x${CLIENT_RANDOM}` }),
    ]);
    expect(secrets).toEqual([
      {
        secret_type: "CLIENT_TRAFFIC_SECRET_0",
        client_random: CLIENT_RANDOM,
        secret: SECRET,
      },
    ]);
  });

  it("excludes invalid rows so a half-filled entry cannot corrupt output", () => {
    const secrets = buildSecrets([
      entry({ id: "good" }),
      entry({ id: "bad", clientRandom: "" }),
    ]);
    expect(secrets).toHaveLength(1);
    expect(secrets[0].client_random).toBe(CLIENT_RANDOM);
  });

  it("returns an empty array when nothing is valid", () => {
    expect(buildSecrets([entry({ secret: "zz" })])).toEqual([]);
  });
});

describe("countValidEntries", () => {
  it("counts only fully-valid entries", () => {
    expect(
      countValidEntries([entry({ id: "a" }), entry({ id: "b", secretType: "" })]),
    ).toBe(1);
  });
});

describe("entry helpers", () => {
  it("makeEntry produces a unique id and blank fields by default", () => {
    const a = makeEntry();
    const b = makeEntry();
    expect(a.id).not.toBe(b.id);
    expect(a).toMatchObject({ secretType: "", clientRandom: "", secret: "" });
  });

  it("entryFromVerifiedKey seeds the default label and the key as the secret", () => {
    const e = entryFromVerifiedKey(SECRET);
    expect(e.secretType).toBe(DEFAULT_SECRET_TYPE);
    expect(e.secret).toBe(SECRET);
    expect(e.clientRandom).toBe("");
  });

  it("updateEntry patches a single field of one entry immutably", () => {
    const list = [entry({ id: "a", secretType: "CLIENT_RANDOM" }), entry({ id: "b" })];
    const next = updateEntry(list, "a", { secretType: "EXPORTER_SECRET" });
    expect(next).not.toBe(list);
    expect(next[1]).toBe(list[1]);
    expect(next[0].secretType).toBe("EXPORTER_SECRET");
  });
});

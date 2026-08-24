/**
 * Pure state + validation helpers for the NSS key-log composer section of
 * KeyVerificationPanel. Kept free of React so the secret-assembly and
 * per-field validation rules can be unit-tested in isolation.
 */
import type { KeylogSecret } from "@/api/types";
import { CLIENT_RANDOM_HEX_LEN, DEFAULT_SECRET_TYPE } from "@/api/keylog-labels";
import { isEvenHex, normalizeHex } from "@/utils/hex";

export interface KeylogEntry {
  id: string;
  secretType: string;
  clientRandom: string;
  secret: string;
}

export interface EntryValidation {
  secretTypeValid: boolean;
  clientRandomValid: boolean;
  secretValid: boolean;
  valid: boolean;
}

/**
 * Build a fresh entry. `crypto.randomUUID` gives a stable React key and a
 * handle a future prefill source (e.g. a pcap TLS session) can target.
 */
export function makeEntry(
  partial: Partial<Omit<KeylogEntry, "id">> = {},
): KeylogEntry {
  // ``crypto.randomUUID`` is undefined in an insecure context (plain http on a
  // LAN IP); it is only a React key here, so fall back to a cheap unique id
  // rather than throwing inside a setState updater and crashing the composer.
  const id =
    typeof crypto !== "undefined" && crypto.randomUUID
      ? crypto.randomUUID()
      : `e-${Date.now()}-${Math.random().toString(36).slice(2)}`;
  return {
    id,
    secretType: partial.secretType ?? "",
    clientRandom: partial.clientRandom ?? "",
    secret: partial.secret ?? "",
  };
}

/** Seed an entry from a verified recovered key (Add to key log). */
export function entryFromVerifiedKey(keyHex: string): KeylogEntry {
  return makeEntry({ secretType: DEFAULT_SECRET_TYPE, secret: keyHex, clientRandom: "" });
}

/** Patch a single field of one entry without mutating the array. */
export function updateEntry(
  entries: KeylogEntry[],
  id: string,
  patch: Partial<Omit<KeylogEntry, "id">>,
): KeylogEntry[] {
  return entries.map((e) => (e.id === id ? { ...e, ...patch } : e));
}

/**
 * Validate one entry:
 *  - secretType must be non-empty.
 *  - clientRandom must be a non-empty even-length hex string, and exactly the
 *    32-byte (64 hex char) TLS ClientHello random — Wireshark keys secrets by
 *    it, so a wrong length silently fails to decrypt.
 *  - secret must be a non-empty even-length hex string.
 */
export function validateEntry(entry: KeylogEntry): EntryValidation {
  const cleanClientRandom = normalizeHex(entry.clientRandom);
  const cleanSecret = normalizeHex(entry.secret);
  const secretTypeValid = entry.secretType.trim().length > 0;
  const clientRandomValid =
    isEvenHex(cleanClientRandom) && cleanClientRandom.length === CLIENT_RANDOM_HEX_LEN;
  const secretValid = isEvenHex(cleanSecret);
  return {
    secretTypeValid,
    clientRandomValid,
    secretValid,
    valid: secretTypeValid && clientRandomValid && secretValid,
  };
}

/** How many entries are fully valid (gates the Export button). */
export function countValidEntries(entries: KeylogEntry[]): number {
  return entries.reduce((n, e) => (validateEntry(e).valid ? n + 1 : n), 0);
}

/**
 * Assemble the export payload from the fully-valid entries only, normalising
 * hex fields. Invalid/partial rows are excluded so a half-filled row can never
 * corrupt the downloaded key log.
 */
export function buildSecrets(entries: KeylogEntry[]): KeylogSecret[] {
  return entries
    .filter((e) => validateEntry(e).valid)
    .map((e) => ({
      secret_type: e.secretType,
      client_random: normalizeHex(e.clientRandom),
      secret: normalizeHex(e.secret),
    }));
}

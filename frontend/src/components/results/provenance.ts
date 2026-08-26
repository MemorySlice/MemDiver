/**
 * How a recovered key was proven — the pure half of {@link VerificationBadge}.
 *
 * Kept in its own module (like `pcap-session.ts` beside the oracle panel) so the
 * component file exports only components: a `.tsx` that also exports helpers
 * breaks React Fast Refresh (`react-refresh/only-export-components`).
 */

/**
 * The three ways a recovered key can be proven, strongest first:
 *  - `"pcap"`     the key decrypted real records from a captured TLS session;
 *  - `"oracle"`   a user-supplied decryption oracle script accepted the key;
 *  - `"verifier"` the key decrypted MemDiver's built-in cipher test vector.
 */
export type ProvenanceKey = "pcap" | "oracle" | "verifier";

const PROVENANCE_KEYS: readonly ProvenanceKey[] = ["pcap", "oracle", "verifier"];

/**
 * Narrow an arbitrary backend `confirmed_by` label to a known provenance key.
 *
 * Anything unrecognized (including `null`/`undefined`) yields `null` so the
 * caller can fall back to a generic label instead of leaking a raw i18n key.
 * The backend deliberately emits labels beyond these three (e.g.
 * `"manual_review"`), so this must stay a runtime narrowing, not a cast.
 */
export function toProvenanceKey(
  value: string | null | undefined,
): ProvenanceKey | null {
  return PROVENANCE_KEYS.find((key) => key === value) ?? null;
}

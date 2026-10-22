import type { KeyMaterial } from "./types";

/**
 * Wire fields (`passphrase`, `key_hex`, `kem_key_hex`) for the key material
 * the caller actually supplied; blank values are dropped. Callers put the
 * result in a POST body or multipart form, never in a query string.
 *
 * Its own module (not `client.ts`) so tests that mock `@/api/client` keep
 * the real encoding in `dump-import.ts`.
 */
export function keyMaterialWire(km?: KeyMaterial): Record<string, string> {
  return {
    ...(km?.passphrase ? { passphrase: km.passphrase } : {}),
    ...(km?.key_hex?.trim() ? { key_hex: km.key_hex.trim() } : {}),
    ...(km?.kem_key_hex?.trim() ? { kem_key_hex: km.kem_key_hex.trim() } : {}),
  };
}

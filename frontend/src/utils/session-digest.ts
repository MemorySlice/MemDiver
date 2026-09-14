/**
 * "Has this workspace changed since it was last saved?", answered in one place.
 *
 * The question is deliberately reduced to: *would saving now write different
 * bytes than last time?* That makes `buildSessionSnapshot` — already the single
 * declared source of truth for what a session contains — the only thing that
 * defines dirtiness too. The alternative, a `markDirty()` flag called from every
 * mutating action across ~18 stores, would invert the dependency direction
 * (`app-store` imports the sibling stores, not the reverse), and would rot
 * silently the first time anyone adds a setter and forgets the call.
 *
 * Two rules keep it honest:
 *
 * 1. **Denylist, never allowlist.** Only the volatile identity fields below are
 *    dropped; everything else counts. A field added to the snapshot is picked up
 *    automatically, which is what lets the payload grow without this file
 *    knowing. An allowlist would silently stop noticing new work.
 *
 * 2. **Uncertainty resolves toward "dirty".** A false positive costs one extra
 *    dialog; a false negative costs the analyst their work. If the two sides are
 *    ever not comparable, say dirty.
 *
 * The known cost of rule 1: a `SessionSnapshot` field that the server sends but
 * `buildSessionSnapshot` does not produce makes a just-loaded session read as
 * dirty forever. That is the intended failure direction, but it means any new
 * snapshot field on the backend must be mirrored into `buildSessionSnapshot.ts`.
 */

import type { SessionSnapshot } from "@/api/types";

/**
 * Fields that say *which save this is*, not *what was saved*. Comparing them
 * would make every session dirty the instant it was written.
 */
const VOLATILE_FIELDS = new Set([
  "session_name",
  "schema_version",
  "memdiver_version",
  "created_at",
]);

/**
 * Recursively sort object keys so two structurally equal payloads stringify
 * identically. A plain `JSON.stringify` preserves insertion order, and a
 * snapshot that has been round-tripped through the API comes back with its
 * nested `analysis_result` keys in a different order than the one the UI built
 * — which would otherwise read as a change.
 */
function sortDeep(value: unknown, seen: WeakSet<object>): unknown {
  if (Array.isArray(value)) {
    // Array ORDER stays significant -- a reordered selection is a real change,
    // unlike a reordered set of object keys.
    if (seen.has(value)) throw new TypeError("cyclic snapshot");
    seen.add(value);
    const mapped = value.map((item) => sortDeep(item, seen));
    seen.delete(value);
    return mapped;
  }
  if (value === null || typeof value !== "object") return value;

  const source = value as Record<string, unknown>;
  // Detected explicitly rather than left to blow the stack: a RangeError would
  // also be caught below, but only after a slow, deep recursion.
  if (seen.has(source)) throw new TypeError("cyclic snapshot");
  seen.add(source);

  const sorted: Record<string, unknown> = {};
  for (const key of Object.keys(source).sort()) {
    sorted[key] = sortDeep(source[key], seen);
  }
  seen.delete(source);
  return sorted;
}

/**
 * A stable projection of *snap*. Two equal digests mean saving would be a no-op.
 *
 * Returns a unique sentinel if the snapshot cannot be serialized at all (a
 * cyclic object, a `BigInt`), because per rule 2 an unanswerable comparison
 * must read as "changed" rather than as "clean".
 */
export function snapshotDigest(snap: Partial<SessionSnapshot>): string {
  try {
    const kept: Record<string, unknown> = {};
    for (const [key, value] of Object.entries(snap)) {
      if (VOLATILE_FIELDS.has(key)) continue;
      // `undefined` and an absent key mean the same thing to the server, so
      // they must not produce different digests.
      if (value === undefined) continue;
      kept[key] = value;
    }
    // Sorting the projection itself (rather than each value) is what orders the
    // TOP-LEVEL keys too -- without it, the same snapshot built by the UI and
    // returned by the API digests differently.
    return JSON.stringify(sortDeep(kept, new WeakSet()));
  } catch {
    return `__undigestable__${Date.now()}_${Math.random()}`;
  }
}

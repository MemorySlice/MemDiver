/**
 * Runtime shape checks shared by every type guard over a server answer.
 *
 * A response can decode to anything — `undefined` for an empty body, `null`,
 * a string — and the `in` operator throws a TypeError on a non-object, so a
 * guard must never apply `in` to a value it has not first proven an object.
 */

/** `v` is a non-null object (arrays included), safe to apply `in` to. */
export const isObject = (v: unknown): v is Record<string, unknown> =>
  typeof v === "object" && v !== null;

/** `v` is an object carrying an own or inherited `key`; false for any non-object. */
export const hasKey = <K extends string>(v: unknown, key: K): v is Record<K, unknown> =>
  isObject(v) && key in v;

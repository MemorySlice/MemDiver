import i18n from "@/i18n";

/** The slice of an i18next instance {@link errorCodeHint} needs. */
type HintTranslator = Pick<typeof i18n, "exists" | "t">;

/**
 * The localized explanation of a backend error `code` (`common:errorCodes.<code>`,
 * e.g. `path.outside_sandbox`), or `null` when there is none.
 *
 * `null` for a missing / unknown code, for a code that names a group of codes
 * rather than a sentence, and for an empty string: the caller already shows the
 * server's own message, so an unknown code simply adds nothing.
 */
export function errorCodeHint(
  code: string | null | undefined,
  translator: HintTranslator = i18n,
): string | null {
  if (!code) return null;
  const key = `common:errorCodes.${code}`;
  if (!translator.exists(key)) return null;
  const text: unknown = translator.t(key, { returnObjects: true });
  return typeof text === "string" && text.trim() !== "" ? text : null;
}

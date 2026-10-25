import type { Vol3Requirement } from "@/api/vol3";

/** A form field's raw value: text for most types, a checkbox state for booleans. */
export type ArgDraft = Record<string, string | boolean>;
/** Field name -> the i18n key suffix (under `args.error.`) of what is wrong. */
export type ArgErrors = Record<string, "required" | "integer">;

const isListOf = (req: Vol3Requirement, type: string) =>
  req.type === "array" && req.items?.type === type;

/** Initial form values: every requirement's default, as the text it would be typed as. */
export function initialDraft(reqs: readonly Vol3Requirement[]): ArgDraft {
  const draft: ArgDraft = {};
  for (const req of reqs) {
    if (req.type === "boolean") draft[req.name] = req.default === true;
    else if (Array.isArray(req.default)) draft[req.name] = req.default.join(", ");
    else draft[req.name] = req.default === null || req.default === undefined ? "" : String(req.default);
  }
  return draft;
}

/** `0x`-prefixed hex or decimal; anything else is not an integer. */
export function parseInteger(text: string): number | null {
  const trimmed = text.trim();
  if (!/^-?(0x[0-9a-f]+|\d+)$/i.test(trimmed)) return null;
  const value = Number(trimmed);
  return Number.isSafeInteger(value) ? value : null;
}

const splitList = (text: string) => text.split(/[\s,]+/).filter((part) => part !== "");

type Parsed = { value: unknown } | { skip: true } | { error: ArgErrors[string] };

function parseField(req: Vol3Requirement, raw: string | boolean | undefined): Parsed {
  const text = typeof raw === "string" ? raw.trim() : "";
  if (req.type === "boolean") {
    // An untouched (unticked, default-false) box is "not chosen": leave it to the plugin.
    if (raw === true) return { value: true };
    return req.default === true ? { value: false } : { skip: true };
  }
  if (text === "") return req.optional || req.default != null ? { skip: true } : { error: "required" };
  if (req.type === "integer") {
    const value = parseInteger(text);
    return value === null ? { error: "integer" } : { value };
  }
  if (isListOf(req, "integer")) {
    const values = splitList(text).map(parseInteger);
    return values.includes(null) ? { error: "integer" } : { value: values };
  }
  return req.type === "array" ? { value: splitList(text) } : { value: text };
}

/**
 * The `args` object of a run. Empty optional fields are OMITTED rather than sent
 * blank, so the backend's own defaults (and the process view's `pid` auto-fill)
 * still apply.
 */
export function buildArgs(
  reqs: readonly Vol3Requirement[],
  draft: ArgDraft,
): { args: Record<string, unknown>; errors: ArgErrors } {
  const args: Record<string, unknown> = {};
  const errors: ArgErrors = {};
  for (const req of reqs) {
    const parsed = parseField(req, draft[req.name]);
    if ("error" in parsed) errors[req.name] = parsed.error;
    else if ("value" in parsed) args[req.name] = parsed.value;
  }
  return { args, errors };
}

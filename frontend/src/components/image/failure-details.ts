/** An item a backend failure names as the cause (`details.implicated` of `profile_build_failed`). */
export interface ImplicatedItem { item: string; reason?: string }

function envelopeOf(err: unknown): Record<string, unknown> | null {
  const raw = (err instanceof Error ? err.message : String(err)).trim();
  if (!raw.startsWith("{")) return null;
  try {
    const parsed: unknown = JSON.parse(raw);
    return parsed && typeof parsed === "object" ? (parsed as Record<string, unknown>) : null;
  } catch { return null; }
}

/** The backend's error code (`kernel_view_required`, `profile_build_failed`, ...), else null. */
export function failureCode(err: unknown): string | null {
  const env = envelopeOf(err);
  const code = env?.code ?? env?.category ?? (env?.details as { code?: unknown } | undefined)?.code;
  if (typeof code === "string") return code;
  const text = typeof env?.error === "string" ? env.error : "";
  return /kernel_view_required/.test(text) ? "kernel_view_required" : null;
}

/** The implicated items of a failed request, `[]` when it names none. */
export function implicatedOf(err: unknown): ImplicatedItem[] {
  const env = envelopeOf(err);
  const list = (env?.details as { implicated?: unknown } | undefined)?.implicated ?? env?.implicated;
  if (!Array.isArray(list)) return [];
  return list.flatMap((x): ImplicatedItem[] => {
    if (typeof x === "string") return [{ item: x }];
    const o = x as { item?: unknown; reason?: unknown } | null;
    return typeof o?.item === "string"
      ? [{ item: o.item, ...(typeof o.reason === "string" ? { reason: o.reason } : {}) }] : [];
  });
}

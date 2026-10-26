import type { DraftMaterialized, IsfProvenance, IsfSection } from "@/api/isf";

export const CAPTURE = "/img.lime";
export const prov = (tier = "manual", over: Partial<IsfProvenance> = {}): IsfProvenance =>
  ({ source: "manual", tier, evidence: [], author: "human", ...over });

/** A `getIsfDraft` answer for one section: the page `[offset, offset+limit)` of `names`. */
export function draftAnswer(
  section: IsfSection, names: string[], opts: { offset?: number; limit?: number; total?: number } = {},
  items: Record<string, unknown> = {}, fieldOrigins?: Record<string, unknown>,
): DraftMaterialized {
  const offset = opts.offset ?? 0;
  const limit = opts.limit ?? 200;
  const shown = names.slice(offset, offset + limit);
  const body = Object.fromEntries(shown.map((n) => [n, items[n] ?? { address: "0x1000" }]));
  const origins = Object.fromEntries(shown.map((n) => [n, { entry_id: `e-${n}`, op: "set_symbol", provenance: prov("probe", { source: "kallsyms" }) }]));
  return {
    name: "d1", capture_id: "c", version: "v", applied: 3, metadata: {}, size_bounds: {},
    counts: { symbols: opts.total ?? names.length, user_types: 1, base_types: 0, enums: 0 },
    sections: { [section]: {
      items: body as never, total: names.length, offset, limit, missing: [],
      truncated: offset + shown.length < names.length, origins, ...(fieldOrigins ? { field_origins: fieldOrigins as never } : {}) } },
  };
}

/** Task WebSocket stand-in: tests play the events of the latest subscriber. */
export const ws = {
  calls: [] as { taskId: string | null; cbs: Record<string, (...a: unknown[]) => void> }[],
};
export const task = (taskId: string) => [...ws.calls].reverse().find((c) => c.taskId === taskId)!.cbs;

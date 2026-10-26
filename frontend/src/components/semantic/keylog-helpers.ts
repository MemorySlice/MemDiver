import type { KeylogResolution, KeylogSpec, SuggestedMeaning } from "@/api/semantic";

/** The server refuses key-log text above this; the client says so before sending. */
export const MAX_KEYLOG_BYTES = 4 * 1024 * 1024;

/** NSS labels an object can be anchored on: the TLS 1.3 secrets, and CLIENT_RANDOM (TLS 1.2 master secret). */
export const KEYLOG_LABELS = [
  "CLIENT_TRAFFIC_SECRET_0",
  "SERVER_TRAFFIC_SECRET_0",
  "CLIENT_HANDSHAKE_TRAFFIC_SECRET",
  "SERVER_HANDSHAKE_TRAFFIC_SECRET",
  "EXPORTER_SECRET",
  "CLIENT_RANDOM",
] as const;
export const DEFAULT_ANCHOR_LABEL = "CLIENT_TRAFFIC_SECRET_0";
/** Anchor choice meaning "let the server pick" (the request then omits anchor_label). */
export const AUTOMATIC_ANCHOR = "";

export type KeylogSource = "file" | "path" | "perDump";

export interface KeylogDraft {
  source: KeylogSource;
  fileName: string;
  text: string;
  lines: number;
  path: string;
  perDump: Record<string, string>;
  /** An NSS label, or AUTOMATIC_ANCHOR ("") to let the server choose. */
  anchorLabel: string;
  /** Labels the analyst switched OFF; the default (empty) means every other label. */
  unrelated: string[];
}

export const emptyKeylogDraft = (): KeylogDraft => ({
  source: "file", fileName: "", text: "", lines: 0, path: "", perDump: {},
  anchorLabel: AUTOMATIC_ANCHOR, unrelated: [],
});

/** Non-blank lines of a key log file. */
export const countKeylogLines = (text: string): number =>
  text.split(/\r?\n/).filter((l) => l.trim() !== "").length;

/** The `keylog` request spec of a draft, or null when nothing usable was given. */
export function keylogSpec(draft: KeylogDraft, dumpPaths: string[]): KeylogSpec | null {
  if (draft.source === "file") return draft.text !== "" ? { text: draft.text } : null;
  if (draft.source === "path") return draft.path.trim() !== "" ? { path: draft.path.trim() } : null;
  const per: Record<string, string> = {};
  for (const p of dumpPaths) {
    const v = (draft.perDump[p] ?? "").trim();
    if (v !== "") per[p] = v;
  }
  return Object.keys(per).length > 0 ? { per_dump: per } : null;
}

/** Selected related labels, or undefined when it is the default (let the server take every other). */
export function relatedLabelsFor(draft: KeylogDraft): string[] | undefined {
  if (draft.unrelated.length === 0) return undefined;
  return KEYLOG_LABELS.filter((l) => l !== draft.anchorLabel && !draft.unrelated.includes(l));
}

/** Absent and ambiguous both leave a dump unanchored; the reason text tells them apart. */
export function resolutionStatus(r: KeylogResolution): "anchored" | "ambiguous" | "absent" {
  if (r.anchored) return "anchored";
  return r.reason.startsWith("ambiguous") ? "ambiguous" : "absent";
}

export interface MeaningDraft { meaning: string; label: string }
export interface RelationshipDraft { kind: string; source: string; target: string }

/** Meanings pre-filled from the key log; only for fields the proposal really contains. */
export function prefilledMeanings(
  suggested: SuggestedMeaning[] | undefined, fieldNames: string[],
): Record<string, MeaningDraft> {
  const out: Record<string, MeaningDraft> = {};
  for (const s of suggested ?? []) {
    if (fieldNames.includes(s.field)) out[s.field] = { meaning: s.meaning, label: s.label };
  }
  return out;
}

/** Each labelled secret is owned by the session's client_random (mirrors the server's default). */
export function prefilledRelationships(
  suggested: SuggestedMeaning[] | undefined, fieldNames: string[],
): RelationshipDraft[] {
  if (!fieldNames.includes("client_random")) return [];
  return (suggested ?? [])
    .filter((s) => s.label !== "" && fieldNames.includes(s.field))
    .map((s) => ({ kind: "owned_by", source: s.field, target: "client_random" }));
}

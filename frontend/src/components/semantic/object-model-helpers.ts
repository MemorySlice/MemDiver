import type { AnchorInstance } from "@/api/semantic";
import { useDumpStore } from "@/stores/dump-store";
import { useHexStore } from "@/stores/hex-store";

/** `+0x10` / `-0x8` / `+0x0`: a delta is signed, so the sign is always shown. */
export function signedHex(n: number): string {
  return `${n < 0 ? "-" : "+"}0x${Math.abs(n).toString(16)}`;
}

/** Normalise a hex needle (whitespace / `0x` tolerated); null when not even-length hex. */
export function normalizeHex(raw: string): string | null {
  const s = raw.trim().replace(/^0x/i, "").replace(/\s+/g, "");
  return s !== "" && s.length % 2 === 0 && /^[0-9a-fA-F]+$/.test(s) ? s.toLowerCase() : null;
}

/** The CSS token that colours a consensus class; undetermined is muted. */
export function classColorVar(cls: string): string {
  switch (cls) {
    case "invariant": return "var(--md-text-muted)";
    case "structural": return "var(--md-variance-structural)";
    case "pointer": return "var(--md-variance-pointer)";
    case "key_candidate": return "var(--md-variance-key-candidate)";
    default: return "var(--md-text-muted)";
  }
}

/**
 * Put the hex viewer on `anchor + delta` of an instance: its dump, its view and the byte.
 * The anchor's own coordinate is used as given (VA when it has one, else its offset in
 * `raw`), never re-derived. Returns false when the dump is not open in the workspace.
 */
export function goToAnchorDelta(instance: AnchorInstance, delta: number): boolean {
  const dumps = useDumpStore.getState();
  const dump = dumps.dumps.find((d) => d.path === instance.dump_path);
  if (!dump) return false;
  const hex = useHexStore.getState();
  if (dumps.activeDumpId !== dump.id) dumps.setActiveDump(dump.id);
  // `offset` is already in the instance's VIEW coordinates: for view "va" it is
  // span-relative (VA minus the view's base), which is what the hex view scrolls
  // in. The absolute `va` is for display only -- scrolling to it lands far past
  // the end of the view (found in the live browser on a real .msl).
  const target = instance.offset + delta;
  const view = instance.view === "va" ? "va" : "raw";
  if (hex.viewMode !== view) hex.showView(view);
  hex.scrollToOffset(target);
  return true;
}

/** The CSS token for a validation verdict; only `pass` is ever styled as success. */
export function verdictColorVar(verdict: string): string {
  switch (verdict) {
    case "pass": return "var(--md-accent-green)";
    case "fail": return "var(--md-variance-key-candidate)";
    default: return "var(--md-text-muted)";
  }
}

/** Held-out paths that are also among the dumps the model was learned on (trimmed match). */
export function leakedPaths(heldOut: string[], learnedOn: string[]): Set<string> {
  const learned = new Set(learnedOn.map((p) => p.trim()));
  return new Set(heldOut.map((p) => p.trim()).filter((p) => p !== "" && learned.has(p)));
}

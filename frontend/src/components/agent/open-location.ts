import { goToAnchorDelta } from "@/components/semantic/object-model-helpers";
import { useDumpStore } from "@/stores/dump-store";
import type { ChatLocation } from "@/stores/agent-reducer";

export function isDumpOpen(dumpPath: string): boolean {
  return useDumpStore.getState().dumps.some((d) => d.path === dumpPath);
}

/** Views the hex viewer can scroll an `offset` in (a "vas" offset has no viewer view). */
const NAVIGABLE_VIEWS = [undefined, "raw", "va"];

/**
 * True when the location can be opened on the RIGHT bytes. An `offset` is relative to its
 * `view` (raw when none is named); a location with only an absolute `va` is NOT navigable:
 * the "va" view scrolls in span-relative offsets, so scrolling to the absolute VA lands far
 * past the end of the view (the span-relative-VA trap, see object-model-helpers.ts).
 */
export function isLocationNavigable(loc: ChatLocation): boolean {
  return loc.offset !== undefined && NAVIGABLE_VIEWS.includes(loc.view);
}

/**
 * Wrap goToAnchorDelta for a tool-result location. False when the dump is not open or the
 * location is not navigable.
 */
export function openLocationInHex(loc: ChatLocation): boolean {
  if (!isLocationNavigable(loc)) return false;
  return goToAnchorDelta({
    dump_path: loc.dump_path, va: loc.va ?? null, offset: loc.offset as number,
    view: loc.view === "va" ? "va" : "raw", basis: "agent", captured_bytes: 0,
  }, 0);
}

export function describeLocation(loc: ChatLocation): string {
  const where = loc.offset !== undefined ? `0x${loc.offset.toString(16)}` : `va 0x${(loc.va ?? 0).toString(16)}`;
  return `${loc.dump_path.split("/").pop() ?? loc.dump_path} @ ${where}`;
}

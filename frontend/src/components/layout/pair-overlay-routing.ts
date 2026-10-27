/**
 * Which overlay renders a pairwise comparison.
 *
 * `HexOverlay` shows RAW FILE offsets. For an `.msl` / `.mdview` those are the
 * container's bytes, not the process's memory, so such a pair goes to the
 * aligned pane, whose gutter is a server-provided VA (invariant W1: the client
 * never applies a coordinate itself). Raw pairs keep `HexOverlay`, where a file
 * offset IS the truthful address.
 */
export type PairOverlayKind = "aligned" | "raw";

interface PairMember {
  path: string;
  format: string;
}

function isMemoryImage(dump: PairMember): boolean {
  return dump.format === "msl" || dump.path.toLowerCase().endsWith(".mdview");
}

export function pairOverlayKind(a: PairMember, b: PairMember): PairOverlayKind {
  return isMemoryImage(a) || isMemoryImage(b) ? "aligned" : "raw";
}

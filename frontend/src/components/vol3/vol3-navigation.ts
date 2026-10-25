import type { PageStateInterval } from "@/api/types";
import type { HexViewMode } from "@/stores/hex-store";

export type ImageViewKind = "physical" | "kernel" | "process";

/** What the hex viewer is showing, as far as address translation is concerned. */
export interface ViewContext {
  /** The active `.mdview`'s address space; `null` until it is known. */
  kind: ImageViewKind | null;
  /** The process view's pid, when known. */
  pid: number | null;
  mode: HexViewMode;
  vaSpanStart: number;
  vaSize: number;
  pageStatesLoaded: boolean;
}

/** An address cell to place in the viewer. */
export interface AddressRef {
  value: bigint;
  /** AddressSpace value of its column. */
  space: string;
  /** The row's pid (process addresses are meaningless without it). */
  pid: number | null;
}

export type NavResolution =
  | { ok: true; offset: number }
  | { ok: false; hint: string; params?: Record<string, string | number> };

const KIND_OF_SPACE: Record<string, ImageViewKind> = {
  physical: "physical", kernel_va: "kernel", process_va: "process",
};

const refuse = (hint: string, params?: Record<string, string | number>): NavResolution =>
  ({ ok: false, hint, ...(params ? { params } : {}) });

/** Is this address in the view's own coordinate system (and pid)? Else the reason. */
export function checkSpaceMatch(ref: AddressRef, ctx: ViewContext): NavResolution | null {
  const wanted = KIND_OF_SPACE[ref.space];
  if (!wanted) return refuse("nav.unsupportedSpace", { space: ref.space });
  if (ctx.kind === null) return refuse("nav.viewUnknown");
  if (wanted !== ctx.kind) return refuse("nav.spaceMismatch", { space: ref.space, view: ctx.kind });
  if (ctx.kind !== "process") return null;
  if (ref.pid === null) return refuse("nav.rowNoPid");
  if (ctx.pid === null) return refuse("nav.viewPidUnknown", { pid: ref.pid });
  if (ref.pid !== ctx.pid) return refuse("nav.pidMismatch", { pid: ref.pid, viewPid: ctx.pid });
  return null;
}

function vasOffsetOf(address: bigint, intervals: readonly PageStateInterval[]): NavResolution {
  for (const iv of intervals) {
    const start = BigInt(iv.va);
    if (address < start || address >= start + BigInt(iv.length)) continue;
    if (iv.state !== "CAPTURED" || iv.vas_offset === undefined) {
      return refuse("nav.notCaptured", { state: iv.state });
    }
    return { ok: true, offset: iv.vas_offset + Number(address - start) };
  }
  return refuse("nav.notCaptured", { state: "UNMAPPED" });
}

/**
 * The hex offset of an address in the current view, or why there is none.
 * `va` view: offset = address - vaSpanStart. `vas` view: the packed offset of the
 * CAPTURED page-state interval holding it (`intervals`). `raw` has no address map.
 */
export function resolveOffset(
  ref: AddressRef,
  ctx: ViewContext,
  intervals: readonly PageStateInterval[] | null,
): NavResolution {
  const mismatch = checkSpaceMatch(ref, ctx);
  if (mismatch) return mismatch;
  if (ctx.mode === "raw") return refuse("nav.rawView");
  if (ctx.mode === "vas") {
    return intervals ? vasOffsetOf(ref.value, intervals) : refuse("nav.pageStatesPending");
  }
  if (!ctx.pageStatesLoaded) return refuse("nav.pageStatesPending");
  const offset = ref.value - BigInt(ctx.vaSpanStart);
  if (offset < 0n || offset >= BigInt(ctx.vaSize)) return refuse("nav.outOfView");
  return { ok: true, offset: Number(offset) };
}

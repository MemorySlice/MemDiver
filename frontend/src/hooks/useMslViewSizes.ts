/**
 * Learn an `.msl` dump's THREE sizes — raw container, VAS projection, sparse VA
 * span — and tell the caller when the answer has landed.
 *
 * An `.msl` is three byte streams behind one path, and they are not close to
 * each other in size: the `aslr_msl` test fixture is 8920 bytes of container,
 * 8192 bytes of VAS projection and a VA span of 1.4e14. Anything that sizes a
 * viewport, counts rows, or bounds a byte request has to ask which coordinate
 * it is in, and `hex-store` starts every dump with all three set to the FILE's
 * size — the container figure — until this probe corrects them.
 *
 * Believing that placeholder has a visible cost. `MslDumpSource` only holds the
 * bytes it captured, so a window past the end of the VAS projection is answered
 * `400 {"error":"anchor offset does not name an addressable byte"}`; the
 * container size over-states the projection by exactly enough to ask for one.
 * `resolved` is therefore part of the contract, not a convenience: a caller
 * that bounds requests by `hex-store.fileSize` must wait for it.
 *
 * Extracted from `HexViewer`, which owned this effect while it was the only
 * viewer. The N-pane layouts never mount `HexViewer`, so re-anchoring on a
 * second dump inside the side-by-side view left the sizes at the container
 * placeholder for the whole session.
 */

import { useEffect, useState } from "react";

import { useHexStore, type HexViewMode } from "@/stores/hex-store";

const KNOWN_VIEWS: readonly HexViewMode[] = ["raw", "vas", "va"];

/** The backend's `distinct_views`, narrowed to views the viewer can render. */
export function parseDistinctViews(value: unknown, fallback: HexViewMode[]): HexViewMode[] {
  if (!Array.isArray(value)) return fallback;
  const views = value.filter((v): v is HexViewMode => KNOWN_VIEWS.includes(v as HexViewMode));
  return views.length > 0 ? views : fallback;
}

interface ProbeAnswer {
  file_size?: number;
  format?: string;
  distinct_views?: unknown;
}

const probe = (base: string, view: HexViewMode): Promise<ProbeAnswer> =>
  fetch(`${base}&view=${view}`).then((r) => r.json());

/**
 * Any dump that is not a `.msl` by extension may still have several views
 * (a gcore ELF core, a gdb_raw/lldb_raw `.bin`): ask the backend, and only
 * when it reports more than one, learn each view's size.
 */
async function probeDetectedViews(base: string): Promise<{
  views: HexViewMode[];
  format: string;
  sizes: Partial<Record<HexViewMode, number>>;
}> {
  const raw = await probe(base, "raw");
  const views = parseDistinctViews(raw.distinct_views, ["raw"]);
  const sizes: Partial<Record<HexViewMode, number>> = { raw: raw.file_size ?? 0 };
  const others = views.filter((v) => v !== "raw");
  const answers = await Promise.all(others.map((v) => probe(base, v)));
  others.forEach((v, i) => {
    sizes[v] = answers[i].file_size ?? 0;
  });
  return { views, format: raw.format ?? "", sizes };
}

/**
 * @returns whether the sizes in `hex-store` describe `dumpPath`. Always `true`
 * for a non-`.msl` dump (one stream, one size, known from the file itself) and
 * `false` while there is no dump at all.
 *
 * Also records the backend-detected `distinct_views` / format in `hex-store`
 * (`setAvailableViews`) for EVERY dump, so a multi-view source that is not a
 * `.msl` by extension (gcore, gdb_raw/lldb_raw) gets its view switch and sizes.
 */
export function useMslViewSizes(dumpPath: string | null, format: string): boolean {
  const setViewSizes = useHexStore((s) => s.setViewSizes);
  const setAvailableViews = useHexStore((s) => s.setAvailableViews);
  // The path the probe has answered for — NOT a boolean. Re-anchoring on
  // another dump must invalidate the previous answer, and comparing paths says
  // so without a second effect to reset a flag.
  const [probedPath, setProbedPath] = useState<string | null>(null);

  useEffect(() => {
    if (!dumpPath || format !== "msl") return;
    let cancelled = false;
    const base = `/api/inspect/hex-raw?dump_path=${encodeURIComponent(dumpPath)}&offset=0&length=1`;
    (async () => {
      try {
        const [rawJson, vasJson, vaJson] = await Promise.all([
          fetch(`${base}&view=raw`).then((r) => r.json()),
          fetch(`${base}&view=vas`).then((r) => r.json()),
          fetch(`${base}&view=va`).then((r) => r.json()),
        ]);
        if (cancelled) return;
        setViewSizes(rawJson.file_size ?? 0, vasJson.file_size ?? 0, vaJson.file_size ?? 0);
        setAvailableViews(
          parseDistinctViews(rawJson.distinct_views, [...KNOWN_VIEWS]),
          rawJson.format ?? "msl",
        );
      } catch {
        /* leave sizes at defaults on network failure */
      } finally {
        // Settled either way: a caller waiting on this must not wait forever
        // because the probe failed. The placeholder sizes are then the best
        // available answer, which is exactly the pre-existing behaviour.
        if (!cancelled) setProbedPath(dumpPath);
      }
    })();
    return () => {
      cancelled = true;
    };
  }, [dumpPath, format, setViewSizes, setAvailableViews]);

  // Every other dump: one probe for what the backend detected. A flat raw
  // dump answers a single view and nothing else changes for it.
  useEffect(() => {
    if (!dumpPath || format === "msl") return;
    let cancelled = false;
    const base = `/api/inspect/hex-raw?dump_path=${encodeURIComponent(dumpPath)}&offset=0&length=1`;
    probeDetectedViews(base)
      .then(({ views, format: detected, sizes }) => {
        if (cancelled) return;
        if (views.length > 1) {
          const raw = sizes.raw ?? 0;
          setViewSizes(raw, sizes.vas ?? raw, sizes.va ?? raw);
        }
        setAvailableViews(views, detected);
      })
      .catch(() => {
        /* single-view behaviour stays in place on network failure */
      });
    return () => {
      cancelled = true;
    };
  }, [dumpPath, format, setViewSizes, setAvailableViews]);

  if (!dumpPath) return false;
  if (format !== "msl") return true;
  return probedPath === dumpPath;
}

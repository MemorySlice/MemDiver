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

import { useHexStore } from "@/stores/hex-store";

/**
 * @returns whether the sizes in `hex-store` describe `dumpPath`. Always `true`
 * for a non-`.msl` dump (one stream, one size, known from the file itself) and
 * `false` while there is no dump at all.
 */
export function useMslViewSizes(dumpPath: string | null, format: string): boolean {
  const setViewSizes = useHexStore((s) => s.setViewSizes);
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
  }, [dumpPath, format, setViewSizes]);

  if (!dumpPath) return false;
  if (format !== "msl") return true;
  return probedPath === dumpPath;
}

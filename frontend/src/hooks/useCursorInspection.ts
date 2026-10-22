import { useEffect, useState } from "react";
import { useTranslation } from "react-i18next";
import { readHex, getEntropy } from "@/api/client";
import type { KeyMaterial } from "@/api/types";
import { useDumpStore } from "@/stores/dump-store";
import { useHexStore } from "@/stores/hex-store";
import type { HexViewMode } from "@/stores/hex-store";

/** Bytes either side of the cursor the local-entropy window spans. */
const ENTROPY_HALF_WINDOW = 128;

export interface CursorInspection {
  /** The view `offset` addresses (the hex viewer's EFFECTIVE current view). */
  view: HexViewMode;
  byteVal: number | null;
  entropy: number | null;
  byteError: string | null;
  entropyError: string | null;
}

/** First byte of a `/api/inspect/hex` line (`"00000000  ab cd …"`), or null. */
export function firstByteOfHexLines(hexLines: string[]): number | null {
  if (hexLines.length === 0) return null;
  const hex = hexLines[0].split(/\s+/)[1];
  if (!hex) return null;
  const value = parseInt(hex, 16);
  return Number.isNaN(value) ? null : value;
}

interface ReadInputs {
  dumpPath: string;
  offset: number;
  view: HexViewMode;
  key: KeyMaterial | undefined;
}

/**
 * Reads what the Investigation panel shows about the byte at the hex cursor.
 *
 * `offset` is a hex-viewer cursor, so it addresses the viewer's CURRENT view
 * (`hex-store.viewMode` — which also tracks the non-persisted, data-driven
 * switches made by `showView` / `setAvailableViews`, not only the persisted
 * preference). Both reads (byte and local entropy) are issued in that same
 * view; reading in the backend's default made the panel describe the byte at
 * the same NUMBER in another view whenever the viewer showed VAS or VA. In the
 * "va" view the cursor is VA-span-relative, which is exactly the coordinate
 * the backend's "va" view reads, so no translation is needed for the read.
 *
 * No `region_filter` is sent: the hex viewer's own chunk reads
 * (`/api/inspect/hex-raw`) are unfiltered, so the cursor is an unfiltered
 * offset and a filtered read would land on a different byte.
 */
export function useCursorInspection(dumpPath: string, offset: number): CursorInspection {
  const { t } = useTranslation("investigation");
  const view = useHexStore((s) => s.viewMode);
  const key = useDumpStore((s) => s.getKeyMaterialByPath(dumpPath));
  const [byteVal, setByteVal] = useState<number | null>(null);
  const [entropy, setEntropy] = useState<number | null>(null);
  const [byteError, setByteError] = useState<string | null>(null);
  const [entropyError, setEntropyError] = useState<string | null>(null);
  const [prev, setPrev] = useState<ReadInputs & { t: typeof t }>({ dumpPath, offset, view, key, t });

  // Clear the previous request's values whenever an input changes (adjusted
  // during render rather than in the fetch effect below).
  if (
    prev.dumpPath !== dumpPath ||
    prev.offset !== offset ||
    prev.view !== view ||
    prev.key !== key ||
    prev.t !== t
  ) {
    setPrev({ dumpPath, offset, view, key, t });
    setByteError(null);
    setEntropyError(null);
    setByteVal(null);
    setEntropy(null);
  }

  useEffect(() => {
    // A late answer for a previous cursor/view must not overwrite this one.
    let live = true;
    readHex(dumpPath, offset, 1, key, { view })
      .then((d) => {
        if (live) setByteVal(firstByteOfHexLines(d.hex_lines ?? []));
      })
      .catch((e) => {
        if (live) setByteError(e instanceof Error ? e.message : t("panel.readByteError"));
      });

    getEntropy(dumpPath, Math.max(0, offset - ENTROPY_HALF_WINDOW), 2 * ENTROPY_HALF_WINDOW, key, { view })
      .then((d) => {
        // Near EOF (or a locked keyed view) the 256-byte window can fall
        // outside the entropy-readable size, in which case the backend returns
        // an error envelope with no `overall_entropy`. Coerce to null so the
        // panel hides the entropy bar rather than rendering
        // (undefined).toFixed() — which throws and unmounts the whole hex
        // viewer via the ErrorBoundary.
        if (live) setEntropy(typeof d.overall_entropy === "number" ? d.overall_entropy : null);
      })
      .catch((e) => {
        if (live) setEntropyError(e instanceof Error ? e.message : t("panel.getEntropyError"));
      });
    return () => {
      live = false;
    };
  }, [dumpPath, offset, view, key, t]);

  return { view, byteVal, entropy, byteError, entropyError };
}

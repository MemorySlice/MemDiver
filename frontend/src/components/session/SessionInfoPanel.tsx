import { useEffect, useState } from "react";
import { getSessionInfo } from "@/api/client";
import type { SessionInfoResponse } from "@/api/types";
import { SessionView } from "./SessionView";
import { CoverageMap } from "@/components/msl/CoverageMap";
import { ImportProvenancePanel } from "./ImportProvenancePanel";
import { useDumpStore } from "@/stores/dump-store";

interface Props {
  mslPath: string;
}

/**
 * MSL session summary: fetches session metadata and renders the info panel
 * (with page-capture coverage), the import provenance (if any) and the
 * per-region CoverageMap.
 */
export function SessionInfoPanel({ mslPath }: Props) {
  const [info, setInfo] = useState<SessionInfoResponse | null>(null);
  const [error, setError] = useState<string | null>(null);
  const keyMaterial = useDumpStore((s) => s.getKeyMaterialByPath(mslPath));
  const [prevSource, setPrevSource] = useState({ mslPath, keyMaterial });

  // Clear the previous session's result as soon as the source changes
  // (adjusted during render rather than in the fetch effect below).
  if (prevSource.mslPath !== mslPath || prevSource.keyMaterial !== keyMaterial) {
    setPrevSource({ mslPath, keyMaterial });
    if (mslPath) {
      setError(null);
      setInfo(null);
    }
  }

  useEffect(() => {
    if (!mslPath) return;
    let cancelled = false;
    getSessionInfo(mslPath, keyMaterial)
      .then((res) => {
        if (!cancelled) setInfo(res);
      })
      .catch((e) => {
        if (!cancelled) setError(String(e));
      });
    return () => {
      cancelled = true;
    };
  }, [mslPath, keyMaterial]);

  if (error) return <p className="p-3 text-xs md-text-error">{error}</p>;
  if (!info) return null;

  return (
    <>
      <SessionView data={info} coverage={info.coverage} />
      <ImportProvenancePanel mslPath={mslPath} />
      <CoverageMap mslPath={mslPath} />
    </>
  );
}

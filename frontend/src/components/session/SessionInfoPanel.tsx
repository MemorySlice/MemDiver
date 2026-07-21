import { useEffect, useState } from "react";
import { getSessionInfo } from "@/api/client";
import type { SessionInfoResponse } from "@/api/types";
import { SessionView } from "./SessionView";
import { CoverageMap } from "@/components/msl/CoverageMap";
import { useDumpStore } from "@/stores/dump-store";

interface Props {
  mslPath: string;
}

/**
 * MSL session summary: fetches session metadata and renders the info panel
 * (with page-capture coverage) followed by the per-region CoverageMap.
 */
export function SessionInfoPanel({ mslPath }: Props) {
  const [info, setInfo] = useState<SessionInfoResponse | null>(null);
  const [error, setError] = useState<string | null>(null);
  const keyMaterial = useDumpStore((s) => s.getKeyMaterialByPath(mslPath));

  useEffect(() => {
    if (!mslPath) return;
    let cancelled = false;
    setError(null);
    setInfo(null);
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
      <CoverageMap mslPath={mslPath} />
    </>
  );
}

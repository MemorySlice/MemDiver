import { useEffect, useMemo, useState } from "react";
import { useTranslation } from "react-i18next";
import { getPageStates } from "@/api/client";
import type { PageState, PageStatesResponse } from "@/api/types";
import { useHexStore } from "@/stores/hex-store";
import { useDumpStore } from "@/stores/dump-store";

interface Props {
  mslPath: string;
}

const STATE_ORDER: PageState[] = ["CAPTURED", "FAILED", "UNMAPPED"];

/** Lowercased state -> the shared swatch/overlay CSS class in hex.css. */
function stateClass(state: PageState): string {
  return `page-state-${state.toLowerCase()}`;
}

export function CoverageMap({ mslPath }: Props) {
  const { t } = useTranslation("hex");
  const [data, setData] = useState<PageStatesResponse | null>(null);
  const [error, setError] = useState<string | null>(null);
  const keyMaterial = useDumpStore((s) => s.getKeyMaterialByPath(mslPath));

  useEffect(() => {
    if (!mslPath) return;
    let cancelled = false;
    setError(null);
    setData(null);
    getPageStates(mslPath, keyMaterial)
      .then((res) => {
        if (!cancelled) setData(res);
      })
      .catch((e) => {
        if (!cancelled) setError(String(e));
      });
    return () => {
      cancelled = true;
    };
  }, [mslPath, keyMaterial]);

  // Per-state page-count totals across every interval, for the legend.
  const counts = useMemo(() => {
    const acc: Record<PageState, number> = {
      CAPTURED: 0,
      FAILED: 0,
      UNMAPPED: 0,
    };
    if (!data) return acc;
    for (const region of data.regions) {
      for (const iv of region.intervals) {
        acc[iv.state] += iv.page_count;
      }
    }
    return acc;
  }, [data]);

  if (error) return <p className="p-3 text-xs md-text-error">{error}</p>;
  if (!data) return null;

  const pct = Math.round(data.coverage * 100);

  const handleIntervalClick = (state: PageState, vasOffset?: number) => {
    if (state !== "CAPTURED" || vasOffset === undefined) return;
    useHexStore.getState().setViewMode("vas");
    useHexStore.getState().scrollToOffset(vasOffset);
  };

  return (
    <div className="p-3 text-xs space-y-3">
      <h3
        className="text-sm font-semibold md-text-accent"
        title={t("pageState.coverageTitle")}
      >
        {t("pageState.coverage", { pct })}
      </h3>

      <div className="flex items-center gap-3 flex-wrap">
        {STATE_ORDER.map((state) => (
          <span key={state} className="flex items-center gap-1">
            <span
              className={`inline-block w-3 h-3 rounded-sm ${stateClass(state)}`}
            />
            <span>{t(`pageState.${state.toLowerCase()}`)}</span>
            <span className="md-text-muted">({counts[state]})</span>
          </span>
        ))}
      </div>

      <div className="space-y-1">
        {data.regions.map((region, ri) => (
          <div key={ri} className="flex h-3 w-full rounded-sm overflow-hidden">
            {region.intervals.map((iv, ii) => {
              const isCaptured = iv.state === "CAPTURED";
              const clickable = isCaptured && iv.vas_offset !== undefined;
              const title = t("pageState.intervalTitle", {
                va: iv.va.toString(16),
                end: (iv.va + iv.length).toString(16),
                state: t(`pageState.${iv.state.toLowerCase()}`),
                count: iv.page_count,
              });
              return (
                <div
                  key={ii}
                  className={`${stateClass(iv.state)} ${clickable ? "cursor-pointer" : ""}`}
                  style={{ flexGrow: iv.length, flexBasis: 0 }}
                  title={title}
                  role={clickable ? "button" : undefined}
                  tabIndex={clickable ? 0 : undefined}
                  onClick={
                    clickable
                      ? () => handleIntervalClick(iv.state, iv.vas_offset)
                      : undefined
                  }
                  onKeyDown={
                    clickable
                      ? (e) => {
                          if (e.key === "Enter" || e.key === " ") {
                            e.preventDefault();
                            handleIntervalClick(iv.state, iv.vas_offset);
                          }
                        }
                      : undefined
                  }
                />
              );
            })}
          </div>
        ))}
      </div>
    </div>
  );
}

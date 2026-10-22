/**
 * Caption row shared by both EntropyChart backends: the resolution the
 * profile was computed at, the high-entropy region count (with a truncation
 * hint) and a warning when the threshold cannot be reached for the window.
 */
import { useTranslation } from "react-i18next";
import { formatBits, type EntropyChartModel } from "./entropy-model";

function ResolutionCaption({ model }: { model: EntropyChartModel }) {
  const { t } = useTranslation("charts");
  if (!model.resolution) return null;
  const text =
    model.resolution === "full"
      ? t("entropy.resolution.full")
      : t("entropy.resolution.sampled", { step: model.step ?? "?" });
  return (
    <span data-testid="entropy-resolution" data-resolution={model.resolution}>
      {text}
    </span>
  );
}

function RegionCount({ model }: { model: EntropyChartModel }) {
  const { t } = useTranslation("charts");
  const text = model.regionsTruncated
    ? t("entropy.regionsTruncated", { shown: model.regions.length, total: model.regionTotal })
    : t("entropy.regions", { count: model.regionTotal });
  return (
    <span
      data-testid="entropy-region-count"
      data-region-total={model.regionTotal}
      data-regions-truncated={model.regionsTruncated ? "true" : "false"}
    >
      {text}
    </span>
  );
}

export function EntropyChartMeta({ model }: { model: EntropyChartModel }) {
  const { t } = useTranslation("charts");
  return (
    <div className="px-3 pt-1 text-xs md-text-muted">
      <div className="flex flex-wrap gap-x-4 gap-y-1">
        <ResolutionCaption model={model} />
        <RegionCount model={model} />
      </div>
      {!model.thresholdReachable && (
        <p role="status" data-testid="entropy-threshold-warning" className="mt-1 md-text-warning">
          {t("entropy.thresholdUnreachable", {
            threshold: formatBits(model.threshold),
            max: formatBits(model.maxEntropy),
          })}
        </p>
      )}
    </div>
  );
}

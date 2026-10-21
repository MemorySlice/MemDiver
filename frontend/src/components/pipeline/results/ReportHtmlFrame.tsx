import { useTranslation } from "react-i18next";

import { artifactDownloadUrl } from "@/api/pipeline";
import { ARTIFACT_NAMES } from "@/components/pipeline/constants";
import { useFetchText } from "@/hooks/useFetchText";

interface Props {
  taskId: string;
  artifactName?: string;
}

/**
 * Renders the n-sweep report.html artifact inside a sandboxed iframe.
 *
 * We fetch the HTML as text and feed it to the iframe via ``srcDoc``
 * so the (optional) Plotly bundle the report references via relative
 * URLs still resolves through the regular artifact endpoint.
 */
export function ReportHtmlFrame({
  taskId,
  artifactName = ARTIFACT_NAMES.NSWEEP_HTML,
}: Props) {
  const { t } = useTranslation("pipeline");
  const { text: html, error, loading } = useFetchText(
    artifactDownloadUrl(taskId, artifactName),
  );

  if (loading) {
    return <div className="md-panel p-3 text-xs md-text-muted">{t("results.report.loading")}</div>;
  }
  if (error) {
    return (
      <div className="md-panel p-3 text-xs" style={{ color: "var(--md-accent-red)" }}>
        {t("results.report.loadError", { error })}
      </div>
    );
  }
  if (!html) {
    return <div className="md-panel p-3 text-xs md-text-muted">{t("results.report.empty")}</div>;
  }

  return (
    <iframe
      srcDoc={html}
      sandbox="allow-scripts"
      className="w-full h-[500px] rounded border border-[var(--md-border)] md-bg-secondary"
      title={t("results.report.frameTitle")}
    />
  );
}

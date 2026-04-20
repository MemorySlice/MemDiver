import { useEffect, useState } from "react";

import { artifactDownloadUrl } from "@/api/pipeline";
import { ARTIFACT_NAMES } from "@/components/pipeline/constants";

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
  const [html, setHtml] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    let cancelled = false;
    setLoading(true);
    setError(null);
    setHtml(null);
    const url = artifactDownloadUrl(taskId, artifactName);
    fetch(url)
      .then(async (res) => {
        if (!res.ok) {
          throw new Error(`HTTP ${res.status}`);
        }
        return res.text();
      })
      .then((text) => {
        if (!cancelled) {
          setHtml(text);
          setLoading(false);
        }
      })
      .catch((err: unknown) => {
        if (!cancelled) {
          setError(err instanceof Error ? err.message : String(err));
          setLoading(false);
        }
      });
    return () => {
      cancelled = true;
    };
  }, [taskId, artifactName]);

  if (loading) {
    return <div className="md-panel p-3 text-xs md-text-muted">Loading report&hellip;</div>;
  }
  if (error) {
    return (
      <div className="md-panel p-3 text-xs" style={{ color: "var(--md-accent-red)" }}>
        Failed to load report: {error}
      </div>
    );
  }
  if (!html) {
    return <div className="md-panel p-3 text-xs md-text-muted">Empty report.</div>;
  }

  return (
    <iframe
      srcDoc={html}
      sandbox="allow-scripts"
      className="w-full h-[500px] rounded border border-[var(--md-border)] md-bg-secondary"
      title="N-sweep report"
    />
  );
}

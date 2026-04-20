import { useEffect, useState } from "react";

import { artifactDownloadUrl } from "@/api/pipeline";
import { ARTIFACT_NAMES } from "@/components/pipeline/constants";

interface Props {
  taskId: string;
  artifactName?: string;
}

/**
 * Fetches the emitted Volatility3 plugin Python source and renders it
 * as a monospace <pre>. Includes copy-to-clipboard and download
 * buttons so analysts can save the plugin next to their vol3 tree.
 */
export function PluginPreview({
  taskId,
  artifactName = ARTIFACT_NAMES.VOL3_PLUGIN,
}: Props) {
  const [source, setSource] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const [copied, setCopied] = useState(false);

  const url = artifactDownloadUrl(taskId, artifactName);

  useEffect(() => {
    let cancelled = false;
    setLoading(true);
    setError(null);
    setSource(null);
    fetch(url)
      .then(async (res) => {
        if (!res.ok) {
          throw new Error(`HTTP ${res.status}`);
        }
        return res.text();
      })
      .then((text) => {
        if (!cancelled) {
          setSource(text);
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
  }, [url]);

  const handleCopy = async () => {
    if (!source) return;
    try {
      await navigator.clipboard.writeText(source);
      setCopied(true);
      setTimeout(() => setCopied(false), 1500);
    } catch {
      setCopied(false);
    }
  };

  const handleDownload = () => {
    const anchor = document.createElement("a");
    anchor.href = url;
    anchor.download = `${artifactName}.py`;
    document.body.appendChild(anchor);
    anchor.click();
    document.body.removeChild(anchor);
  };

  if (loading) {
    return <div className="md-panel p-3 text-xs md-text-muted">Loading plugin&hellip;</div>;
  }
  if (error) {
    return (
      <div className="md-panel p-3 text-xs" style={{ color: "var(--md-accent-red)" }}>
        Failed to load plugin: {error}
      </div>
    );
  }

  return (
    <div className="md-panel flex flex-col">
      <div className="flex items-center justify-between px-3 py-1.5 border-b border-[var(--md-border)]">
        <span className="text-xs md-text-accent font-semibold">{artifactName}.py</span>
        <div className="flex gap-2">
          <button
            onClick={handleCopy}
            className="text-[11px] px-2 py-0.5 rounded hover:bg-[var(--md-bg-hover)] md-text-secondary"
          >
            {copied ? "Copied!" : "Copy"}
          </button>
          <button
            onClick={handleDownload}
            className="text-[11px] px-2 py-0.5 rounded bg-[var(--md-accent-blue)] text-white"
          >
            Download
          </button>
        </div>
      </div>
      <pre
        className="font-mono text-[10px] p-3 overflow-y-auto md-text-secondary"
        style={{ maxHeight: "400px", whiteSpace: "pre" }}
      >
        {source}
      </pre>
    </div>
  );
}

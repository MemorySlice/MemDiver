import { useCallback, useState } from "react";
import { useTranslation } from "react-i18next";
import { useDumpStore } from "@/stores/dump-store";
import { useAppStore } from "@/stores/app-store";

interface UploadResult {
  source: string;
  output: string;
  regions_written: number;
  total_bytes: number;
}

export function FileUpload() {
  const { t } = useTranslation("misc");
  const [uploading, setUploading] = useState(false);
  const [result, setResult] = useState<UploadResult | null>(null);
  const [error, setError] = useState<string | null>(null);

  const handleUpload = useCallback(async (file: File) => {
    setUploading(true);
    setError(null);
    setResult(null);
    try {
      const form = new FormData();
      form.append("file", file);
      const res = await fetch("/api/dumps/upload", { method: "POST", body: form });
      if (!res.ok) throw new Error(`Upload failed: ${res.status}`);
      const data = (await res.json()) as UploadResult;
      setResult(data);
      // Register the freshly imported dump so it is actually usable: without
      // this the import is a dead end — the converted .msl path is displayed
      // but nothing loads it. Add it to the dump store, make it active, and
      // switch to file mode so the hex viewer mounts on it.
      const name = data.output.split(/[\\/]/).pop() || data.output;
      const id = useDumpStore.getState().addDump({
        path: data.output,
        name,
        size: data.total_bytes,
        format: "msl",
      });
      useDumpStore.getState().setActiveDump(id);
      useAppStore.getState().setInputMode("file");
    } catch (e) {
      setError(e instanceof Error ? e.message : t("upload.failed"));
    } finally {
      setUploading(false);
    }
  }, [t]);

  const handleDrop = useCallback((e: React.DragEvent) => {
    e.preventDefault();
    const file = e.dataTransfer.files[0];
    if (file) handleUpload(file);
  }, [handleUpload]);

  return (
    <div className="p-3 space-y-3 text-xs">
      <h3 className="text-sm font-semibold md-text-accent">{t("upload.heading")}</h3>
      <div
        onDrop={handleDrop}
        onDragOver={(e) => e.preventDefault()}
        className="border-2 border-dashed border-[var(--md-border)] rounded-lg p-6 text-center hover:border-[var(--md-accent-blue)] transition-colors cursor-pointer"
        onClick={() => {
          const input = document.createElement("input");
          input.type = "file";
          input.accept = ".dump,.bin,.raw,.msl";
          input.onchange = () => { if (input.files?.[0]) handleUpload(input.files[0]); };
          input.click();
        }}
      >
        {uploading ? (
          <p className="md-text-accent">{t("upload.uploading")}</p>
        ) : (
          <>
            <p>{t("upload.dropHint")}</p>
            <p className="md-text-muted mt-1">{t("upload.acceptedTypes")}</p>
          </>
        )}
      </div>

      {error && (
        <p className="break-words" style={{ color: "var(--md-accent-red)" }}>{error}</p>
      )}

      {result && (
        <div className="md-panel p-2 space-y-1 min-w-0">
          <p style={{ color: "var(--md-accent-green)" }}>{t("upload.importSuccessful")}</p>
          {/*
           * Import output is a temp path (e.g. /var/folders/.../tmpXXXX.msl) —
           * one long unbreakable token. Without break-all it overflows the
           * panel horizontally instead of wrapping. `title` keeps the full
           * path reachable on hover even when the panel is narrow.
           */}
          <p className="min-w-0">
            {t("upload.output")}{" "}
            <span className="font-mono break-all" title={result.output}>
              {result.output}
            </span>
          </p>
          <p>{t("upload.regionsSize", { regions: result.regions_written, size: (result.total_bytes / 1024).toFixed(1) })}</p>
        </div>
      )}
    </div>
  );
}

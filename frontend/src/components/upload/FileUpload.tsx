import { useCallback, useState } from "react";

interface UploadResult {
  source: string;
  output: string;
  regions_written: number;
  total_bytes: number;
}

export function FileUpload() {
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
      setResult(await res.json());
    } catch (e) {
      setError(e instanceof Error ? e.message : "Upload failed");
    } finally {
      setUploading(false);
    }
  }, []);

  const handleDrop = useCallback((e: React.DragEvent) => {
    e.preventDefault();
    const file = e.dataTransfer.files[0];
    if (file) handleUpload(file);
  }, [handleUpload]);

  return (
    <div className="p-3 space-y-3 text-xs">
      <h3 className="text-sm font-semibold md-text-accent">Import Dump</h3>
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
          <p className="md-text-accent">Uploading...</p>
        ) : (
          <>
            <p>Drop a dump file here or click to browse</p>
            <p className="md-text-muted mt-1">.dump, .bin, .raw, .msl</p>
          </>
        )}
      </div>

      {error && <p style={{ color: "var(--md-accent-red)" }}>{error}</p>}

      {result && (
        <div className="md-panel p-2 space-y-1">
          <p style={{ color: "var(--md-accent-green)" }}>Import successful</p>
          <p>Output: <span className="font-mono">{result.output}</span></p>
          <p>Regions: {result.regions_written} | Size: {(result.total_bytes / 1024).toFixed(1)} KB</p>
        </div>
      )}
    </div>
  );
}

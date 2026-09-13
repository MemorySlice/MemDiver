import { useCallback, useState } from "react";
import { useTranslation } from "react-i18next";
import { useDumpStore } from "@/stores/dump-store";
import { importDumpFile } from "@/api/dump-import";
import { useAppStore } from "@/stores/app-store";
import { DumpSelectionStrip } from "@/components/dumps/DumpSelectionStrip";
import { MainViewSwitcher } from "@/components/hex/MainViewSwitcher";

type QueueStatus = "pending" | "uploading" | "done" | "failed";

interface QueueItem {
  name: string;
  status: QueueStatus;
  output?: string;
  regionsWritten?: number;
  totalBytes?: number;
  error?: string;
}

/**
 * Import one or more dumps, and make the multi-dump workflow reachable from
 * here rather than only from the Dumps tab.
 *
 * Two rules this component exists to keep:
 *
 *   1. SEQUENTIAL, never parallel. `/api/dumps/upload` converts raw captures to
 *      `.msl` server-side; firing eight at once degrades every response instead
 *      of finishing any of them sooner, and the per-file progress becomes
 *      meaningless.
 *   2. NO FOCUS THEFT. `addDump` already claims focus only when the store was
 *      empty; this component used to override that with an unconditional
 *      `setActiveDump`, so importing a second dump yanked the analyst out of
 *      the pane they were reading. `hadActiveDump` is sampled BEFORE the batch
 *      so a dump added mid-batch cannot make the answer drift.
 */
export function FileUpload() {
  const { t } = useTranslation("misc");
  const [uploading, setUploading] = useState(false);
  const [queue, setQueue] = useState<QueueItem[]>([]);
  const dumpCount = useDumpStore((s) => s.dumps.length);

  const patchItem = useCallback((index: number, patch: Partial<QueueItem>) => {
    setQueue((items) =>
      items.map((item, i) => (i === index ? { ...item, ...patch } : item)),
    );
  }, []);

  const handleUpload = useCallback(
    async (files: File[]) => {
      if (files.length === 0) return;
      setUploading(true);
      setQueue(files.map((f) => ({ name: f.name, status: "pending" as const })));

      const hadActiveDump = useDumpStore.getState().activeDumpId !== null;
      let firstNewDumpId: string | null = null;
      let imported = 0;

      for (let i = 0; i < files.length; i++) {
        patchItem(i, { status: "uploading" });
        try {
          // ONE ingestion path for every dropzone in the app (this tab and the
          // Live-Consensus builder both end here), so a dump dropped anywhere
          // joins the single dump set the session works from instead of living
          // in a private, unrelated inbox. `addDump` inside the helper also
          // puts it into `selectedDumpIds`, so it shows up as a pane at once.
          const dump = await importDumpFile(files[i]);

          if (firstNewDumpId === null) firstNewDumpId = dump.id;
          imported += 1;
          patchItem(i, {
            status: "done",
            output: dump.path,
            regionsWritten: dump.regionsWritten,
            totalBytes: dump.size,
          });
        } catch (e) {
          patchItem(i, {
            status: "failed",
            error: e instanceof Error ? e.message : t("upload.failed"),
          });
        }
      }

      if (imported > 0) {
        useAppStore.getState().setInputMode("file");
        // Only claim focus when there was nothing to steal it from.
        if (!hadActiveDump && firstNewDumpId) {
          useDumpStore.getState().setActiveDump(firstNewDumpId);
        }
      }
      setUploading(false);
    },
    [patchItem, t],
  );

  const handleDrop = useCallback(
    (e: React.DragEvent) => {
      e.preventDefault();
      const files = Array.from(e.dataTransfer.files);
      if (files.length > 0) void handleUpload(files);
    },
    [handleUpload],
  );

  const openPicker = useCallback(() => {
    const input = document.createElement("input");
    input.type = "file";
    input.multiple = true;
    input.accept = ".dump,.bin,.raw,.msl";
    input.onchange = () => {
      const files = Array.from(input.files ?? []);
      if (files.length > 0) void handleUpload(files);
    };
    input.click();
  }, [handleUpload]);

  const done = queue.filter((q) => q.status === "done").length;
  const failed = queue.filter((q) => q.status === "failed").length;
  const inFlight = queue.findIndex((q) => q.status === "uploading");

  const statusLabel = (item: QueueItem): string => {
    switch (item.status) {
      case "pending":
        return t("upload.statusPending");
      case "uploading":
        return t("upload.statusUploading");
      case "done":
        // Deliberately the full "Import successful" sentence: this is the
        // per-file success line, not a terse pill.
        return t("upload.importSuccessful");
      case "failed":
        return t("upload.statusFailed");
    }
  };

  return (
    <div className="p-3 space-y-3 text-xs">
      <h3 className="text-sm font-semibold md-text-accent">{t("upload.heading")}</h3>
      <div
        data-testid="upload-dropzone"
        onDrop={handleDrop}
        onDragOver={(e) => e.preventDefault()}
        className="border-2 border-dashed border-[var(--md-border)] rounded-lg p-6 text-center hover:border-[var(--md-accent-blue)] transition-colors cursor-pointer"
        onClick={openPicker}
      >
        {uploading ? (
          <p className="md-text-accent">
            {inFlight >= 0
              ? t("upload.batchProgress", { current: inFlight + 1, total: queue.length })
              : t("upload.uploading")}
          </p>
        ) : (
          <>
            <p>{t("upload.dropHint")}</p>
            <p className="md-text-muted mt-1">{t("upload.acceptedTypes")}</p>
          </>
        )}
      </div>

      {queue.length > 0 && (
        <div className="space-y-2" data-testid="upload-queue">
          <p className="font-semibold">{t("upload.queueHeading")}</p>
          {queue.map((item, i) => (
            <div
              key={`${item.name}-${i}`}
              data-testid="upload-queue-item"
              data-status={item.status}
              className="md-panel p-2 space-y-1 min-w-0"
            >
              <p className="flex items-center gap-2 min-w-0">
                <span className="truncate flex-1">{item.name}</span>
                <span
                  className="shrink-0"
                  style={{
                    color:
                      item.status === "done"
                        ? "var(--md-accent-green)"
                        : item.status === "failed"
                          ? "var(--md-accent-red)"
                          : "var(--md-text-muted)",
                  }}
                >
                  {statusLabel(item)}
                </span>
              </p>

              {item.status === "done" && item.output && (
                <>
                  {/*
                   * Import output is a temp path (e.g.
                   * /var/folders/.../tmpXXXX.msl) — one long unbreakable token.
                   * Without break-all it overflows the panel horizontally
                   * instead of wrapping. `title` keeps the full path reachable
                   * on hover even when the panel is narrow.
                   */}
                  <p className="min-w-0">
                    {t("upload.output")}{" "}
                    <span className="font-mono break-all" title={item.output}>
                      {item.output}
                    </span>
                  </p>
                  <p>
                    {t("upload.regionsSize", {
                      regions: item.regionsWritten ?? 0,
                      size: ((item.totalBytes ?? 0) / 1024).toFixed(1),
                    })}
                  </p>
                </>
              )}

              {item.status === "failed" && item.error && (
                <p className="break-words" style={{ color: "var(--md-accent-red)" }}>
                  {item.error}
                </p>
              )}
            </div>
          ))}

          <p className="md-text-muted" data-testid="upload-batch-summary">
            {t("upload.batchSummary", { count: done })}
            {failed > 0 ? ` ${t("upload.batchFailed", { count: failed })}` : ""}
          </p>
        </div>
      )}

      {/*
       * The multi-dump workflow has to be reachable from the tab the analyst is
       * already on. Before this, importing a second dump left no visible way to
       * compare it with the first without hunting through the Dumps tab.
       */}
      {dumpCount >= 2 && (
        <div className="space-y-2" data-testid="upload-multi-dump">
          <p className="font-semibold">{t("upload.multiDumpHeading")}</p>
          <DumpSelectionStrip />
          <MainViewSwitcher />
        </div>
      )}
    </div>
  );
}

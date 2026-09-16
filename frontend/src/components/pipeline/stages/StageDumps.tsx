/**
 * Stage 1 — dump source paths.
 *
 * Two ways in, both kept on purpose:
 *
 * 1. The path editor — type / paste absolute paths, one per line. This is the
 *    precise route: an analyst who already knows the N dumps that belong in one
 *    consensus matrix can name exactly those and nothing else. Every pasted
 *    line is classified first (see ``pasteLines``): a folder pasted here lands
 *    in the same scan panel route 2 uses, and a path that does not exist is
 *    refused out loud instead of becoming a phantom dump.
 * 2. **Browse folder…** — point at a corpus directory and let the server walk
 *    it (``GET /api/path/discover-dumps``), then tick the dumps to keep. This
 *    is the route for a real dataset, where the runs sit three or four levels
 *    down and naming them by hand is not realistic.
 *
 * Paths from either route are handed to the backend as absolute strings, and
 * the server validates each one exists before dispatching the worker.
 *
 * Dragging files in and auto-resolving their absolute paths is a
 * v2 enhancement — the browser sandbox prevents us from seeing a
 * File's real filesystem path anyway, so drag-drop would need to
 * upload via ``/api/dumps/upload`` and then reference the server
 * copy. For now we trust the analyst to provide real paths.
 */

import { useCallback, useState } from "react";
import { useTranslation } from "react-i18next";

import { discoverDumps, readableFailure } from "@/api/client";
import type { DiscoverDumpsResult } from "@/api/types";
import { FileBrowser } from "@/components/wizard/FileBrowser";
import type { WizardStage } from "@/stores/pipeline-store";
import { usePipelineStore } from "@/stores/pipeline-store";

interface Props {
  onAdvance: (next: WizardStage) => void;
}

/**
 * Every kind ``RunDiscovery.dump_file_for`` can return, so a kind that is
 * absent from the scanned directory still gets a checkbox (showing a count of
 * zero) instead of quietly disappearing from the filter.
 */
const DUMP_KINDS = ["msl", "gcore", "gdb_raw", "lldb_raw", "raw"] as const;

/** `.msl` is the default corpus format, and the only kind preselected. */
const DEFAULT_KINDS = ["msl"];

/**
 * The one `discover-dumps` error that means "this path is fine, it is simply a
 * file". The endpoint mirrors the browse contract — 200 with an `error` string,
 * never a raised status — so this string is how we tell a dump apart from a
 * typo without a second endpoint.
 */
const NOT_A_DIRECTORY = "Path is not a directory";

/** What one pasted line turned out to be. */
type PastedLine =
  | { verdict: "directory"; path: string; found: DiscoverDumpsResult }
  | { verdict: "file"; path: string }
  | { verdict: "rejected"; path: string; reason: string };

export function StageDumps({ onAdvance }: Props) {
  const { t } = useTranslation("pipeline");
  const sourcePaths = usePipelineStore((s) => s.form.sourcePaths);
  const updateForm = usePipelineStore((s) => s.updateForm);

  const [draft, setDraft] = useState<string>("");

  // --- paste classification --------------------------------------------
  const [pasting, setPasting] = useState(false);
  const [rejected, setRejected] = useState<
    Array<{ path: string; reason: string }>
  >([]);
  const [deferredDirs, setDeferredDirs] = useState<string[]>([]);

  // --- directory discovery ---------------------------------------------
  const [browserOpen, setBrowserOpen] = useState(false);
  const [scanPath, setScanPath] = useState<string | null>(null);
  const [scanning, setScanning] = useState(false);
  const [result, setResult] = useState<DiscoverDumpsResult | null>(null);
  const [scanError, setScanError] = useState<string | null>(null);
  const [kinds, setKinds] = useState<string[]>(DEFAULT_KINDS);
  const [chosen, setChosen] = useState<string[]>([]);

  /**
   * Adopt a discovery result as the visible tick-list.
   *
   * Everything discovered starts ticked: the common case is "take them all".
   * Shared by the browse route and the paste route so the paste route does not
   * have to re-ask the server for a directory it has already scanned.
   */
  const showDiscovery = useCallback((res: DiscoverDumpsResult): void => {
    setResult(res);
    setChosen(res.dumps.map((d) => d.path));
  }, []);

  /**
   * Ask the server which dumps live under `path`, for the given kinds.
   *
   * The kind filter is applied server-side rather than in the browser because
   * `counts_by_kind` is computed over everything discovered, *before* the
   * filter — so a round trip is what keeps the unselected kinds' counts real.
   */
  const runScan = useCallback(
    async (path: string, wanted: string[]) => {
      setScanning(true);
      setScanError(null);
      try {
        showDiscovery(await discoverDumps(path, wanted));
      } catch (err) {
        setResult(null);
        setChosen([]);
        setScanError(readableFailure(err));
      } finally {
        setScanning(false);
      }
    },
    [showDiscovery],
  );

  const handleDirectory = (path: string): void => {
    setBrowserOpen(false);
    setScanPath(path);
    void runScan(path, kinds);
  };

  const toggleKind = (kind: string): void => {
    const next = kinds.includes(kind)
      ? kinds.filter((k) => k !== kind)
      : [...DUMP_KINDS].filter((k) => k === kind || kinds.includes(k));
    setKinds(next);
    if (scanPath) void runScan(scanPath, next);
  };

  const toggleDump = (path: string): void => {
    setChosen((prev) =>
      prev.includes(path) ? prev.filter((p) => p !== path) : [...prev, path],
    );
  };

  const dismissScan = (): void => {
    setScanPath(null);
    setResult(null);
    setScanError(null);
    setChosen([]);
  };

  /**
   * Append paths to the form, de-duplicated and in the order given.
   *
   * The order is load-bearing: the N-dump consensus alignment downstream pairs
   * dumps positionally, so a shuffled list silently mis-pairs. `Set` preserves
   * insertion order, which is why it is the dedupe used here.
   *
   * Reads the live store instead of the render-time `sourcePaths` because the
   * paste route calls this *after* awaiting its classification round trips, by
   * which point the captured array can be stale.
   */
  const appendPaths = (paths: string[]): void => {
    if (paths.length === 0) return;
    const current = usePipelineStore.getState().form.sourcePaths;
    updateForm({ sourcePaths: Array.from(new Set([...current, ...paths])) });
  };

  /**
   * Merge the ticked dumps into the form.
   *
   * Driven off `result.dumps` rather than off `chosen` so the server's sort
   * order survives.
   *
   * Confirming ends the scan. Leaving the panel up after the merge rendered
   * the same paths twice on one screen — once as a still-live tick-list, once
   * as the selected-dump list below it — which on a 95-dump corpus is a wall
   * of text an analyst has to re-read to tell the two apart. Re-adding is
   * harmless (`appendPaths` dedupes), so nothing is lost by closing it; the
   * Browse button re-opens the scan.
   */
  const addDiscovered = (): void => {
    if (!result) return;
    appendPaths(
      result.dumps.map((d) => d.path).filter((p) => chosen.includes(p)),
    );
    dismissScan();
  };

  /**
   * Decide what one pasted line actually is, in a single round trip.
   *
   * `discover-dumps` answers both questions at once: no `error` means it walked
   * a directory, and `NOT_A_DIRECTORY` means the path exists but is a file —
   * i.e. a dump. Anything else ("Path does not exist", a transport failure) is
   * a path we must not accept.
   */
  const classifyLine = async (path: string): Promise<PastedLine> => {
    try {
      const found = await discoverDumps(path, kinds);
      if (found.error === undefined || found.error === "") {
        return { verdict: "directory", path, found };
      }
      if (found.error === NOT_A_DIRECTORY) return { verdict: "file", path };
      return { verdict: "rejected", path, reason: found.error };
    } catch (err) {
      return { verdict: "rejected", path, reason: readableFailure(err) };
    }
  };

  /**
   * Take the textarea's lines, but only after classifying each one.
   *
   * Pasting a dataset *directory* here used to add the directory itself as if
   * it were a dump ("1 dump selected"), and a typo used to become a phantom
   * dump that only failed much later inside the run. So: files are added
   * verbatim, and a directory is routed into the scan panel the Browse route
   * already uses rather than being expanded silently — that panel is the only
   * place the kind filter and the pre-filter `counts_by_kind` are visible,
   * which is what rescues a corpus that happens to hold no `.msl` at all.
   *
   * The panel scans one directory at a time, so any further directories and
   * every rejected line are left in the textarea: that is the repair path, and
   * it keeps the explanation next to the text it is about.
   */
  const pasteLines = async (): Promise<void> => {
    if (pasting) return;
    const lines = draft
      .split("\n")
      .map((l) => l.trim())
      .filter((l) => l.length > 0);
    if (lines.length === 0) return;

    setPasting(true);
    try {
      const verdicts = await Promise.all(lines.map(classifyLine));
      const dirs = verdicts.filter((v) => v.verdict === "directory");
      const refused = verdicts.filter((v) => v.verdict === "rejected");
      const deferred = dirs.slice(1).map((d) => d.path);

      appendPaths(
        verdicts.filter((v) => v.verdict === "file").map((v) => v.path),
      );

      const first = dirs[0];
      if (first) {
        setScanPath(first.path);
        setScanError(null);
        showDiscovery(first.found);
      }

      setRejected(refused.map((r) => ({ path: r.path, reason: r.reason })));
      setDeferredDirs(deferred);
      setDraft([...refused.map((r) => r.path), ...deferred].join("\n"));
    } finally {
      setPasting(false);
    }
  };

  const removeAt = (idx: number): void => {
    updateForm({
      sourcePaths: sourcePaths.filter((_, i) => i !== idx),
    });
  };

  const clearAll = (): void => {
    updateForm({ sourcePaths: [] });
  };

  const canAdvance = sourcePaths.length >= 1;
  const counts = result?.counts_by_kind ?? {};

  return (
    <div className="p-4 space-y-3">
      <div>
        <h3 className="text-sm font-semibold md-text-accent">
          {t("stages.dumps.title")}
        </h3>
        <p className="text-xs md-text-muted">
          {t("stages.dumps.subtitlePrefix")} <code>.dump</code>{" "}
          {t("stages.dumps.subtitleAnd")} <code>.msl</code>{" "}
          {t("stages.dumps.subtitleBody")}
        </p>
      </div>

      <div className="md-panel p-3 space-y-2">
        <div className="flex items-center gap-2">
          <button
            type="button"
            onClick={() => setBrowserOpen(true)}
            className="text-xs px-2 py-1 rounded bg-[var(--md-bg-hover)] md-text-secondary hover:bg-[var(--md-border)]"
          >
            {t("stages.dumps.browseFolder")}
          </button>
          <span className="text-xs md-text-muted">
            {t("stages.dumps.browseHint")}
          </span>
        </div>
      </div>

      {(scanPath !== null || scanError !== null) && (
        <div className="md-panel">
          <div className="flex items-center justify-between gap-2 px-3 py-2 border-b border-[var(--md-border)]">
            <span className="text-xs md-text-muted truncate font-mono">
              {t("stages.dumps.discoveredIn", { path: scanPath ?? "" })}
            </span>
            <button
              type="button"
              onClick={dismissScan}
              className="md-text-muted hover:text-[var(--md-accent-red)] text-xs"
              aria-label={t("stages.dumps.discoverDismiss")}
            >
              ×
            </button>
          </div>

          <fieldset className="px-3 py-2 border-b border-[var(--md-border)]">
            <legend className="text-xs md-text-muted">
              {t("stages.dumps.discoverKinds")}
            </legend>
            <div className="flex flex-wrap gap-3 pt-1">
              {DUMP_KINDS.map((kind) => (
                <label
                  key={kind}
                  className="flex items-center gap-1 text-xs md-text-secondary"
                >
                  <input
                    type="checkbox"
                    checked={kinds.includes(kind)}
                    onChange={() => toggleKind(kind)}
                  />
                  <span className="font-mono">
                    {t("stages.dumps.discoverKindOption", {
                      kind,
                      count: counts[kind] ?? 0,
                    })}
                  </span>
                </label>
              ))}
            </div>
          </fieldset>

          {scanError !== null && (
            <p className="px-3 py-2 text-xs md-text-error">
              {t("stages.dumps.discoverError", { message: scanError })}
            </p>
          )}
          {result?.error && (
            <p className="px-3 py-2 text-xs md-text-error">
              {t("stages.dumps.discoverError", { message: result.error })}
            </p>
          )}
          {result?.truncated && (
            <p className="px-3 py-2 text-xs md-text-error">
              {t("stages.dumps.discoverTruncated", {
                count: result.dumps.length,
              })}
            </p>
          )}

          {scanning ? (
            <p className="px-3 py-2 text-xs md-text-muted">
              {t("stages.dumps.discovering")}
            </p>
          ) : result && result.dumps.length > 0 ? (
            <ul className="max-h-48 overflow-y-auto divide-y divide-[var(--md-border)]">
              {result.dumps.map((dump) => (
                <li key={dump.path} className="px-3 py-1.5">
                  <label className="flex items-center gap-2 text-[11px] font-mono">
                    <input
                      type="checkbox"
                      checked={chosen.includes(dump.path)}
                      onChange={() => toggleDump(dump.path)}
                      aria-label={t("stages.dumps.discoverSelectDump", {
                        path: dump.path,
                      })}
                    />
                    <span className="flex-1 truncate">{dump.path}</span>
                    <span className="md-text-muted">{dump.kind}</span>
                  </label>
                </li>
              ))}
            </ul>
          ) : (
            scanError === null &&
            !result?.error && (
              <p className="px-3 py-2 text-xs md-text-muted">
                {t("stages.dumps.discoverEmpty")}
              </p>
            )
          )}

          <div className="flex items-center justify-between gap-2 px-3 py-2 border-t border-[var(--md-border)]">
            <div className="flex items-center gap-2">
              <button
                type="button"
                onClick={() => setChosen(result?.dumps.map((d) => d.path) ?? [])}
                className="text-xs px-2 py-1 rounded bg-[var(--md-bg-hover)] md-text-secondary hover:bg-[var(--md-border)]"
              >
                {t("stages.dumps.discoverSelectAll")}
              </button>
              <button
                type="button"
                onClick={() => setChosen([])}
                className="text-xs px-2 py-1 rounded bg-[var(--md-bg-hover)] md-text-secondary hover:bg-[var(--md-border)]"
              >
                {t("stages.dumps.discoverSelectNone")}
              </button>
            </div>
            <button
              type="button"
              onClick={addDiscovered}
              disabled={scanning || chosen.length === 0}
              aria-busy={scanning}
              className="text-xs px-2 py-1 rounded bg-[var(--md-accent-blue)] md-text-on-accent disabled:opacity-50"
            >
              {t("stages.dumps.discoverAdd", { count: chosen.length })}
            </button>
          </div>
        </div>
      )}

      <div className="md-panel p-3 space-y-2">
        <p className="text-xs md-text-muted">{t("stages.dumps.pasteHint")}</p>
        <textarea
          value={draft}
          onChange={(e) => setDraft(e.target.value)}
          placeholder={t("stages.dumps.placeholder")}
          rows={4}
          className="w-full px-2 py-1 text-xs bg-[var(--md-bg-primary)] border border-[var(--md-border)] rounded font-mono"
        />
        {rejected.length > 0 && (
          <ul className="space-y-0.5">
            {rejected.map((entry) => (
              <li key={entry.path} className="text-xs md-text-error">
                {t("stages.dumps.pasteRejected", {
                  path: entry.path,
                  reason: entry.reason,
                })}
              </li>
            ))}
          </ul>
        )}
        {deferredDirs.length > 0 && (
          <p className="text-xs md-text-muted">
            {t("stages.dumps.pasteMoreFolders", {
              count: deferredDirs.length,
              paths: deferredDirs.join(", "),
            })}
          </p>
        )}
        <div className="flex items-center justify-between">
          <button
            type="button"
            onClick={() => void pasteLines()}
            disabled={draft.trim().length === 0 || pasting}
            aria-busy={pasting}
            className="text-xs px-2 py-1 rounded bg-[var(--md-accent-blue)] md-text-on-accent disabled:opacity-50"
          >
            {pasting
              ? t("stages.dumps.pasteChecking")
              : t("stages.dumps.addPaths")}
          </button>
          {sourcePaths.length > 0 && (
            <button
              type="button"
              onClick={clearAll}
              className="text-xs px-2 py-1 rounded bg-[var(--md-bg-hover)] md-text-secondary hover:bg-[var(--md-accent-red)] hover:text-[var(--md-bg-primary)]"
            >
              {t("stages.dumps.clearAll")}
            </button>
          )}
        </div>
      </div>

      {sourcePaths.length > 0 ? (
        <div className="md-panel">
          <div className="px-3 py-2 border-b border-[var(--md-border)] text-xs md-text-muted space-y-1">
            <div>
              {t("stages.dumps.selectedCount", { count: sourcePaths.length })}
            </div>
            {/*
              Above the list, not after it: the REFERENCE badge this sentence
              explains is on row 1, and the list scrolls — with 95 dumps a note
              rendered below the list is ~95 rows away from the only badge it
              is about, so the analyst never sees the two together.

              Not decoration either: the sweep binds its reference bytes from
              `sources[0]` once, outside the N loop, and every hit is sliced
              from that one array — the other dumps only sharpen the variance
              filter. With per-run keys, a first dump from a different run than
              the oracle's vault returns zero hits and looks exactly like "the
              key is not here", so the list has to say which row that is.
            */}
            <p>{t("stages.dumps.referenceNote")}</p>
          </div>
          <ul className="max-h-48 overflow-y-auto divide-y divide-[var(--md-border)]">
            {sourcePaths.map((path, idx) => (
              <li
                key={`${path}-${idx}`}
                className="flex items-center gap-2 px-3 py-1.5 text-[11px] font-mono"
              >
                <span className="md-text-muted w-6 text-right">
                  {idx + 1}
                </span>
                <span className="flex-1 truncate">{path}</span>
                {/*
                  A chip, and spaced away from the × beside it: as a bare 10px
                  muted word it sat flush against the delete control and read
                  as a second, low-contrast button. The background and border
                  are what say "label, not action" without a hover — this row
                  has to stay legible at a glance, so no tooltip-only tricks.
                */}
                {idx === 0 && (
                  <span className="shrink-0 mr-2 px-1.5 py-0.5 rounded border border-[var(--md-border)] bg-[var(--md-bg-hover)] md-text-secondary uppercase tracking-wide text-[10px]">
                    {t("stages.dumps.referenceBadge")}
                  </span>
                )}
                <button
                  type="button"
                  onClick={() => removeAt(idx)}
                  className="md-text-muted hover:text-[var(--md-accent-red)]"
                  aria-label={t("stages.dumps.removePath", { path })}
                >
                  ×
                </button>
              </li>
            ))}
          </ul>
        </div>
      ) : (
        <div className="md-panel p-3 text-xs md-text-muted text-center">
          {t("stages.dumps.empty")}
        </div>
      )}

      <div className="flex justify-between items-center pt-2">
        <button
          type="button"
          onClick={() => onAdvance("recipe")}
          className="text-xs px-3 py-1.5 rounded bg-[var(--md-bg-hover)] md-text-secondary hover:bg-[var(--md-border)]"
        >
          {t("stages.dumps.back")}
        </button>
        <button
          type="button"
          disabled={!canAdvance}
          onClick={() => onAdvance("oracle")}
          className="text-xs px-3 py-1.5 rounded bg-[var(--md-accent-blue)] md-text-on-accent disabled:opacity-50"
        >
          {t("stages.dumps.next")}
        </button>
      </div>

      {browserOpen && (
        <FileBrowser
          onSelect={handleDirectory}
          onClose={() => setBrowserOpen(false)}
        />
      )}
    </div>
  );
}

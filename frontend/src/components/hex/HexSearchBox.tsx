import { useCallback, useEffect, useMemo, useState } from "react";
import { useTranslation } from "react-i18next";

import { useHexStore } from "@/stores/hex-store";
import { useHexSearch } from "@/hooks/useHexSearch";
import {
  NEEDLE_FORMATS,
  NeedleError,
  detectFormat,
  parseNeedle,
  plausibleAlternatives,
  previewHex,
  type ConcreteNeedleFormat,
  type NeedleFormat,
} from "@/utils/needle";

/**
 * The search group, extracted from `HexToolbar` and taught more than hex.
 *
 * ── Why this is its own component ───────────────────────────────────────────
 * `HexToolbar`'s layout comment is load-bearing: its three `shrink-0` groups
 * already filled the toolbar, and the file-name span once measured ZERO pixels
 * because it was the only flexible item left. A format selector plus a preview
 * line added to that same flex row would re-break it. Here they live on their
 * own sub-row inside one group instead of competing for the toolbar's main
 * axis.
 *
 * ── Why the preview is not a nicety ─────────────────────────────────────────
 * `dead` is a word and a byte pair. Any auto-detection is guessing, so instead
 * of guessing silently this shows the bytes it WILL search for, before it
 * searches — and names the other reading beside them. A wrong guess you can
 * see costs one click; a wrong guess you cannot see costs an afternoon, and in
 * a forensics tool it can be mistaken for the dump not containing the secret.
 *
 * ── Why `auto` is resolved HERE and not on the wire ─────────────────────────
 * The request always carries a CONCRETE format. If the server re-resolved
 * `auto` itself, the preview and the search would be two independent readings
 * of the same string and could disagree — which is precisely the failure the
 * preview exists to prevent. `core/needle.py` still understands `auto` for the
 * CLI and MCP surfaces, where there is no preview to disagree with.
 */

/** Below this, a needle matches so much that the hit list stops being useful. */
const SHORT_NEEDLE_BYTES = 4;

export function HexSearchBox() {
  const { t } = useTranslation("hex");
  const dumpPath = useHexStore((s) => s.dumpPath);
  const viewMode = useHexStore((s) => s.viewMode);
  const setSearchOffsets = useHexStore((s) => s.setSearchOffsets);
  const setHighlightedRegions = useHexStore((s) => s.setHighlightedRegions);

  const [patternInput, setPatternInput] = useState("");
  const [format, setFormat] = useState<NeedleFormat>("auto");

  const { offsets, patternLen, truncated, isSearching, error, search, clear } =
    useHexSearch(dumpPath ?? "");

  /**
   * What this input means RIGHT NOW, recomputed per keystroke.
   *
   * Parsing is pure and cheap (bounded by the length of a typed pattern), and
   * a parse failure is a normal state here — half-typed hex is invalid hex —
   * so it is carried as a value rather than thrown at the render.
   */
  const resolved = useMemo(() => {
    const text = patternInput.trim();
    if (!text) return null;
    let concrete: ConcreteNeedleFormat;
    try {
      concrete = format === "auto" ? detectFormat(text) : format;
    } catch {
      return null;
    }
    try {
      return {
        format: concrete,
        bytes: parseNeedle(text, concrete),
        alternatives: format === "auto" ? plausibleAlternatives(text) : [],
        error: null as string | null,
      };
    } catch (e) {
      return {
        format: concrete,
        bytes: null,
        alternatives: [],
        error: e instanceof NeedleError ? e.message : String(e),
      };
    }
  }, [patternInput, format]);

  const handleFind = useCallback(() => {
    if (!dumpPath || !resolved?.bytes) return;
    search(patternInput.trim(), viewMode, resolved.format);
  }, [dumpPath, resolved, patternInput, viewMode, search]);

  // Push hits into the shared store (minimap) and the highlight overlay.
  // Depends on `offsets`/`patternLen`, which the hook updates atomically, so
  // clearing the input below can never re-fire it against a stale pattern.
  useEffect(() => {
    if (isSearching) return;
    if (offsets.length === 0) return;
    setSearchOffsets(offsets);
    const existing = useHexStore.getState().highlightedRegions;
    const nonSearch = existing.filter((r) => r.type !== "search");
    setHighlightedRegions([
      ...nonSearch,
      ...offsets.map((offset) => ({
        offset,
        length: Math.max(1, patternLen),
        type: "search" as const,
        label: t("toolbar.searchHitLabel"),
      })),
    ]);
  }, [offsets, patternLen, isSearching, setSearchOffsets, setHighlightedRegions, t]);

  const handleClear = useCallback(() => {
    setPatternInput("");
    clear();
    setSearchOffsets([]);
    const existing = useHexStore.getState().highlightedRegions;
    setHighlightedRegions(existing.filter((r) => r.type !== "search"));
  }, [clear, setSearchOffsets, setHighlightedRegions]);

  const formatLabel = (f: NeedleFormat) => t(`toolbar.format_${f}`);
  const isShort =
    resolved?.bytes != null && resolved.bytes.length < SHORT_NEEDLE_BYTES;

  /*
   * A Fragment, NOT a wrapper div, and the preview is `w-full`.
   *
   * `HexToolbar`'s row is `flex flex-wrap`, so a `w-full` item takes a line of
   * its own — which is exactly what the preview wants. Wrapping both in a
   * column div instead made the sub-row's text the group's intrinsic width:
   * it overflowed the toolbar horizontally, pushed the view-mode and go-to
   * groups onto separate lines, and turned a two-line toolbar into a
   * four-line one. The preview must be able to take the full width WITHOUT
   * widening the control group that sits beside it.
   */
  return (
    <>
      <div className="flex items-center gap-1 shrink-0" data-testid="hex-search-box">
        <label className="sr-only" htmlFor="hex-search-format">
          {t("toolbar.searchFormatLabel")}
        </label>
        <select
          id="hex-search-format"
          data-testid="hex-search-format"
          value={format}
          title={t("toolbar.searchFormatTitle")}
          onChange={(e) => setFormat(e.target.value as NeedleFormat)}
          className="px-1 py-0.5 rounded border border-[var(--md-border)] bg-transparent text-xs"
        >
          {NEEDLE_FORMATS.map((f) => (
            <option key={f} value={f}>{formatLabel(f)}</option>
          ))}
        </select>
        <label className="sr-only" htmlFor="hex-search-pattern">
          {t("toolbar.patternPlaceholder")}
        </label>
        <input
          id="hex-search-pattern"
          data-testid="hex-search-pattern"
          type="text"
          value={patternInput}
          onChange={(e) => setPatternInput(e.target.value)}
          onKeyDown={(e) => e.key === "Enter" && handleFind()}
          placeholder={t("toolbar.patternPlaceholder")}
          className="w-40 px-2 py-0.5 rounded border border-[var(--md-border)] bg-transparent text-xs"
        />
        <button
          onClick={handleFind}
          disabled={isSearching || !resolved?.bytes}
          data-testid="hex-search-find"
          className="px-2 py-0.5 rounded border border-[var(--md-border)] hover:bg-[var(--md-bg-hover)] disabled:opacity-50"
        >
          {isSearching ? t("toolbar.finding") : t("toolbar.find")}
        </button>
        {error && (
          <span className="md-text-error truncate max-w-[12rem]" title={error}>
            {error}
          </span>
        )}
        {!error && !isSearching && offsets.length > 0 && (
          <span className="md-text-secondary whitespace-nowrap" data-testid="hex-search-hits">
            {truncated
              ? t("toolbar.hitsTruncated", { count: offsets.length })
              : t("toolbar.hits", { count: offsets.length })}
          </span>
        )}
        {(offsets.length > 0 || patternInput) && (
          <button
            onClick={handleClear}
            title={t("toolbar.clearSearch")}
            aria-label={t("toolbar.clearSearch")}
            className="px-1.5 py-0.5 rounded border border-[var(--md-border)] hover:bg-[var(--md-bg-hover)]"
          >
            ✕
          </button>
        )}
      </div>

      {/*
        The sub-row: what will actually be searched for. Only rendered once
        there is something to say, so an empty box stays an empty box.
      */}
      {resolved && (
        <div
          data-testid="hex-search-subrow"
          className="w-full flex flex-wrap items-center gap-x-2 text-[0.6875rem] leading-tight"
        >
          {resolved.error ? (
            <span className="md-text-error" data-testid="hex-search-parse-error">
              {resolved.error}
            </span>
          ) : (
            <>
              <span className="md-text-muted" data-testid="hex-search-preview">
                {t("toolbar.previewResolved", {
                  format: formatLabel(resolved.format),
                  count: resolved.bytes!.length,
                })}
              </span>
              <span className="font-mono md-text-secondary truncate max-w-[16rem]">
                {previewHex(resolved.bytes!)}
              </span>
              {isShort && (
                <span className="md-text-warning" data-testid="hex-search-short-warning">
                  {t("toolbar.shortNeedleWarning", {
                    count: resolved.bytes!.length,
                  })}
                </span>
              )}
              {/*
                The ambiguity, named. Only the FIRST alternative gets a button:
                `dead` is hex-or-text, and offering a menu of readings for a
                four-character input turns a one-click correction back into a
                decision.
              */}
              {resolved.alternatives.length > 0 && (
                <button
                  type="button"
                  data-testid="hex-search-switch-format"
                  title={t("toolbar.alsoValidAs", {
                    format: formatLabel(resolved.alternatives[0]),
                  })}
                  onClick={() => setFormat(resolved.alternatives[0])}
                  className="underline md-text-muted hover:text-[var(--md-accent)]"
                >
                  {t("toolbar.searchAsInstead", {
                    format: formatLabel(resolved.alternatives[0]),
                  })}
                </button>
              )}
            </>
          )}
        </div>
      )}
    </>
  );
}

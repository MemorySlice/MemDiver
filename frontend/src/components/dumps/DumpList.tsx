import { useTranslation } from "react-i18next";
import { useDumpStore } from "../../stores/dump-store";
import { useConsensusRun, useConsensusStore } from "../../stores/consensus-store";
import { useAppStore } from "@/stores/app-store";
import { AddDumpButton } from "./AddDumpButton";
import { TagStatusBadge } from "./TagStatusBadge";
import { TagStatusUnlock } from "./TagStatusUnlock";

const SIZE_UNITS = ["B", "KB", "MB", "GB", "TB"] as const;

/**
 * Byte counts at the scale this tool actually sees.
 *
 * Dumps here run from a 7 KB synthetic MSL to multi-gigabyte gcore captures;
 * printing every one of them in KB turned a 1.2 GB dump into "1258291.2 KB",
 * which is unreadable exactly where the number matters most.
 */
function formatSize(bytes: number): string {
  if (bytes < 0) return "--";
  if (bytes === 0) return "0 B";
  let value = bytes;
  let unit = 0;
  while (value >= 1024 && unit < SIZE_UNITS.length - 1) {
    value /= 1024;
    unit += 1;
  }
  return `${value.toFixed(1)} ${SIZE_UNITS[unit]}`;
}

/**
 * The sidebar roster of loaded dumps.
 *
 * Each row carries THREE separate things, which the previous design conflated
 * into one click target:
 *
 *   - a participation checkbox (`selectedDumpIds`) — is this dump in the
 *     analysis at all;
 *   - a focus radio plus the row body (`activeDumpId`) — which dump the
 *     single-pane viewer and the alignment anchor point at;
 *   - badges (ORIGIN / FOCUS) saying WHY a row looks different, so the state is
 *     never carried by colour alone.
 *
 * The old "Same" checkbox is gone from the row. It wrote `DumpEntry.sameProcess`,
 * which no reader in the app ever consulted, and it occupied the slot the
 * participation checkbox needs. The store field and `toggleSameProcess` remain
 * (both `@deprecated`) — this component simply stops rendering a control for
 * them.
 */
export function DumpList() {
  const { t } = useTranslation("dumps");
  const dumps = useDumpStore((s) => s.dumps);
  const activeDumpId = useDumpStore((s) => s.activeDumpId);
  const originDumpId = useDumpStore((s) => s.originDumpId);
  const selectedDumpIds = useDumpStore((s) => s.selectedDumpIds);
  const setActiveDump = useDumpStore((s) => s.setActiveDump);
  const removeDump = useDumpStore((s) => s.removeDump);
  const toggleDumpSelected = useDumpStore((s) => s.toggleDumpSelected);
  const selectAllDumps = useDumpStore((s) => s.selectAllDumps);
  const setSelectedDumps = useDumpStore((s) => s.setSelectedDumps);
  const setMainView = useDumpStore((s) => s.setMainView);
  const aslrNormalize = useDumpStore((s) => s.aslrNormalize);
  const toggleAslrNormalize = useDumpStore((s) => s.toggleAslrNormalize);
  const getSelectedDumpPaths = useDumpStore((s) => s.getSelectedDumpPaths);

  const consensusLoading = useConsensusStore((s) => s.loading);
  const consensusError = useConsensusStore((s) => s.error);
  const consensusAvailable = useConsensusStore((s) => s.available);
  const consensusCounts = useConsensusStore((s) => s.counts);
  const overlayEnabled = useConsensusStore((s) => s.overlayEnabled);
  const toggleOverlay = useConsensusStore((s) => s.toggleOverlay);
  // The app's ONE way to start a build, shared with `HexAlignmentChip`,
  // `OverlayAlignSwitch`, `NoConsensusPrompt` and the overlay's raw-offset
  // banner. This row used to call `runConsensus` straight off the store, so the
  // in-flight flag those four disable themselves on was never set: a slow build
  // started here left all four live and a second POST could be issued over it.
  const { running: consensusRunning, run } = useConsensusRun();

  const mode = useAppStore((s) => s.mode);
  // An empty selection means "all of them" (store invariant I2), so the count
  // the button promises has to be computed the same way the paths are.
  const selectedCount = selectedDumpIds.length || dumps.length;
  const enoughSelected = selectedCount >= 2;
  const canRunConsensus = enoughSelected && !consensusLoading && !consensusRunning;
  const allRaw = dumps.length > 0 && dumps.every((d) => d.format === "raw");

  /*
   * "Only focused" is the meaningful inverse of "Select all" here, because the
   * selection can never actually be empty: I2 reads an empty `selectedDumpIds`
   * as "all of them" (so a literal "Select none" round-trips straight back to
   * everything and reads as a dead control), and I3 keeps `activeDumpId` inside
   * the selection because the focused dump is the alignment anchor the
   * side-by-side and overlay views are built on. The narrowest legal selection
   * is therefore exactly the focused dump.
   */
  const alreadyOnlyFocused =
    activeDumpId !== null &&
    selectedDumpIds.length === 1 &&
    selectedDumpIds[0] === activeDumpId;
  const canSelectOnlyFocused = activeDumpId !== null && !alreadyOnlyFocused;
  const onlyFocusedTitle = activeDumpId === null
    ? t("selection.selectOnlyFocusedNoFocusTitle")
    : alreadyOnlyFocused
      ? t("selection.selectOnlyFocusedAlreadyTitle")
      : t("selection.selectOnlyFocusedTitle");

  const handleRunConsensus = () => {
    // Honours the selection instead of silently sweeping every loaded dump —
    // with nine imported, the old behaviour was a correctness surprise.
    run(getSelectedDumpPaths(), aslrNormalize);
  };

  return (
    <div className="p-3 space-y-3 text-xs">
      <h3 className="text-sm font-semibold md-text-accent">{t("list.title")}</h3>

      <AddDumpButton />

      {dumps.length === 0 ? (
        <p className="md-text-muted">{t("list.empty")}</p>
      ) : (
        <>
          <div className="space-y-1.5" data-testid="dump-selection-header">
            <div className="flex items-center gap-2 flex-wrap">
              <button
                type="button"
                onClick={selectAllDumps}
                data-testid="dump-select-all"
                className="px-1.5 py-0.5 rounded border border-[var(--md-border)] hover:bg-[var(--md-bg-hover)]"
              >
                {t("selection.selectAll")}
              </button>
              <button
                type="button"
                onClick={() => {
                  if (activeDumpId !== null) setSelectedDumps([activeDumpId]);
                }}
                disabled={!canSelectOnlyFocused}
                title={onlyFocusedTitle}
                data-testid="dump-select-only-focused"
                className="px-1.5 py-0.5 rounded border border-[var(--md-border)] hover:bg-[var(--md-bg-hover)] disabled:opacity-40"
              >
                {t("selection.selectOnlyFocused")}
              </button>
              <span className="md-text-muted" data-testid="dump-selection-count">
                {t("selection.countLabel", {
                  selected: selectedCount,
                  total: dumps.length,
                })}
              </span>
            </div>
            <div className="flex items-center gap-2 flex-wrap">
              <button
                type="button"
                onClick={() => setMainView("sideBySide")}
                disabled={!enoughSelected}
                title={enoughSelected ? undefined : t("selection.needTwoTitle")}
                data-testid="dump-view-side-by-side"
                className="px-1.5 py-0.5 rounded border border-[var(--md-border)] hover:bg-[var(--md-bg-hover)] disabled:opacity-40"
              >
                {t("selection.viewSideBySide")}
              </button>
              <button
                type="button"
                onClick={() => setMainView("overlay")}
                disabled={!enoughSelected}
                title={enoughSelected ? undefined : t("selection.needTwoTitle")}
                data-testid="dump-view-overlay"
                className="px-1.5 py-0.5 rounded border border-[var(--md-border)] hover:bg-[var(--md-bg-hover)] disabled:opacity-40"
              >
                {t("selection.viewOverlay")}
              </button>
            </div>
          </div>

          <div className="space-y-1">
            {dumps.map((d) => {
              const focused = d.id === activeDumpId;
              const selected = selectedDumpIds.includes(d.id);
              return (
                <div
                  key={d.id}
                  data-testid="dump-row"
                  data-dump-id={d.id}
                  aria-current={focused ? "true" : undefined}
                  onClick={() => setActiveDump(d.id)}
                  className="flex items-start gap-2 p-2 rounded cursor-pointer hover:bg-[var(--md-bg-hover)]"
                  style={{
                    border: focused
                      ? "1.5px solid var(--md-accent-blue)"
                      : "1px solid var(--md-border)",
                  }}
                >
                  <input
                    type="checkbox"
                    className="mt-0.5"
                    checked={selected}
                    aria-label={t("selection.participateLabel", { name: d.name })}
                    data-testid={`dump-select-${d.id}`}
                    // Participation must never be a disguised focus change:
                    // the click stops here so the row handler below never sees
                    // it.
                    onClick={(e) => e.stopPropagation()}
                    onChange={() => toggleDumpSelected(d.id)}
                  />
                  <input
                    type="radio"
                    className="mt-0.5"
                    name="memdiver-dump-focus-list"
                    checked={focused}
                    aria-label={t("selection.focusLabel", { name: d.name })}
                    data-testid={`dump-focus-${d.id}`}
                    onClick={(e) => e.stopPropagation()}
                    onChange={() => setActiveDump(d.id)}
                  />

                  <div className="flex-1 min-w-0">
                    <div className="flex items-center gap-2 min-w-0">
                      <span className="font-mono truncate flex-1" title={d.path}>
                        {d.name}
                      </span>
                      <span
                        className="px-1.5 py-0.5 rounded text-[10px] font-semibold uppercase shrink-0"
                        style={{
                          background: d.format === "msl"
                            ? "var(--md-accent-blue)"
                            : "var(--md-bg-tertiary)",
                          color: d.format === "msl"
                            ? "var(--md-bg-primary)"
                            : "var(--md-text-primary)",
                        }}
                      >
                        {d.format}
                      </span>
                      <TagStatusBadge status={d.tagStatus} />
                    </div>
                    <div className="flex items-center gap-2 mt-0.5 md-text-muted">
                      <span>{formatSize(d.size)}</span>
                      {d.id === originDumpId && (
                        <span
                          data-testid={`dump-origin-${d.id}`}
                          title={t("selection.originTitle")}
                          className="px-1 rounded text-[10px] font-semibold uppercase"
                          style={{ background: "var(--md-bg-tertiary)" }}
                        >
                          {t("selection.originBadge")}
                        </span>
                      )}
                      {/*
                       * The accent border alone would make focus a
                       * colour-only signal; the pill states it in words too.
                       */}
                      {focused && (
                        <span
                          data-testid={`dump-focus-badge-${d.id}`}
                          title={t("selection.focusTitle")}
                          className="px-1 rounded text-[10px] font-semibold uppercase"
                          style={{ background: "var(--md-bg-tertiary)" }}
                        >
                          {t("selection.focusBadge")}
                        </span>
                      )}
                    </div>
                    {d.tagStatus === "missing_key" && (
                      <TagStatusUnlock dumpId={d.id} />
                    )}
                  </div>

                  <button
                    onClick={(e) => { e.stopPropagation(); removeDump(d.id); }}
                    className="px-1 hover:text-[var(--md-accent-red)]"
                    title={t("list.removeTitle")}
                  >
                    x
                  </button>
                </div>
              );
            })}
          </div>
        </>
      )}

      {mode === "exploration" && (
        <>
          <hr className="border-[var(--md-border)]" />

          <div className="space-y-2">
            <label
              className={`flex items-center gap-2 ${allRaw ? "opacity-50 cursor-not-allowed" : "cursor-pointer"}`}
              title={allRaw ? t("consensus.aslrDisabledTitle") : undefined}
            >
              <input
                type="checkbox"
                checked={aslrNormalize}
                onChange={toggleAslrNormalize}
                disabled={allRaw}
              />
              <span>{t("consensus.aslrLabel")}</span>
            </label>
            {allRaw && (
              <p className="text-[10px] md-text-muted ml-5">
                {t("consensus.aslrHint")}
              </p>
            )}

            <button
              onClick={handleRunConsensus}
              disabled={!canRunConsensus}
              data-testid="dump-run-consensus"
              className="w-full px-3 py-1.5 text-xs font-medium rounded border border-[var(--md-border)] hover:bg-[var(--md-bg-hover)] disabled:opacity-40"
            >
              {consensusLoading
                ? t("consensus.running")
                : t("consensus.runScoped", { count: selectedCount })}
            </button>

            {consensusLoading && (
              <div className="flex items-center gap-2 md-text-muted">
                <span className="inline-block w-3 h-3 border-2 border-current border-t-transparent rounded-full animate-spin" />
                {t("consensus.computing")}
              </div>
            )}

            {consensusError && (
              <p className="text-[var(--md-accent-red)]">{consensusError}</p>
            )}

            {consensusAvailable && consensusCounts && (
              <div className="md-text-muted space-y-0.5">
                {Object.entries(consensusCounts).map(([label, count]) => (
                  <div key={label} className="flex justify-between">
                    <span>{label}</span>
                    <span className="font-mono">{count}</span>
                  </div>
                ))}
              </div>
            )}

            <label className="flex items-center gap-2 cursor-pointer">
              <input
                type="checkbox"
                checked={overlayEnabled}
                onChange={toggleOverlay}
                disabled={!consensusAvailable}
              />
              <span className={!consensusAvailable ? "opacity-40" : ""}>
                {t("consensus.overlayLabel")}
              </span>
            </label>
          </div>
        </>
      )}
    </div>
  );
}

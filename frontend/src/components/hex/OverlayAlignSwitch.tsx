import { useTranslation } from "react-i18next";

import { SegmentedControl } from "@/components/common/SegmentedControl";
import { useConsensusRun } from "@/stores/consensus-store";
import { useMultiHexStore } from "@/stores/multi-hex-store";

/**
 * `Align: delta-fit │ raw offsets` — WHAT put these bytes in correspondence.
 *
 * ── Why this is not a new mechanism ─────────────────────────────────────────
 * MemDiver already has exactly one lever for this, and it is the `normalize`
 * flag on `POST /api/analysis/consensus`:
 *
 *   delta-fit    <=> `normalize: true`  => `virtual_address` / `module_offset`
 *   raw offsets  <=> `normalize: false` => `file_offset`, the flat build
 *
 * So this control is a second, better-placed gesture onto `runConsensus`, not a
 * parallel alignment engine. It shares `dump-store.aslrNormalize` with the
 * dump-list checkbox and with `HexAlignmentChip`'s re-run, so the three cannot
 * drift into disagreeing about what the next build will be.
 *
 * ── It reflects the BUILD, not the checkbox ─────────────────────────────────
 * The selected segment is derived from `multi-hex-store.alignment.method` — the
 * coordinate the bytes ON SCREEN are actually in — and NOT from
 * `aslrNormalize`, which is only an intent for the NEXT build. The two
 * legitimately disagree for the whole duration of a rebuild, and a switch that
 * tracked the intent would claim the grid had already moved coordinate while it
 * still held the old one. `null` (no window yet) selects neither, rather than
 * defaulting to a coordinate nobody has computed.
 *
 * ── Why flipping to raw is allowed to look broken ───────────────────────────
 * A flat build compares byte 0x1000 of one dump with byte 0x1000 of another
 * with no regard for where either was mapped, so the grid floods with variance.
 * That flood is the POINT: it is the control condition that shows the aligned
 * build is doing work, which is why the caution says "expected" rather than
 * hiding the option. It is stated in the UI, next to the switch, because a
 * screenful of red with no explanation is indistinguishable from a finding.
 *
 * `HexOverlayPane`'s `hex-overlay-raw-offset` banner is the complementary, and
 * deliberately separate, message: it names the FIX ("enable ASLR normalization
 * and re-run") for a user who did not choose raw on purpose. This one names the
 * CONSEQUENCE for a user who did.
 */

/**
 * The two builds, and the `normalize` flag each one is.
 *
 * Module-private, unlike `OVERLAY_RENDER_MODES` which lives in its store: this
 * list is not persisted state and nothing else needs it, and exporting a
 * non-component from a component file costs the file its fast refresh.
 */
const ALIGN_OPTIONS = [
  { id: "delta-fit", normalize: true },
  { id: "raw-offsets", normalize: false },
] as const;

type AlignOptionId = (typeof ALIGN_OPTIONS)[number]["id"];

const LABEL_KEY: Record<AlignOptionId, string> = {
  "delta-fit": "alignSwitch.deltaFit",
  "raw-offsets": "alignSwitch.rawOffsets",
};

const TITLE_KEY: Record<AlignOptionId, string> = {
  "delta-fit": "alignSwitch.deltaFitTitle",
  "raw-offsets": "alignSwitch.rawOffsetsTitle",
};

/** The visible label, referenced by the group rather than duplicated into it. */
const LABEL_ID = "hex-overlay-align-switch-label";

export interface OverlayAlignSwitchProps {
  /**
   * The dumps a flip rebuilds over — the LIVE selection, so the new build
   * covers the dumps on screen and `consensus-store.builtFrom` keeps matching.
   */
  paths: string[];
}

export function OverlayAlignSwitch({ paths }: OverlayAlignSwitchProps) {
  const { t } = useTranslation("hex");

  const alignment = useMultiHexStore((s) => s.alignment);
  // ONE in-flight flag for the whole app: the chip, the banner and this switch
  // all render at once, and a `useState` each meant clicking one left the other
  // two live. See `useConsensusRun`.
  const { running, run } = useConsensusRun();

  const method = alignment?.method ?? null;
  /**
   * Which option the LIVE window is. `null` = no aligned window yet, which
   * selects neither segment; `module_offset` and `virtual_address` are both
   * normalized builds and both read as delta-fit, because the distinction
   * between them is the alignment KEY, not whether ASLR was normalized — and
   * `HexAlignmentChip` already states which of the two it was, in words.
   */
  const liveNormalized = method === null ? null : method !== "file_offset";
  const liveOption =
    liveNormalized === null
      ? null
      : (ALIGN_OPTIONS.find((o) => o.normalize === liveNormalized)?.id ?? null);

  /**
   * Rebuild in the other coordinate.
   *
   * Goes through `runConsensus` and nothing else: a rebuild mints a NEW
   * `consensus_id`, and `consensus-store` re-derives `builtFrom` /
   * `builtNormalized` from the response in the same `set()`. Poking
   * `consensusId` directly would leave those two describing the previous build,
   * which is the state `consensusCoversSelection` exists to fence off.
   *
   * Two guards, both load-bearing: `useConsensusRun`'s shared in-flight flag
   * stops a double-click from issuing a second build over the first, and the
   * already-live check here stops a click on the selected segment from re-running
   * a build that would come back identical. The `aslrNormalize` nudge — this
   * control shares that intent with the dump-list checkbox and with
   * `HexAlignmentChip`'s re-run — now also lives in `useConsensusRun`.
   */
  const rebuild = (normalize: boolean) => {
    if (liveNormalized === normalize) return;
    run(paths, normalize);
  };

  return (
    <div className="flex flex-wrap items-center gap-2">
      <span id={LABEL_ID} className="md-text-muted">
        {t("alignSwitch.label")}
      </span>

      <SegmentedControl
        aria-labelledby={LABEL_ID}
        testId="hex-overlay-align-switch"
        data={{ "data-method": method ?? "pending" }}
        selected={liveOption}
        onSelect={(id) => {
          const option = ALIGN_OPTIONS.find((o) => o.id === id);
          if (option) rebuild(option.normalize);
        }}
        options={ALIGN_OPTIONS.map((option) => ({
          id: option.id,
          label: t(LABEL_KEY[option.id]),
          title: t(TITLE_KEY[option.id]),
          testId: `hex-overlay-align-${option.id}`,
          disabled: running,
        }))}
      />

      {running && (
        <span role="status" data-testid="hex-overlay-align-running" className="md-text-muted">
          {t("alignSwitch.running")}
        </span>
      )}

      {/*
        The caution rides the LIVE method, not the click: it describes the grid
        that is actually on screen, so it survives a reload and it does not
        appear for the second between the click and the new window arriving.
      */}
      {method === "file_offset" && (
        <p
          data-testid="hex-overlay-align-raw-caution"
          className="basis-full md-text-muted"
        >
          {t("alignSwitch.rawCaution")}
        </p>
      )}
    </div>
  );
}

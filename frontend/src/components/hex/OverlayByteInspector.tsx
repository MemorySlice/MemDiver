import { useTranslation } from "react-i18next";

import { useAlignedSelection } from "@/hooks/useAlignedPanes";
import { useHexStore } from "@/stores/hex-store";
import { useMultiHexStore } from "@/stores/multi-hex-store";
import { byteToAscii, byteToHex } from "@/utils/hex-codec";
import { VARIANCE_META, varianceCategoryForCode } from "@/utils/variance-classes";

/**
 * What every dump holds at the cursor, as a table.
 *
 * The overlay collapses N dumps into one byte stream, so the ring that says
 * "these disagree" cannot say WHICH of them disagrees or by how much. A hover
 * tooltip cannot carry a table and is invisible to a keyboard user, so this
 * panel — not the tooltip — is the primary affordance for that question.
 *
 * Bytes come from `multi-hex-store`, already cached for the visible window, so
 * moving the cursor costs no request. `isPresentAt` is consulted for every row:
 * a dump that does not hold the byte reads "absent", never `00`, because `00`
 * is a claim about memory contents and absence is the opposite of one.
 */

/** `0x0004_A118` — grouped so a 32-bit offset can be read at a glance. */
function formatOffset(offset: number): string {
  const hex = offset.toString(16).toUpperCase().padStart(8, "0");
  return `0x${hex.slice(0, 4)}_${hex.slice(4)}`;
}


export function OverlayByteInspector() {
  const { t } = useTranslation("hex");
  const cursorOffset = useHexStore((s) => s.cursorOffset);
  const { anchor, selected } = useAlignedSelection();
  // Rotates this component when bytes land, so the table fills in as the
  // window loads instead of staying on "absent" until the next cursor move.
  const chunkVersionByPath = useMultiHexStore((s) => s.chunkVersionByPath);

  if (cursorOffset === null || !anchor) {
    return (
      <div className="h-full p-3 overflow-auto md-bg-secondary" data-testid="overlay-byte-inspector">
        <h3 className="text-xs font-semibold uppercase tracking-wider mb-2 md-text-muted">
          {t("inspector.title")}
        </h3>
        <p className="text-sm md-text-secondary">{t("inspector.noCursor")}</p>
      </div>
    );
  }

  void chunkVersionByPath;
  const store = useMultiHexStore.getState();
  const classCode = store.getClassAt(cursorOffset);
  // `undefined` (gap / unclassified) and any unknown code both read as
  // "no class" rather than silently claiming INVARIANT.
  const classCategory = classCode === undefined ? null : varianceCategoryForCode(classCode);
  const anchorPresent = store.isPresentAt(anchor.path, cursorOffset);
  const anchorByte = anchorPresent ? store.getByteAt(anchor.path, cursorOffset) : undefined;

  const rows = selected.map((dump) => {
    const isAnchor = dump.id === anchor.id;
    const present = store.isPresentAt(dump.path, cursorOffset);
    const value = present ? store.getByteAt(dump.path, cursorOffset) : undefined;
    // Absent counts as "not the same as the anchor": the analyst asked what
    // every dump holds here, and "nothing" is a different answer from the
    // anchor's byte, not a missing one.
    const differs = !isAnchor && (!present || value !== anchorByte);
    return { dump, isAnchor, present, value, differs };
  });

  const differing = rows.filter((r) => r.differs).length;

  return (
    <div
      className="h-full p-3 overflow-auto md-bg-secondary text-xs space-y-2"
      data-testid="overlay-byte-inspector"
    >
      <h3 className="text-xs font-semibold uppercase tracking-wider md-text-muted">
        {t("inspector.title")}
      </h3>

      {/*
        Load bearing since the overlay began painting a weighted plurality: the
        grid can now show a byte that no dump holds at this offset, so this
        panel has to say out loud that its own column is not that byte. Every
        row below is a real read, mask-checked, from one file.
      */}
      <p data-testid="overlay-inspector-ground-truth" className="md-text-muted">
        {t("inspector.groundTruth")}
      </p>

      <div className="flex flex-wrap items-center gap-2" data-testid="overlay-inspector-summary">
        <span className="font-mono">{t("inspector.offset", { offset: formatOffset(cursorOffset) })}</span>
        <span aria-hidden="true" className="md-text-muted">
          ·
        </span>
        <span
          data-testid="overlay-inspector-class"
          className={classCategory ? VARIANCE_META[classCategory].byteClass : undefined}
        >
          {classCategory
            ? t("inspector.class", { name: t(VARIANCE_META[classCategory].labelKey) })
            : t("inspector.classNone")}
        </span>
        <span aria-hidden="true" className="md-text-muted">
          ·
        </span>
        <span data-testid="overlay-inspector-differ-count">
          {differing > 0
            ? t("inspector.differSummary", { differing, total: rows.length })
            : t("inspector.identical", { total: rows.length })}
        </span>
      </div>

      <table className="w-full font-mono">
        <thead>
          <tr className="md-text-muted text-left">
            <th scope="col" className="font-normal">
              {t("inspector.colDump")}
            </th>
            <th scope="col" className="font-normal">
              {t("inspector.colByte")}
            </th>
            <th scope="col" className="font-normal">
              {t("inspector.colChar")}
            </th>
            <th scope="col" className="font-normal" />
          </tr>
        </thead>
        <tbody>
          {rows.map(({ dump, isAnchor, present, value, differs }) => (
            <tr
              key={dump.id}
              data-testid={`overlay-inspector-row-${dump.id}`}
              data-differs={differs ? "true" : "false"}
              data-present={present ? "true" : "false"}
            >
              <th scope="row" className="font-normal text-left truncate max-w-[12rem]" title={dump.path}>
                <span aria-hidden="true">{isAnchor ? "● " : "  "}</span>
                {dump.name}
                {isAnchor && (
                  <span className="ml-1 md-text-muted" data-testid={`overlay-inspector-anchor-${dump.id}`}>
                    ({t("inspector.anchor")})
                  </span>
                )}
              </th>
              <td data-testid={`overlay-inspector-byte-${dump.id}`}>
                {present && value !== undefined ? byteToHex(value).toUpperCase() : "--"}
              </td>
              <td>{present && value !== undefined ? byteToAscii(value) : ""}</td>
              <td className="md-text-muted">
                {!present ? (
                  <span data-testid={`overlay-inspector-absent-${dump.id}`}>
                    {t("inspector.absent")}
                  </span>
                ) : differs ? (
                  <span title={t("inspector.differs")} aria-label={t("inspector.differs")}>
                    {"≠"}
                  </span>
                ) : null}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

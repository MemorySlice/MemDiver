import { useEffect, useMemo, useState } from "react";

import i18n from "@/i18n";
import { readableFailure } from "@/api/client";
import {
  getIsfDraft, type DraftRef, type DraftSection, type IsfItem, type IsfOrigin, type IsfSection,
} from "@/api/isf";

export const PAGE_SIZE = 200;

export interface TreeRow { name: string; item: IsfItem; origin: IsfOrigin | null }

const SECTION_TAG: Record<IsfSection, string> = {
  symbols: "symbol", user_types: "type", base_types: "base_type", enums: "enum",
};
export const sectionTag = (s: IsfSection) => SECTION_TAG[s];

interface Page {
  total: number; offset: number; limit: number; rows: TreeRow[];
  fieldOrigins: Record<string, IsfOrigin | null>; counts: Record<IsfSection, number>;
}

function pageOf(section: DraftSection, counts: Record<IsfSection, number>): Page {
  const rows = Object.entries(section.items).map(([name, item]) => ({
    name, item, origin: section.origins?.[name] ?? null,
  }));
  return { total: section.total, offset: section.offset, limit: section.limit, rows,
    fieldOrigins: section.field_origins ?? {}, counts };
}

/**
 * One page of one draft section, searched and paged by the server (name-sorted;
 * `search` is a case-insensitive substring over names). Field provenance comes from
 * the section's `field_origins`, top-level provenance from `origins`.
 */
export function useDraftData(
  ref: DraftRef, name: string, rev: number, section: IsfSection, offset: number, search: string,
) {
  // An answer carries the key of the request it answers; a mismatch means "still loading".
  const [answer, setAnswer] = useState<{ key: string; scope: string; page: Page } | null>(null);
  const [failure, setFailure] = useState<{ key: string; message: string } | null>(null);
  const { caseDir, captureId } = ref;
  const q = search.trim();
  const scope = [caseDir, captureId, name].join("\u0000");
  const key = [caseDir, captureId, name, rev, section, offset, q].join("\u0000");

  useEffect(() => {
    let live = true;
    getIsfDraft({ caseDir, captureId }, name, {
      only: { [section]: [] }, includeOrigins: true, limit: PAGE_SIZE, offset, search: q,
    }).then((draft) => {
      const body = draft.sections?.[section];
      if (!live) return;
      if (body) setAnswer({ key, scope, page: pageOf(body, draft.counts) });
      else setFailure({ key, message: i18n.t("isf:tree.noSection") });
    }).catch((e) => { if (live) setFailure({ key, message: readableFailure(e) }); });
    return () => { live = false; };
  }, [caseDir, captureId, name, rev, section, offset, q, key, scope]);

  const current = answer?.key === key ? answer.page : null;
  const error = failure?.key === key ? failure.message : null;
  const empty = useMemo(() => [] as TreeRow[], []);
  return {
    // The last good counts of THIS draft stay up while the next page loads; another draft's never do.
    counts: (current ?? (answer?.scope === scope ? answer.page : null))?.counts ?? null,
    rows: current?.rows ?? empty, total: current?.total ?? 0, offset: current?.offset ?? offset,
    fieldOrigins: current?.fieldOrigins ?? {}, loading: current === null && error === null, error,
  };
}

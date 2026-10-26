import { useEffect, useState } from "react";

import { listIsfTries, type IsfTryEntry } from "@/api/annotations";
import { readableFailure } from "@/api/client";
import type { DraftRef } from "@/api/isf";

/**
 * The draft's earlier tries, read from the analysis record (`kind=isf_try`), newest first.
 * `refreshKey` re-reads after a run or an edit.
 */
export function usePastTries(ref: DraftRef, draft: string, refreshKey: number) {
  const [answer, setAnswer] = useState<{ key: string; entries: IsfTryEntry[]; error: string | null } | null>(null);
  const { caseDir, captureId } = ref;
  const key = [caseDir, captureId, draft, refreshKey].join("\u0000");

  useEffect(() => {
    let live = true;
    listIsfTries(caseDir, captureId)
      .then((r) => {
        if (live) setAnswer({ key, error: null,
          entries: r.entries.filter((e) => e.payload?.draft === draft).reverse() });
      })
      .catch((e) => { if (live) setAnswer({ key, entries: [], error: readableFailure(e) }); });
    return () => { live = false; };
  }, [caseDir, captureId, draft, key]);

  const current = answer?.key === key ? answer : null;
  return { entries: current?.entries ?? answer?.entries ?? [], error: current?.error ?? null, loading: current === null };
}

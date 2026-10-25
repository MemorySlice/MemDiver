import { useCallback, useEffect, useState } from "react";

import { addAnnotation, listAnnotations, retractAnnotation } from "@/api/annotations";
import { readableFailure } from "@/api/client";
import {
  DEFAULT_RULES, TABLE_RULE_KIND, rulePayload, rulesFromEntries,
  type HighlightRule, type StoredRule,
} from "./highlight-rules";

const EMPTY: StoredRule[] = [];
let counter = 0;
const newRuleId = () => `rule:${Date.now().toString(36)}:${(counter += 1)}`;

/**
 * The highlight rules in force: the built-in defaults plus the user's rules
 * stored in the case's analysis record (`table_rule` entries of the view's
 * capture). Loaded when a case and capture are known; `disable` RETRACTS the
 * entry (the log is append-only), it never edits it.
 */
export function useTableRules(caseDir: string, captureId: string | null) {
  // Rules are kept with the (case, capture) they were loaded for: another key reads as none.
  const key = `${caseDir.trim()}\u0000${captureId ?? ""}`;
  const [loaded, setLoaded] = useState<{ key: string; rules: StoredRule[]; error: string | null } | null>(null);
  const [actionError, setActionError] = useState<string | null>(null);
  const ready = caseDir.trim() !== "" && Boolean(captureId);
  const stored = loaded?.key === key ? loaded.rules : EMPTY;
  const error = actionError ?? (loaded?.key === key ? loaded.error : null);

  const [version, setVersion] = useState(0);
  const reload = useCallback(() => setVersion((v) => v + 1), []);

  useEffect(() => {
    if (!ready || !captureId) return;
    let cancelled = false;
    listAnnotations(caseDir.trim(), captureId, TABLE_RULE_KIND)
      .then((out) => { if (!cancelled) { setLoaded({ key, rules: rulesFromEntries(out.entries), error: null }); setActionError(null); } })
      .catch((err) => { if (!cancelled) setLoaded({ key, rules: [], error: readableFailure(err) }); });
    return () => { cancelled = true; };
  }, [ready, caseDir, captureId, key, version]);

  const add = useCallback(async (rule: Omit<HighlightRule, "id">) => {
    if (!ready || !captureId) return;
    const full: HighlightRule = { ...rule, id: newRuleId() };
    try {
      await addAnnotation({
        case_dir: caseDir.trim(), capture_id: captureId, kind: TABLE_RULE_KIND,
        label: `${full.table}.${full.column}`, payload: rulePayload(full),
      });
      reload();
    } catch (err) {
      setActionError(readableFailure(err));
    }
  }, [ready, caseDir, captureId, reload]);

  const disable = useCallback(async (rule: StoredRule) => {
    if (!ready || !captureId) return;
    try {
      await retractAnnotation({
        case_dir: caseDir.trim(), capture_id: captureId, entry_id: rule.entryId,
        reason: "rule disabled",
      });
      reload();
    } catch (err) {
      setActionError(readableFailure(err));
    }
  }, [ready, caseDir, captureId, reload]);

  return { rules: [...DEFAULT_RULES, ...stored] as HighlightRule[], stored, ready, error, add, disable };
}

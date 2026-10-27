import { useCallback, useEffect, useRef, useState } from "react";

/** The case directory is typed key by key: only a value that has rested is listed. */
export const CASE_LIST_DEBOUNCE_MS = 400;

import { readableFailure } from "@/api/client";
import {
  deleteYaraRule, getYaraRule, listYaraRules, putYaraRule,
  type RuleScope, type YaraRule, type YaraRuleMeta, type YaraRulePutResult,
} from "@/api/yara";
import { useDebounced } from "@/hooks/useDebounced";
import { importLocalRules, type ImportReport } from "./import-local-rules";

export { readRules, STORAGE_KEY } from "./import-local-rules";

export interface SaveOutcome {
  ok: boolean;
  /** The store's compile-check of what was saved (a bad draft is saved and flagged). */
  put?: YaraRulePutResult;
  error?: string;
}

/**
 * Named YARA rules from the backend store: the per-user library plus, with a case
 * directory, that case's rules (a case rule shadows a library rule of the same name).
 * Mutations report their outcome, so a refused write is never shown as saved. On first
 * use the rules an earlier version kept in `localStorage` are imported once into the
 * library, never overwriting a stored rule.
 */
export function useSavedRules(caseDir: string) {
  const [rules, setRules] = useState<YaraRuleMeta[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [caseError, setCaseError] = useState<string | null>(null);
  const [importReport, setImportReport] = useState<ImportReport | null>(null);
  const caseKey = caseDir.trim();
  const listKey = useDebounced(caseKey, CASE_LIST_DEBOUNCE_MS);
  const latest = useRef(0);

  const refresh = useCallback((): Promise<void> => {
    const ticket = ++latest.current;
    const live = () => ticket === latest.current;
    return listYaraRules(listKey || undefined).then((list) => {
      if (!live()) return;
      setRules(list.rules);
      setCaseError(list.case_error ?? null);
      setError(null);
    }, async (e) => {
      if (!live()) return;
      if (listKey === "") { setRules([]); setCaseError(null); setError(readableFailure(e)); return; }
      // A refused or unreadable case directory must not hide the library.
      setCaseError(readableFailure(e));
      try {
        const library = await listYaraRules();
        if (live()) { setRules(library.rules); setError(null); }
      } catch (inner) {
        if (live()) { setRules([]); setError(readableFailure(inner)); }
      }
    });
  }, [listKey]);

  useEffect(() => { void refresh(); }, [refresh]);

  // Once per mount, library only: independent of the case directory (and of its keystrokes).
  const refreshRef = useRef(refresh);
  useEffect(() => { refreshRef.current = refresh; }, [refresh]);
  useEffect(() => {
    let live = true;
    void importLocalRules().then((report) => {
      if (!live || report === null) return;
      setImportReport(report);
      void refreshRef.current();
    });
    return () => { live = false; };
  }, []);

  const save = useCallback(async (name: string, source: string, scope: RuleScope): Promise<SaveOutcome> => {
    try {
      const put = await putYaraRule(name, source, scope, caseKey || undefined);
      await refresh();
      return { ok: true, put };
    } catch (e) {
      return { ok: false, error: readableFailure(e) };
    }
  }, [caseKey, refresh]);

  const load = useCallback(
    (name: string, scope: RuleScope): Promise<YaraRule> =>
      // A library rule is fetched WITHOUT the case, so a case namesake cannot answer for it.
      getYaraRule(name, scope === "case" ? caseKey || undefined : undefined),
    [caseKey]);

  const remove = useCallback(async (name: string, scope: RuleScope): Promise<string | null> => {
    try {
      await deleteYaraRule(name, scope, caseKey || undefined);
      await refresh();
      return null;
    } catch (e) {
      return readableFailure(e);
    }
  }, [caseKey, refresh]);

  return { rules, error, caseError, importReport, save, load, remove, refresh };
}

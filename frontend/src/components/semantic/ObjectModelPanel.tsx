import { useMemo, useRef, useState } from "react";
import { useTranslation } from "react-i18next";
import { useShallow } from "zustand/react/shallow";

import { readableFailure } from "@/api/client";
import {
  getAnchorConsensus, proposeLayout,
  type AnchorConsensusResult, type AnchorInputs, type ProposeLayoutRequest, type ProposedLayoutResult,
} from "@/api/semantic";
import { useDumpStore } from "@/stores/dump-store";
import { KeylogInput } from "./KeylogInput";
import { BuildModelSection } from "./ObjectModelBuild";
import { AnchorResults, LayoutResults } from "./ObjectModelResults";
import {
  emptyKeylogDraft, keylogSpec, relatedLabelsFor, type KeylogDraft,
} from "./keylog-helpers";
import { goToAnchorDelta, normalizeHex } from "./object-model-helpers";

const inputClass =
  "w-full px-1 py-0.5 text-xs rounded border border-[var(--md-border)] bg-[var(--md-bg-secondary)]";
const buttonClass =
  "px-2 py-1 text-xs rounded border border-[var(--md-border)] hover:bg-[var(--md-bg-hover)] disabled:opacity-40";
const baseName = (p: string) => p.split("/").pop() || p;

interface RelatedRow { id: number; name: string; hex: Record<string, string> }
type Outcome =
  | { kind: "anchor"; result: AnchorConsensusResult }
  | { kind: "layout"; result: ProposedLayoutResult; request: ProposeLayoutRequest; seq: number };

/** The workspace's selected dumps (all open dumps when none is selected). */
function useCohortPaths(): string[] {
  const { dumps, selected } = useDumpStore(
    useShallow((s) => ({ dumps: s.dumps, selected: s.selectedDumpIds })));
  return useMemo(() => {
    const chosen = selected.length > 0 ? dumps.filter((d) => selected.includes(d.id)) : dumps;
    return chosen.map((d) => d.path);
  }, [dumps, selected]);
}

/** Anchor a heap object across N dumps by a verified needle, then read its layout. */
export function ObjectModelPanel() {
  const { t } = useTranslation("objectModel");
  const paths = useCohortPaths();
  const [inputMode, setInputMode] = useState<"needle" | "keylog">("needle");
  const [keylog, setKeylog] = useState<KeylogDraft>(emptyKeylogDraft);
  const [same, setSame] = useState(false);
  const [shared, setShared] = useState("");
  const [needles, setNeedles] = useState<Record<string, string>>({});
  const [related, setRelated] = useState<RelatedRow[]>([]);
  const [deltaStart, setDeltaStart] = useState(-2048);
  const [length, setLength] = useState(6144);
  const [occurrence, setOccurrence] = useState(0);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [outcome, setOutcome] = useState<Outcome | null>(null);
  const proposalSeq = useRef(0); // identity of each proposal, so build/export/validate state never outlives it

  const keylogInputs = (): AnchorInputs | null => {
    const spec = keylogSpec(keylog, paths);
    if (spec === null) { setError(t("errors.noKeylog")); return null; }
    const labels = relatedLabelsFor(keylog);
    return {
      dump_paths: paths, keylog: spec,
      ...(keylog.anchorLabel !== "" ? { anchor_label: keylog.anchorLabel } : {}),
      ...(labels ? { related_labels: labels } : {}),
      occurrence, delta_start: deltaStart, length,
    };
  };

  const inputs = (): AnchorInputs | null => {
    if (inputMode === "keylog") return keylogInputs();
    const map: Record<string, string> = {};
    for (const p of paths) {
      const raw = same ? shared : needles[p] ?? "";
      if (raw.trim() === "") continue;
      const hex = normalizeHex(raw);
      if (hex === null) { setError(t("errors.badHex", { dump: baseName(p) })); return null; }
      map[p] = hex;
    }
    if (Object.keys(map).length === 0) { setError(t("errors.noNeedles")); return null; }
    return {
      dump_paths: paths, needles: map, occurrence,
      delta_start: deltaStart, length,
    };
  };

  const relatedBody = (): Record<string, Record<string, string>> | null | undefined => {
    const out: Record<string, Record<string, string>> = {};
    for (const row of related) {
      if (row.name.trim() === "") continue;
      const per: Record<string, string> = {};
      for (const p of paths) {
        const raw = row.hex[p] ?? "";
        if (raw.trim() === "") continue;
        const hex = normalizeHex(raw);
        if (hex === null) { setError(t("errors.badRelated", { name: row.name, dump: baseName(p) })); return null; }
        per[p] = hex;
      }
      if (Object.keys(per).length > 0) out[row.name.trim()] = per;
    }
    return Object.keys(out).length > 0 ? out : undefined;
  };

  const run = async (kind: Outcome["kind"]) => {
    setError(null);
    const base = inputs();
    if (base === null) return;
    const rel = kind === "layout" && inputMode === "needle" ? relatedBody() : undefined;
    if (rel === null) return;
    setBusy(true);
    try {
      if (kind === "anchor") {
        setOutcome({ kind, result: await getAnchorConsensus(base) });
      } else {
        const request = { ...base, ...(rel ? { related: rel } : {}) };
        setOutcome({ kind, result: await proposeLayout(request), request, seq: ++proposalSeq.current });
      }
    } catch (e) {
      setOutcome(null);
      setError(t("errors.failed", { message: readableFailure(e) }));
    } finally {
      setBusy(false);
    }
  };

  const onGoto = (...args: Parameters<typeof goToAnchorDelta>) => {
    if (!goToAnchorDelta(...args)) setError(t("errors.notOpen"));
  };

  if (paths.length === 0) {
    return <p className="p-3 text-xs md-text-muted">{t("noDumps")}</p>;
  }

  return (
    <div className="p-2 text-xs flex flex-col gap-2" data-testid="object-model-panel">
      <h3 className="font-semibold">{t("title")}</h3>
      <select
        aria-label={t("keylog.modeLabel")} className={inputClass} value={inputMode}
        onChange={(e) => setInputMode(e.target.value as "needle" | "keylog")}
      >
        <option value="needle">{t("keylog.modeNeedle")}</option>
        <option value="keylog">{t("keylog.modeKeylog")}</option>
      </select>
      {inputMode === "keylog" && <KeylogInput paths={paths} draft={keylog} onChange={setKeylog} />}
      {inputMode === "needle" && (
        <label className="flex items-center gap-1">
          <input type="checkbox" checked={same} onChange={(e) => setSame(e.target.checked)} />
          {t("sameForAll")}
        </label>
      )}
      {inputMode === "keylog" ? null : same ? (
        <input
          aria-label={t("sharedNeedle")} placeholder={t("sharedNeedle")} className={inputClass}
          value={shared} onChange={(e) => setShared(e.target.value)}
        />
      ) : (
        <div className="flex flex-col gap-1">
          <span className="md-text-muted">{t("dumpsHeading")}</span>
          {paths.map((p) => (
            <label key={p} className="flex items-center gap-1">
              <span className="w-24 truncate" title={p}>{baseName(p)}</span>
              <input
                aria-label={t("needleFor", { dump: baseName(p) })} className={inputClass}
                value={needles[p] ?? ""}
                onChange={(e) => setNeedles({ ...needles, [p]: e.target.value })}
              />
            </label>
          ))}
        </div>
      )}
      <div className="grid grid-cols-3 gap-1">
        {([
          ["deltaStart", deltaStart, setDeltaStart],
          ["length", length, setLength],
          ["occurrence", occurrence, setOccurrence],
        ] as const).map(([key, value, set]) => (
          <label key={key} className="flex flex-col">
            {t(`params.${key}`)}
            <input
              type="number" className={inputClass} value={value}
              onChange={(e) => set(Number(e.target.value))}
            />
          </label>
        ))}
      </div>
      {inputMode === "needle" && <RelatedEditor paths={paths} rows={related} onChange={setRelated} />}
      <div className="flex gap-1">
        <button className={buttonClass} disabled={busy} onClick={() => void run("anchor")}>
          {busy ? t("actions.running") : t("actions.anchor")}
        </button>
        <button className={buttonClass} disabled={busy} onClick={() => void run("layout")}>
          {busy ? t("actions.running") : t("actions.propose")}
        </button>
      </div>
      {error && <p role="alert" className="text-[var(--md-variance-key-candidate)]">{error}</p>}
      {outcome?.kind === "anchor" && <AnchorResults result={outcome.result} onGoto={onGoto} />}
      {outcome?.kind === "layout" && <LayoutResults result={outcome.result} onGoto={onGoto} />}
      {outcome?.kind === "layout" && (
        <BuildModelSection key={outcome.seq} layout={outcome.result} request={outcome.request} />
      )}
    </div>
  );
}

function RelatedEditor(props: {
  paths: string[]; rows: RelatedRow[]; onChange: (rows: RelatedRow[]) => void;
}) {
  const { t } = useTranslation("objectModel");
  const { paths, rows, onChange } = props;
  const patch = (id: number, change: Partial<RelatedRow>) =>
    onChange(rows.map((r) => (r.id === id ? { ...r, ...change } : r)));
  return (
    <div className="flex flex-col gap-1">
      <span className="md-text-muted">{t("related.title")}</span>
      {rows.map((row) => (
        <div key={row.id} className="flex flex-col gap-0.5 border-l border-[var(--md-border)] pl-1">
          <div className="flex gap-1">
            <input
              aria-label={t("related.name")} placeholder={t("related.name")} className={inputClass}
              value={row.name} onChange={(e) => patch(row.id, { name: e.target.value })}
            />
            <button className={buttonClass} onClick={() => onChange(rows.filter((r) => r.id !== row.id))}>
              {t("related.remove")}
            </button>
          </div>
          {paths.map((p) => (
            <input
              key={p} className={inputClass}
              aria-label={t("related.hexFor", { name: row.name, dump: baseName(p) })}
              placeholder={baseName(p)} value={row.hex[p] ?? ""}
              onChange={(e) => patch(row.id, { hex: { ...row.hex, [p]: e.target.value } })}
            />
          ))}
        </div>
      ))}
      <button
        className={buttonClass}
        onClick={() => onChange([...rows, { id: rows.reduce((m, r) => Math.max(m, r.id), 0) + 1, name: "", hex: {} }])}
      >
        {t("related.add")}
      </button>
    </div>
  );
}

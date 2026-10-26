import { useState } from "react";
import { useTranslation } from "react-i18next";

import { readableFailure } from "@/api/client";
import {
  buildArtifactModel, exportArtifactModel,
  type BuildModelResult, type ExportModelResult, type FieldMeaningSpec,
  type ProposeLayoutRequest, type ProposedLayoutResult, type RelationshipSpec,
} from "@/api/semantic";
import { prefilledMeanings, prefilledRelationships } from "./keylog-helpers";
import { ValidateSection } from "./ObjectModelValidate";

const inputClass =
  "w-full px-1 py-0.5 text-xs rounded border border-[var(--md-border)] bg-[var(--md-bg-secondary)]";
const buttonClass =
  "px-2 py-1 text-xs rounded border border-[var(--md-border)] hover:bg-[var(--md-bg-hover)] disabled:opacity-40";
const RELATIONSHIP_KINDS = ["owned_by", "same_object", "pointer"] as const;

interface FieldDraft { meaning: string; label: string }
interface RelDraft { id: number; kind: string; source: string; target: string }

const splitList = (s: string) => s.split(",").map((x) => x.trim()).filter((x) => x !== "");

/** Turn a proposed layout into a built model, an exported plugin and a held-out validation. */
export function BuildModelSection(props: {
  layout: ProposedLayoutResult; request: ProposeLayoutRequest;
}) {
  const { layout, request } = props;
  const { t } = useTranslation("objectModel");
  const names = [...new Set(layout.fields.map((f) => f.name))];
  const [name, setName] = useState("");
  const [outPath, setOutPath] = useState("");
  // From a key log the meanings / owned_by relationships arrive pre-filled (still editable).
  const prefilled = layout.suggested_meanings !== undefined && layout.suggested_meanings.length > 0;
  const [drafts, setDrafts] = useState<Record<string, FieldDraft>>(
    () => prefilledMeanings(layout.suggested_meanings, names));
  const [rels, setRels] = useState<RelDraft[]>(
    () => prefilledRelationships(layout.suggested_meanings, names).map((r, i) => ({ id: i + 1, ...r })));
  const [library, setLibrary] = useState("");
  const [states, setStates] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [built, setBuilt] = useState<BuildModelResult | null>(null);

  const patchField = (field: string, change: Partial<FieldDraft>) =>
    setDrafts({ ...drafts, [field]: { ...(drafts[field] ?? { meaning: "", label: "" }), ...change } });
  const patchRel = (id: number, change: Partial<RelDraft>) =>
    setRels(rels.map((r) => (r.id === id ? { ...r, ...change } : r)));

  const build = async () => {
    setError(null);
    if (name.trim() === "" || outPath.trim() === "") { setError(t("build.needNameAndPath")); return; }
    const meanings: FieldMeaningSpec[] = names
      .filter((n) => (drafts[n]?.meaning ?? "").trim() !== "")
      .map((n) => ({ field: n, meaning: drafts[n].meaning.trim(), label: drafts[n].label.trim() }));
    const relationships: RelationshipSpec[] = rels
      .filter((r) => r.source !== "" && r.target !== "")
      .map(({ kind, source, target }) => ({ kind, source, target }));
    const applicability = {
      ...(library.trim() ? { library: library.trim() } : {}),
      ...(splitList(states).length > 0 ? { states: splitList(states) } : {}),
    };
    setBusy(true);
    try {
      setBuilt(await buildArtifactModel({
        ...request, name: name.trim(), meanings, relationships,
        ...(Object.keys(applicability).length > 0 ? { applicability } : {}),
        out_path: outPath.trim(),
      }));
    } catch (e) {
      setBuilt(null);
      setError(t("build.refused", { message: readableFailure(e) }));
    } finally {
      setBusy(false);
    }
  };

  const learnedOn = [...(request.dump_paths ?? []), ...layout.instances.map((i) => i.dump_path)];
  return (
    <section className="flex flex-col gap-1 border-t border-[var(--md-border)] pt-2" data-testid="build-model">
      <h4 className="font-semibold">{t("build.title")}</h4>
      <input aria-label={t("build.name")} placeholder={t("build.name")} className={inputClass}
        value={name} onChange={(e) => setName(e.target.value)} />
      {prefilled && <p data-testid="build-prefilled" className="md-text-muted">{t("build.prefilled")}</p>}
      <span className="md-text-muted">{t("build.fieldsHeading")}</span>
      {names.map((n) => (
        <div key={n} className="flex gap-1 items-center">
          <span className="w-24 truncate" title={n}>{n}</span>
          <input aria-label={t("build.meaning", { field: n })} placeholder={t("build.noMeaning")}
            className={inputClass} value={drafts[n]?.meaning ?? ""}
            onChange={(e) => patchField(n, { meaning: e.target.value })} />
          <input aria-label={t("build.label", { field: n })} placeholder={t("build.label", { field: n })}
            className={inputClass} value={drafts[n]?.label ?? ""}
            onChange={(e) => patchField(n, { label: e.target.value })} />
        </div>
      ))}
      <span className="md-text-muted">{t("build.relationshipsHeading")}</span>
      {rels.map((r) => (
        <div key={r.id} className="flex gap-1 items-center">
          <select aria-label={t("build.relKind")} className={inputClass} value={r.kind}
            onChange={(e) => patchRel(r.id, { kind: e.target.value })}>
            {RELATIONSHIP_KINDS.map((k) => <option key={k} value={k}>{k}</option>)}
          </select>
          {(["source", "target"] as const).map((side) => (
            <select key={side} aria-label={t(side === "source" ? "build.relSource" : "build.relTarget")}
              className={inputClass} value={r[side]}
              onChange={(e) => patchRel(r.id, { [side]: e.target.value })}>
              <option value="" />
              {names.map((n) => <option key={n} value={n}>{n}</option>)}
            </select>
          ))}
          <button className={buttonClass} onClick={() => setRels(rels.filter((x) => x.id !== r.id))}>
            {t("build.removeRelationship")}
          </button>
        </div>
      ))}
      <button className={buttonClass}
        onClick={() => setRels([...rels, { id: rels.reduce((m, r) => Math.max(m, r.id), 0) + 1, kind: RELATIONSHIP_KINDS[0], source: "", target: "" }])}>
        {t("build.addRelationship")}
      </button>
      <input aria-label={t("build.library")} placeholder={t("build.library")} className={inputClass}
        value={library} onChange={(e) => setLibrary(e.target.value)} />
      <input aria-label={t("build.states")} placeholder={t("build.states")} className={inputClass}
        value={states} onChange={(e) => setStates(e.target.value)} />
      <input aria-label={t("build.outPath")} placeholder={t("build.outPath")} className={inputClass}
        value={outPath} onChange={(e) => setOutPath(e.target.value)} />
      <button className={buttonClass} disabled={busy} onClick={() => void build()}>
        {busy ? t("actions.running") : t("build.action")}
      </button>
      {error && <p role="alert" data-testid="build-error" className="text-[var(--md-variance-key-candidate)]">{error}</p>}
      {built && (
        <div data-testid="build-result" className="flex flex-col gap-1">
          <p>{t("build.built")}</p>
          <p>{t("build.path")}: <code>{built.path}</code></p>
          <p>{t("build.sha256")}: <code>{built.sha256}</code></p>
          {built.problems.length > 0 && (
            <ul data-testid="build-problems" className="list-disc pl-5 text-[var(--md-variance-key-candidate)]">
              {built.problems.map((p, i) => <li key={i}>{p}</li>)}
            </ul>
          )}
          <ExportSection modelPath={built.path} />
          <ValidateSection modelPath={built.path} learnedOn={learnedOn} />
        </div>
      )}
    </section>
  );
}

function ExportSection({ modelPath }: { modelPath: string }) {
  const { t } = useTranslation("objectModel");
  const [outPath, setOutPath] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [result, setResult] = useState<ExportModelResult | null>(null);
  const run = async () => {
    setError(null);
    if (outPath.trim() === "") { setError(t("export.needPath")); return; }
    setBusy(true);
    try {
      setResult(await exportArtifactModel({ model_path: modelPath, out_path: outPath.trim() }));
    } catch (e) {
      setResult(null);
      setError(t("export.refused", { message: readableFailure(e) }));
    } finally {
      setBusy(false);
    }
  };
  return (
    <section className="flex flex-col gap-1 border-t border-[var(--md-border)] pt-2" data-testid="export-plugin">
      <h4 className="font-semibold">{t("export.title")}</h4>
      <input aria-label={t("export.outPath")} placeholder={t("export.outPath")} className={inputClass}
        value={outPath} onChange={(e) => setOutPath(e.target.value)} />
      <button className={buttonClass} disabled={busy} onClick={() => void run()}>
        {busy ? t("actions.running") : t("export.action")}
      </button>
      {error && <p role="alert" data-testid="export-error" className="text-[var(--md-variance-key-candidate)]">{error}</p>}
      {result && (
        <div data-testid="export-result">
          <p>{t("export.path")}: <code>{result.path}</code></p>
          <p>{t("export.sha256")}: <code>{result.sha256}</code></p>
          <p>{t("export.className")}: <code>{result.class_name}</code></p>
          <p>{t("export.bytes")}: {result.bytes}</p>
        </div>
      )}
    </section>
  );
}

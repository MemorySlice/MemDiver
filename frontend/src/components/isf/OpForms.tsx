import { useState } from "react";
import { useTranslation } from "react-i18next";

import { readableFailure } from "@/api/client";
import { setIsfDraft, type DraftRef, type SetOpRequest, type TypeDescriptor } from "@/api/isf";
import { useActiveDump } from "@/hooks/useActiveDump";
import { parseInteger, toHex } from "./number-input";
import { emptyProvenance, provenanceBody, withEvidence, type ProvenanceDraft } from "./provenance-draft";
import { ProvenanceFields } from "./ProvenanceFields";
import { selectionAddress } from "./selection-address";
import { defaultDescriptor, descriptorComplete } from "./type-descriptor";
import { TypeDescriptorBuilder } from "./TypeDescriptorBuilder";
import { buttonClass, errorStyle, inputClass } from "./ui";

export type OpKind = "symbol" | "struct" | "field" | "base_type";
const OPS: readonly OpKind[] = ["symbol", "struct", "field", "base_type"];

/** Entry the tree asked to edit (pre-fills the matching form). */
export interface EditFocus { op: OpKind; name: string; field?: string; nonce: number }

interface Props { draftRef: DraftRef; draft: string; focus: EditFocus | null; onApplied: () => void }

const Field = ({ label, children }: { label: string; children: React.ReactNode }) => (
  <label className="block space-y-0.5"><span className="md-text-secondary">{label}</span>{children}</label>
);

/** Set symbol / struct / field / base type, each with provenance. */
export function OpForms({ draftRef, draft, focus, onApplied }: Props) {
  const { t } = useTranslation("isf");
  const viewPath = useActiveDump()?.path ?? "";
  const [op, setOp] = useState<OpKind>("symbol");
  const [name, setName] = useState("");
  const [address, setAddress] = useState("");
  const [size, setSize] = useState("");
  const [structKind, setStructKind] = useState("struct");
  const [structName, setStructName] = useState("");
  const [fieldName, setFieldName] = useState("");
  const [offset, setOffset] = useState("");
  const [structBase, setStructBase] = useState("");
  const [fieldType, setFieldType] = useState<TypeDescriptor>(defaultDescriptor("base"));
  const [symbolType, setSymbolType] = useState<TypeDescriptor | null>(null);
  const [signed, setSigned] = useState(false);
  const [baseKind, setBaseKind] = useState("int");
  const [endian, setEndian] = useState("little");
  const [prov, setProv] = useState<ProvenanceDraft>(emptyProvenance());
  const [error, setError] = useState<string | null>(null);
  const [note, setNote] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  // A tree click pre-fills the matching form (adjusted during render, once per click).
  const [seenFocus, setSeenFocus] = useState<EditFocus | null>(null);
  if (focus && focus !== seenFocus) {
    setSeenFocus(focus);
    setOp(focus.op);
    if (focus.op === "field") { setStructName(focus.name); setFieldName(focus.field ?? ""); }
    else setName(focus.name);
  }

  // Name/Size/Address are shared by several op tabs; a fresh tab starts them empty.
  const switchOp = (next: OpKind) => {
    if (next === op) return;
    setOp(next);
    setName(""); setSize(""); setAddress(""); setSymbolType(null);
  };

  const fromSelection = async (apply: (address: bigint) => string | null) => {
    setError(null);
    const sel = await selectionAddress(viewPath);
    if (!sel.ok) { setError(t(`selection.hint.${sel.hint}`)); return; }
    const problem = apply(sel.address);
    if (problem) setError(problem);
  };
  const addressFromSelection = () => fromSelection((a) => {
    setAddress(toHex(a));
    setProv((p) => withEvidence(p, t("selection.evidence", { address: toHex(a) })));
    return null;
  });
  const baseFromSelection = () => fromSelection((a) => { setStructBase(toHex(a)); return null; });
  const offsetFromSelection = () => fromSelection((a) => {
    const base = parseInteger(structBase);
    if (base === null) return t("field.baseNeeded");
    if (a < base) return t("field.selectionBelowBase");
    setOffset((a - base).toString());
    setProv((p) => withEvidence(p, t("selection.evidenceOffset", { address: toHex(a), base: toHex(base) })));
    return null;
  });

  const build = (): { req: SetOpRequest; ok: true } | { ok: false; why: string } => {
    const provenance = provenanceBody(prov);
    if (op === "symbol") {
      const addr = parseInteger(address);
      if (!name.trim() || addr === null) return { ok: false, why: t("form.needNameAddress") };
      return { ok: true, req: { op, provenance, args: {
        name: name.trim(), address: toHex(addr), ...(symbolType ? { type: symbolType } : {}) } } };
    }
    if (op === "struct") {
      const n = Number(size);
      if (!name.trim() || size === "" || !Number.isInteger(n) || n < 0) return { ok: false, why: t("form.needNameSize") };
      return { ok: true, req: { op, provenance, args: { name: name.trim(), size: n, kind: structKind } } };
    }
    if (op === "field") {
      const off = Number(offset);
      if (!structName.trim() || !fieldName.trim() || offset === "" || !Number.isInteger(off) || off < 0
        || !descriptorComplete(fieldType)) return { ok: false, why: t("form.needField") };
      return { ok: true, req: { op, provenance, args: {
        struct: structName.trim(), field: fieldName.trim(), offset: off, type: fieldType } } };
    }
    const n = Number(size);
    if (!name.trim() || size === "" || !Number.isInteger(n) || n < 0) return { ok: false, why: t("form.needNameSize") };
    return { ok: true, req: { op, provenance, args: {
      name: name.trim(), size: n, signed, kind: baseKind, endian } } };
  };

  const submit = async () => {
    const built = build();
    if (!built.ok) { setError(built.why); return; }
    setBusy(true); setError(null); setNote(null);
    try {
      await setIsfDraft(draftRef, draft, built.req);
      setNote(t("form.applied", { op: t(`op.${op}`) }));
      onApplied();
    } catch (e) { setError(readableFailure(e)); }
    setBusy(false);
  };

  return (
    <section className="space-y-1" data-testid="isf-edit">
      <h4 className="font-semibold">{t("edit.title")}</h4>
      <div role="tablist" className="flex flex-wrap gap-1" aria-label={t("edit.title")}>
        {OPS.map((o) => (
          <button key={o} type="button" role="tab" aria-selected={op === o} data-testid={`isf-op-${o}`}
            onClick={() => switchOp(o)}
            className={`${buttonClass} ${op === o ? "bg-[var(--md-bg-hover)] md-text-accent" : ""}`}>{t(`op.${o}`)}</button>
        ))}
      </div>
      {(op === "symbol" || op === "struct" || op === "base_type") && (
        <Field label={t("form.name")}>
          <input type="text" value={name} className={inputClass} data-testid="isf-form-name"
            onChange={(e) => setName(e.target.value)} /></Field>
      )}
      {op === "symbol" && (
        <>
          <Field label={t("form.address")}>
            <div className="flex gap-1">
              <input type="text" value={address} className={inputClass} data-testid="isf-form-address"
                placeholder="0xffffffff81000000" onChange={(e) => setAddress(e.target.value)} />
              <button type="button" className={buttonClass} data-testid="isf-from-selection-address"
                onClick={() => void addressFromSelection()}>{t("selection.use")}</button>
            </div>
          </Field>
          <label className="flex items-center gap-1">
            <input type="checkbox" checked={symbolType !== null} data-testid="isf-symbol-typed"
              onChange={(e) => setSymbolType(e.target.checked ? defaultDescriptor("base") : null)} />
            <span>{t("form.symbolType")}</span></label>
          {symbolType && <TypeDescriptorBuilder value={symbolType} onChange={setSymbolType} testId="isf-symbol-type" />}
        </>
      )}
      {(op === "struct" || op === "base_type") && (
        <Field label={t("form.size")}>
          <input type="number" min={0} value={size} className={inputClass} data-testid="isf-form-size"
            onChange={(e) => setSize(e.target.value)} /></Field>
      )}
      {op === "struct" && (
        <select value={structKind} className={inputClass} aria-label={t("form.structKind")}
          data-testid="isf-form-structkind" onChange={(e) => setStructKind(e.target.value)}>
          <option value="struct">struct</option><option value="union">union</option></select>
      )}
      {op === "base_type" && (
        <div className="grid grid-cols-3 gap-1">
          <select value={baseKind} className={inputClass} aria-label={t("form.baseKind")}
            onChange={(e) => setBaseKind(e.target.value)}>
            {["int", "char", "bool", "float", "void", "pointer"].map((k) => <option key={k}>{k}</option>)}</select>
          <select value={endian} className={inputClass} aria-label={t("form.endian")}
            onChange={(e) => setEndian(e.target.value)}><option>little</option><option>big</option></select>
          <label className="flex items-center gap-1">
            <input type="checkbox" checked={signed} onChange={(e) => setSigned(e.target.checked)} />
            <span>{t("form.signed")}</span></label>
        </div>
      )}
      {op === "field" && (
        <>
          <Field label={t("form.struct")}>
            <input type="text" value={structName} className={inputClass} data-testid="isf-form-struct"
              onChange={(e) => setStructName(e.target.value)} /></Field>
          <Field label={t("form.field")}>
            <input type="text" value={fieldName} className={inputClass} data-testid="isf-form-field"
              onChange={(e) => setFieldName(e.target.value)} /></Field>
          <Field label={t("field.base")}>
            <div className="flex gap-1">
              <input type="text" value={structBase} className={inputClass} data-testid="isf-form-base"
                placeholder="0xffff888000001000" onChange={(e) => setStructBase(e.target.value)} />
              <button type="button" className={buttonClass} data-testid="isf-from-selection-base"
                onClick={() => void baseFromSelection()}>{t("selection.use")}</button>
            </div>
          </Field>
          <Field label={t("form.offset")}>
            <div className="flex gap-1">
              <input type="number" min={0} value={offset} className={inputClass} data-testid="isf-form-offset"
                onChange={(e) => setOffset(e.target.value)} />
              <button type="button" className={buttonClass} data-testid="isf-from-selection-offset"
                title={t("field.offsetFromSelectionHint")} onClick={() => void offsetFromSelection()}>
                {t("field.offsetFromSelection")}</button>
            </div>
          </Field>
          <TypeDescriptorBuilder value={fieldType} onChange={setFieldType} testId="isf-field-type" />
        </>
      )}
      <ProvenanceFields value={prov} onChange={setProv} />
      <button type="button" className={buttonClass} disabled={busy} data-testid="isf-form-submit"
        onClick={() => void submit()}>{t("form.apply")}</button>
      {error && <p role="alert" data-testid="isf-form-error" style={errorStyle}>{error}</p>}
      {note && <p role="status" data-testid="isf-form-note" className="md-text-secondary">{note}</p>}
    </section>
  );
}

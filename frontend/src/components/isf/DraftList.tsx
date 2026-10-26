import { useState } from "react";
import { useTranslation } from "react-i18next";

import { readableFailure } from "@/api/client";
import { createIsfDraft, type DraftRef, type DraftSummaryRow } from "@/api/isf";
import { buttonClass, errorStyle, inputClass } from "./ui";

const ARCHES = ["x86_64", "aarch64", "arm", "x86"] as const;
const SLUG = /^[A-Za-z0-9][A-Za-z0-9._-]*$/;

/** The capture's drafts, plus create (name + arch). */
export function DraftList({ draftRef, drafts, selected, error, noCase = false, onSelect, onCreated, onRefresh }: {
  draftRef: DraftRef | null;
  drafts: DraftSummaryRow[];
  selected: string | null;
  error: string | null;
  /** The case directory does not exist yet: not an error, creating a draft starts it. */
  noCase?: boolean;
  onSelect: (name: string) => void;
  onCreated: (name: string) => void;
  onRefresh: () => void;
}) {
  const { t } = useTranslation("isf");
  const [name, setName] = useState("");
  const [arch, setArch] = useState<string>("x86_64");
  const [failure, setFailure] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const valid = SLUG.test(name.trim());

  const create = async () => {
    if (!draftRef || !valid) return;
    setBusy(true); setFailure(null);
    try {
      await createIsfDraft(draftRef, name.trim(), arch);
      onCreated(name.trim());
      setName("");
    } catch (e) { setFailure(readableFailure(e)); }
    setBusy(false);
  };

  return (
    <section className="space-y-1" data-testid="isf-drafts">
      <div className="flex items-center justify-between">
        <h4 className="font-semibold">{t("drafts.title")}</h4>
        <button type="button" className={buttonClass} disabled={!draftRef} data-testid="isf-refresh"
          onClick={onRefresh}>{t("drafts.refresh")}</button>
      </div>
      {(error || failure) && <p role="alert" data-testid="isf-drafts-error" style={errorStyle}>{error ?? failure}</p>}
      {draftRef && noCase && <p className="md-text-muted" data-testid="isf-drafts-nocase">{t("drafts.noCase")}</p>}
      {draftRef && drafts.length === 0 && !error && !noCase && <p className="md-text-muted" data-testid="isf-drafts-empty">{t("drafts.empty")}</p>}
      <ul className="space-y-0.5">
        {drafts.map((d) => (
          <li key={d.name}>
            <button type="button" data-testid="isf-draft" aria-pressed={selected === d.name}
              className={`${buttonClass} w-full text-left ${selected === d.name ? "bg-[var(--md-bg-hover)] md-text-accent" : ""}`}
              onClick={() => onSelect(d.name)}>
              <span className="font-mono">{d.name}</span>{" "}
              <span className="md-text-secondary">
                {t("drafts.row", { arch: d.arch, symbols: d.counts.symbols, types: d.counts.user_types, applied: d.applied })}</span>
            </button>
          </li>
        ))}
      </ul>
      <div className="flex gap-1">
        <input type="text" value={name} className={inputClass} data-testid="isf-new-name"
          aria-label={t("drafts.name")} placeholder={t("drafts.name")} onChange={(e) => setName(e.target.value)} />
        <select value={arch} className={inputClass} data-testid="isf-new-arch" aria-label={t("drafts.arch")}
          onChange={(e) => setArch(e.target.value)}>{ARCHES.map((a) => <option key={a}>{a}</option>)}</select>
        <button type="button" className={buttonClass} disabled={!draftRef || !valid || busy}
          data-testid="isf-create" onClick={() => void create()}>{t("drafts.create")}</button>
      </div>
      {name.trim() !== "" && !valid && <p className="md-text-muted">{t("drafts.nameRule")}</p>}
    </section>
  );
}

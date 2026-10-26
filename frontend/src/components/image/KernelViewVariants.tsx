import { useState } from "react";
import { useTranslation } from "react-i18next";

import type { OpenViewArgs, PagingOverride } from "@/api/image";

const inputClass =
  "w-full px-2 py-1 text-xs rounded border border-[var(--md-border)] bg-[var(--md-bg-secondary)]";
const buttonClass =
  "px-2 py-1 text-xs rounded border border-[var(--md-border)] hover:bg-[var(--md-bg-hover)] disabled:opacity-40";

type Extra = Pick<OpenViewArgs, "no_profile" | "paging" | "draft" | "draft_version">;

/** Hex text to a PGD; null when it is not a hex address. */
function parsePgd(text: string): number | string | null {
  if (!/^(0x)?[0-9a-f]+$/i.test(text)) return null;
  const value = BigInt(text.toLowerCase().startsWith("0x") ? text : `0x${text}`);
  return value <= BigInt(Number.MAX_SAFE_INTEGER) ? Number(value) : `0x${value.toString(16)}`;
}

/** Kernel-view variants beyond the profile-based one: no profile (+ manual paging) and an ISF draft. */
export function KernelViewVariants({ disabled, caseDir, onOpen }: {
  disabled: boolean;
  caseDir: string;
  onOpen: (extra: Extra) => void;
}) {
  const { t } = useTranslation("image");
  const [pgd, setPgd] = useState("");
  const [arch, setArch] = useState("");
  const [vaBits, setVaBits] = useState("");
  const [draft, setDraft] = useState("");
  const [version, setVersion] = useState("");
  const [localError, setLocalError] = useState<string | null>(null);

  const openNoProfile = () => {
    const text = pgd.trim();
    const parsed = text === "" ? undefined : parsePgd(text);
    if (parsed === null) { setLocalError(t("views.badPgd")); return; }
    setLocalError(null);
    const paging: PagingOverride = {
      ...(parsed !== undefined ? { pgd_phys: parsed } : {}),
      ...(arch ? { arch } : {}),
      ...(vaBits ? { va_bits: Number(vaBits) } : {}),
    };
    const hasPaging = Object.keys(paging).length > 0;
    onOpen({ no_profile: true, ...(hasPaging ? { paging: { ...paging, page_size: 4096 } } : {}) });
  };
  const draftReady = draft.trim() !== "" && caseDir.trim() !== "";
  const openDraft = () => {
    setLocalError(null);
    onOpen({ draft: draft.trim(), ...(version.trim() ? { draft_version: version.trim() } : {}) });
  };

  return (
    <div className="space-y-2" data-testid="kernel-variants">
      <div className="space-y-1">
        <button disabled={disabled} className={buttonClass} data-testid="open-noprofile"
          onClick={openNoProfile}>{t("views.openNoProfile")}</button>
        <p className="md-text-muted">{t("views.noProfileHint")}</p>
        <details data-testid="paging-section">
          <summary className="cursor-pointer md-text-secondary">{t("views.paging")}</summary>
          <div className="space-y-1 pt-1">
            <label className="block space-y-0.5"><span className="md-text-secondary">{t("views.pgdPhys")}</span>
              <input type="text" value={pgd} className={inputClass} data-testid="paging-pgd"
                placeholder={t("views.pgdPlaceholder")} onChange={(e) => setPgd(e.target.value)} /></label>
            <div className="grid grid-cols-2 gap-1">
              <label className="block space-y-0.5"><span className="md-text-secondary">{t("views.arch")}</span>
                <select value={arch} className={inputClass} data-testid="paging-arch"
                  onChange={(e) => setArch(e.target.value)}>
                  <option value="">{t("views.auto")}</option>
                  <option value="x86_64">x86_64</option><option value="aarch64">aarch64</option></select></label>
              <label className="block space-y-0.5"><span className="md-text-secondary">{t("views.vaBits")}</span>
                <select value={vaBits} className={inputClass} data-testid="paging-vabits"
                  onChange={(e) => setVaBits(e.target.value)}>
                  <option value="">{t("views.auto")}</option>
                  <option value="48">48</option><option value="57">57</option><option value="39">39</option></select></label>
            </div>
          </div>
        </details>
      </div>
      <div className="space-y-1">
        <span className="md-text-secondary">{t("views.draftTitle")}</span>
        <div className="grid grid-cols-2 gap-1">
          <input type="text" value={draft} className={inputClass} data-testid="draft-name"
            aria-label={t("views.draftName")} placeholder={t("views.draftName")}
            onChange={(e) => setDraft(e.target.value)} />
          <input type="text" value={version} className={inputClass} data-testid="draft-version"
            aria-label={t("views.draftVersion")} placeholder={t("views.draftVersion")}
            onChange={(e) => setVersion(e.target.value)} />
        </div>
        <button disabled={disabled || !draftReady} className={buttonClass} data-testid="open-draft"
          title={draftReady ? undefined : t("views.draftNeedsCase")} onClick={openDraft}>{t("views.openDraft")}</button>
      </div>
      {localError && <p role="alert" data-testid="variants-error" style={{ color: "var(--md-accent-red)" }}>{localError}</p>}
    </div>
  );
}

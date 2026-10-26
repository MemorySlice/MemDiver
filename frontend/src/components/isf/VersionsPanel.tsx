import { useEffect, useState } from "react";
import { useTranslation } from "react-i18next";

import { readableFailure } from "@/api/client";
import {
  diffIsfDraft, getIsfDraftVersions, retractIsfEntry,
  type DraftDiff, type DraftRef, type DraftVersion,
} from "@/api/isf";
import { ProvenanceBadge } from "./ProvenanceBadge";
import { buttonClass, errorStyle, inputClass } from "./ui";

const brief = (value: unknown): string => {
  const text = JSON.stringify(value) ?? "";
  return text.length > 80 ? `${text.slice(0, 77)}...` : text;
};

function DiffView({ diff }: { diff: DraftDiff }) {
  const { t } = useTranslation("isf");
  return (
    <div data-testid="isf-diff" className="space-y-1">
      <p data-testid="isf-diff-summary">
        {diff.equal ? t("versions.diffEqual", { against: diff.against })
          : t("versions.diffCounts", { against: diff.against, ...diff.counts })}
        {diff.truncated ? ` · ${t("versions.diffTruncated", { shown: diff.items.length, total: diff.total })}` : ""}
      </p>
      <table className="text-xs"><tbody>
        {diff.items.map((i) => (
          <tr key={i.key.join("/")} data-testid="isf-diff-row" data-change={i.change}>
            <td className="pr-2 font-medium">{t(`versions.change.${i.change}`)}</td>
            <td className="pr-2 font-mono">{i.key.join(" / ")}</td>
            <td className="pr-2 font-mono md-text-secondary">{brief(i.before)}</td>
            <td className="font-mono">{brief(i.after)}</td>
          </tr>
        ))}
      </tbody></table>
    </div>
  );
}

/** Operation history of the draft, diff against a version or an ISF file, retract an op. */
export function VersionsPanel({ draftRef, draft, rev, onChanged }: {
  draftRef: DraftRef; draft: string; rev: number; onChanged: () => void;
}) {
  const { t } = useTranslation("isf");
  const [versions, setVersions] = useState<DraftVersion[]>([]);
  const [total, setTotal] = useState(0);
  const [diffAnswer, setDiffAnswer] = useState<{ draft: string; rev: number; diff: DraftDiff } | null>(null);
  // A diff describes one version of one draft; an edit retires it.
  const diff = diffAnswer && diffAnswer.draft === draft && diffAnswer.rev === rev ? diffAnswer.diff : null;
  const [isfPath, setIsfPath] = useState("");
  const [confirm, setConfirm] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const { caseDir, captureId } = draftRef;

  useEffect(() => {
    let live = true;
    getIsfDraftVersions({ caseDir, captureId }, draft, 500)
      .then((v) => { if (live) { setVersions(v.versions); setTotal(v.total); } })
      .catch((e) => { if (live) setError(readableFailure(e)); });
    return () => { live = false; };
  }, [caseDir, captureId, draft, rev]);

  const guarded = async (work: () => Promise<void>) => {
    setError(null);
    try { await work(); } catch (e) { setError(readableFailure(e)); }
  };
  const diffAgainst = (against: { version: string } | { isf: string }) =>
    guarded(async () => setDiffAnswer({ draft, rev, diff: await diffIsfDraft(draftRef, draft, against) }));
  const retract = (entryId: string) => guarded(async () => {
    await retractIsfEntry(draftRef, draft, entryId);
    setConfirm(null);
    onChanged();
  });

  return (
    <section className="space-y-1" data-testid="isf-versions">
      <h4 className="font-semibold">{t("versions.title", { total })}</h4>
      {error && <p role="alert" data-testid="isf-versions-error" style={errorStyle}>{error}</p>}
      <div className="flex gap-1">
        <input type="text" value={isfPath} className={inputClass} data-testid="isf-diff-isf-path"
          aria-label={t("versions.isfPath")} placeholder={t("versions.isfPath")}
          onChange={(e) => setIsfPath(e.target.value)} />
        <button type="button" className={buttonClass} disabled={isfPath.trim() === ""} data-testid="isf-diff-isf"
          onClick={() => void diffAgainst({ isf: isfPath.trim() })}>{t("versions.diffIsf")}</button>
      </div>
      <ol className="space-y-0.5" data-testid="isf-version-list">
        {[...versions].reverse().map((v) => (
          <li key={v.entry_id} data-testid="isf-version" data-retracted={v.retracted || undefined}
            className="flex flex-wrap items-center gap-1">
            <span className={v.retracted ? "line-through md-text-muted" : ""}>
              {t(`versions.op.${v.op}`, { defaultValue: v.op })}{v.key ? ` ${v.key.slice(1).join(".")}` : ""}</span>
            <ProvenanceBadge provenance={v.provenance} />
            {v.retracted && <span className="md-text-muted">{t("versions.retracted")}</span>}
            <button type="button" className={buttonClass} data-testid="isf-diff-version"
              onClick={() => void diffAgainst({ version: v.entry_id })}>{t("versions.diffVs")}</button>
            {!v.retracted && v.op !== "create" && (confirm === v.entry_id ? (
              <span className="inline-flex gap-1">
                <button type="button" className={buttonClass} data-testid="isf-retract-confirm"
                  onClick={() => void retract(v.entry_id)}>{t("versions.retractConfirm")}</button>
                <button type="button" className={buttonClass} onClick={() => setConfirm(null)}>{t("tree.cancel")}</button>
              </span>
            ) : (
              <button type="button" className={buttonClass} data-testid="isf-retract"
                onClick={() => setConfirm(v.entry_id)}>{t("versions.retract")}</button>
            ))}
          </li>
        ))}
      </ol>
      {diff && <DiffView diff={diff} />}
    </section>
  );
}

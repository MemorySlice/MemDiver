import { useState } from "react";
import { useTranslation } from "react-i18next";

import type {
  AnchorCommon, AnchorConsensusResult, AnchorInstance, KeylogOutputs, KeylogParseSummary,
  ProposedLayoutResult,
} from "@/api/semantic";
import { resolutionStatus } from "./keylog-helpers";
import { classColorVar, signedHex } from "./object-model-helpers";

export type OnGoto = (instance: AnchorInstance, delta: number) => void;

const baseName = (p: string) => p.split("/").pop() || p;
const cell = "px-1 py-0.5 text-left align-top";

export function ClassBadge({ cls }: { cls: string }) {
  return (
    <span
      data-testid="class-badge"
      className="px-1 rounded text-[10px] border border-current"
      style={{ color: classColorVar(cls) }}
    >
      {cls}
    </span>
  );
}

const MAX_MALFORMED_SHOWN = 20;

/** Lines the key log parser dropped or skipped: malformed is a warning, the rest is info. */
export function KeylogParseReport({ summary }: { summary: KeylogParseSummary }) {
  const { t } = useTranslation("objectModel");
  const source = summary.path ?? summary.dump_path ?? summary.text ?? "";
  const ignored = Object.entries(summary.ignored ?? {});
  const details = summary.malformed_details ?? [];
  const mismatches = summary.length_mismatches ?? [];
  if (summary.malformed <= 0 && ignored.length === 0 && mismatches.length === 0) return null;
  return (
    <div data-testid="keylog-parse-report" className="mb-1">
      {summary.malformed > 0 && (
        <div role="alert" data-testid="keylog-malformed"
          className="p-2 mb-1 rounded border border-[var(--md-variance-key-candidate)]">
          <p className="font-semibold">{t("keylog.parse.malformedTitle", { count: summary.malformed, source })}</p>
          <ul>
            {details.slice(0, MAX_MALFORMED_SHOWN).map((d) => (
              <li key={d.line} data-testid="keylog-malformed-line">
                {t("keylog.parse.line", { line: d.line })}: {d.reason}
              </li>
            ))}
          </ul>
          {details.length > MAX_MALFORMED_SHOWN && (
            <p data-testid="keylog-malformed-more">
              {t("keylog.parse.more", { count: details.length - MAX_MALFORMED_SHOWN })}
            </p>
          )}
        </div>
      )}
      {mismatches.length > 0 && (
        <p data-testid="keylog-length-mismatch" className="md-text-muted">
          {t("keylog.parse.lengthMismatch", { count: mismatches.length, sessions: mismatches.join(", ") })}
        </p>
      )}
      {ignored.length > 0 && (
        <p data-testid="keylog-ignored" className="md-text-muted">
          {t("keylog.parse.ignored", {
            count: ignored.reduce((n, [, c]) => n + c, 0),
            labels: ignored.map(([l, c]) => `${l} x${c}`).join(", "),
          })}
        </p>
      )}
    </div>
  );
}

/** Per dump: the key-log session chosen, or why none could be (absent / ambiguous). */
function KeylogResolutionView({ result }: { result: KeylogOutputs }) {
  const { t } = useTranslation("objectModel");
  const rows = result.keylog_resolution ?? [];
  const summaries = result.keylog_summary ?? [];
  if (rows.length === 0 && summaries.length === 0) return null;
  const failed = rows.filter((r) => !r.anchored).length;
  return (
    <div data-testid="keylog-resolution" className="text-xs mb-2">
      {summaries.map((s, i) => <KeylogParseReport key={i} summary={s} />)}
      {failed > 0 && (
        <p role="alert" data-testid="keylog-unanchored"
          className="font-semibold p-2 mb-1 rounded border border-[var(--md-variance-key-candidate)]">
          {t("keylog.resolution.failedTitle", { count: failed })}
        </p>
      )}
      <table className="w-full">
        <caption className="text-left font-semibold md-text-muted">
          {t("keylog.resolution.title", { label: result.keylog_anchor_label ?? "" })}
        </caption>
        <thead><tr>
          {["dump", "status", "clientRandom", "candidates", "reason"].map((k) => (
            <th key={k} className={cell}>{t(`keylog.resolution.${k}`)}</th>
          ))}
        </tr></thead>
        <tbody>
          {rows.map((r) => {
            const status = resolutionStatus(r);
            return (
              <tr key={r.dump_path} data-testid="keylog-resolution-row" data-status={status}
                className={r.anchored ? "" : "text-[var(--md-variance-key-candidate)]"}>
                <td className={cell} title={r.dump_path}>{baseName(r.dump_path)}</td>
                <td className={`${cell} font-semibold`}>{t(`keylog.resolution.${status}`)}</td>
                <td className={cell}><code>{r.client_random ?? ""}</code></td>
                <td className={cell}>{r.candidates}</td>
                <td className={cell}>{r.reason}</td>
              </tr>
            );
          })}
        </tbody>
      </table>
    </div>
  );
}

/** Warnings and unanchored dumps first: a dump with no anchor must never be silent. */
function Caveats({ result }: { result: AnchorCommon & KeylogOutputs }) {
  const { t } = useTranslation("objectModel");
  return (
    <>
      <KeylogResolutionView result={result} />
      {result.unanchored.length > 0 && (
        <div role="alert" data-testid="unanchored" className="text-xs p-2 mb-2 rounded border border-[var(--md-variance-key-candidate)]">
          <p className="font-semibold">{t("unanchored.title", { count: result.unanchored.length })}</p>
          <ul>
            {result.unanchored.map((u) => (
              <li key={u.dump_path} title={u.dump_path}>
                {baseName(u.dump_path)}: {u.reason} ({t("unanchored.occurrences", { count: u.occurrences })})
              </li>
            ))}
          </ul>
        </div>
      )}
      {result.warnings.length > 0 && (
        <ul data-testid="warnings" className="text-xs p-2 mb-2 rounded border border-[var(--md-border)] list-disc pl-5">
          {result.warnings.map((w, i) => <li key={i}>{w}</li>)}
        </ul>
      )}
    </>
  );
}

function Instances({ result }: { result: AnchorCommon }) {
  const { t } = useTranslation("objectModel");
  return (
    <table className="w-full text-xs mb-2" data-testid="instances">
      <caption className="text-left font-semibold md-text-muted">{t("instances.title", { count: result.instances.length })}</caption>
      <thead><tr>
        <th className={cell}>{t("instances.dump")}</th>
        <th className={cell}>{t("instances.basis")}</th>
        <th className={cell}>{t("instances.captured")}</th>
      </tr></thead>
      <tbody>
        {result.instances.map((i) => (
          <tr key={i.dump_path}>
            <td className={cell} title={i.dump_path}>{baseName(i.dump_path)}</td>
            <td className={cell}>{i.basis}</td>
            <td className={cell}>{i.captured_bytes}</td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}

export function AnchorResults({ result, onGoto }: { result: AnchorConsensusResult; onGoto: OnGoto }) {
  const { t } = useTranslation("objectModel");
  const first = result.instances[0];
  return (
    <div data-testid="anchor-results">
      <Caveats result={result} />
      <Instances result={result} />
      <table className="w-full text-xs">
        <thead><tr>
          <th className={cell}>{t("regions.delta")}</th>
          <th className={cell}>{t("regions.length")}</th>
          <th className={cell}>{t("regions.class")}</th>
          <th className={cell}>{t("regions.minCaptured")}</th>
          <th className={cell}>{t("regions.maxDistinct")}</th>
        </tr></thead>
        <tbody>
          {result.regions.map((r) => (
            <tr
              key={r.delta_start}
              data-testid="region-row"
              className={first ? "cursor-pointer hover:bg-[var(--md-bg-hover)]" : ""}
              onClick={() => first && onGoto(first, r.delta_start)}
            >
              <td className={cell}>{signedHex(r.delta_start)}..{signedHex(r.delta_end)}</td>
              <td className={cell}>{r.length}</td>
              <td className={cell}><ClassBadge cls={r.class} /></td>
              <td className={cell}>{r.min_captured}</td>
              <td className={cell}>{r.max_distinct}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

export function LayoutResults({ result, onGoto }: { result: ProposedLayoutResult; onGoto: OnGoto }) {
  const { t } = useTranslation("objectModel");
  const [kind, setKind] = useState("");
  const kinds = [...new Set(result.fields.map((f) => f.kind))];
  const shown = kind ? result.fields.filter((f) => f.kind === kind) : result.fields;
  const first = result.instances[0];
  return (
    <div data-testid="layout-results">
      <Caveats result={result} />
      <Instances result={result} />
      <p className="text-xs mb-1" data-testid="bounds">
        {result.base_delta === null
          ? t("layout.noBounds")
          : t("layout.bounds", { base: signedHex(result.base_delta), size: result.total_size ?? 0 })}
      </p>
      {result.bounds_evidence.length > 0 && (
        <ul className="text-xs md-text-muted list-disc pl-5 mb-2">
          {result.bounds_evidence.map((e, i) => <li key={i}>{e}</li>)}
        </ul>
      )}
      <label className="text-xs flex items-center gap-1 mb-1">
        {t("layout.filterKind")}
        <select
          aria-label={t("layout.filterKind")}
          value={kind}
          onChange={(e) => setKind(e.target.value)}
          className="text-xs border border-[var(--md-border)] bg-[var(--md-bg-secondary)] rounded"
        >
          <option value="">{t("layout.allKinds")}</option>
          {kinds.map((k) => <option key={k} value={k}>{k}</option>)}
        </select>
      </label>
      <table className="w-full text-xs">
        <thead><tr>
          <th className={cell}>{t("layout.delta")}</th>
          <th className={cell}>{t("layout.length")}</th>
          <th className={cell}>{t("layout.kind")}</th>
          <th className={cell}>{t("layout.name")}</th>
          <th className={cell}>{t("layout.evidence")}</th>
        </tr></thead>
        <tbody>
          {shown.map((f) => (
            <tr
              key={`${f.delta}:${f.kind}:${f.name}`}
              data-testid="field-row"
              className={first ? "cursor-pointer hover:bg-[var(--md-bg-hover)]" : ""}
              onClick={() => first && onGoto(first, f.delta)}
            >
              <td className={cell}>{signedHex(f.delta)}</td>
              <td className={cell}>{f.length}</td>
              <td className={cell}>{f.kind}</td>
              <td className={cell}>{f.name}</td>
              <td className={cell}>
                {f.evidence.join("; ")}
                {f.alternatives.length > 0 && (
                  <span className="md-text-muted"> {t("layout.alternatives", { count: f.alternatives.length })}</span>
                )}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

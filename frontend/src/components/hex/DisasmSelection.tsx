import { useCallback, useEffect, useState } from "react";
import { useTranslation } from "react-i18next";

import { readableFailure } from "@/api/client";
import { disassemble, type DisasmResult } from "@/api/disasm";
import { Modal } from "@/components/common/Modal";
import { selectionAddress } from "@/components/isf/selection-address";
import { useActiveDump } from "@/hooks/useActiveDump";
import { wireIntHex } from "@/api/lossless-json";
import { useHexStore } from "@/stores/hex-store";

/** Most bytes of one selection that are sent for decoding. */
export const MAX_DISASM_BYTES = 65536;
const ARCHES = ["auto", "x86_64", "aarch64", "arm", "x86", "mips", "mipsel"] as const;
const buttonClass =
  "px-2 py-0.5 rounded border border-[var(--md-border)] hover:bg-[var(--md-bg-hover)] disabled:opacity-50";

interface Answer { result: DisasmResult; sentBytes: number; selectedBytes: number }

/** "Disassemble selection": decode the captured bytes under the current hex selection. */
export function DisasmSelection() {
  const { t } = useTranslation("isf");
  const dumpPath = useActiveDump()?.path ?? "";
  const selection = useHexStore((s) => s.selection);
  const [open, setOpen] = useState(false);
  const [arch, setArch] = useState<string>("auto");
  const [answer, setAnswer] = useState<Answer | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const run = useCallback(async (chosenArch: string) => {
    setBusy(true); setError(null); setAnswer(null);
    try {
      const sel = await selectionAddress(dumpPath);
      if (!sel.ok) { setError(t(`selection.hint.${sel.hint}`)); return; }
      const sent = Math.min(sel.length, MAX_DISASM_BYTES);
      const result = await disassemble(dumpPath, sel.address, sent, { arch: chosenArch });
      setAnswer({ result, sentBytes: sent, selectedBytes: sel.length });
    } catch (e) { setError(readableFailure(e)); }
    finally { setBusy(false); }
  }, [dumpPath, t]);

  useEffect(() => { if (selection === null) setOpen(false); }, [selection]);
  if (selection === null || dumpPath === "") return null;

  return (
    <>
      <button type="button" className={buttonClass} data-testid="disasm-open"
        onClick={() => { setOpen(true); void run(arch); }}>{t("disasm.action")}</button>
      {open && (
        <Modal title={t("disasm.title")} onClose={() => setOpen(false)} testId="disasm-modal">
          <div className="space-y-2 text-xs">
            <label className="flex items-center gap-2">
              <span>{t("disasm.arch")}</span>
              <select value={arch} data-testid="disasm-arch" disabled={busy}
                className="px-1 py-0.5 rounded border border-[var(--md-border)] bg-[var(--md-bg-secondary)]"
                onChange={(e) => { setArch(e.target.value); void run(e.target.value); }}>
                {ARCHES.map((a) => <option key={a} value={a}>{a}</option>)}</select>
            </label>
            {busy && <p role="status">{t("disasm.running")}</p>}
            {error && <p role="alert" data-testid="disasm-error" style={{ color: "var(--md-accent-red)" }}>{error}</p>}
            {answer && <DisasmResultView answer={answer} />}
          </div>
        </Modal>
      )}
    </>
  );
}

export function DisasmResultView({ answer }: { answer: Answer }) {
  const { t } = useTranslation("isf");
  const { result, sentBytes, selectedBytes } = answer;
  const { coverage } = result;
  return (
    <div data-testid="disasm-result" className="space-y-1">
      <p data-testid="disasm-summary" className="md-text-secondary">
        {t("disasm.summary", { arch: result.arch, address: result.address, count: result.row_count,
          captured: coverage.captured, requested: coverage.requested })}</p>
      {selectedBytes > sentBytes && (
        <p data-testid="disasm-capped" style={{ color: "var(--md-accent-orange)" }}>
          {t("disasm.capped", { sent: sentBytes, selected: selectedBytes })}</p>
      )}
      {result.truncated && (
        <p data-testid="disasm-truncated" style={{ color: "var(--md-accent-orange)" }}>
          {t("disasm.truncated", { max: result.max_insns })}</p>
      )}
      {coverage.gaps.length > 0 && (
        <ul data-testid="disasm-gaps" className="space-y-0.5">
          {coverage.gaps.map((g, i) => (
            <li key={i} style={{ color: "var(--md-accent-orange)" }}>
              {t("disasm.gap", { start: g.start_hex ?? wireIntHex(g.start),
                length: g.length, reason: g.reason })}</li>
          ))}
        </ul>
      )}
      {result.stops.length > 0 && (
        <p data-testid="disasm-stops" className="md-text-secondary">
          {t("disasm.stops", { count: result.stops.length, first: result.stops[0].addr_hex ?? result.stops[0].addr })}</p>
      )}
      <div className="overflow-auto max-h-96">
        <table className="text-xs font-mono"><thead><tr>
          <th className="text-left pr-3">{t("disasm.col.addr")}</th>
          <th className="text-left pr-3">{t("disasm.col.bytes")}</th>
          <th className="text-left pr-3">{t("disasm.col.mnemonic")}</th>
          <th className="text-left">{t("disasm.col.opStr")}</th></tr></thead>
        <tbody>{result.rows.map((r) => (
          <tr key={r.addr} data-testid="disasm-row" data-stop={r.stop_reason ?? undefined}>
            <td className="pr-3">{r.addr}</td><td className="pr-3 md-text-secondary">{r.bytes}</td>
            <td className="pr-3">{r.mnemonic}</td><td>{r.op_str}</td></tr>))}
        </tbody></table>
      </div>
    </div>
  );
}

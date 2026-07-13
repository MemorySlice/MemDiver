import { useMemo, useState } from "react";
import { useTranslation, Trans } from "react-i18next";
import { verifyKey } from "@/api/client";
import { useHexStore } from "@/stores/hex-store";
import { useActiveDump } from "@/hooks/useActiveDump";
import { useVerificationStore } from "@/stores/verification-store";

const INPUT = "w-full px-1.5 py-1 rounded border border-[var(--md-border)] bg-[var(--md-bg-primary)] text-xs font-mono";
const BTN = "px-2 py-1 rounded border border-[var(--md-border)] hover:bg-[var(--md-bg-hover)] text-xs";

function normalizeHex(value: string): string {
  return value.replace(/\s+/g, "").replace(/^0x/i, "");
}

function isHex(value: string): boolean {
  return /^[0-9a-fA-F]*$/.test(value);
}

/**
 * Parse an offset string without silent truncation. A '0x'/'0X' prefix means
 * hex; a bare numeric string means decimal. A bare string containing hex
 * letters (e.g. '1f') is ambiguous and rejected (returns NaN) rather than being
 * misread as decimal, which would verify the wrong offset.
 */
function parseOffset(raw: string): number {
  const value = raw.trim();
  if (/^0x/i.test(value)) {
    const body = value.slice(2);
    return /^[0-9a-fA-F]+$/.test(body) ? parseInt(body, 16) : NaN;
  }
  return /^[0-9]+$/.test(value) ? parseInt(value, 10) : NaN;
}

export function KeyVerificationPanel() {
  const { t } = useTranslation("misc");
  const activeDump = useActiveDump();
  const dumpPath = activeDump?.path ?? "";
  const selection = useHexStore((s) => s.selection);
  const cursorOffset = useHexStore((s) => s.cursorOffset);
  const addBookmark = useHexStore((s) => s.addBookmark);

  const {
    ciphertextHex,
    ivHex,
    cipher,
    isVerifying,
    result,
    error,
    setCiphertextHex,
    setIvHex,
    setCipher,
    startVerify,
    setResult,
    setError,
    reset,
  } = useVerificationStore();

  const { prefillOffset, prefillLength } = useMemo(() => {
    if (selection) {
      const start = Math.min(selection.anchor, selection.active);
      const len = Math.abs(selection.active - selection.anchor) + 1;
      return { prefillOffset: start, prefillLength: len };
    }
    if (cursorOffset !== null) {
      return { prefillOffset: cursorOffset, prefillLength: 32 };
    }
    return { prefillOffset: 0, prefillLength: 32 };
  }, [selection, cursorOffset]);

  const [offsetInput, setOffsetInput] = useState<string>("");
  const [lengthInput, setLengthInput] = useState<string>("");

  const effectiveOffset = offsetInput.trim()
    ? parseOffset(offsetInput)
    : prefillOffset;
  const effectiveLength = lengthInput.trim() ? parseInt(lengthInput, 10) : prefillLength;

  const cleanCiphertext = normalizeHex(ciphertextHex);
  const cleanIv = normalizeHex(ivHex);

  const ciphertextValid = cleanCiphertext.length > 0 && cleanCiphertext.length % 2 === 0 && isHex(cleanCiphertext);
  const ivValid = cleanIv.length === 0 || (cleanIv.length % 2 === 0 && isHex(cleanIv));
  const offsetValid = Number.isFinite(effectiveOffset) && effectiveOffset >= 0;
  const lengthValid = Number.isFinite(effectiveLength) && effectiveLength > 0;

  const canVerify =
    !!dumpPath && ciphertextValid && ivValid && offsetValid && lengthValid && !isVerifying;

  async function runVerify() {
    if (!canVerify) return;
    startVerify();
    try {
      const res = await verifyKey({
        dump_path: dumpPath,
        offset: effectiveOffset,
        length: effectiveLength,
        ciphertext_hex: cleanCiphertext,
        iv_hex: cleanIv.length > 0 ? cleanIv : undefined,
        cipher,
      });
      setResult(res);
    } catch (e) {
      setError(e instanceof Error ? e.message : t("verification.requestFailed"));
    }
  }

  const handleCopyKey = () => {
    if (result?.key_hex) {
      navigator.clipboard.writeText(result.key_hex).catch(() => {});
    }
  };

  const handleBookmark = () => {
    if (!result || result.verified !== true) return;
    addBookmark({
      offset: result.offset,
      length: effectiveLength,
      label: t("verification.bookmarkLabel", { cipher: result.cipher }),
    });
  };

  if (!dumpPath) {
    return (
      <p className="p-3 text-xs md-text-muted">
        {t("verification.loadDumpHint")}
      </p>
    );
  }

  return (
    <div className="p-3 space-y-3 text-xs">
      <div className="space-y-1">
        <p className="font-medium md-text-secondary">{t("verification.heading")}</p>
        <p className="text-[10px] md-text-muted">
          <Trans
            t={t}
            i18nKey="verification.description"
            components={[<span className="font-mono" />]}
          />
        </p>
      </div>

      <div className="grid grid-cols-2 gap-2">
        <label className="block">
          <span className="text-[10px] md-text-muted">{t("verification.offset")}</span>
          <input
            className={INPUT}
            value={offsetInput}
            onChange={(e) => setOffsetInput(e.target.value)}
            placeholder={`0x${prefillOffset.toString(16).toUpperCase()}`}
          />
        </label>
        <label className="block">
          <span className="text-[10px] md-text-muted">{t("verification.length")}</span>
          <input
            className={INPUT}
            value={lengthInput}
            onChange={(e) => setLengthInput(e.target.value)}
            placeholder={String(prefillLength)}
          />
        </label>
      </div>

      <label className="block">
        <span className="text-[10px] md-text-muted">{t("verification.ciphertextLabel")}</span>
        <textarea
          className={`${INPUT} resize-y`}
          rows={3}
          value={ciphertextHex}
          onChange={(e) => setCiphertextHex(e.target.value)}
          placeholder={t("verification.ciphertextPlaceholder")}
        />
        {!ciphertextValid && ciphertextHex.length > 0 && (
          <p className="text-[10px] md-text-error mt-0.5">{t("verification.ciphertextInvalid")}</p>
        )}
      </label>

      <div className="grid grid-cols-2 gap-2">
        <label className="block">
          <span className="text-[10px] md-text-muted">{t("verification.ivLabel")}</span>
          <input
            className={INPUT}
            value={ivHex}
            onChange={(e) => setIvHex(e.target.value)}
            placeholder={t("verification.ivPlaceholder")}
          />
          {!ivValid && (
            <p className="text-[10px] md-text-error mt-0.5">{t("verification.ivInvalid")}</p>
          )}
        </label>
        <label className="block">
          <span className="text-[10px] md-text-muted">{t("verification.cipherLabel")}</span>
          <select
            className={INPUT}
            value={cipher}
            onChange={(e) => setCipher(e.target.value)}
          >
            <option value="AES-256-CBC">AES-256-CBC</option>
          </select>
        </label>
      </div>

      <div className="flex items-center gap-2">
        <button
          onClick={runVerify}
          disabled={!canVerify}
          className="px-3 py-1.5 rounded text-white disabled:opacity-40 transition-opacity flex items-center gap-1.5"
          style={{ background: "var(--md-accent-blue)" }}
        >
          {isVerifying && <span className="md-spinner" style={{ width: 10, height: 10, borderWidth: 1.5 }} />}
          {isVerifying ? t("verification.verifying") : t("verification.verifyKey")}
        </button>
        {(result || error) && (
          <button onClick={reset} className={BTN}>{t("common:clear")}</button>
        )}
      </div>

      {error && <p className="text-[10px] md-text-error">{error}</p>}

      {result && (
        <div className="md-panel p-2 space-y-1">
          {result.verified === true ? (
            <p className="text-[11px]">
              <span className="md-text-accent font-semibold">{t("verification.keyVerified")}</span>{" "}
              {t("verification.verifiedAtOffset", {
                offset: result.offset.toString(16).toUpperCase(),
                cipher: result.cipher,
              })}
            </p>
          ) : result.verified === false ? (
            <p className="text-[11px] md-text-error">
              {t("verification.noMatch", {
                offset: result.offset.toString(16).toUpperCase(),
                cipher: result.cipher,
              })}
            </p>
          ) : (
            <p className="text-[11px] md-text-muted">
              {t("verification.returnedNull")}
            </p>
          )}
          {result.key_hex && (
            <pre className="font-mono text-[10px] p-1 rounded bg-[var(--md-bg)] border border-[var(--md-border)] overflow-x-auto">
              {result.key_hex}
            </pre>
          )}
          {result.verified === true && (
            <div className="flex gap-1 pt-1">
              <button onClick={handleCopyKey} className={BTN}>{t("verification.copyKeyHex")}</button>
              <button onClick={handleBookmark} className={BTN}>{t("verification.bookmarkOffset")}</button>
            </div>
          )}
        </div>
      )}
    </div>
  );
}

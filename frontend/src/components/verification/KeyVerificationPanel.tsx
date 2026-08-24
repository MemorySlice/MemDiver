import { useMemo, useState } from "react";
import { useTranslation, Trans } from "react-i18next";
import { verifyKey, exportKeylog } from "@/api/client";
import { downloadTextFile } from "@/utils/download";
import { normalizeHex, isHex } from "@/utils/hex";
import { NSS_KEYLOG_LABELS, CLIENT_RANDOM_HEX_LEN } from "@/api/keylog-labels";
import {
  buildSecrets,
  countValidEntries,
  entryFromVerifiedKey,
  makeEntry,
  updateEntry,
  validateEntry,
  type KeylogEntry,
} from "./keylog-composer";
import {
  pcapVersionLabel,
  shortClientRandom,
} from "@/components/pipeline/oracle/pcap-session";
import { useHexStore } from "@/stores/hex-store";
import { useDumpStore } from "@/stores/dump-store";
import { usePipelineStore } from "@/stores/pipeline-store";
import { useActiveDump } from "@/hooks/useActiveDump";
import { useVerificationStore } from "@/stores/verification-store";

const INPUT = "w-full px-1.5 py-1 rounded border border-[var(--md-border)] bg-[var(--md-bg-primary)] text-xs font-mono";
const BTN = "px-2 py-1 rounded border border-[var(--md-border)] hover:bg-[var(--md-bg-hover)] text-xs";
const INPUT_ERR = "border-[var(--md-accent-red)]";

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
    nonceHex,
    aadHex,
    tagHex,
    cipher,
    isVerifying,
    result,
    error,
    setCiphertextHex,
    setIvHex,
    setNonceHex,
    setAadHex,
    setTagHex,
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

  // Armed pcap sessions (from the Pipeline oracle stage) offer their real TLS
  // client_randoms as prefill options — the one field memory alone cannot yield.
  const pcapSessions = usePipelineStore((s) => s.pcapSessions);

  // --- NSS key-log composer (multi-secret) ---
  const [entries, setEntries] = useState<KeylogEntry[]>([]);
  const [keylogError, setKeylogError] = useState<string | null>(null);
  const [keylogCount, setKeylogCount] = useState<number | null>(null);
  const validEntryCount = countValidEntries(entries);

  // Every entry mutation invalidates the last export summary, so route all of
  // them through one helper that resets ``keylogCount``. Keeps that invariant
  // in a single place rather than repeated after each ``setEntries`` call.
  const mutateEntries = (updater: Parameters<typeof setEntries>[0]) => {
    setEntries(updater);
    setKeylogCount(null);
  };

  const effectiveOffset = offsetInput.trim()
    ? parseOffset(offsetInput)
    : prefillOffset;
  const effectiveLength = lengthInput.trim() ? parseInt(lengthInput, 10) : prefillLength;

  const cleanCiphertext = normalizeHex(ciphertextHex);
  const cleanIv = normalizeHex(ivHex);
  const cleanNonce = normalizeHex(nonceHex);
  const cleanAad = normalizeHex(aadHex);
  const cleanTag = normalizeHex(tagHex);

  const isOptionalHexValid = (value: string): boolean =>
    value.length === 0 || (value.length % 2 === 0 && isHex(value));

  const ciphertextValid = cleanCiphertext.length > 0 && cleanCiphertext.length % 2 === 0 && isHex(cleanCiphertext);
  const ivValid = isOptionalHexValid(cleanIv);
  const nonceValid = isOptionalHexValid(cleanNonce);
  const aadValid = isOptionalHexValid(cleanAad);
  const tagValid = isOptionalHexValid(cleanTag);
  const offsetValid = Number.isFinite(effectiveOffset) && effectiveOffset >= 0;
  const lengthValid = Number.isFinite(effectiveLength) && effectiveLength > 0;

  const canVerify =
    !!dumpPath &&
    ciphertextValid &&
    ivValid &&
    nonceValid &&
    aadValid &&
    tagValid &&
    offsetValid &&
    lengthValid &&
    !isVerifying;

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
        nonce_hex: cleanNonce.length > 0 ? cleanNonce : undefined,
        aad_hex: cleanAad.length > 0 ? cleanAad : undefined,
        tag_hex: cleanTag.length > 0 ? cleanTag : undefined,
        cipher,
        ...useDumpStore.getState().getKeyMaterialByPath(dumpPath),
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

  // Push the verified recovered key into the composer as a new entry. The user
  // still has to supply the real client_random (from the handshake/pcap) before
  // the entry becomes exportable — memory alone cannot recover it.
  const handleAddToKeylog = () => {
    if (!result || result.verified !== true || !result.key_hex) return;
    mutateEntries((prev) => [...prev, entryFromVerifiedKey(result.key_hex!)]);
  };

  const handleAddEntry = () => {
    mutateEntries((prev) => [...prev, makeEntry()]);
  };

  const patchEntry = (id: string, patch: Partial<Omit<KeylogEntry, "id">>) => {
    mutateEntries((prev) => updateEntry(prev, id, patch));
  };

  // Synergy: prefill one row's client_random from an armed pcap TLS session.
  const prefillClientRandomFromPcap = (id: string, clientRandom: string) => {
    if (!clientRandom) return;
    patchEntry(id, { clientRandom });
  };

  const removeEntry = (id: string) => {
    mutateEntries((prev) => prev.filter((e) => e.id !== id));
  };

  const clearEntries = () => {
    mutateEntries([]);
    setKeylogError(null);
  };

  // The real, Wireshark-loadable export: assemble every fully-valid entry into
  // a multi-secret NSS key log and download it.
  const handleComposerExport = async () => {
    const secrets = buildSecrets(entries);
    if (secrets.length === 0) return;
    setKeylogError(null);
    try {
      const res = await exportKeylog({ secrets });
      downloadTextFile(res.keylog, "memdiver.keylog");
      setKeylogCount(res.count);
    } catch (e) {
      setKeylogCount(null);
      setKeylogError(e instanceof Error ? e.message : t("verification.exportFailed"));
    }
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
            data-testid="verify-offset-input"
          />
        </label>
        <label className="block">
          <span className="text-[10px] md-text-muted">{t("verification.length")}</span>
          <input
            className={INPUT}
            value={lengthInput}
            onChange={(e) => setLengthInput(e.target.value)}
            placeholder={String(prefillLength)}
            data-testid="verify-length-input"
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
          data-testid="verify-ciphertext-input"
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
            data-testid="verify-iv-input"
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
            data-testid="verify-cipher-select"
          >
            <option value="AES-128-CBC">AES-128-CBC</option>
            <option value="AES-256-CBC">AES-256-CBC</option>
            <option value="AES-128-GCM">AES-128-GCM</option>
            <option value="AES-256-GCM">AES-256-GCM</option>
            <option value="CHACHA20-POLY1305">CHACHA20-POLY1305</option>
          </select>
        </label>
      </div>

      <div className="space-y-1">
        <p className="text-[10px] md-text-muted">{t("verification.aeadHint")}</p>
        <div className="grid grid-cols-3 gap-2">
          <label className="block">
            <span className="text-[10px] md-text-muted">{t("verification.nonceLabel")}</span>
            <input
              className={INPUT}
              value={nonceHex}
              onChange={(e) => setNonceHex(e.target.value)}
              placeholder={t("verification.noncePlaceholder")}
              data-testid="verify-nonce-input"
            />
            {!nonceValid && (
              <p className="text-[10px] md-text-error mt-0.5">{t("verification.nonceInvalid")}</p>
            )}
          </label>
          <label className="block">
            <span className="text-[10px] md-text-muted">{t("verification.aadLabel")}</span>
            <input
              className={INPUT}
              value={aadHex}
              onChange={(e) => setAadHex(e.target.value)}
              placeholder={t("verification.aadPlaceholder")}
              data-testid="verify-aad-input"
            />
            {!aadValid && (
              <p className="text-[10px] md-text-error mt-0.5">{t("verification.aadInvalid")}</p>
            )}
          </label>
          <label className="block">
            <span className="text-[10px] md-text-muted">{t("verification.tagLabel")}</span>
            <input
              className={INPUT}
              value={tagHex}
              onChange={(e) => setTagHex(e.target.value)}
              placeholder={t("verification.tagPlaceholder")}
              data-testid="verify-tag-input"
            />
            {!tagValid && (
              <p className="text-[10px] md-text-error mt-0.5">{t("verification.tagInvalid")}</p>
            )}
          </label>
        </div>
      </div>

      <div className="flex items-center gap-2">
        <button
          onClick={runVerify}
          disabled={!canVerify}
          className="px-3 py-1.5 rounded text-white disabled:opacity-40 transition-opacity flex items-center gap-1.5"
          style={{ background: "var(--md-accent-blue)" }}
          data-testid="verify-submit-btn"
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
            <p className="text-[11px]" data-testid="verify-result-verified">
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
            <pre
              className="font-mono text-[10px] p-1 rounded bg-[var(--md-bg)] border border-[var(--md-border)] overflow-x-auto"
              data-testid="verify-key-hex"
            >
              {result.key_hex}
            </pre>
          )}
          {result.verified === true && (
            <div className="flex flex-wrap gap-1 pt-1">
              <button onClick={handleCopyKey} className={BTN}>{t("verification.copyKeyHex")}</button>
              <button onClick={handleBookmark} className={BTN}>{t("verification.bookmarkOffset")}</button>
              <button
                onClick={handleAddToKeylog}
                className={BTN}
                data-testid="verify-add-to-keylog"
              >
                {t("verification.addToKeylog")}
              </button>
            </div>
          )}
        </div>
      )}

      <div
        className="md-panel p-2 space-y-2"
        data-testid="keylog-section"
      >
        <div className="space-y-1">
          <p className="font-medium md-text-secondary">{t("verification.keylogHeading")}</p>
          <p className="text-[10px] md-text-muted">{t("verification.keylogHint")}</p>
        </div>

        {entries.map((entry) => {
          const v = validateEntry(entry);
          return (
            <div
              key={entry.id}
              data-testid="keylog-entry-row"
              className="space-y-1 border border-[var(--md-border)] rounded p-1.5"
            >
              <div className="grid grid-cols-[1fr_auto] gap-1 items-start">
                <label className="block">
                  <span className="text-[10px] md-text-muted">{t("verification.secretTypeLabel")}</span>
                  <select
                    className={`${INPUT} ${v.secretTypeValid ? "" : INPUT_ERR}`}
                    value={entry.secretType}
                    onChange={(e) => patchEntry(entry.id, { secretType: e.target.value })}
                    data-testid="keylog-entry-secret-type"
                  >
                    <option value="">{t("verification.secretTypePlaceholder")}</option>
                    {NSS_KEYLOG_LABELS.map((label) => (
                      <option key={label} value={label}>{label}</option>
                    ))}
                  </select>
                </label>
                <button
                  onClick={() => removeEntry(entry.id)}
                  className={`${BTN} self-end`}
                  data-testid="keylog-entry-remove"
                  aria-label={t("verification.removeEntry")}
                  title={t("verification.removeEntry")}
                >
                  {t("verification.removeEntry")}
                </button>
              </div>

              <label className="block">
                <span className="text-[10px] md-text-muted">{t("verification.clientRandomLabel")}</span>
                <input
                  className={`${INPUT} ${v.clientRandomValid || entry.clientRandom.length === 0 ? "" : INPUT_ERR}`}
                  value={entry.clientRandom}
                  onChange={(e) => patchEntry(entry.id, { clientRandom: e.target.value })}
                  placeholder={t("verification.clientRandomPlaceholder", { len: CLIENT_RANDOM_HEX_LEN })}
                  data-testid="keylog-entry-client-random"
                />
                {!v.clientRandomValid && entry.clientRandom.length > 0 && (
                  <p className="text-[10px] md-text-error mt-0.5">
                    {t("verification.clientRandomInvalid", { len: CLIENT_RANDOM_HEX_LEN })}
                  </p>
                )}
              </label>

              {pcapSessions.length > 0 && (
                <select
                  className={INPUT}
                  value=""
                  onChange={(e) => {
                    prefillClientRandomFromPcap(entry.id, e.target.value);
                  }}
                  data-testid="keylog-prefill-pcap"
                  aria-label={t("verification.prefillPcapLabel")}
                >
                  <option value="">{t("verification.prefillPcapLabel")}</option>
                  {pcapSessions.map((session, index) => (
                    <option key={`${session.client_random}-${index}`} value={session.client_random}>
                      {t("verification.prefillPcapOption", {
                        version: pcapVersionLabel(session.version),
                        random: shortClientRandom(session.client_random),
                      })}
                    </option>
                  ))}
                </select>
              )}

              <label className="block">
                <span className="text-[10px] md-text-muted">{t("verification.secretLabel")}</span>
                <input
                  className={`${INPUT} ${v.secretValid || entry.secret.length === 0 ? "" : INPUT_ERR}`}
                  value={entry.secret}
                  onChange={(e) => patchEntry(entry.id, { secret: e.target.value })}
                  placeholder={t("verification.secretPlaceholder")}
                  data-testid="keylog-entry-secret"
                />
                {!v.secretValid && entry.secret.length > 0 && (
                  <p className="text-[10px] md-text-error mt-0.5">{t("verification.secretInvalid")}</p>
                )}
              </label>
            </div>
          );
        })}

        <div className="flex flex-wrap items-center gap-1">
          <button
            onClick={handleAddEntry}
            className={BTN}
            data-testid="keylog-add-entry"
          >
            {t("verification.addEntry")}
          </button>
          <button
            onClick={handleComposerExport}
            className={`${BTN} disabled:opacity-40`}
            disabled={validEntryCount === 0}
            data-testid="keylog-export"
          >
            {t("verification.exportKeylog")}
          </button>
          {entries.length > 0 && (
            <button onClick={clearEntries} className={BTN}>{t("verification.clearAll")}</button>
          )}
        </div>

        {keylogError && <p className="text-[10px] md-text-error">{keylogError}</p>}
        {keylogCount !== null && (
          <p className="text-[10px] md-text-accent">
            {t("verification.exportSuccess", { count: keylogCount })}
          </p>
        )}
        {/* A successful export drops incomplete rows silently; warn so a
            missing secret is not mistaken for a complete key log. keylogCount
            resets to null on any edit, so this only shows for the last export. */}
        {keylogCount !== null && entries.length > validEntryCount && (
          <p className="text-[10px] md-text-warning" data-testid="keylog-export-skipped">
            {t("verification.exportSkipped", {
              skipped: entries.length - validEntryCount,
            })}
          </p>
        )}
      </div>
    </div>
  );
}

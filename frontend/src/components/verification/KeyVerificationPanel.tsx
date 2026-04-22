import { useMemo, useState } from "react";
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

export function KeyVerificationPanel() {
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
    ? parseInt(offsetInput.replace(/^0x/i, ""), offsetInput.toLowerCase().startsWith("0x") ? 16 : 10)
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
      setError(e instanceof Error ? e.message : "Verification request failed");
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
      label: `verified ${result.cipher} key`,
    });
  };

  if (!dumpPath) {
    return (
      <p className="p-3 text-xs md-text-muted">
        Load a dump file to verify candidate key bytes against a known ciphertext.
      </p>
    );
  }

  return (
    <div className="p-3 space-y-3 text-xs">
      <div className="space-y-1">
        <p className="font-medium md-text-secondary">Key Verification</p>
        <p className="text-[10px] md-text-muted">
          Decrypts a known ciphertext with the selected byte range as the candidate key. Verifies
          the result matches MemDiver&apos;s plaintext probe. Only <span className="font-mono">AES-256-CBC</span> is supported today.
        </p>
      </div>

      <div className="grid grid-cols-2 gap-2">
        <label className="block">
          <span className="text-[10px] md-text-muted">Offset</span>
          <input
            className={INPUT}
            value={offsetInput}
            onChange={(e) => setOffsetInput(e.target.value)}
            placeholder={`0x${prefillOffset.toString(16).toUpperCase()}`}
          />
        </label>
        <label className="block">
          <span className="text-[10px] md-text-muted">Length</span>
          <input
            className={INPUT}
            value={lengthInput}
            onChange={(e) => setLengthInput(e.target.value)}
            placeholder={String(prefillLength)}
          />
        </label>
      </div>

      <label className="block">
        <span className="text-[10px] md-text-muted">Ciphertext (hex)</span>
        <textarea
          className={`${INPUT} resize-y`}
          rows={3}
          value={ciphertextHex}
          onChange={(e) => setCiphertextHex(e.target.value)}
          placeholder="Paste hex-encoded ciphertext..."
        />
        {!ciphertextValid && ciphertextHex.length > 0 && (
          <p className="text-[10px] md-text-error mt-0.5">Ciphertext must be an even-length hex string.</p>
        )}
      </label>

      <div className="grid grid-cols-2 gap-2">
        <label className="block">
          <span className="text-[10px] md-text-muted">IV (hex, optional)</span>
          <input
            className={INPUT}
            value={ivHex}
            onChange={(e) => setIvHex(e.target.value)}
            placeholder="default 000102...0f"
          />
          {!ivValid && (
            <p className="text-[10px] md-text-error mt-0.5">Invalid hex.</p>
          )}
        </label>
        <label className="block">
          <span className="text-[10px] md-text-muted">Cipher</span>
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
          {isVerifying ? "Verifying..." : "Verify Key"}
        </button>
        {(result || error) && (
          <button onClick={reset} className={BTN}>Clear</button>
        )}
      </div>

      {error && <p className="text-[10px] md-text-error">{error}</p>}

      {result && (
        <div className="md-panel p-2 space-y-1">
          {result.verified === true ? (
            <p className="text-[11px]">
              <span className="md-text-accent font-semibold">Key verified</span> at offset
              {" "}0x{result.offset.toString(16).toUpperCase()} ({result.cipher})
            </p>
          ) : result.verified === false ? (
            <p className="text-[11px] md-text-error">
              No match at offset 0x{result.offset.toString(16).toUpperCase()} ({result.cipher})
            </p>
          ) : (
            <p className="text-[11px] md-text-muted">
              Verification returned null. Check dump path, cipher, or length.
            </p>
          )}
          {result.key_hex && (
            <pre className="font-mono text-[10px] p-1 rounded bg-[var(--md-bg)] border border-[var(--md-border)] overflow-x-auto">
              {result.key_hex}
            </pre>
          )}
          {result.verified === true && (
            <div className="flex gap-1 pt-1">
              <button onClick={handleCopyKey} className={BTN}>Copy key hex</button>
              <button onClick={handleBookmark} className={BTN}>Bookmark offset</button>
            </div>
          )}
        </div>
      )}
    </div>
  );
}

import { useId } from "react";
import { useTranslation } from "react-i18next";
import type { KeyMaterial } from "@/api/types";

export interface EncryptedMslOptionsProps {
  /** Current key inputs (component state of the caller; never persisted). */
  keyMaterial: KeyMaterial;
  onKeyMaterialChange: (next: KeyMaterial) => void;
  /**
   * Re-run the preview with the entered key material. Omitted (batch upload,
   * no preview yet): no unlock button, a batch hint instead of the status.
   */
  onUnlock?: () => void;
  /** The last preview opened the container with the supplied key. */
  decrypted?: boolean;
  decryptOutput: boolean;
  onDecryptOutputChange: (next: boolean) => void;
  disabled?: boolean;
}

const INPUT_CLASS =
  "w-full mt-0.5 px-2 py-1 text-sm rounded border border-[var(--md-border)] bg-[var(--md-bg-secondary)]";

/**
 * Key inputs for an encrypted `.msl`: unlock the preview (so its regions can
 * be listed and filtered) and choose how the materialized copy is written —
 * re-encrypted with the same key by default, or plaintext on explicit opt-in.
 */
export function EncryptedMslOptions({
  keyMaterial,
  onKeyMaterialChange,
  onUnlock,
  decrypted = false,
  decryptOutput,
  onDecryptOutputChange,
  disabled = false,
}: EncryptedMslOptionsProps) {
  const { t } = useTranslation("import");
  const warningId = useId();
  const hasInput = Boolean(keyMaterial.passphrase || keyMaterial.key_hex?.trim());
  const set = (patch: Partial<KeyMaterial>) => onKeyMaterialChange({ ...keyMaterial, ...patch });

  return (
    <fieldset
      className="space-y-2 p-2 rounded border border-[var(--md-border)] text-sm"
      data-testid="encrypted-msl-options"
    >
      <legend className="font-medium px-1">{t("encrypted.legend")}</legend>
      <p className="text-xs md-text-secondary">
        {!onUnlock
          ? t("encrypted.batchHint")
          : decrypted ? t("encrypted.unlocked") : t("encrypted.locked")}
      </p>
      {/* Not a <form>: this step may sit inside a wizard form. Enter unlocks. */}
      <div
        className="space-y-2"
        onKeyDown={(e) => {
          if (e.key === "Enter" && e.target instanceof HTMLInputElement) {
            e.preventDefault();
            if (hasInput) onUnlock?.();
          }
        }}
      >
        <label className="block text-xs">
          {t("encrypted.passphrase")}
          <input
            type="password"
            autoComplete="off"
            value={keyMaterial.passphrase ?? ""}
            disabled={disabled}
            onChange={(e) => set({ passphrase: e.target.value })}
            data-testid="encrypted-passphrase"
            className={INPUT_CLASS}
          />
        </label>
        <label className="block text-xs">
          {t("encrypted.keyHex")}
          <input
            type="password"
            autoComplete="off"
            spellCheck={false}
            value={keyMaterial.key_hex ?? ""}
            disabled={disabled}
            onChange={(e) => set({ key_hex: e.target.value })}
            data-testid="encrypted-key-hex"
            className={INPUT_CLASS}
          />
        </label>
        {onUnlock && (
        <button
          type="button"
          onClick={onUnlock}
          disabled={disabled || !hasInput}
          data-testid="encrypted-unlock"
          className="text-xs px-2 py-0.5 rounded border border-[var(--md-border)] hover:bg-[var(--md-bg-hover)] disabled:opacity-50"
        >
          {t("encrypted.unlock")}
        </button>
        )}
      </div>
      <p className="text-xs md-text-secondary" data-testid="encrypted-reencrypt-note">
        {t("encrypted.reencryptNote")}
      </p>
      <label className="flex items-start gap-2 cursor-pointer">
        <input
          type="checkbox"
          checked={decryptOutput}
          disabled={disabled}
          onChange={(e) => onDecryptOutputChange(e.target.checked)}
          aria-describedby={decryptOutput ? warningId : undefined}
          data-testid="encrypted-decrypt-output"
          className="mt-0.5 accent-[var(--md-accent-red)]"
        />
        <span className="font-medium">{t("encrypted.decryptOutput")}</span>
      </label>
      {decryptOutput && (
        <p
          id={warningId}
          role="alert"
          className="text-xs"
          style={{ color: "var(--md-accent-red)" }}
          data-testid="encrypted-decrypt-warning"
        >
          {t("encrypted.decryptOutputWarning")}
        </p>
      )}
    </fieldset>
  );
}

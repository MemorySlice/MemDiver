/**
 * Oracle upload + arm workflow.
 *
 * Steps surfaced to the user, in order:
 *  1. Drop or browse for a ``.py`` file (≤1 MB).
 *  2. See the server-computed sha256 + detected Shape (1 stateless /
 *     2 stateful) and the first ~50 lines of source for a sanity check.
 *  3. Click "Arm oracle" — this POSTs the sha256 back, the server
 *     re-hashes on disk, and flips the ``armed`` flag if both match.
 *     An armed oracle is the only kind the pipeline's ``/run``
 *     endpoint will accept.
 *
 * Security posture: the server refuses uploads until an oracle directory
 * is configured, and enforces a 1 MB cap, 0o600 permissions, and pycache
 * purge. The client does nothing security-sensitive — we only show the data
 * the server returned.
 *
 * Because that directory is off by default, the dropzone alone used to be a
 * guaranteed 503: nothing in the UI said the feature was disabled, let alone
 * how to turn it on. So when the status says ``enabled: false`` the dropzone
 * is replaced by a consent panel that states plainly what is being allowed
 * (MemDiver executing Python the user supplies) and where the files land.
 * Enabling re-points the live registry server-side and answers with the fresh
 * status, so the dropzone appears without a reload.
 */

import { useEffect, useRef, useState } from "react";
import { useTranslation } from "react-i18next";

import type { OracleEntry, OracleStatus } from "@/api/oracles";
import { usePipelineStore } from "@/stores/pipeline-store";
import { useOracleStore } from "@/stores/oracle-store";

const MAX_UPLOAD_BYTES = 1_000_000;

/**
 * The variable that pins the oracle directory outside the UI's control.
 *
 * Mirrors ``ENV_VAR`` in api/routers/oracles.py. It is a machine identifier,
 * not prose, so it is interpolated into the translated sentence rather than
 * being part of it.
 */
const ORACLE_DIR_ENV_VAR = "MEMDIVER_ORACLE_DIR";

function shortSha(sha: string): string {
  return sha.length >= 12 ? sha.slice(0, 12) + "…" : sha;
}

/**
 * Shown in place of the dropzone while oracle storage is disabled.
 *
 * When the directory is pinned by the environment variable the button is
 * omitted on purpose: ``POST /api/oracles/enable`` answers 409 in that case,
 * so offering it would only ever produce a failure the user cannot act on
 * from here.
 */
function OracleConsentPanel({
  status,
}: {
  status: OracleStatus;
}) {
  const { t } = useTranslation("pipeline");
  const enable = useOracleStore((s) => s.enable);
  const [enabling, setEnabling] = useState(false);

  async function handleEnable(): Promise<void> {
    setEnabling(true);
    try {
      await enable();
    } finally {
      setEnabling(false);
    }
  }

  if (status.env_pinned) {
    return (
      <div className="md-panel p-4 space-y-2" data-testid="oracle-consent-panel">
        <div className="md-text-accent font-semibold text-xs">
          {t("oracle.upload.consentPinnedHeading")}
        </div>
        <div className="text-xs md-text-muted">
          {t("oracle.upload.consentPinnedBody", { envVar: ORACLE_DIR_ENV_VAR })}
        </div>
        <div className="text-xs md-text-muted font-mono break-all">
          {t("oracle.upload.consentPinnedPath", {
            path: status.path ?? status.default_path,
          })}
        </div>
      </div>
    );
  }

  return (
    <div className="md-panel p-4 space-y-2" data-testid="oracle-consent-panel">
      <div className="md-text-accent font-semibold text-xs">
        {t("oracle.upload.consentHeading")}
      </div>
      <div className="text-xs md-text-muted">
        {t("oracle.upload.consentBody")}
      </div>
      <div className="text-xs md-text-muted break-all">
        {t("oracle.upload.consentStorage", { path: status.default_path })}
      </div>
      <button
        type="button"
        data-testid="oracle-enable-btn"
        aria-busy={enabling}
        disabled={enabling}
        onClick={() => void handleEnable()}
        className="text-xs px-3 py-1 rounded bg-[var(--md-accent-blue)] md-text-on-accent disabled:opacity-50 hover:opacity-90"
      >
        {enabling
          ? t("oracle.upload.consentEnabling")
          : t("oracle.upload.consentEnable")}
      </button>
    </div>
  );
}

export function OracleUpload() {
  const { t } = useTranslation("pipeline");
  const uploaded = useOracleStore((s) => s.uploaded);
  const status = useOracleStore((s) => s.status);
  const selectedOracleId = useOracleStore((s) => s.selectedOracleId);
  const loading = useOracleStore((s) => s.loading);
  const error = useOracleStore((s) => s.error);
  const upload = useOracleStore((s) => s.upload);
  const arm = useOracleStore((s) => s.arm);
  const remove = useOracleStore((s) => s.remove);
  const selectOracle = useOracleStore((s) => s.selectOracle);
  const clearError = useOracleStore((s) => s.clearError);
  const refresh = useOracleStore((s) => s.refresh);
  const updateForm = usePipelineStore((s) => s.updateForm);

  // Fetch the status this component BRANCHES on, rather than relying on a
  // sibling to have done it. ``refresh`` used to be called only by
  // OracleExamplePicker, which mounts on the *Examples* tab -- but Upload is
  // the default tab, so on the path a first-time user actually walks, `status`
  // stayed null and the consent panel never rendered: they got the dropzone
  // and a 503, which is the whole defect this panel exists to prevent.
  useEffect(() => {
    if (status === null) void refresh();
  }, [status, refresh]);

  const inputRef = useRef<HTMLInputElement>(null);
  const [description, setDescription] = useState("");
  const [localError, setLocalError] = useState<string | null>(null);

  const selectedEntry = uploaded.find((o) => o.id === selectedOracleId) ?? null;

  async function handleFile(file: File): Promise<void> {
    setLocalError(null);
    clearError();
    if (file.size > MAX_UPLOAD_BYTES) {
      setLocalError(
        t("oracle.upload.sizeError", { size: file.size, cap: MAX_UPLOAD_BYTES }),
      );
      return;
    }
    const entry = await upload(file, description || undefined);
    if (entry) {
      updateForm({ oracleId: entry.id, oracleSha256: null });
    }
  }

  async function handleArm(entry: OracleEntry): Promise<void> {
    const ok = await arm(entry.id, entry.sha256);
    if (ok) {
      updateForm({ oracleId: entry.id, oracleSha256: entry.sha256 });
    }
  }

  async function handleRemove(entry: OracleEntry): Promise<void> {
    const ok = await remove(entry.id);
    if (ok && selectedOracleId === entry.id) {
      updateForm({ oracleId: null, oracleSha256: null });
    }
  }

  return (
    <div className="space-y-3">
      {/* The consent panel replaces the dropzone while oracle storage is
          off; `status === null` means the first refresh has not answered
          yet, and we keep today's optimistic dropzone for that moment
          rather than flashing a panel that may be wrong. */}
      {status !== null && !status.enabled ? (
        <OracleConsentPanel status={status} />
      ) : (
        <>
        <div
          role="button"
          tabIndex={0}
          aria-label={t("oracle.upload.dropTitle")}
          className="md-panel p-4 text-xs text-center cursor-pointer hover:bg-[var(--md-bg-hover)] transition-colors"
          onClick={() => inputRef.current?.click()}
          onKeyDown={(e) => {
            if (e.key === "Enter" || e.key === " ") {
              e.preventDefault();
              inputRef.current?.click();
            }
          }}
          onDragOver={(e) => {
            e.preventDefault();
          }}
          onDrop={(e) => {
            e.preventDefault();
            const f = e.dataTransfer.files[0];
            if (f) void handleFile(f);
          }}
        >
          <input
            ref={inputRef}
            type="file"
            accept=".py,text/x-python"
            className="hidden"
            onChange={(e) => {
              const f = e.target.files?.[0];
              if (f) void handleFile(f);
              if (inputRef.current) inputRef.current.value = "";
            }}
          />
          <div className="md-text-accent font-semibold mb-1">
            {t("oracle.upload.dropTitle")}
          </div>
          <div className="md-text-muted">
            {t("oracle.upload.dropBodyPrefix")} <code>verify</code>
            {t("oracle.upload.dropBodyMid")} <code>build_oracle</code>
            {t("oracle.upload.dropBodyTail")}
          </div>
        </div>

        <div>
          <label className="block text-xs md-text-muted mb-1">
            {t("oracle.upload.descriptionLabel")}
          </label>
          <input
            type="text"
            value={description}
            onChange={(e) => setDescription(e.target.value)}
            placeholder={t("oracle.upload.descriptionPlaceholder")}
            className="w-full px-2 py-1 text-xs bg-[var(--md-bg-primary)] border border-[var(--md-border)] rounded"
          />
        </div>
        </>
      )}

      {/*
        Prefixed, never bare. The store's ``error`` is shared by every oracle
        action, so a sentence dropped here unattributed ("oracle execution
        disabled; ...") reads as though the upload just above it failed, even
        when it came from a dry-run or the Examples tab. Saying which operation
        failed costs one clause and keeps the server's own words intact.
      */}
      {(localError || error) && (
        <div className="text-xs md-text-error">
          {t("oracle.upload.errorPrefix", { error: localError || error })}
        </div>
      )}
      {loading && (
        <div className="text-xs md-text-muted">{t("oracle.upload.processing")}</div>
      )}

      {uploaded.length > 0 && (
        <div className="space-y-2">
          <div className="text-xs md-text-muted font-semibold uppercase tracking-wide">
            {t("oracle.upload.uploadedHeading")}
          </div>
          {uploaded.map((o) => {
            const isSelected = selectedOracleId === o.id;
            return (
              <div
                key={o.id}
                role="button"
                tabIndex={0}
                aria-selected={isSelected}
                className={`md-panel p-3 space-y-2 cursor-pointer transition-colors ${
                  isSelected
                    ? "border-2 border-[var(--md-accent-blue)]"
                    : "hover:bg-[var(--md-bg-hover)]"
                }`}
                onClick={() => selectOracle(o.id)}
                onKeyDown={(e) => {
                  if (e.key === "Enter" || e.key === " ") {
                    e.preventDefault();
                    selectOracle(o.id);
                  }
                }}
              >
                <div className="flex items-center justify-between gap-2">
                  <div className="flex items-center gap-2 min-w-0">
                    <span className="md-text-accent font-mono text-xs truncate">
                      {o.filename}
                    </span>
                    <span className="inline-block text-[10px] uppercase tracking-wide md-text-on-accent rounded px-1.5 py-0.5 bg-[var(--md-accent-purple)]">
                      {t("oracle.upload.shape", { shape: o.shape })}
                    </span>
                    {o.armed ? (
                      <span
                        className="inline-block text-[10px] uppercase tracking-wide md-text-on-accent rounded px-1.5 py-0.5"
                        style={{ background: "var(--md-accent-green)" }}
                      >
                        {t("oracle.upload.armed")}
                      </span>
                    ) : (
                      <span
                        className="inline-block text-[10px] uppercase tracking-wide md-text-on-accent rounded px-1.5 py-0.5"
                        style={{ background: "var(--md-accent-orange)" }}
                      >
                        {t("oracle.upload.unarmed")}
                      </span>
                    )}
                  </div>
                  <div className="flex items-center gap-1">
                    {!o.armed && (
                      <button
                        type="button"
                        onClick={(e) => {
                          e.stopPropagation();
                          void handleArm(o);
                        }}
                        className="text-xs px-2 py-1 rounded bg-[var(--md-accent-blue)] md-text-on-accent hover:opacity-90"
                        title={t("oracle.upload.armTitle")}
                      >
                        {t("oracle.upload.arm")}
                      </button>
                    )}
                    <button
                      type="button"
                      onClick={(e) => {
                        e.stopPropagation();
                        void handleRemove(o);
                      }}
                      className="text-xs px-2 py-1 rounded bg-[var(--md-bg-hover)] md-text-secondary hover:bg-[var(--md-accent-red)] hover:text-[var(--md-bg-primary)]"
                    >
                      {t("common:delete")}
                    </button>
                  </div>
                </div>
                <div className="text-[10px] md-text-muted font-mono">
                  {t("oracle.upload.shaMeta", { sha: shortSha(o.sha256), size: o.size })}
                </div>
                {o.description && (
                  <div className="text-xs md-text-muted italic">
                    {o.description}
                  </div>
                )}
                {isSelected && selectedEntry === o && o.head_lines.length > 0 && (
                  <pre className="text-[10px] font-mono bg-[var(--md-bg-primary)] p-2 rounded border border-[var(--md-border)] overflow-x-auto max-h-40">
                    {o.head_lines.slice(0, 30).join("\n")}
                    {o.head_lines.length > 30 && "\n…"}
                  </pre>
                )}
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
}

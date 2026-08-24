/**
 * Pcap oracle upload + session picker.
 *
 * Flow surfaced to the user:
 *  1. Drop or browse for a ``.pcap``/``.pcapng`` capture of the same TLS
 *     session. The file POSTs to ``/api/pcaps/upload`` and the returned
 *     server-side path becomes ``form.pcapPath`` (the run request's oracle
 *     source when no BYO oracle is armed).
 *  2. The uploaded path is validated via ``/api/pcaps/validate``; the parsed
 *     TLS sessions are stored (``setPcapSessions``) for the picker below and
 *     for the key-log composer's client_random prefill synergy.
 *  3. Clicking a session row restricts matching to that session's
 *     client_random (``form.tlsClientRandom``); "match any session" clears it.
 *
 * The dropzone mirrors ``FileUpload``'s detached-filechooser pattern so
 * Playwright can drive it via ``page.on('filechooser')``.
 */

import { useCallback, useRef, useState } from "react";
import { useTranslation } from "react-i18next";

import { ApiError } from "@/api/client";
import { uploadPcap, validatePcap, type PcapSession } from "@/api/pipeline";
import { usePipelineStore } from "@/stores/pipeline-store";
import { pcapSessionSummary, sessionHasAppRecords } from "./pcap-session";

type UploadPhase = "idle" | "uploading" | "validating";

function isDpktMissing(message: string): boolean {
  return /dpkt/i.test(message);
}

export function PcapUpload() {
  const { t } = useTranslation("pipeline");
  const pcapPath = usePipelineStore((s) => s.form.pcapPath);
  const tlsClientRandom = usePipelineStore((s) => s.form.tlsClientRandom);
  const sessions = usePipelineStore((s) => s.pcapSessions);
  const updateForm = usePipelineStore((s) => s.updateForm);
  const setPcapSessions = usePipelineStore((s) => s.setPcapSessions);

  const [phase, setPhase] = useState<UploadPhase>("idle");
  const [error, setError] = useState<string | null>(null);

  // Concurrency guard: a second file dropped while an upload/validate is in
  // flight would interleave ``updateForm({pcapPath})`` (capture A) with
  // ``setPcapSessions`` (capture B), arming a run against the wrong capture.
  // A ref (not ``phase``) avoids a stale-closure race between rapid drops.
  const inFlightRef = useRef(false);

  const handleFile = useCallback(
    async (file: File): Promise<void> => {
      if (inFlightRef.current) return;
      inFlightRef.current = true;
      setError(null);
      setPcapSessions([]);
      // Drop any session selected from a previous capture so it cannot silently
      // restrict the new run to a client_random that isn't in this capture.
      updateForm({ tlsClientRandom: null });
      setPhase("uploading");
      try {
        const uploaded = await uploadPcap(file);
        updateForm({ pcapPath: uploaded.pcap_path });
        setPhase("validating");
        const validated = await validatePcap(uploaded.pcap_path);
        setPcapSessions(validated.sessions);
      } catch (e) {
        // Never leave a usable ``pcapPath`` behind on failure: a set-but-broken
        // path would let StageOracle unlock "Next" with no valid oracle.
        updateForm({ pcapPath: null });
        const message =
          e instanceof ApiError || e instanceof Error
            ? e.message
            : String(e);
        setError(isDpktMissing(message) ? t("stages.oracle.pcap.dpktMissing") : message);
      } finally {
        setPhase("idle");
        inFlightRef.current = false;
      }
    },
    [setPcapSessions, updateForm, t],
  );

  const openFilePicker = useCallback((): void => {
    const input = document.createElement("input");
    input.type = "file";
    input.accept = ".pcap,.pcapng,.cap";
    input.onchange = () => {
      if (input.files?.[0]) void handleFile(input.files[0]);
    };
    input.click();
  }, [handleFile]);

  const selectSession = (session: PcapSession): void => {
    updateForm({ tlsClientRandom: session.client_random });
  };

  const matchAny = (): void => {
    updateForm({ tlsClientRandom: null });
  };

  const hasClientRandom = !!tlsClientRandom && tlsClientRandom.trim().length > 0;
  const busy = phase !== "idle";

  return (
    <div className="space-y-2">
      <div
        data-testid="pcap-upload-dropzone"
        role="button"
        tabIndex={busy ? -1 : 0}
        aria-disabled={busy}
        aria-label={t("stages.oracle.pcap.uploadTitle")}
        onClick={() => {
          if (!busy) openFilePicker();
        }}
        onKeyDown={(e) => {
          if (busy) return;
          if (e.key === "Enter" || e.key === " ") {
            e.preventDefault();
            openFilePicker();
          }
        }}
        onDragOver={(e) => e.preventDefault()}
        onDrop={(e) => {
          e.preventDefault();
          if (busy) return;
          const f = e.dataTransfer.files[0];
          if (f) void handleFile(f);
        }}
        className={`border-2 border-dashed border-[var(--md-border)] rounded-lg p-4 text-center text-xs transition-colors ${
          busy
            ? "opacity-50 cursor-not-allowed"
            : "cursor-pointer hover:border-[var(--md-accent-blue)]"
        }`}
      >
        <div className="md-text-accent font-semibold mb-1">
          {t("stages.oracle.pcap.uploadTitle")}
        </div>
        <div className="md-text-muted">{t("stages.oracle.pcap.uploadHint")}</div>
      </div>

      {phase !== "idle" && (
        <div data-testid="pcap-upload-status" className="text-xs md-text-muted">
          {phase === "uploading"
            ? t("stages.oracle.pcap.uploading")
            : t("stages.oracle.pcap.validating")}
        </div>
      )}

      {error && (
        <div data-testid="pcap-upload-error" className="text-xs md-text-error">
          {t("stages.oracle.pcap.uploadError", { error })}
        </div>
      )}

      {pcapPath && (
        <div className="text-[10px] md-text-muted font-mono break-all">
          <span data-testid="pcap-uploaded-path">{pcapPath}</span>
        </div>
      )}

      {sessions.length > 0 && (
        <div data-testid="pcap-session-list" className="space-y-1">
          <div className="text-xs md-text-muted font-semibold uppercase tracking-wide">
            {t("stages.oracle.pcap.sessionsHeading")}
          </div>
          <button
            type="button"
            data-testid="pcap-session-match-any"
            aria-selected={!hasClientRandom}
            onClick={matchAny}
            className={`w-full text-left text-xs px-2 py-1.5 rounded transition-colors ${
              !hasClientRandom
                ? "border border-[var(--md-accent-blue)] md-text-accent"
                : "bg-[var(--md-bg-hover)] md-text-secondary hover:bg-[var(--md-border)]"
            }`}
          >
            {t("stages.oracle.pcap.matchAny")}
          </button>
          {sessions.map((session, index) => {
            const summary = pcapSessionSummary(session);
            const isSelected = tlsClientRandom === session.client_random;
            // The oracle can only verify a session that carries application_data
            // records; selecting a handshake-only session yields a misleading
            // "no session matched" error, so disable it outright.
            const usable = sessionHasAppRecords(session);
            return (
              <button
                key={`${session.client_random}-${index}`}
                type="button"
                data-testid="pcap-session-row"
                data-session-random={session.client_random}
                aria-selected={isSelected}
                aria-disabled={!usable}
                disabled={!usable}
                onClick={() => selectSession(session)}
                className={`w-full text-left text-xs px-2 py-1.5 rounded transition-colors ${
                  !usable
                    ? "bg-[var(--md-bg-hover)] md-text-muted opacity-50 cursor-not-allowed"
                    : isSelected
                    ? "border border-[var(--md-accent-blue)] md-text-accent"
                    : "bg-[var(--md-bg-hover)] md-text-secondary hover:bg-[var(--md-border)]"
                }`}
              >
                <span className="font-mono text-[10px] break-all block md-text-muted">
                  {session.client_random}
                </span>
                {t("stages.oracle.pcap.sessionRow", {
                  version: summary.version,
                  cipher: summary.cipher,
                  clientRecords: summary.clientRecords,
                  serverRecords: summary.serverRecords,
                })}
                {!usable && (
                  <span className="block md-text-warning mt-0.5">
                    {t("stages.oracle.pcap.noAppRecords")}
                  </span>
                )}
              </button>
            );
          })}
        </div>
      )}

      {pcapPath && sessions.length === 0 && phase === "idle" && !error && (
        <div className="text-xs md-text-muted">
          {t("stages.oracle.pcap.noSessions")}
        </div>
      )}
    </div>
  );
}

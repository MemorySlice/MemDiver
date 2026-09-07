/**
 * Protocol field browser — the byte-addressed view of an armed capture.
 *
 * The session picker above this answers "which handshake is this?". This
 * answers the next question: **"which bytes of that handshake could I go
 * looking for in a memory dump, and what is each one called?"** The names are
 * the point. A ``field_id`` such as ``client_random`` or ``sni`` is what
 * ``locate-key --pcap-field`` (and the MCP ``locate_key`` tool's ``pcap_field``
 * form) takes instead of 64 pasted hex characters, so this panel is where an
 * operator discovers the id rather than transcribing the value — the single
 * most common way a hunt ends in a confident census of the wrong bytes.
 *
 * Three deliberate choices:
 *
 *  - **Lazy.** Nothing is fetched until the panel is opened. ``include_fields``
 *    costs a second server-side read of the capture, and the arm request that
 *    populated the picker above does not ask for it, so an operator who only
 *    wants to pick a session pays nothing.
 *  - **``searchable`` is rendered as a permission, not decoration.** The flag is
 *    derived on the backend (a byte/string run of at least 8 bytes); a field
 *    without it matches everywhere in any real multi-megabyte dump, so
 *    ``locate_key`` refuses it. Showing which fields are usable here is what
 *    stops the refusal being a surprise.
 *  - **It refuses to guess a session**, exactly as the backend does: with
 *    several sessions parsed and none picked above, it asks rather than showing
 *    the first one's fields, because the wrong session's ``client_random`` is a
 *    perfectly valid-looking needle from another handshake.
 */

import { useCallback, useEffect, useState } from "react";
import { useTranslation } from "react-i18next";

import { validatePcap, type PcapSession } from "@/api/pipeline";
// The two pure helpers live beside the other pcap display helpers, not here:
// this file exports a component, and react-refresh needs a component module to
// export nothing else.
import { pcapFieldPreview, selectFieldSession } from "./pcap-session";
import { pcapErrorMessage } from "./use-pcap-arm";

export interface PcapFieldBrowserProps {
  /** Server-side path of the armed capture. */
  pcapPath: string;
  /** ``form.tlsClientRandom`` — the session picked above, or null for "any". */
  clientRandom: string | null;
}

export function PcapFieldBrowser({ pcapPath, clientRandom }: PcapFieldBrowserProps) {
  const { t } = useTranslation("pipeline");

  const [isOpen, setIsOpen] = useState(false);
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [sessions, setSessions] = useState<PcapSession[] | null>(null);

  // A new capture invalidates everything: fields already fetched belong to the
  // previous file, and leaving them on screen under a new path would offer
  // field ids that capture does not have.
  useEffect(() => {
    setIsOpen(false);
    setSessions(null);
    setError(null);
  }, [pcapPath]);

  const load = useCallback(async (): Promise<void> => {
    setIsLoading(true);
    setError(null);
    try {
      const validated = await validatePcap(pcapPath, { includeFields: true });
      setSessions(validated.sessions);
    } catch (e) {
      setError(pcapErrorMessage(e, t("stages.oracle.pcap.dpktMissing")));
    } finally {
      setIsLoading(false);
    }
  }, [pcapPath, t]);

  const toggle = useCallback((): void => {
    const opening = !isOpen;
    setIsOpen(opening);
    // Fetch once, on the first open. A later re-open reuses what is already
    // held, so browsing is not a request per click.
    if (opening && sessions === null && !isLoading) void load();
  }, [isLoading, isOpen, load, sessions]);

  const session = sessions ? selectFieldSession(sessions, clientRandom) : undefined;
  const fields = session?.fields ?? [];
  const notes = session?.field_notes ?? [];

  return (
    <div className="space-y-1" data-testid="pcap-field-browser">
      <button
        type="button"
        data-testid="pcap-field-browser-toggle"
        aria-expanded={isOpen}
        onClick={toggle}
        className="text-xs md-text-accent hover:underline"
      >
        {isOpen
          ? t("stages.oracle.pcap.fieldsHide")
          : t("stages.oracle.pcap.fieldsShow")}
      </button>

      {isOpen && (
        <div className="space-y-1">
          <div className="text-[10px] md-text-muted">
            {t("stages.oracle.pcap.fieldsHint")}
          </div>

          {isLoading && (
            <div data-testid="pcap-field-browser-status" className="text-xs md-text-muted">
              {t("stages.oracle.pcap.fieldsLoading")}
            </div>
          )}

          {error && (
            <div data-testid="pcap-field-browser-error" className="text-xs md-text-error">
              {t("stages.oracle.pcap.fieldsError", { error })}
            </div>
          )}

          {/* Several sessions and none picked: ask, never show the first one's
              fields -- the same refusal the backend makes, for the same reason. */}
          {sessions !== null && !isLoading && !error && !session && (
            <div data-testid="pcap-field-browser-pick-session" className="text-xs md-text-warning">
              {t("stages.oracle.pcap.fieldsPickSession")}
            </div>
          )}

          {session && fields.length === 0 && (
            <div data-testid="pcap-field-browser-empty" className="text-xs md-text-muted">
              {t("stages.oracle.pcap.fieldsNone")}
            </div>
          )}

          {fields.map((field) => (
            <div
              key={field.field_id}
              data-testid="pcap-field-row"
              data-field-id={field.field_id}
              data-searchable={field.searchable}
              title={field.value_hex || undefined}
              className={`text-xs px-2 py-1 rounded bg-[var(--md-bg-hover)] ${
                field.searchable ? "" : "opacity-60"
              }`}
            >
              <div className="flex items-baseline justify-between gap-2">
                <span className="font-mono md-text-accent break-all">
                  {field.field_id}
                </span>
                <span
                  data-testid="pcap-field-searchable"
                  className={`text-[10px] shrink-0 ${
                    field.searchable ? "md-text-secondary" : "md-text-muted"
                  }`}
                >
                  {field.searchable
                    ? t("stages.oracle.pcap.fieldSearchable")
                    : t("stages.oracle.pcap.fieldNotSearchable")}
                </span>
              </div>
              <div className="md-text-muted text-[10px]">
                {t("stages.oracle.pcap.fieldMeta", {
                  label: field.label,
                  type: field.type,
                  length: field.length,
                })}
              </div>
              <div className="font-mono text-[10px] md-text-secondary break-all">
                {pcapFieldPreview(field)}
              </div>
              {field.provenance && (
                <div className="md-text-muted text-[10px]">
                  {t("stages.oracle.pcap.fieldProvenance", {
                    direction: field.provenance.direction,
                    recordIndex: field.provenance.record_index,
                    streamOffset: field.provenance.stream_offset,
                  })}
                </div>
              )}
            </div>
          ))}

          {notes.length > 0 && (
            <div data-testid="pcap-field-notes" className="space-y-0.5">
              <div className="text-[10px] md-text-muted font-semibold uppercase tracking-wide">
                {t("stages.oracle.pcap.fieldNotesHeading")}
              </div>
              {notes.map((note) => (
                <div key={note.code} className="text-[10px] md-text-muted">
                  {note.detail}
                </div>
              ))}
            </div>
          )}
        </div>
      )}
    </div>
  );
}

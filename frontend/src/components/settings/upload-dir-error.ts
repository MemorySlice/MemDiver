/**
 * Classifier for the "no upload directory configured" rejection.
 *
 * ``POST /api/pcaps/upload`` answers 409 with a token-prefixed plain-string
 * detail when the upload directory has not been chosen yet:
 *
 *     upload_dir_unconfigured: no upload directory configured; choose one in
 *     Settings -> Storage
 *
 * The token exists so the frontend can tell *this* 409 apart from any other
 * conflict and answer it with the configure-on-first-use prompt instead of a
 * dead-end error message.
 *
 * Modelled on ``isDpktMissing`` in ``pipeline/oracle/use-pcap-arm.ts``: a pure
 * message-only predicate, so both the component and its test can share exactly
 * the classification the product ships.
 */

/** The machine token the backend prefixes onto the 409 detail. */
export const UPLOAD_DIR_UNCONFIGURED = "upload_dir_unconfigured";

/**
 * True when ``message`` carries the upload-dir-unconfigured token.
 *
 * Deliberately message-only: the HTTP status check stays at the call site
 * (``e.status === 409 && isUploadDirUnconfigured(e.message)``) so that a
 * different status carrying the same words can never open the prompt.
 */
export function isUploadDirUnconfigured(message: string): boolean {
  return new RegExp(`\\b${UPLOAD_DIR_UNCONFIGURED}\\b`).test(message);
}

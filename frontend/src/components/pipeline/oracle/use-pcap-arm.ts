/**
 * "Arm a pcap" — the validate half of the oracle pcap flow, shared by every
 * surface that can point the run at a server-side capture.
 *
 * Arming means: ``POST /api/pcaps/validate`` on a server-side path, then
 * publish the parsed TLS sessions into the pipeline store
 * (``setPcapSessions``). Those sessions feed two consumers — the session
 * picker in ``PcapUpload`` and the key-log composer's ``client_random``
 * prefill dropdown — so *nothing* downstream works until a path has been
 * armed.
 *
 * Two callers need exactly this, which is why it lives in a hook rather than
 * inside ``PcapUpload``:
 *  - ``PcapUpload`` after it has POSTed a file to ``/api/pcaps/upload``;
 *  - ``StageOracle``'s manual-path "Arm / re-validate" button, which is also
 *    the only way to re-populate the sessions after a page reload —
 *    ``pcapSessions`` is deliberately not persisted while ``form.pcapPath``
 *    is (see the ``partialize`` note in ``pipeline-store``).
 */

import { useCallback, useRef, useState } from "react";
import { useTranslation } from "react-i18next";

import { ApiError } from "@/api/client";
import { validatePcap } from "@/api/pipeline";
import { usePipelineStore } from "@/stores/pipeline-store";

/**
 * ``dpkt`` is an optional backend dependency. Its absence surfaces as a plain
 * capability-error string, which reads like a stack-trace fragment to a user
 * who only dropped a capture, so it gets a friendlier translation.
 */
export function isDpktMissing(message: string): boolean {
  return /dpkt/i.test(message);
}

/**
 * Render one thrown value as the message to show the user, substituting the
 * friendly text for the dpkt-missing case. Pure, and exported so the upload
 * half in ``PcapUpload`` classifies its own failures identically.
 */
export function pcapErrorMessage(error: unknown, dpktMissingMessage: string): string {
  const message =
    error instanceof ApiError || error instanceof Error ? error.message : String(error);
  return isDpktMissing(message) ? dpktMissingMessage : message;
}

export interface ArmOptions {
  /**
   * Whether a failed arm should also clear ``form.pcapPath``. Defaults to
   * ``true`` (the uploaded-capture case). Pass ``false`` when the path was
   * typed by hand so a typo stays on screen to be corrected.
   */
  clearPathOnFailure?: boolean;
}

export interface PcapArm {
  /** Validate ``path`` server-side and publish its sessions to the store. */
  arm: (path: string, options?: ArmOptions) => Promise<void>;
  /** True while a validate request is in flight. */
  isArming: boolean;
  /** Translated failure message from the last ``arm``, or null. */
  error: string | null;
  /** Clear ``error`` without touching the store. */
  reset: () => void;
}

export function usePcapArm(): PcapArm {
  const { t } = useTranslation("pipeline");
  const setPcapSessions = usePipelineStore((s) => s.setPcapSessions);
  const updateForm = usePipelineStore((s) => s.updateForm);

  const [isArming, setIsArming] = useState(false);
  const [error, setError] = useState<string | null>(null);

  // Concurrency guard: two overlapping arms would interleave their
  // ``setPcapSessions`` calls, so the picker could end up showing capture A's
  // sessions for capture B's path. A ref (not ``isArming``) avoids a
  // stale-closure race between two calls made in the same tick.
  const inFlightRef = useRef(false);

  const arm = useCallback(
    async (path: string, options?: ArmOptions): Promise<void> => {
      if (inFlightRef.current) return;
      inFlightRef.current = true;
      setError(null);
      setPcapSessions([]);
      setIsArming(true);
      try {
        const validated = await validatePcap(path);
        setPcapSessions(validated.sessions);
        // A client_random picked from a *previous* capture would silently
        // restrict the run to a session this capture does not contain. Keep
        // the selection only while the freshly parsed sessions still offer it.
        const selected = usePipelineStore.getState().form.tlsClientRandom;
        if (
          selected &&
          !validated.sessions.some((session) => session.client_random === selected)
        ) {
          updateForm({ tlsClientRandom: null });
        }
      } catch (e) {
        // An *uploaded* capture that fails to parse leaves nothing worth
        // keeping, and a set-but-broken ``pcapPath`` would let StageOracle
        // unlock "Next" with no valid oracle -- so the upload path clears it.
        // A *typed* path is different: clearing it would delete the text the
        // user is trying to correct, so StageOracle keeps it editable and the
        // error banner carries the failure instead.
        if (options?.clearPathOnFailure ?? true) {
          updateForm({ pcapPath: null });
        }
        setError(pcapErrorMessage(e, t("stages.oracle.pcap.dpktMissing")));
      } finally {
        setIsArming(false);
        inFlightRef.current = false;
      }
    },
    [setPcapSessions, updateForm, t],
  );

  const reset = useCallback((): void => {
    setError(null);
  }, []);

  return { arm, isArming, error, reset };
}

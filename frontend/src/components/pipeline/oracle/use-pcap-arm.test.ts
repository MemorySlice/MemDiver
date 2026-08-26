import { describe, it, expect, vi, beforeEach } from "vitest";
import { act, renderHook, waitFor } from "@testing-library/react";
// Real strings, so the dpkt-missing assertion checks the message the user
// actually sees rather than a key name.
import "@/i18n";

import { ApiError } from "@/api/client";
import type { PcapSession, PcapValidateResult } from "@/api/pipeline";

// The hook's only network call. Mocked so every arm outcome is scriptable.
const validatePcap = vi.fn();
vi.mock("@/api/pipeline", () => ({
  validatePcap: (...a: unknown[]) => validatePcap(...a),
}));

import { usePipelineStore } from "@/stores/pipeline-store";
import { isDpktMissing, pcapErrorMessage, usePcapArm } from "./use-pcap-arm";

function makeSession(overrides: Partial<PcapSession> = {}): PcapSession {
  return {
    client_random: "a".repeat(64),
    server_random: "b".repeat(64),
    version: "13",
    cipher_suite: 0x1301,
    cipher_name: "TLS_AES_128_GCM_SHA256",
    client_app_records: 3,
    server_app_records: 5,
    has_app_records: true,
    ...overrides,
  };
}

function makeResult(sessions: PcapSession[]): PcapValidateResult {
  return {
    pcap_path: "/srv/capture.pcap",
    session_count: sessions.length,
    sessions,
  };
}

/** Fresh store slice per test so one arm cannot leak into the next. */
function resetStore(): void {
  usePipelineStore.setState((s) => ({
    pcapSessions: [],
    form: { ...s.form, pcapPath: "/srv/capture.pcap", tlsClientRandom: null },
  }));
}

describe("isDpktMissing", () => {
  it("matches the optional-dependency message case-insensitively", () => {
    expect(isDpktMissing("module 'dpkt' is not installed")).toBe(true);
    expect(isDpktMissing("DPKT missing")).toBe(true);
    expect(isDpktMissing("truncated capture file")).toBe(false);
  });
});

describe("pcapErrorMessage", () => {
  it("substitutes the friendly text only for the dpkt case", () => {
    expect(pcapErrorMessage(new Error("no dpkt here"), "friendly")).toBe("friendly");
    expect(pcapErrorMessage(new ApiError(400, "bad magic"), "friendly")).toBe("bad magic");
  });

  it("stringifies a non-Error throw", () => {
    expect(pcapErrorMessage("plain string", "friendly")).toBe("plain string");
  });
});

describe("usePcapArm", () => {
  beforeEach(() => {
    validatePcap.mockReset();
    resetStore();
  });

  it("publishes the parsed sessions to the store on success", async () => {
    const sessions = [makeSession(), makeSession({ client_random: "c".repeat(64) })];
    validatePcap.mockResolvedValue(makeResult(sessions));

    const { result } = renderHook(() => usePcapArm());
    await act(async () => {
      await result.current.arm("/srv/capture.pcap");
    });

    expect(validatePcap).toHaveBeenCalledWith("/srv/capture.pcap");
    expect(usePipelineStore.getState().pcapSessions).toEqual(sessions);
    expect(result.current.error).toBeNull();
    expect(result.current.isArming).toBe(false);
    // A successful arm must leave the path usable.
    expect(usePipelineStore.getState().form.pcapPath).toBe("/srv/capture.pcap");
  });

  it("keeps a selected client_random the new capture still contains", async () => {
    const keep = makeSession();
    usePipelineStore.setState((s) => ({
      form: { ...s.form, tlsClientRandom: keep.client_random },
    }));
    validatePcap.mockResolvedValue(makeResult([keep]));

    const { result } = renderHook(() => usePcapArm());
    await act(async () => {
      await result.current.arm("/srv/capture.pcap");
    });

    expect(usePipelineStore.getState().form.tlsClientRandom).toBe(keep.client_random);
  });

  it("drops a selected client_random the new capture does not contain", async () => {
    usePipelineStore.setState((s) => ({
      form: { ...s.form, tlsClientRandom: "d".repeat(64) },
    }));
    validatePcap.mockResolvedValue(makeResult([makeSession()]));

    const { result } = renderHook(() => usePcapArm());
    await act(async () => {
      await result.current.arm("/srv/capture.pcap");
    });

    expect(usePipelineStore.getState().form.tlsClientRandom).toBeNull();
  });

  it("surfaces the friendly message when the backend lacks dpkt", async () => {
    validatePcap.mockRejectedValue(
      new ApiError(400, "pcap parsing requires the optional 'dpkt' dependency"),
    );

    const { result } = renderHook(() => usePcapArm());
    await act(async () => {
      await result.current.arm("/srv/capture.pcap");
    });

    expect(result.current.error).toBe(
      "The server cannot parse pcaps because the optional 'dpkt' dependency is not installed.",
    );
    // Never leave a usable path behind: an un-armed path would still unlock
    // the wizard's "Next" with no valid oracle.
    expect(usePipelineStore.getState().form.pcapPath).toBeNull();
  });

  it("surfaces the API message verbatim for a generic parse failure", async () => {
    validatePcap.mockRejectedValue(new ApiError(400, "not a pcap: bad magic 0xdeadbeef"));

    const { result } = renderHook(() => usePcapArm());
    await act(async () => {
      await result.current.arm("/srv/nope.bin");
    });

    expect(result.current.error).toBe("not a pcap: bad magic 0xdeadbeef");
    expect(usePipelineStore.getState().pcapSessions).toEqual([]);
    expect(usePipelineStore.getState().form.pcapPath).toBeNull();
  });

  it("keeps a hand-typed path on screen when clearPathOnFailure is false", async () => {
    // The manual-path "Arm / re-validate" control passes this so a typo stays
    // editable; the uploaded-capture path keeps the clearing default.
    validatePcap.mockRejectedValue(new ApiError(400, "capture not found"));
    usePipelineStore.getState().updateForm({ pcapPath: "/srv/typo.pcap" });

    const { result } = renderHook(() => usePcapArm());
    await act(async () => {
      await result.current.arm("/srv/typo.pcap", { clearPathOnFailure: false });
    });

    expect(result.current.error).toBe("capture not found");
    expect(usePipelineStore.getState().pcapSessions).toEqual([]);
    expect(usePipelineStore.getState().form.pcapPath).toBe("/srv/typo.pcap");
  });

  it("clears a previous error via reset()", async () => {
    validatePcap.mockRejectedValue(new ApiError(400, "boom"));

    const { result } = renderHook(() => usePcapArm());
    await act(async () => {
      await result.current.arm("/srv/capture.pcap");
    });
    expect(result.current.error).toBe("boom");

    act(() => {
      result.current.reset();
    });
    expect(result.current.error).toBeNull();
  });

  it("guards concurrent arm() calls so two captures cannot interleave", async () => {
    let release: (value: PcapValidateResult) => void = () => {};
    validatePcap.mockReturnValueOnce(
      new Promise<PcapValidateResult>((resolve) => {
        release = resolve;
      }),
    );

    const { result } = renderHook(() => usePcapArm());

    let first: Promise<void> = Promise.resolve();
    let second: Promise<void> = Promise.resolve();
    act(() => {
      first = result.current.arm("/srv/first.pcap");
      // Fired while the first is still in flight: must be dropped, not queued.
      second = result.current.arm("/srv/second.pcap");
    });

    await waitFor(() => expect(result.current.isArming).toBe(true));
    // The second call resolves immediately without touching the network.
    await act(async () => {
      await second;
    });
    expect(validatePcap).toHaveBeenCalledTimes(1);
    expect(validatePcap).toHaveBeenCalledWith("/srv/first.pcap");

    await act(async () => {
      release(makeResult([makeSession()]));
      await first;
    });

    expect(result.current.isArming).toBe(false);
    expect(usePipelineStore.getState().pcapSessions).toHaveLength(1);
  });
});

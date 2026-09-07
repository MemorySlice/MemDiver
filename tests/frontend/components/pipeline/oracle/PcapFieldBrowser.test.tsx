/**
 * The protocol field browser — C2's discovery surface.
 *
 * What is worth pinning here is not the markup but the three judgements the
 * component makes:
 *
 *  - it is **lazy**: ``include_fields`` costs a second server-side read of the
 *    capture, so nothing is requested until the panel is opened, and re-opening
 *    reuses what was fetched;
 *  - it renders ``searchable`` as a **permission**, because a field without it
 *    matches everywhere in a real dump and ``locate_key`` refuses it — showing
 *    which ids are usable is what stops that refusal being a surprise;
 *  - with several sessions parsed and none picked, it **asks instead of
 *    guessing**, mirroring the backend refusal for the same reason: another
 *    session's ``client_random`` is a perfectly valid-looking needle from the
 *    wrong handshake.
 */

import { describe, it, expect, beforeEach, vi } from "vitest";
import { render, screen, waitFor } from "@testing-library/react";
import { act } from "react";
import "@testing-library/jest-dom/vitest";
// Real strings: the assertions below check the English a user actually sees.
import "@/i18n";

import type { PcapField, PcapSession } from "@/api/pipeline";

const validatePcap = vi.fn();
vi.mock("@/api/pipeline", () => ({
  validatePcap: (...a: unknown[]) => validatePcap(...a),
}));

import { PcapFieldBrowser } from "@/components/pipeline/oracle/PcapFieldBrowser";
import { selectFieldSession } from "@/components/pipeline/oracle/pcap-session";

const CLIENT_RANDOM = "a".repeat(64);
const OTHER_RANDOM = "b".repeat(64);

function makeField(overrides: Partial<PcapField> = {}): PcapField {
  return {
    field_id: "client_random",
    label: "ClientHello.random",
    type: "bytes",
    value_hex: "aa".repeat(32),
    value: null,
    length: 32,
    source: "client_hello",
    provenance: {
      direction: "client",
      record_index: 0,
      stream_offset: 16,
      record_offset: 11,
    },
    searchable: true,
    ...overrides,
  };
}

function makeSession(overrides: Partial<PcapSession> = {}): PcapSession {
  return {
    client_random: CLIENT_RANDOM,
    server_random: "c".repeat(64),
    version: "13",
    cipher_suite: 0x1301,
    cipher_name: "TLS_AES_128_GCM_SHA256",
    client_app_records: 2,
    server_app_records: 3,
    has_app_records: true,
    ...overrides,
  };
}

async function openBrowser(): Promise<void> {
  await act(async () => {
    screen.getByTestId("pcap-field-browser-toggle").click();
  });
}

beforeEach(() => {
  validatePcap.mockReset();
});

describe("PcapFieldBrowser", () => {
  it("requests nothing until it is opened", () => {
    render(<PcapFieldBrowser pcapPath="/tmp/a.pcap" clientRandom={null} />);

    expect(validatePcap).not.toHaveBeenCalled();
    expect(screen.getByTestId("pcap-field-browser-toggle")).toHaveAttribute(
      "aria-expanded",
      "false",
    );
  });

  it("asks for the fields explicitly on the first open", async () => {
    validatePcap.mockResolvedValue({
      pcap_path: "/tmp/a.pcap",
      session_count: 1,
      sessions: [makeSession({ fields: [makeField()] })],
    });
    render(<PcapFieldBrowser pcapPath="/tmp/a.pcap" clientRandom={null} />);

    await openBrowser();

    // The opt-in is what makes the arm request byte-identical to before C2.
    expect(validatePcap).toHaveBeenCalledWith("/tmp/a.pcap", {
      includeFields: true,
    });
    await waitFor(() =>
      expect(screen.getByTestId("pcap-field-row")).toBeInTheDocument(),
    );
  });

  it("renders the field id, its metadata and its wire provenance", async () => {
    validatePcap.mockResolvedValue({
      pcap_path: "/tmp/a.pcap",
      session_count: 1,
      sessions: [makeSession({ fields: [makeField()] })],
    });
    render(<PcapFieldBrowser pcapPath="/tmp/a.pcap" clientRandom={null} />);
    await openBrowser();

    const row = await waitFor(() => screen.getByTestId("pcap-field-row"));
    // The id is the payload of this panel: it is what a caller names on
    // ``locate-key --pcap-field`` instead of pasting 64 hex characters.
    expect(row).toHaveAttribute("data-field-id", "client_random");
    expect(row).toHaveTextContent("client_random");
    expect(row).toHaveTextContent("ClientHello.random");
    // The record a dump hit can be cross-checked against.
    expect(row).toHaveTextContent("client record 0");
    expect(row).toHaveTextContent("+16");
  });

  it("labels a non-searchable field as unusable rather than hiding it", async () => {
    // Hidden would be worse than labelled: the field IS in the handshake, and
    // an operator who cannot see it cannot learn why it is not offered.
    validatePcap.mockResolvedValue({
      pcap_path: "/tmp/a.pcap",
      session_count: 1,
      sessions: [
        makeSession({
          fields: [
            makeField(),
            makeField({
              field_id: "client_ext.0x000b",
              type: "bytes",
              length: 2,
              value_hex: "0100",
              searchable: false,
            }),
          ],
        }),
      ],
    });
    render(<PcapFieldBrowser pcapPath="/tmp/a.pcap" clientRandom={null} />);
    await openBrowser();

    const rows = await waitFor(() => screen.getAllByTestId("pcap-field-row"));
    expect(rows).toHaveLength(2);
    expect(rows[0]).toHaveAttribute("data-searchable", "true");
    expect(rows[0]).toHaveTextContent("searchable");
    expect(rows[1]).toHaveAttribute("data-searchable", "false");
    expect(rows[1]).toHaveTextContent("not a needle");
  });

  it("shows the session's field notes, so an absence is explained", async () => {
    validatePcap.mockResolvedValue({
      pcap_path: "/tmp/a.pcap",
      session_count: 1,
      sessions: [
        makeSession({
          fields: [makeField()],
          field_notes: [
            {
              code: "tls13_certificates_encrypted",
              detail: "TLS 1.3 encrypts the Certificate handshake message.",
            },
          ],
        }),
      ],
    });
    render(<PcapFieldBrowser pcapPath="/tmp/a.pcap" clientRandom={null} />);
    await openBrowser();

    await waitFor(() =>
      expect(screen.getByTestId("pcap-field-notes")).toHaveTextContent(
        "TLS 1.3 encrypts the Certificate handshake message.",
      ),
    );
  });

  it("asks which session rather than showing the wrong one's fields", async () => {
    validatePcap.mockResolvedValue({
      pcap_path: "/tmp/a.pcap",
      session_count: 2,
      sessions: [
        makeSession({ fields: [makeField()] }),
        makeSession({
          client_random: OTHER_RANDOM,
          fields: [makeField({ value_hex: "bb".repeat(32) })],
        }),
      ],
    });
    render(<PcapFieldBrowser pcapPath="/tmp/a.pcap" clientRandom={null} />);
    await openBrowser();

    await waitFor(() =>
      expect(screen.getByTestId("pcap-field-browser-pick-session")).toBeInTheDocument(),
    );
    expect(screen.queryByTestId("pcap-field-row")).not.toBeInTheDocument();
  });

  it("shows the picked session's fields when one is selected", async () => {
    validatePcap.mockResolvedValue({
      pcap_path: "/tmp/a.pcap",
      session_count: 2,
      sessions: [
        makeSession({ fields: [makeField({ field_id: "first_only" })] }),
        makeSession({
          client_random: OTHER_RANDOM,
          fields: [makeField({ field_id: "second_only" })],
        }),
      ],
    });
    render(
      <PcapFieldBrowser pcapPath="/tmp/a.pcap" clientRandom={OTHER_RANDOM} />,
    );
    await openBrowser();

    const row = await waitFor(() => screen.getByTestId("pcap-field-row"));
    expect(row).toHaveAttribute("data-field-id", "second_only");
  });

  it("says so when a session yields no fields at all", async () => {
    validatePcap.mockResolvedValue({
      pcap_path: "/tmp/a.pcap",
      session_count: 1,
      sessions: [makeSession({ fields: [] })],
    });
    render(<PcapFieldBrowser pcapPath="/tmp/a.pcap" clientRandom={null} />);
    await openBrowser();

    await waitFor(() =>
      expect(screen.getByTestId("pcap-field-browser-empty")).toBeInTheDocument(),
    );
  });

  it("surfaces a failed read, with the friendly dpkt wording", async () => {
    validatePcap.mockRejectedValue(new Error("pcap parsing needs dpkt."));
    render(<PcapFieldBrowser pcapPath="/tmp/a.pcap" clientRandom={null} />);
    await openBrowser();

    const error = await waitFor(() =>
      screen.getByTestId("pcap-field-browser-error"),
    );
    expect(error).toHaveTextContent("dpkt");
    expect(screen.queryByTestId("pcap-field-row")).not.toBeInTheDocument();
  });

  it("fetches once, not once per click", async () => {
    validatePcap.mockResolvedValue({
      pcap_path: "/tmp/a.pcap",
      session_count: 1,
      sessions: [makeSession({ fields: [makeField()] })],
    });
    render(<PcapFieldBrowser pcapPath="/tmp/a.pcap" clientRandom={null} />);

    await openBrowser(); // open + fetch
    await waitFor(() => expect(validatePcap).toHaveBeenCalledTimes(1));
    await openBrowser(); // collapse
    await openBrowser(); // re-open, reusing what is held
    expect(validatePcap).toHaveBeenCalledTimes(1);
  });

  it("drops fields belonging to a previous capture", async () => {
    validatePcap.mockResolvedValue({
      pcap_path: "/tmp/a.pcap",
      session_count: 1,
      sessions: [makeSession({ fields: [makeField()] })],
    });
    const { rerender } = render(
      <PcapFieldBrowser pcapPath="/tmp/a.pcap" clientRandom={null} />,
    );
    await openBrowser();
    await waitFor(() =>
      expect(screen.getByTestId("pcap-field-row")).toBeInTheDocument(),
    );

    // A new capture must not leave the old capture's ids on screen: they would
    // be field names the new file does not have.
    rerender(<PcapFieldBrowser pcapPath="/tmp/b.pcap" clientRandom={null} />);
    await waitFor(() =>
      expect(screen.queryByTestId("pcap-field-row")).not.toBeInTheDocument(),
    );
    expect(screen.getByTestId("pcap-field-browser-toggle")).toHaveAttribute(
      "aria-expanded",
      "false",
    );
  });
});

describe("selectFieldSession", () => {
  it("selects a single-session capture by itself", () => {
    const only = makeSession();
    expect(selectFieldSession([only], null)).toBe(only);
  });

  it("refuses to pick between several sessions", () => {
    const sessions = [makeSession(), makeSession({ client_random: OTHER_RANDOM })];
    expect(selectFieldSession(sessions, null)).toBeUndefined();
  });

  it("honours an explicit selection", () => {
    const first = makeSession();
    const second = makeSession({ client_random: OTHER_RANDOM });
    expect(selectFieldSession([first, second], OTHER_RANDOM)).toBe(second);
  });

  it("returns undefined for a selection the capture does not hold", () => {
    // A client_random left over from a previous capture: better to ask again
    // than to fall back to a session the user did not choose.
    expect(selectFieldSession([makeSession()], "f".repeat(64))).toBeUndefined();
  });
});

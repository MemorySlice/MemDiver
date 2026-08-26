import { describe, it, expect } from "vitest";
import { render, screen } from "@testing-library/react";
// See ErrorBoundary.test.tsx: needed so `tsc -b` sees jest-dom's augmentation.
import "@testing-library/jest-dom/vitest";
// Real i18n (no mock) so the assertions below prove the English strings exist.
import "@/i18n";

import { toProvenanceKey } from "@/components/results/provenance";
import { VerificationBadge } from "@/components/results/VerificationBadge";

describe("VerificationBadge provenance", () => {
  it("labels a pcap-confirmed key with its capture provenance", () => {
    render(<VerificationBadge verified confirmedBy="pcap" />);
    const badge = screen.getByTestId("verification-badge");
    expect(badge).toHaveTextContent("Verified via pcap capture");
    expect(badge).toHaveAttribute("data-confirmed-by", "pcap");
    expect(badge).toHaveAttribute(
      "title",
      "This key decrypted real records from the captured TLS session",
    );
  });

  it("labels an oracle-confirmed key with its script provenance", () => {
    render(<VerificationBadge verified confirmedBy="oracle" />);
    const badge = screen.getByTestId("verification-badge");
    expect(badge).toHaveTextContent("Verified via oracle script");
    expect(badge).toHaveAttribute("data-confirmed-by", "oracle");
    expect(badge).toHaveAttribute(
      "title",
      "Your decryption oracle script accepted this key",
    );
  });

  it("labels a verifier-confirmed key with its test-vector provenance", () => {
    render(<VerificationBadge verified confirmedBy="verifier" />);
    const badge = screen.getByTestId("verification-badge");
    expect(badge).toHaveTextContent("Verified by cipher verifier");
    expect(badge).toHaveAttribute("data-confirmed-by", "verifier");
    expect(badge).toHaveAttribute(
      "title",
      "This key decrypted MemDiver's built-in cipher test vector",
    );
  });

  // Regression guard: existing callers pass no `confirmedBy` and must keep
  // seeing exactly the pre-provenance badge.
  it("falls back to the plain verified label when no provenance is given", () => {
    render(<VerificationBadge verified />);
    const badge = screen.getByTestId("verification-badge");
    expect(badge).toHaveTextContent("Verified");
    expect(badge).not.toHaveTextContent("via");
    expect(badge).toHaveAttribute("data-confirmed-by", "");
    expect(badge).toHaveAttribute("title", "Decryption verified");
  });

  it("degrades an unknown provenance label instead of leaking an i18n key", () => {
    const { container } = render(
      <VerificationBadge verified confirmedBy="manual_review" />,
    );
    const badge = screen.getByTestId("verification-badge");
    expect(badge).toHaveTextContent("Verified");
    expect(badge).toHaveAttribute("data-confirmed-by", "");
    expect(badge).toHaveAttribute("title", "Decryption verified");
    expect(container.innerHTML).not.toContain("verification.provenance");
    expect(container.innerHTML).not.toContain("manual_review");
  });
});

describe("VerificationBadge non-verified branches", () => {
  it("renders the failed badge unchanged", () => {
    render(<VerificationBadge verified={false} />);
    const badge = screen.getByTestId("verification-badge");
    expect(badge).toHaveTextContent("Failed");
    expect(badge).toHaveAttribute("title", "Decryption failed");
    expect(badge).toHaveAttribute("data-confirmed-by", "");
  });

  it("renders the unknown badge unchanged", () => {
    render(<VerificationBadge verified={null} />);
    const badge = screen.getByTestId("verification-badge");
    expect(badge).toHaveTextContent("?");
    expect(badge).toHaveAttribute("title", "Not verified");
    expect(badge).toHaveAttribute("data-confirmed-by", "");
  });

  // A failed hit carrying a stale provenance label must stay a failure badge.
  it("keeps the failed badge even when a provenance label is present", () => {
    render(<VerificationBadge verified={false} confirmedBy="pcap" />);
    const badge = screen.getByTestId("verification-badge");
    expect(badge).toHaveTextContent("Failed");
    expect(badge).toHaveAttribute("data-confirmed-by", "pcap");
  });
});

describe("toProvenanceKey", () => {
  it("accepts the three known provenance labels", () => {
    expect(toProvenanceKey("pcap")).toBe("pcap");
    expect(toProvenanceKey("oracle")).toBe("oracle");
    expect(toProvenanceKey("verifier")).toBe("verifier");
  });

  it("rejects missing and unrecognized labels", () => {
    expect(toProvenanceKey(null)).toBeNull();
    expect(toProvenanceKey(undefined)).toBeNull();
    expect(toProvenanceKey("")).toBeNull();
    expect(toProvenanceKey("manual_review")).toBeNull();
    expect(toProvenanceKey("PCAP")).toBeNull();
  });
});

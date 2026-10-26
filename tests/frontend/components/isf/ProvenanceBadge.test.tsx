import { describe, expect, it } from "vitest";
import { render, screen } from "@testing-library/react";
import "@testing-library/jest-dom/vitest";
import "@/i18n";

import { ISF_TIERS } from "@/api/isf";
import { ProvenanceBadge, ProvenanceDetail } from "@/components/isf/ProvenanceBadge";
import { prov } from "./helpers";

describe("ProvenanceBadge", () => {
  it.each(ISF_TIERS)("labels the %s tier with a word and a distinct tier attribute", (tier) => {
    render(<ProvenanceBadge provenance={prov(tier)} />);
    const badge = screen.getByTestId("provenance-badge");
    expect(badge).toHaveAttribute("data-tier", tier);
    expect(badge.textContent).toBe(tier.replace(/_/g, " "));
  });

  it("puts source, author and evidence in the hover text", () => {
    render(<ProvenanceBadge provenance={prov("probe", { source: "kallsyms", author: "tool:pakunoda", evidence: ["probe kallsyms", "image sha256 ab"] })} />);
    const title = screen.getByTestId("provenance-badge").getAttribute("title")!;
    expect(title).toContain("Source: kallsyms");
    expect(title).toContain("Author: tool:pakunoda");
    expect(title).toContain("Evidence: image sha256 ab");
  });

  it("says when there is no provenance instead of inventing one", () => {
    render(<ProvenanceBadge provenance={null} />);
    expect(screen.getByTestId("provenance-badge")).toHaveAttribute("data-tier", "unknown");
  });

  it("expands to every evidence line", () => {
    render(<ProvenanceDetail provenance={prov("code", { evidence: ["a", "b"] })} />);
    expect(screen.getByTestId("provenance-detail")).toHaveTextContent("Evidence: a");
    expect(screen.getByTestId("provenance-detail")).toHaveTextContent("Evidence: b");
  });
});

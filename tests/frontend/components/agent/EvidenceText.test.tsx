import { describe, expect, it } from "vitest";
import { render, screen } from "@testing-library/react";
import "@/i18n";

import { EvidenceText } from "@/components/agent/EvidenceText";

describe("EvidenceText", () => {
  it("renders evidence tags as badges and keeps the surrounding text", () => {
    render(<EvidenceText text={"[seen] key at 0x10\nnext [inferred] guess [unknown]"} />);
    expect(screen.getByTestId("evidence-seen")).toHaveTextContent("seen");
    expect(screen.getByTestId("evidence-inferred")).toBeInTheDocument();
    expect(screen.getByTestId("evidence-unknown")).toBeInTheDocument();
    expect(screen.getByText(/key at 0x10/)).toBeInTheDocument();
  });

  it("never turns markup into elements", () => {
    const { container } = render(<EvidenceText text={"<img src=x onerror=alert(1)> **bold**"} />);
    expect(container.querySelector("img")).toBeNull();
    expect(container.textContent).toContain("<img");
  });
});

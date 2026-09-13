/**
 * Tests for `@/components/common/DocPanel` — the in-app documentation
 * slide-over that replaced four dead `/docs/<path>.md` links.
 *
 * `fetch` is stubbed rather than `@/api/docs`, so the real client path
 * (URL shape, JSON envelope, `ApiError` on a 404) is exercised end to end.
 */

import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import { render, screen, waitFor, fireEvent, act } from "@testing-library/react";
import "@testing-library/jest-dom/vitest";
import "@/i18n";
import { DocPanel } from "@/components/common/DocPanel";
import { EmptyState } from "@/components/common/EmptyState";

function jsonResponse(body: unknown, ok = true, status = 200): Response {
  return {
    ok,
    status,
    json: async () => body,
    text: async () => (typeof body === "string" ? body : JSON.stringify(body)),
  } as unknown as Response;
}

const CONSENSUS_MD = [
  "# Consensus view",
  "",
  ":::{admonition} Available in",
  ":class: tip",
  "**SPA** · **Marimo** sandbox",
  ":::",
  "",
  "Per-byte variance classification across N dumps.",
  "",
  "See also: [](../architecture/architect.md).",
  "",
].join("\n");

const fetchMock = vi.fn();

beforeEach(() => {
  fetchMock.mockReset();
  vi.stubGlobal("fetch", fetchMock);
});

afterEach(() => {
  vi.unstubAllGlobals();
});

describe("DocPanel", () => {
  it("opens as a labelled modal dialog and fetches the requested page", async () => {
    fetchMock.mockResolvedValueOnce(
      jsonResponse({ path: "visualizations/consensus.md", content: CONSENSUS_MD }),
    );
    render(<DocPanel doc="visualizations/consensus.md" onClose={vi.fn()} />);

    const dialog = screen.getByRole("dialog");
    expect(dialog).toHaveAttribute("aria-modal", "true");
    // aria-labelledby must point at an element that exists and has text.
    const labelId = dialog.getAttribute("aria-labelledby")!;
    expect(document.getElementById(labelId)).toHaveTextContent(/consensus\.md/);

    await waitFor(() => expect(fetchMock).toHaveBeenCalledTimes(1));
    expect(fetchMock.mock.calls[0][0]).toBe("/api/docs/visualizations/consensus.md");
  });

  it("renders the fetched markdown, degrading the MyST directive", async () => {
    fetchMock.mockResolvedValueOnce(
      jsonResponse({ path: "visualizations/consensus.md", content: CONSENSUS_MD }),
    );
    render(<DocPanel doc="visualizations/consensus.md" onClose={vi.fn()} />);

    await screen.findByText("Consensus view");
    const body = screen.getByTestId("doc-panel-content");
    expect(body.querySelector("h1")).toHaveTextContent("Consensus view");
    expect(body.querySelector("aside")).toHaveTextContent("Available in");
    expect(body.textContent).not.toContain(":::");
    expect(body.textContent).toContain("Per-byte variance classification");
  });

  it("shows a loading state before the response lands", async () => {
    let resolve!: (r: Response) => void;
    fetchMock.mockReturnValueOnce(new Promise<Response>((r) => (resolve = r)));
    render(<DocPanel doc="visualizations/consensus.md" onClose={vi.fn()} />);

    expect(screen.getByRole("status")).toHaveTextContent(/Loading documentation/i);
    await act(async () => {
      resolve(jsonResponse({ path: "visualizations/consensus.md", content: "# Hi\n" }));
    });
    await screen.findByText("Hi");
  });

  it("closes on Escape", async () => {
    fetchMock.mockResolvedValueOnce(
      jsonResponse({ path: "visualizations/consensus.md", content: "# Hi\n" }),
    );
    const onClose = vi.fn();
    render(<DocPanel doc="visualizations/consensus.md" onClose={onClose} />);
    await screen.findByText("Hi");

    fireEvent.keyDown(document, { key: "Escape" });
    expect(onClose).toHaveBeenCalledTimes(1);
  });

  it("closes on the close button and on a backdrop click", async () => {
    fetchMock.mockResolvedValue(
      jsonResponse({ path: "visualizations/consensus.md", content: "# Hi\n" }),
    );
    const onClose = vi.fn();
    const { unmount } = render(
      <DocPanel doc="visualizations/consensus.md" onClose={onClose} />,
    );
    await screen.findByText("Hi");

    fireEvent.click(screen.getByRole("button", { name: "Close" }));
    expect(onClose).toHaveBeenCalledTimes(1);
    unmount();

    onClose.mockClear();
    render(<DocPanel doc="visualizations/consensus.md" onClose={onClose} />);
    await screen.findByText("Hi");
    fireEvent.click(screen.getByTestId("doc-panel-overlay"));
    expect(onClose).toHaveBeenCalledTimes(1);
  });

  it("focuses the close button on open and restores focus on close", async () => {
    fetchMock.mockResolvedValueOnce(
      jsonResponse({ path: "visualizations/consensus.md", content: "# Hi\n" }),
    );
    const trigger = document.createElement("button");
    document.body.appendChild(trigger);
    trigger.focus();
    expect(document.activeElement).toBe(trigger);

    const { unmount } = render(
      <DocPanel doc="visualizations/consensus.md" onClose={vi.fn()} />,
    );
    await screen.findByText("Hi");
    expect(document.activeElement).toBe(screen.getByRole("button", { name: "Close" }));

    unmount();
    expect(document.activeElement).toBe(trigger);
    trigger.remove();
  });

  it("navigates to a relative .md link WITHIN the panel", async () => {
    fetchMock
      .mockResolvedValueOnce(
        jsonResponse({ path: "visualizations/consensus.md", content: CONSENSUS_MD }),
      )
      .mockResolvedValueOnce(
        jsonResponse({ path: "architecture/architect.md", content: "# Architect internals\n" }),
      );
    render(<DocPanel doc="visualizations/consensus.md" onClose={vi.fn()} />);
    await screen.findByText("Consensus view");

    fireEvent.click(screen.getByRole("button", { name: "architect" }));

    await screen.findByText("Architect internals");
    expect(fetchMock.mock.calls[1][0]).toBe("/api/docs/architecture/architect.md");
    // Still in the panel -- no browser navigation, no unmount.
    expect(screen.getByRole("dialog")).toBeInTheDocument();
  });

  it("surfaces the backend's published-docs fallback as a real link on a 404", async () => {
    fetchMock.mockResolvedValueOnce(
      jsonResponse(
        {
          detail: {
            message: "Documentation page not found: visualizations/gone.md",
            path: "visualizations/gone.md",
            docs_url: "https://memoryslice.github.io/MemDiver/visualizations/gone.html",
          },
        },
        false,
        404,
      ),
    );
    render(<DocPanel doc="visualizations/gone.md" onClose={vi.fn()} />);

    const alert = await screen.findByRole("alert");
    expect(alert).toHaveTextContent(/could not be loaded/i);
    const link = screen.getByRole("link");
    expect(link).toHaveAttribute(
      "href",
      "https://memoryslice.github.io/MemDiver/visualizations/gone.html",
    );
    expect(link).toHaveAttribute("target", "_blank");
  });

  it("falls back to a locally-derived URL when the request never reached the backend", async () => {
    fetchMock.mockRejectedValueOnce(new TypeError("Failed to fetch"));
    render(<DocPanel doc="quickstart/experiment.md" onClose={vi.fn()} />);

    await screen.findByRole("alert");
    expect(screen.getByRole("link")).toHaveAttribute(
      "href",
      "https://memoryslice.github.io/MemDiver/quickstart/experiment.html",
    );
  });
});

describe("EmptyState secondary link", () => {
  it("opens the doc panel from a `doc:` secondary, and closes back to it", async () => {
    fetchMock.mockResolvedValue(
      jsonResponse({ path: "visualizations/consensus.md", content: "# Consensus view\n" }),
    );
    render(
      <EmptyState
        title="Nothing yet"
        secondary={{ label: "About consensus", doc: "visualizations/consensus.md" }}
      />,
    );

    // A button, not an anchor: `/docs/...` never resolved in any environment.
    const trigger = screen.getByRole("button", { name: "About consensus" });
    expect(screen.queryByRole("link")).toBeNull();

    fireEvent.click(trigger);
    await screen.findByText("Consensus view");
    expect(fetchMock.mock.calls[0][0]).toBe("/api/docs/visualizations/consensus.md");

    fireEvent.click(screen.getByRole("button", { name: "Close" }));
    expect(screen.queryByRole("dialog")).toBeNull();
  });

  it("leaves an `href:` secondary rendering exactly as before", () => {
    render(
      <EmptyState
        title="Nothing yet"
        secondary={{ label: "Read more", href: "https://example.invalid/guide" }}
      />,
    );
    const link = screen.getByRole("link", { name: "Read more" });
    expect(link).toHaveAttribute("href", "https://example.invalid/guide");
    expect(link).toHaveAttribute("target", "_blank");
    expect(link).toHaveAttribute("rel", "noreferrer");
  });

  it("leaves a relative `href:` secondary without the external-link attributes", () => {
    render(
      <EmptyState title="Nothing yet" secondary={{ label: "Local", href: "/settings" }} />,
    );
    const link = screen.getByRole("link", { name: "Local" });
    expect(link).toHaveAttribute("href", "/settings");
    expect(link).not.toHaveAttribute("target");
  });
});

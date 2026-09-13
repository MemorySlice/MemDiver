/**
 * Tests for `@/utils/markdown` — the dependency-free renderer behind the
 * in-app documentation panel.
 *
 * The security tests at the bottom are the reason this module is hand-rolled
 * rather than `marked` + `dangerouslySetInnerHTML`: every construct must reach
 * the DOM as a React TEXT node, so raw HTML in a doc is inert.
 */

import { describe, it, expect, vi } from "vitest";
import { render, screen } from "@testing-library/react";
import "@testing-library/jest-dom/vitest";
import {
  isExternalHref,
  parseInline,
  renderMarkdown,
  resolveDocPath,
} from "@/utils/markdown";
import type { MarkdownOptions } from "@/utils/markdown";

/** Render a markdown source and hand back the container element. */
function md(source: string, options?: MarkdownOptions): HTMLElement {
  const { container } = render(renderMarkdown(source, options));
  return container;
}

// ---------------------------------------------------------------------------
// Block constructs
// ---------------------------------------------------------------------------

describe("headings", () => {
  it("renders h1-h3 at the right level", () => {
    const c = md("# One\n\n## Two\n\n### Three\n");
    expect(c.querySelector("h1")).toHaveTextContent("One");
    expect(c.querySelector("h2")).toHaveTextContent("Two");
    expect(c.querySelector("h3")).toHaveTextContent("Three");
  });

  it("clamps a level deeper than h6", () => {
    const c = md("####### Seven\n");
    // Seven hashes is not a heading in CommonMark either; it must at least not
    // emit an invalid <h7>.
    expect(c.querySelector("h7")).toBeNull();
  });
});

describe("paragraphs", () => {
  it("joins wrapped lines into one paragraph and splits on a blank line", () => {
    const c = md("first line\nsecond line\n\nnew paragraph\n");
    const paragraphs = c.querySelectorAll("p");
    expect(paragraphs).toHaveLength(2);
    expect(paragraphs[0]).toHaveTextContent("first line second line");
    expect(paragraphs[1]).toHaveTextContent("new paragraph");
  });
});

describe("lists", () => {
  it("renders an unordered list", () => {
    const c = md("- alpha\n- beta\n- gamma\n");
    expect(c.querySelector("ul")).not.toBeNull();
    expect(c.querySelectorAll("li")).toHaveLength(3);
    expect(c.querySelectorAll("li")[1]).toHaveTextContent("beta");
  });

  it("renders an ordered list", () => {
    const c = md("1. first\n2. second\n");
    expect(c.querySelector("ol")).not.toBeNull();
    expect(c.querySelectorAll("li")).toHaveLength(2);
  });

  it("keeps an indented fenced code block inside its list item", () => {
    // The exact shape of step 3 in docs/quickstart/experiment.md.
    const c = md(
      ["1. Run:", "", "   ```bash", "   memdiver experiment --num-runs 10", "   ```", "", "2. Inspect the output."].join(
        "\n",
      ),
    );
    const items = c.querySelectorAll("li");
    expect(items).toHaveLength(2);
    expect(items[0].querySelector("pre")).not.toBeNull();
    expect(items[0].querySelector("pre")).toHaveTextContent("memdiver experiment --num-runs 10");
    expect(items[1]).toHaveTextContent("Inspect the output.");
  });
});

describe("fenced code blocks", () => {
  it("preserves the body verbatim and records the language", () => {
    const c = md("```bash\nsudo apt install lldb\n# a comment\n```\n");
    const pre = c.querySelector("pre");
    expect(pre).not.toBeNull();
    expect(pre).toHaveAttribute("data-language", "bash");
    expect(pre!.textContent).toBe("sudo apt install lldb\n# a comment");
  });

  it("does not treat a `#` inside a fence as a heading", () => {
    const c = md("```\n# not a heading\n```\n");
    expect(c.querySelector("h1")).toBeNull();
  });
});

describe("tables", () => {
  it("renders a GFM pipe table with a header row", () => {
    const c = md(
      ["| Backend | Output |", "|---|---|", "| `memslicer` | `.msl` |", "| `lldb` | `.dump` |"].join("\n"),
    );
    expect(c.querySelectorAll("th")).toHaveLength(2);
    expect(c.querySelectorAll("th")[0]).toHaveTextContent("Backend");
    const rows = c.querySelectorAll("tbody tr");
    expect(rows).toHaveLength(2);
    expect(rows[0]).toHaveTextContent("memslicer");
    // Inline markup inside a cell is still parsed.
    expect(rows[0].querySelector("code")).toHaveTextContent("memslicer");
  });
});

describe("blockquotes", () => {
  it("renders a blockquote and parses its contents as blocks", () => {
    const c = md("> quoted **text**\n> second line\n");
    const quote = c.querySelector("blockquote");
    expect(quote).not.toBeNull();
    expect(quote).toHaveTextContent("quoted text second line");
    expect(quote!.querySelector("strong")).toHaveTextContent("text");
  });
});

// ---------------------------------------------------------------------------
// Inline constructs
// ---------------------------------------------------------------------------

describe("inline", () => {
  it("renders inline code", () => {
    const c = md("run `memdiver web` now\n");
    expect(c.querySelector("code")).toHaveTextContent("memdiver web");
  });

  it("renders bold and italic", () => {
    const c = md("**bold** and *italic* and __also bold__\n");
    expect(c.querySelectorAll("strong")[0]).toHaveTextContent("bold");
    expect(c.querySelectorAll("strong")[1]).toHaveTextContent("also bold");
    expect(c.querySelector("em")).toHaveTextContent("italic");
  });

  it("does not treat inline emphasis markers inside code as markup", () => {
    const c = md("`a * b * c`\n");
    expect(c.querySelector("em")).toBeNull();
    expect(c.querySelector("code")).toHaveTextContent("a * b * c");
  });

  it("renders an external link as a new-tab anchor", () => {
    const c = md("see [the site](https://example.invalid/page)\n");
    const link = c.querySelector("a")!;
    expect(link).toHaveAttribute("href", "https://example.invalid/page");
    expect(link).toHaveAttribute("target", "_blank");
    expect(link.getAttribute("rel")).toContain("noreferrer");
    expect(link).toHaveTextContent("the site");
  });

  it("keeps a relative .md link inside the panel", () => {
    const onDocLink = vi.fn();
    md("See also: [architect](../architecture/architect.md).\n", {
      basePath: "visualizations/consensus.md",
      onDocLink,
    });
    // A button, never an anchor: following it in the browser is the very bug
    // this feature fixes.
    expect(document.querySelector("a")).toBeNull();
    screen.getByRole("button", { name: "architect" }).click();
    expect(onDocLink).toHaveBeenCalledWith("architecture/architect.md");
  });

  it("labels an empty [] link from its target, as Sphinx would", () => {
    const onDocLink = vi.fn();
    md("See also: [](../architecture/architect.md).\n", {
      basePath: "visualizations/architect.md",
      onDocLink,
    });
    expect(screen.getByRole("button", { name: "architect" })).toBeInTheDocument();
  });
});

// ---------------------------------------------------------------------------
// MyST / Sphinx degradation
// ---------------------------------------------------------------------------

describe("MyST directives", () => {
  it("renders a `:::{admonition} Title` colon fence as a titled callout", () => {
    const c = md(
      [":::{admonition} Available in", ":class: tip", "**SPA** · **Marimo** sandbox", ":::", ""].join("\n"),
    );
    const aside = c.querySelector("aside")!;
    expect(aside).not.toBeNull();
    expect(aside).toHaveTextContent("Available in");
    expect(aside).toHaveTextContent("SPA");
    // The `:class:` OPTION line is chrome, not prose -- it must not be shown.
    expect(c.textContent).not.toContain(":class:");
    expect(c.textContent).not.toContain(":::");
  });

  it("titles a bare `:::{note}` from the supplied label", () => {
    const c = md([":::{note}", "`fridump` is not friTap.", ":::", ""].join("\n"), {
      labels: { note: "Hinweis" },
    });
    expect(c.querySelector("aside")).toHaveTextContent("Hinweis");
    expect(c.querySelector("aside")).toHaveTextContent("is not friTap");
  });

  it("degrades a ```{figure} directive to its alt text as a caption", () => {
    const c = md(
      [
        "```{figure} /_static/screenshots/07_consensus_tab.png",
        ":alt: Consensus chart with stacked bars",
        ":align: center",
        "```",
        "",
      ].join("\n"),
      { labels: { figure: "Figure" } },
    );
    expect(c.querySelector("figcaption")).toHaveTextContent("Consensus chart with stacked bars");
    // No broken <img> for an asset the SPA does not serve, and no raw syntax.
    expect(c.querySelector("img")).toBeNull();
    expect(c.textContent).not.toContain(":alt:");
    expect(c.textContent).not.toContain("```");
  });

  it("renders a role as its target text, not its raw syntax", () => {
    const c = md("See {ref}`consensus-view` for details.\n");
    expect(c).toHaveTextContent("See consensus-view for details.");
    expect(c.textContent).not.toContain("{ref}");
    expect(c.textContent).not.toContain("`");
  });
});

// ---------------------------------------------------------------------------
// Path helpers
// ---------------------------------------------------------------------------

describe("resolveDocPath", () => {
  it("resolves a sibling", () => {
    expect(resolveDocPath("visualizations/consensus.md", "architect.md")).toBe(
      "visualizations/architect.md",
    );
  });

  it("resolves a parent-relative target", () => {
    expect(resolveDocPath("visualizations/consensus.md", "../quickstart/web.md")).toBe(
      "quickstart/web.md",
    );
  });

  it("drops an anchor", () => {
    expect(resolveDocPath("visualizations/consensus.md", "architect.md#workflow")).toBe(
      "visualizations/architect.md",
    );
  });

  it("refuses to climb above the docs root", () => {
    expect(resolveDocPath("visualizations/consensus.md", "../../pyproject.toml")).toBeNull();
    expect(resolveDocPath("index.md", "../secret.md")).toBeNull();
  });
});

describe("isExternalHref", () => {
  it.each([
    ["https://example.invalid", true],
    ["http://example.invalid", true],
    ["mailto:a@b.invalid", true],
    ["../architecture/architect.md", false],
    ["#anchor", false],
    ["javascript:alert(1)", false],
  ])("%s -> %s", (href, expected) => {
    expect(isExternalHref(href)).toBe(expected);
  });
});

// ---------------------------------------------------------------------------
// SECURITY — nothing in a doc may become live HTML
// ---------------------------------------------------------------------------

describe("HTML in the source is inert", () => {
  it("renders a <script> tag as visible text and never inserts one", () => {
    const c = md('Danger: <script>window.__xss = 1;</script> done\n');
    expect(c.querySelector("script")).toBeNull();
    expect((window as unknown as { __xss?: number }).__xss).toBeUndefined();
    // It is visible TEXT, which is the point: nothing was silently stripped.
    expect(c.textContent).toContain("<script>window.__xss = 1;</script>");
  });

  it("renders an <img onerror=...> as visible text and never inserts one", () => {
    const c = md('<img src=x onerror="window.__xss2 = 1">\n');
    expect(c.querySelector("img")).toBeNull();
    expect((window as unknown as { __xss2?: number }).__xss2).toBeUndefined();
    expect(c.textContent).toContain('<img src=x onerror="window.__xss2 = 1">');
  });

  it("keeps HTML inside a fenced code block literal too", () => {
    const c = md("```html\n<script>alert(1)</script>\n```\n");
    expect(c.querySelector("script")).toBeNull();
    expect(c.querySelector("pre")!.textContent).toBe("<script>alert(1)</script>");
  });

  it("never produces a javascript: anchor from a link", () => {
    const c = md("[click](javascript:alert(1))\n");
    expect(c.querySelector("a")).toBeNull();
    expect(c.textContent).toContain("click");
  });

  it("parseInline returns nodes, never an HTML string", () => {
    const nodes = parseInline("<b>x</b> **y**");
    expect(Array.isArray(nodes)).toBe(true);
    expect(nodes.some((n) => typeof n === "string" && n.includes("<b>"))).toBe(true);
  });
});

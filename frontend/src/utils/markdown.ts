/**
 * A small, dependency-free markdown renderer for the in-app documentation
 * panel (`@/components/common/DocPanel`).
 *
 * SECURITY — the whole reason this is hand-rolled rather than
 * `marked` + `dangerouslySetInnerHTML`: every function here returns a React
 * NODE TREE, never an HTML string. Source text reaches the DOM only as a React
 * text child, which React escapes. `<script>alert(1)</script>` or
 * `<img src=x onerror=...>` in a doc therefore renders as visible literal
 * text and can never execute. There is no `dangerouslySetInnerHTML` in this
 * file and none may be added: the corollary is that raw-HTML blocks in
 * markdown are deliberately NOT supported.
 *
 * SCOPE — the constructs actually present in `docs/visualizations/*.md` and
 * `docs/quickstart/experiment.md`, no more (YAGNI): headings, paragraphs,
 * ordered/unordered lists (with nested blocks), fenced code, inline code,
 * links, bold/italic, GFM pipe tables and blockquotes.
 *
 * MyST/Sphinx — those files are Sphinx sources, so they carry constructs that
 * are NOT CommonMark. Printing their raw syntax at the reader would be worse
 * than useless, so each degrades to its meaning instead:
 *
 *   - `:::{note}` / `:::{admonition} Title` colon fences  -> a titled callout.
 *   - ```` ```{figure} path ```` with a `:alt:` option     -> a caption built
 *     from the alt text (the `/_static/` image is not served by the SPA, so
 *     there is nothing to show; the alt text is the information).
 *   - `` {ref}`target` `` and friends (roles)             -> the target text.
 *   - `[](some/page.md)` with an empty label               -> the target's
 *     basename, which is what Sphinx would have resolved the title to.
 */

import { createElement, Fragment, type ReactNode } from "react";

/** Labels for generated chrome. Supplied from i18n by the caller. */
export interface MarkdownLabels {
  note?: string;
  tip?: string;
  warning?: string;
  caution?: string;
  important?: string;
  figure?: string;
}

export interface MarkdownOptions {
  /**
   * `docs/`-relative path of the document being rendered. Relative `.md` links
   * resolve against its directory.
   */
  basePath?: string;
  /**
   * Invoked with a `docs/`-relative path when a relative `.md` link is
   * activated. Present => such links render as in-panel buttons rather than
   * browser navigation; absent => they render as inert text.
   */
  onDocLink?: (docPath: string) => void;
  labels?: MarkdownLabels;
}

// ---------------------------------------------------------------------------
// Link classification + path resolution
// ---------------------------------------------------------------------------

const EXTERNAL_SCHEME = /^(https?:|mailto:)/i;

/** True for a link that should leave the panel and open in the browser. */
export function isExternalHref(href: string): boolean {
  return EXTERNAL_SCHEME.test(href);
}

/**
 * Resolve a doc-relative href against the directory of `basePath`.
 *
 * `resolveDocPath("visualizations/architect.md", "../architecture/architect.md")`
 * -> `"architecture/architect.md"`. Any attempt to climb above the docs root
 * returns `null` rather than a path with a surviving `..`, so a malformed doc
 * can never ask the backend for something outside the tree.
 */
export function resolveDocPath(basePath: string, href: string): string | null {
  const [target] = href.split("#");
  if (!target) return null;
  const segments = target.startsWith("/")
    ? target.slice(1).split("/")
    : [...basePath.split("/").slice(0, -1), ...target.split("/")];

  const out: string[] = [];
  for (const segment of segments) {
    if (segment === "" || segment === ".") continue;
    if (segment === "..") {
      if (out.length === 0) return null;
      out.pop();
      continue;
    }
    out.push(segment);
  }
  return out.length > 0 ? out.join("/") : null;
}

/** The label Sphinx would have resolved an empty `[]()` link title to. */
function labelFromHref(href: string): string {
  const last = href.split("#")[0].split("/").filter(Boolean).pop() ?? href;
  return last.replace(/\.md$/, "");
}

// ---------------------------------------------------------------------------
// Inline
// ---------------------------------------------------------------------------

/**
 * One ordered alternation. Order is load-bearing: `**` must precede `*`, and
 * code spans must come first so their contents stay literal.
 */
const INLINE_TOKEN = new RegExp(
  [
    /(?<code>`+[^`]*`+)/.source,
    /\{(?<role>[A-Za-z0-9_:+-]+)\}`(?<roleTarget>[^`]*)`/.source,
    /!?\[(?<linkText>[^\]]*)\]\((?<linkHref>[^)\s]*)(?:\s+"[^"]*")?\)/.source,
    /(?<strongStars>\*\*(?:[^*]|\*(?!\*))+\*\*)/.source,
    /(?<strongUnders>__[^_]+__)/.source,
    /(?<emStar>\*[^*\n]+\*)/.source,
    /(?<emUnder>\b_[^_\n]+_\b)/.source,
  ].join("|"),
);

function inlineCode(text: string, key: number): ReactNode {
  return createElement(
    "code",
    {
      key,
      className:
        "px-[var(--space-1)] py-px rounded-[var(--radius-sm)] font-mono text-[0.92em] break-words",
      style: {
        background: "var(--md-bg-tertiary)",
        color: "var(--md-text-bright)",
      },
    },
    text,
  );
}

function docLink(
  text: ReactNode,
  href: string,
  opts: MarkdownOptions,
  key: number,
): ReactNode {
  const linkClass = "underline underline-offset-2 hover:no-underline";
  const linkStyle = { color: "var(--md-accent-blue)" };

  if (isExternalHref(href)) {
    return createElement(
      "a",
      {
        key,
        href,
        target: "_blank",
        rel: "noreferrer noopener",
        className: linkClass,
        style: linkStyle,
      },
      text,
    );
  }

  // A relative `.md` link must navigate WITHIN the panel: following it in the
  // browser would hit the SPA's static catch-all, which is the very bug this
  // whole feature exists to fix.
  const resolved = opts.basePath ? resolveDocPath(opts.basePath, href) : null;
  if (opts.onDocLink && resolved && resolved.endsWith(".md")) {
    const navigate = opts.onDocLink;
    return createElement(
      "button",
      {
        key,
        type: "button",
        onClick: () => navigate(resolved),
        className: `${linkClass} bg-transparent p-0 text-left`,
        style: linkStyle,
      },
      text,
    );
  }

  // An in-tree target we cannot serve (an anchor, a `/_static/` asset, a doc
  // link with no handler): show the text, offer no dead destination.
  return createElement("span", { key, style: { color: "var(--md-text-secondary)" } }, text);
}

/** Parse one line of inline markdown into a React node list. */
export function parseInline(text: string, opts: MarkdownOptions = {}): ReactNode[] {
  const out: ReactNode[] = [];
  let rest = text;
  let key = 0;

  while (rest.length > 0) {
    const match = INLINE_TOKEN.exec(rest);
    if (!match || match.index === undefined) {
      out.push(rest);
      break;
    }
    if (match.index > 0) out.push(rest.slice(0, match.index));
    const g = match.groups ?? {};

    if (g.code !== undefined) {
      out.push(inlineCode(g.code.replace(/^`+|`+$/g, ""), key++));
    } else if (g.role !== undefined) {
      // A Sphinx role: the target text is the only part a reader can use.
      out.push(createElement(Fragment, { key: key++ }, g.roleTarget ?? ""));
    } else if (g.linkHref !== undefined) {
      const href = g.linkHref;
      const raw = g.linkText ?? "";
      const label = raw.trim() === "" ? labelFromHref(href) : raw;
      out.push(docLink(parseInline(label, opts), href, opts, key++));
    } else if (g.strongStars !== undefined || g.strongUnders !== undefined) {
      const body = (g.strongStars ?? g.strongUnders)!.slice(2, -2);
      out.push(
        createElement(
          "strong",
          { key: key++, className: "font-semibold", style: { color: "var(--md-text-bright)" } },
          parseInline(body, opts),
        ),
      );
    } else {
      const body = (g.emStar ?? g.emUnder)!.slice(1, -1);
      out.push(createElement("em", { key: key++ }, parseInline(body, opts)));
    }
    rest = rest.slice(match.index + match[0].length);
  }
  return out;
}

// ---------------------------------------------------------------------------
// Block-level line classification
// ---------------------------------------------------------------------------

const HEADING = /^(#{1,6})\s+(.*)$/;
const BACKTICK_FENCE = /^(\s*)(`{3,}|~{3,})\s*(.*)$/;
const COLON_FENCE = /^:{3,}\s*(?:\{([A-Za-z0-9_-]+)\})?\s*(.*)$/;
const UL_ITEM = /^(\s*)([-*+])\s+(.*)$/;
const OL_ITEM = /^(\s*)(\d+)[.)]\s+(.*)$/;
const BLOCKQUOTE = /^\s*>\s?(.*)$/;
const TABLE_DIVIDER = /^\s*\|?\s*:?-{2,}:?\s*(\|\s*:?-{2,}:?\s*)*\|?\s*$/;
const DIRECTIVE_OPTION = /^\s*:([A-Za-z0-9_-]+):\s*(.*)$/;

const ADMONITION_TONE: Record<string, string> = {
  note: "var(--md-accent-blue)",
  tip: "var(--md-accent-green)",
  hint: "var(--md-accent-green)",
  important: "var(--md-accent-purple)",
  warning: "var(--md-accent-orange)",
  caution: "var(--md-accent-orange)",
  attention: "var(--md-accent-orange)",
  danger: "var(--md-accent-red)",
  error: "var(--md-accent-red)",
};

function titleCase(word: string): string {
  return word.charAt(0).toUpperCase() + word.slice(1);
}

/** Strip `:key: value` option lines from the head of a directive body. */
function splitDirectiveOptions(body: string[]): {
  options: Record<string, string>;
  rest: string[];
} {
  const options: Record<string, string> = {};
  let i = 0;
  for (; i < body.length; i++) {
    const m = DIRECTIVE_OPTION.exec(body[i]);
    if (!m) break;
    options[m[1].toLowerCase()] = m[2].trim();
  }
  return { options, rest: body.slice(i) };
}

/** Remove `indent` leading spaces from each line, tolerating short lines. */
function dedent(lines: string[], indent: number): string[] {
  return lines.map((line) =>
    line.slice(0, indent).trim() === "" ? line.slice(indent) : line.trimStart(),
  );
}

// ---------------------------------------------------------------------------
// Block builders
// ---------------------------------------------------------------------------

function admonition(
  kind: string,
  argument: string,
  body: string[],
  opts: MarkdownOptions,
  key: number,
): ReactNode {
  const { options, rest } = splitDirectiveOptions(body);
  const cssClass = (options["class"] ?? "").split(/\s+/)[0];
  const tone =
    ADMONITION_TONE[kind] ?? ADMONITION_TONE[cssClass] ?? "var(--md-accent-blue)";
  const labelled = opts.labels?.[kind as keyof MarkdownLabels];
  const title = argument.trim() || labelled || titleCase(kind);

  return createElement(
    "aside",
    {
      key,
      className:
        "my-[var(--space-3)] px-[var(--space-3)] py-[var(--space-2)] rounded-[var(--radius-md)] border-l-2",
      style: { borderLeftColor: tone, background: "var(--md-bg-secondary)" },
    },
    createElement(
      "p",
      {
        className: "font-semibold text-[var(--text-xs)] uppercase tracking-wide",
        style: { color: tone },
      },
      title,
    ),
    ...renderBlocks(rest, opts, 1),
  );
}

function figure(
  argument: string,
  body: string[],
  opts: MarkdownOptions,
  key: number,
): ReactNode {
  const { options } = splitDirectiveOptions(body);
  const caption = options["alt"] || labelFromHref(argument);
  const label = opts.labels?.figure ?? "Figure";
  return createElement(
    "figure",
    {
      key,
      className:
        "my-[var(--space-3)] px-[var(--space-3)] py-[var(--space-2)] rounded-[var(--radius-md)] border border-dashed",
      style: { borderColor: "var(--md-border)", background: "var(--md-bg-secondary)" },
    },
    createElement(
      "figcaption",
      { className: "text-[var(--text-xs)]", style: { color: "var(--md-text-muted)" } },
      createElement("span", { className: "font-semibold uppercase tracking-wide" }, label),
      " — ",
      ...parseInline(caption, opts),
    ),
  );
}

function codeBlock(lines: string[], language: string, key: number): ReactNode {
  return createElement(
    "pre",
    {
      key,
      className:
        "my-[var(--space-3)] p-[var(--space-3)] rounded-[var(--radius-md)] overflow-x-auto text-[var(--text-xs)] leading-relaxed",
      style: { background: "var(--md-bg-tertiary)", color: "var(--md-text-primary)" },
      "data-language": language || undefined,
    },
    createElement("code", { className: "font-mono whitespace-pre" }, lines.join("\n")),
  );
}

function tableRowCells(line: string): string[] {
  return line
    .trim()
    .replace(/^\|/, "")
    .replace(/\|$/, "")
    .split("|")
    .map((cell) => cell.trim());
}

function table(
  header: string,
  rows: string[],
  opts: MarkdownOptions,
  key: number,
): ReactNode {
  const headers = tableRowCells(header);
  return createElement(
    "div",
    { key, className: "my-[var(--space-3)] overflow-x-auto" },
    createElement(
      "table",
      { className: "w-full text-left text-[var(--text-xs)] border-collapse" },
      createElement(
        "thead",
        null,
        createElement(
          "tr",
          null,
          ...headers.map((cell, i) =>
            createElement(
              "th",
              {
                key: i,
                scope: "col",
                className: "px-[var(--space-2)] py-[var(--space-1)] border-b font-semibold",
                style: {
                  borderColor: "var(--md-border)",
                  color: "var(--md-text-bright)",
                },
              },
              ...parseInline(cell, opts),
            ),
          ),
        ),
      ),
      createElement(
        "tbody",
        null,
        ...rows.map((row, r) =>
          createElement(
            "tr",
            { key: r },
            ...tableRowCells(row).map((cell, c) =>
              createElement(
                "td",
                {
                  key: c,
                  className: "px-[var(--space-2)] py-[var(--space-1)] border-b align-top",
                  style: { borderColor: "var(--md-border)" },
                },
                ...parseInline(cell, opts),
              ),
            ),
          ),
        ),
      ),
    ),
  );
}

const HEADING_CLASS: Record<number, string> = {
  1: "text-[var(--text-lg)] font-semibold mt-[var(--space-2)] mb-[var(--space-3)]",
  2: "text-[var(--text-md)] font-semibold mt-[var(--space-4)] mb-[var(--space-2)]",
  3: "text-[var(--text-sm)] font-semibold mt-[var(--space-3)] mb-[var(--space-2)]",
};

// ---------------------------------------------------------------------------
// The block loop
// ---------------------------------------------------------------------------

/**
 * Parse `lines` into block-level React nodes.
 *
 * `depth` only guards against a pathological doc recursing forever through
 * nested list items / blockquotes; nothing in the real corpus comes close.
 */
function renderBlocks(
  lines: string[],
  opts: MarkdownOptions,
  depth = 0,
): ReactNode[] {
  if (depth > 8) return [lines.join("\n")];

  const out: ReactNode[] = [];
  let key = 0;
  let i = 0;

  while (i < lines.length) {
    const line = lines[i];

    if (line.trim() === "") {
      i++;
      continue;
    }

    // --- backtick fence: code block, or a MyST directive -------------------
    const fence = BACKTICK_FENCE.exec(line);
    if (fence) {
      const [, indent, marker, info] = fence;
      const closer = new RegExp(`^\\s*${marker[0]}{${marker.length},}\\s*$`);
      const body: string[] = [];
      i++;
      while (i < lines.length && !closer.test(lines[i])) body.push(lines[i++]);
      i++; // consume the closing fence (or fall off the end)
      const dedented = dedent(body, indent.length);
      const directive = /^\{([A-Za-z0-9_-]+)\}\s*(.*)$/.exec(info.trim());
      if (directive) {
        const [, name, argument] = directive;
        out.push(
          name === "figure" || name === "image"
            ? figure(argument, dedented, opts, key++)
            : admonition(name, argument, dedented, opts, key++),
        );
      } else {
        out.push(codeBlock(dedented, info.trim(), key++));
      }
      continue;
    }

    // --- colon fence: always a directive ----------------------------------
    // Only an OPENING fence (`:::{name}`) starts a directive. A bare `:::` at
    // top level is a stray closer and must fall through to the paragraph
    // branch rather than swallowing the rest of the document.
    const colon = COLON_FENCE.exec(line);
    if (colon && colon[1]) {
      const [, name, argument] = colon;
      const body: string[] = [];
      i++;
      while (i < lines.length && !/^:{3,}\s*$/.test(lines[i])) body.push(lines[i++]);
      i++;
      out.push(
        name === "figure" || name === "image"
          ? figure(argument ?? "", body, opts, key++)
          : admonition(name ?? "note", argument ?? "", body, opts, key++),
      );
      continue;
    }

    // --- heading -----------------------------------------------------------
    const heading = HEADING.exec(line);
    if (heading) {
      const level = heading[1].length;
      out.push(
        createElement(
          `h${Math.min(level, 6)}`,
          {
            key: key++,
            className: HEADING_CLASS[level] ?? HEADING_CLASS[3],
            style: { color: "var(--md-text-bright)" },
          },
          ...parseInline(heading[2], opts),
        ),
      );
      i++;
      continue;
    }

    // --- table --------------------------------------------------------------
    if (
      line.includes("|") &&
      i + 1 < lines.length &&
      TABLE_DIVIDER.test(lines[i + 1])
    ) {
      const header = line;
      i += 2;
      const rows: string[] = [];
      while (i < lines.length && lines[i].includes("|") && lines[i].trim() !== "") {
        rows.push(lines[i++]);
      }
      out.push(table(header, rows, opts, key++));
      continue;
    }

    // --- blockquote ---------------------------------------------------------
    if (BLOCKQUOTE.test(line)) {
      const body: string[] = [];
      while (i < lines.length && BLOCKQUOTE.test(lines[i])) {
        body.push(BLOCKQUOTE.exec(lines[i++])![1]);
      }
      out.push(
        createElement(
          "blockquote",
          {
            key: key++,
            className: "my-[var(--space-3)] pl-[var(--space-3)] border-l-2 italic",
            style: { borderLeftColor: "var(--md-border)", color: "var(--md-text-secondary)" },
          },
          ...renderBlocks(body, opts, depth + 1),
        ),
      );
      continue;
    }

    // --- lists --------------------------------------------------------------
    const listMatch = UL_ITEM.exec(line) ?? OL_ITEM.exec(line);
    if (listMatch) {
      const ordered = UL_ITEM.exec(line) === null;
      const [consumed, items] = collectListItems(lines, i, ordered);
      i = consumed;
      out.push(
        createElement(
          ordered ? "ol" : "ul",
          {
            key: key++,
            className: `my-[var(--space-2)] pl-[var(--space-5)] space-y-[var(--space-1)] ${
              ordered ? "list-decimal" : "list-disc"
            }`,
          },
          ...items.map((item, index) =>
            createElement("li", { key: index }, ...renderListItem(item, opts, depth)),
          ),
        ),
      );
      continue;
    }

    // --- paragraph ----------------------------------------------------------
    const paragraph: string[] = [];
    while (
      i < lines.length &&
      lines[i].trim() !== "" &&
      !HEADING.test(lines[i]) &&
      !BACKTICK_FENCE.test(lines[i]) &&
      !COLON_FENCE.test(lines[i]) &&
      !BLOCKQUOTE.test(lines[i]) &&
      !UL_ITEM.test(lines[i]) &&
      !OL_ITEM.test(lines[i])
    ) {
      paragraph.push(lines[i++]);
    }
    if (paragraph.length === 0) {
      // Defensive: a line that matched nothing above and nothing here would
      // otherwise spin forever.
      paragraph.push(lines[i++]);
    }
    out.push(
      createElement(
        "p",
        {
          key: key++,
          className: "my-[var(--space-2)] leading-relaxed",
          style: { color: "var(--md-text-secondary)" },
        },
        ...parseInline(paragraph.join(" "), opts),
      ),
    );
  }

  return out;
}

/**
 * Gather the raw (dedented) lines of every item in one list, starting at
 * `start`. Continuation lines indented past the marker belong to the item —
 * that is what carries the fenced `bash` block inside step 3 of
 * `docs/quickstart/experiment.md`.
 */
function collectListItems(
  lines: string[],
  start: number,
  ordered: boolean,
): [number, string[][]] {
  const pattern = ordered ? OL_ITEM : UL_ITEM;
  const first = pattern.exec(lines[start])!;
  const baseIndent = first[1].length;
  const items: string[][] = [];
  let current: string[] | null = null;
  let i = start;

  while (i < lines.length) {
    const line = lines[i];
    const item = pattern.exec(line);
    if (item && item[1].length === baseIndent) {
      current = [item[3]];
      items.push(current);
      i++;
      continue;
    }
    if (line.trim() === "") {
      // A blank line ends the list unless the NEXT line continues this item.
      const next = lines[i + 1];
      const continues =
        next !== undefined &&
        (next.trim() === "" ||
          next.search(/\S/) > baseIndent ||
          pattern.exec(next)?.[1].length === baseIndent);
      if (!continues) break;
      if (current) current.push("");
      i++;
      continue;
    }
    if (current && line.search(/\S/) > baseIndent) {
      current.push(line);
      i++;
      continue;
    }
    break;
  }

  // Drop the trailing blanks a lookahead may have banked.
  for (const item of items) {
    while (item.length > 0 && item[item.length - 1].trim() === "") item.pop();
  }
  return [i, items];
}

/**
 * Render one list item. A single-paragraph item is unwrapped so the bullet
 * hugs its text instead of sitting beside a block with its own margins.
 */
function renderListItem(
  item: string[],
  opts: MarkdownOptions,
  depth: number,
): ReactNode[] {
  const [head, ...tail] = item;
  const continuation = dedent(tail, indentOf(tail));
  if (continuation.every((line) => line.trim() === "")) {
    return parseInline(head, opts);
  }
  return renderBlocks([head, ...continuation], opts, depth + 1);
}

/** The smallest leading-whitespace width across the non-blank lines. */
function indentOf(lines: string[]): number {
  const widths = lines
    .filter((line) => line.trim() !== "")
    .map((line) => line.search(/\S/));
  return widths.length > 0 ? Math.min(...widths) : 0;
}

// ---------------------------------------------------------------------------
// Public entry point
// ---------------------------------------------------------------------------

/**
 * Render a markdown document as a React node tree.
 *
 * Never returns an HTML string, and never touches `dangerouslySetInnerHTML` —
 * see the module docstring.
 */
export function renderMarkdown(source: string, options: MarkdownOptions = {}): ReactNode {
  const lines = source.replace(/\r\n?/g, "\n").split("\n");
  return createElement(Fragment, null, ...renderBlocks(lines, options));
}

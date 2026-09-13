/**
 * Typed client for the in-app documentation surface:
 *   `GET /api/docs/{doc_path}` — one markdown page out of the bundled `docs/`.
 *
 * Mirrors `api/routers/docs.py` 1:1. The endpoint answers JSON rather than
 * `text/markdown` precisely so the shared `request()` helper in `./client`
 * (which always parses JSON) can call it unmodified, and so the 404 body can
 * carry the published-docs fallback as a structured field rather than prose
 * the caller has to scrape.
 *
 * The four SPA empty states that link here used to point at `/docs/<path>.md`,
 * which nothing has ever served in any environment — FastAPI's Swagger UI owns
 * `/docs`, and the Vite dev server's `server.fs.allow` excludes the repo-root
 * `docs/` tree on purpose.
 */

import { ApiError, request } from "./client";

/** Where the same markdown is published as HTML. Mirrors `PUBLISHED_DOCS_URL`. */
export const PUBLISHED_DOCS_URL = "https://memoryslice.github.io/MemDiver/";

export interface DocPage {
  /** The `docs/`-relative path that was requested, echoed back. */
  path: string;
  /** Raw markdown source. Never HTML — the renderer escapes everything. */
  content: string;
}

/** Fetch one `docs/`-relative markdown page, e.g. `visualizations/consensus.md`. */
export const getDoc = (docPath: string) =>
  request<DocPage>(
    `/api/docs/${docPath.split("/").map(encodeURIComponent).join("/")}`,
  );

/**
 * The published-docs URL a `docs/`-relative `.md` path maps to (`.md` ->
 * `.html`). Mirrors `_published_url_for` in the router so the panel can offer a
 * working link even when the request never reached the backend at all.
 */
export function publishedDocUrl(docPath: string): string {
  const asHtml = docPath.endsWith(".md")
    ? `${docPath.slice(0, -".md".length)}.html`
    : docPath;
  return PUBLISHED_DOCS_URL + asHtml.replace(/^\/+/, "");
}

/**
 * Pull the router's `docs_url` out of a failed `getDoc`, falling back to the
 * locally-derived one.
 *
 * `request()` throws `ApiError` carrying the raw response BODY as its message,
 * so the structured 404 detail has to be re-parsed here. A transport failure
 * (backend down, offline) is not an `ApiError` at all and has no body — which
 * is exactly the case the local fallback exists for.
 */
export function fallbackDocUrl(docPath: string, error: unknown): string {
  if (error instanceof ApiError) {
    try {
      const detail = (JSON.parse(error.message) as { detail?: unknown }).detail;
      if (detail && typeof detail === "object" && "docs_url" in detail) {
        const url = (detail as { docs_url?: unknown }).docs_url;
        if (typeof url === "string" && url.startsWith(PUBLISHED_DOCS_URL)) {
          return url;
        }
      }
    } catch {
      // Not JSON (a proxy error page, an empty body) — use the local mapping.
    }
  }
  return publishedDocUrl(docPath);
}

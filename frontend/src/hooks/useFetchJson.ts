/**
 * GET a JSON endpoint whenever `url` changes, for the read-only inspector
 * panels (MSL process/module/handle lists, block navigator, ...).
 *
 * A `null` url means "nothing to fetch yet" and leaves the last result alone.
 * On a url change the previous error is cleared at once (while rendering, not
 * in an effect); the previous data stays on screen until the new body lands
 * unless `resetDataOnChange` is set.
 */

import { useEffect, useState } from "react";

export interface FetchJsonOptions {
  /** Drop the previous body as soon as the url changes. */
  resetDataOnChange?: boolean;
}

export interface FetchJsonResult<T> {
  data: T | null;
  error: string | null;
}

async function getJson<T>(url: string): Promise<T> {
  const res = await fetch(url);
  if (!res.ok) throw new Error(`HTTP ${res.status}`);
  return res.json() as Promise<T>;
}

export function useFetchJson<T>(
  url: string | null,
  { resetDataOnChange = false }: FetchJsonOptions = {},
): FetchJsonResult<T> {
  const [data, setData] = useState<T | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [requestedUrl, setRequestedUrl] = useState(url);

  if (requestedUrl !== url) {
    setRequestedUrl(url);
    if (url) {
      setError(null);
      if (resetDataOnChange) setData(null);
    }
  }

  useEffect(() => {
    if (!url) return;
    getJson<T>(url)
      .then((body) => setData(body))
      .catch((e) => setError(String(e)));
  }, [url]);

  return { data, error };
}

/** `/api/inspect/<endpoint>?msl_path=...`, or `null` when no MSL is open. */
export function mslInspectUrl(endpoint: string, mslPath: string): string | null {
  if (!mslPath) return null;
  return `/api/inspect/${endpoint}?msl_path=${encodeURIComponent(mslPath)}`;
}

/**
 * GET a text artifact (plugin source, report HTML) whenever `url` changes.
 *
 * The result is remembered together with the url it belongs to, so `loading`
 * is simply "no result for THIS url yet" — a url change shows the loading
 * state immediately without resetting anything inside an effect. Responses
 * for a url that is no longer current are ignored.
 */

import { useEffect, useState } from "react";

export interface FetchTextResult {
  text: string | null;
  error: string | null;
  loading: boolean;
}

interface LoadedText {
  url: string;
  text: string | null;
  error: string | null;
}

async function getText(url: string): Promise<string> {
  const res = await fetch(url);
  if (!res.ok) throw new Error(`HTTP ${res.status}`);
  return res.text();
}

function errorMessage(err: unknown): string {
  return err instanceof Error ? err.message : String(err);
}

export function useFetchText(url: string): FetchTextResult {
  const [loaded, setLoaded] = useState<LoadedText | null>(null);

  useEffect(() => {
    let cancelled = false;
    getText(url)
      .then((text) => {
        if (!cancelled) setLoaded({ url, text, error: null });
      })
      .catch((err: unknown) => {
        if (!cancelled) setLoaded({ url, text: null, error: errorMessage(err) });
      });
    return () => {
      cancelled = true;
    };
  }, [url]);

  const current = loaded?.url === url ? loaded : null;
  return {
    text: current?.text ?? null,
    error: current?.error ?? null,
    loading: current === null,
  };
}

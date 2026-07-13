import { useCallback, useRef, useState } from "react";

interface SearchResult {
  offsets: number[];
  // Byte length of the pattern these offsets came from, as reported by the
  // backend. Pairs atomically with `offsets` so consumers never have to
  // re-derive it from a live input that may have changed since the search.
  patternLen: number;
  truncated: boolean;
  isSearching: boolean;
  error: string | null;
}

const EMPTY_RESULT: SearchResult = {
  offsets: [],
  patternLen: 0,
  truncated: false,
  isSearching: false,
  error: null,
};

export function useHexSearch(dumpPath: string) {
  const [results, setResults] = useState<SearchResult>(EMPTY_RESULT);
  const abortRef = useRef<AbortController | null>(null);

  const search = useCallback(
    async (patternHex: string, view: string = "raw") => {
      abortRef.current?.abort();
      const controller = new AbortController();
      abortRef.current = controller;

      setResults({ ...EMPTY_RESULT, isSearching: true });

      try {
        const res = await fetch(
          `/api/inspect/byte-search?dump_path=${encodeURIComponent(dumpPath)}` +
            `&pattern_hex=${encodeURIComponent(patternHex)}` +
            `&view=${encodeURIComponent(view)}&max_results=500`,
          { signal: controller.signal },
        );
        if (!res.ok) throw new Error(`Search failed: ${res.status}`);
        const data = await res.json();
        if (data.error) {
          setResults({ ...EMPTY_RESULT, error: data.error });
          return;
        }
        setResults({
          offsets: data.offsets || [],
          patternLen: data.pattern_len || 0,
          truncated: data.truncated || false,
          isSearching: false,
          error: null,
        });
      } catch (e) {
        if ((e as Error).name !== "AbortError") {
          setResults((prev) => ({
            ...prev,
            isSearching: false,
            error: (e as Error).message,
          }));
        }
      }
    },
    [dumpPath],
  );

  const cancel = useCallback(() => {
    abortRef.current?.abort();
    setResults((prev) => ({ ...prev, isSearching: false }));
  }, []);

  const clear = useCallback(() => {
    abortRef.current?.abort();
    setResults(EMPTY_RESULT);
  }, []);

  return { ...results, search, cancel, clear };
}

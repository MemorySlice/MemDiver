import { useCallback, useRef, useState } from "react";

interface SearchResult {
  offsets: number[];
  truncated: boolean;
  isSearching: boolean;
  error: string | null;
}

export function useHexSearch(dumpPath: string) {
  const [results, setResults] = useState<SearchResult>({
    offsets: [],
    truncated: false,
    isSearching: false,
    error: null,
  });
  const abortRef = useRef<AbortController | null>(null);

  const search = useCallback(
    async (patternHex: string) => {
      abortRef.current?.abort();
      const controller = new AbortController();
      abortRef.current = controller;

      setResults({ offsets: [], truncated: false, isSearching: true, error: null });

      try {
        const res = await fetch(
          `/api/inspect/strings?dump_path=${encodeURIComponent(dumpPath)}&offset=0&length=0&min_length=${patternHex.length / 2}`,
          { signal: controller.signal },
        );
        if (!res.ok) throw new Error(`Search failed: ${res.status}`);
        const data = await res.json();
        const offsets = (data.strings || []).map(
          (s: { offset: number }) => s.offset,
        );
        setResults({
          offsets,
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

  return { ...results, search, cancel };
}

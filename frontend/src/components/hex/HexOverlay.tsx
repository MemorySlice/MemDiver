import { useCallback, useEffect, useState, type ReactElement } from "react";
import { useTranslation } from "react-i18next";
import { decodeBase64, byteToHex, byteToAscii } from "@/utils/hex-codec";
import "../../styles/hex.css";

interface OverlayProps {
  pathA: string;
  pathB: string;
}

const PAGE_SIZE = 512;
const BYTES_PER_ROW = 16;

function nameFromPath(p: string): string {
  const parts = p.replace(/\\/g, "/").split("/");
  return parts[parts.length - 1] || p;
}

export function HexOverlay({ pathA, pathB }: OverlayProps) {
  const { t } = useTranslation("hex");
  const [offset, setOffset] = useState(0);
  const [bytesA, setBytesA] = useState<Uint8Array | null>(null);
  const [bytesB, setBytesB] = useState<Uint8Array | null>(null);
  const [fileSize, setFileSize] = useState(0);
  const [loading, setLoading] = useState(false);

  const loadPage = useCallback(
    async (off: number) => {
      setLoading(true);
      const fetchRaw = async (path: string): Promise<Uint8Array> => {
        const url = `/api/inspect/hex-raw?dump_path=${encodeURIComponent(path)}&offset=${off}&length=${PAGE_SIZE}`;
        const res = await fetch(url);
        if (!res.ok) return new Uint8Array(0);
        const json = await res.json();
        setFileSize((prev) => Math.max(prev, json.file_size ?? 0));
        return decodeBase64(json.bytes ?? json.data ?? "");
      };
      const [a, b] = await Promise.all([fetchRaw(pathA), fetchRaw(pathB)]);
      setBytesA(a);
      setBytesB(b);
      setOffset(off);
      setLoading(false);
    },
    [pathA, pathB],
  );

  useEffect(() => {
    setFileSize(0);
    loadPage(0);
  }, [loadPage]);

  const totalPages = Math.max(1, Math.ceil(fileSize / PAGE_SIZE));
  const currentPage = Math.floor(offset / PAGE_SIZE);
  const rowCount = Math.ceil(PAGE_SIZE / BYTES_PER_ROW);

  const rows: ReactElement[] = [];
  for (let r = 0; r < rowCount; r++) {
    const rowOff = offset + r * BYTES_PER_ROW;
    const hexCells: ReactElement[] = [];
    const asciiCells: ReactElement[] = [];

    for (let c = 0; c < BYTES_PER_ROW; c++) {
      const idx = r * BYTES_PER_ROW + c;
      const a = bytesA && idx < bytesA.length ? bytesA[idx] : undefined;
      const b = bytesB && idx < bytesB.length ? bytesB[idx] : undefined;

      const bothPresent = a !== undefined && b !== undefined;
      const same = bothPresent && a === b;
      const missing = a === undefined && b === undefined;

      let hexText = "--";
      let asciiText = " ";
      let style: React.CSSProperties = {};

      if (missing) {
        style = { opacity: 0.2 };
      } else if (!bothPresent) {
        hexText = a !== undefined ? byteToHex(a) : byteToHex(b!);
        asciiText = a !== undefined ? byteToAscii(a) : byteToAscii(b!);
        style = { opacity: 0.3 };
      } else if (same) {
        hexText = byteToHex(a);
        asciiText = byteToAscii(a);
        style = { opacity: 0.4 };
      } else {
        hexText = byteToHex(a!);
        asciiText = byteToAscii(a!);
        style = { color: "var(--md-accent-red)", fontWeight: "bold" };
      }

      hexCells.push(
        <span
          key={c}
          className="hex-byte"
          style={style}
          title={!same && bothPresent ? `B: ${byteToHex(b!)}` : undefined}
        >
          {hexText}
        </span>,
      );
      asciiCells.push(
        <span key={c} className="hex-char" style={style}>
          {asciiText}
        </span>,
      );
    }

    rows.push(
      <div key={r} className="hex-row">
        <span className="hex-offset">{rowOff.toString(16).padStart(8, "0")}</span>
        <span className="hex-bytes">{hexCells}</span>
        <span className="hex-separator" />
        <span className="hex-ascii">{asciiCells}</span>
      </div>,
    );
  }

  return (
    <div style={{ display: "flex", flexDirection: "column", height: "100%" }}>
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", padding: "4px 8px", borderBottom: "1px solid var(--md-border)", fontSize: 12 }}>
        <span style={{ color: "var(--md-text-secondary)" }}>
          A: <strong>{nameFromPath(pathA)}</strong> | B: <strong>{nameFromPath(pathB)}</strong>
        </span>
        <span style={{ color: "var(--md-text-muted)" }}>
          {t("overlay.page", { current: currentPage + 1, total: totalPages })}
        </span>
      </div>
      <div style={{ flex: 1, overflow: "auto", opacity: loading ? 0.5 : 1 }}>
        {rows}
      </div>
      <div style={{ display: "flex", justifyContent: "center", gap: 8, padding: "4px 8px", borderTop: "1px solid var(--md-border)" }}>
        <button disabled={currentPage === 0} onClick={() => loadPage(offset - PAGE_SIZE)}>
          {t("overlay.prev")}
        </button>
        <button disabled={currentPage >= totalPages - 1} onClick={() => loadPage(offset + PAGE_SIZE)}>
          {t("overlay.next")}
        </button>
      </div>
    </div>
  );
}

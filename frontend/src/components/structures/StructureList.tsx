import { useEffect, useState, useCallback } from "react";
import { StructureEditor } from "./StructureEditor";
import { downloadJsonFile } from "@/utils/download";
import { useHexStore } from "@/stores/hex-store";
import { useActiveDump } from "@/hooks/useActiveDump";
import { autoDetectStructure, applyStructure } from "@/api/client";

interface StructureEntry {
  name: string;
  protocol: string;
  description: string;
  total_size: number;
  field_count: number;
  tags: string[];
}

function groupByProtocol(items: StructureEntry[]) {
  const groups: Record<string, StructureEntry[]> = {};
  for (const s of items) {
    const key = s.protocol || "general";
    (groups[key] ??= []).push(s);
  }
  return Object.entries(groups).sort(([a], [b]) => a.localeCompare(b));
}

function downloadJson(name: string) {
  fetch(`/api/structures/${encodeURIComponent(name)}/export`)
    .then((r) => r.json())
    .then((data) => downloadJsonFile(data, `${name}.json`));
}

export function StructureList() {
  const [structures, setStructures] = useState<StructureEntry[]>([]);
  const [loading, setLoading] = useState(true);
  const [showEditor, setShowEditor] = useState(false);
  const [applyingName, setApplyingName] = useState<string | null>(null);
  const [detecting, setDetecting] = useState(false);
  const [detectResult, setDetectResult] = useState<string | null>(null);

  const activeDump = useActiveDump();
  const cursorOffset = useHexStore((s) => s.cursorOffset);
  const setOverlay = useHexStore((s) => s.setActiveStructureOverlay);
  const dumpPath = activeDump?.path ?? "";
  const canApply = !!dumpPath && cursorOffset !== null;

  const reload = useCallback(() => {
    setLoading(true);
    fetch("/api/structures/list")
      .then((r) => r.json())
      .then(setStructures)
      .catch(() => {})
      .finally(() => setLoading(false));
  }, []);

  useEffect(reload, [reload]);

  const handleApply = async (name: string) => {
    if (!canApply) return;
    setApplyingName(name);
    try {
      const res = await applyStructure(dumpPath, cursorOffset!, name);
      setOverlay({
        structureName: res.structure.name,
        baseOffset: res.structure.offset,
        totalSize: res.structure.total_size,
        fields: res.structure.fields,
      });
    } catch {
      // silently ignore
    } finally {
      setApplyingName(null);
    }
  };

  const handleAutoDetect = async () => {
    if (!canApply) return;
    setDetecting(true);
    setDetectResult(null);
    try {
      const res = await autoDetectStructure(dumpPath, cursorOffset!);
      if (res.match) {
        setOverlay({
          structureName: res.match.name,
          baseOffset: cursorOffset!,
          totalSize: res.match.total_size,
          fields: res.match.fields,
        });
        setDetectResult(`Matched: ${res.match.name} (${(res.match.confidence * 100).toFixed(0)}%)`);
      } else {
        setDetectResult("No matching structure found");
      }
    } catch {
      setDetectResult("Detection failed");
    } finally {
      setDetecting(false);
    }
  };

  const handleDelete = (name: string) => {
    fetch(`/api/structures/${encodeURIComponent(name)}`, { method: "DELETE" })
      .then((r) => { if (r.ok) reload(); });
  };

  if (loading) {
    return (
      <div className="p-3 text-xs md-text-muted flex items-center gap-2">
        <span className="inline-block w-3 h-3 border-2 border-current border-t-transparent rounded-full animate-spin" />
        Loading structures...
      </div>
    );
  }

  const grouped = groupByProtocol(structures);

  return (
    <div className="p-3 text-xs space-y-3" data-tour-id="structures-panel">
      <div className="flex items-center justify-between">
        <h3 className="text-sm font-semibold md-text-accent">Structure Definitions</h3>
        <button
          onClick={() => setShowEditor(true)}
          className="px-2 py-1 text-xs font-medium rounded border border-[var(--md-border)] hover:bg-[var(--md-bg-hover)]"
        >
          + Create New
        </button>
      </div>

      <div className="flex gap-1">
        <button
          onClick={handleAutoDetect}
          disabled={!canApply || detecting}
          data-tour-id="structure-autodetect-button"
          className="flex-1 px-2 py-1 text-xs font-medium rounded border border-[var(--md-border)] hover:bg-[var(--md-bg-hover)] disabled:opacity-40"
          title={!canApply ? "Position cursor on hex view first" : "Auto-detect structure at cursor offset"}
        >
          {detecting ? "Detecting..." : "Auto-detect at cursor"}
        </button>
      </div>

      {detectResult && (
        <p className="text-[10px] md-text-muted">{detectResult}</p>
      )}

      {showEditor && (
        <StructureEditor
          onSave={() => { setShowEditor(false); reload(); }}
          onCancel={() => setShowEditor(false)}
        />
      )}

      {structures.length === 0 ? (
        <p className="md-text-muted">No structures defined.</p>
      ) : (
        grouped.map(([protocol, items]) => (
          <div key={protocol}>
            <div className="font-medium md-text-secondary uppercase tracking-wider text-[10px] mb-1">
              {protocol}
            </div>
            <div className="space-y-1 ml-1 border-l border-[var(--md-border)] pl-2">
              {items.map((s) => (
                <div key={s.name} className="flex items-start gap-2 py-1 px-1 rounded hover:bg-[var(--md-bg-hover)]">
                  <div className="flex-1 min-w-0">
                    <span className="font-semibold">{s.name}</span>
                    <span className="ml-2 md-text-muted">{s.total_size}B / {s.field_count} fields</span>
                    {s.description && (
                      <div className="md-text-muted truncate" title={s.description}>
                        {s.description.length > 60 ? s.description.slice(0, 60) + "..." : s.description}
                      </div>
                    )}
                  </div>
                  <button
                    onClick={() => handleApply(s.name)}
                    disabled={!canApply || applyingName === s.name}
                    data-tour-id="structure-apply-button"
                    className="px-1 hover:md-text-accent disabled:opacity-30"
                    title={canApply ? `Apply at offset 0x${(cursorOffset ?? 0).toString(16)}` : "Position cursor on hex view first"}
                  >
                    {applyingName === s.name ? "..." : "\u25B6"}
                  </button>
                  <button onClick={() => downloadJson(s.name)} className="px-1 hover:md-text-accent" title="Export JSON">
                    &#x2913;
                  </button>
                  <button onClick={() => handleDelete(s.name)} className="px-1 hover:text-[var(--md-accent-red)]" title="Delete">
                    x
                  </button>
                </div>
              ))}
            </div>
          </div>
        ))
      )}
    </div>
  );
}

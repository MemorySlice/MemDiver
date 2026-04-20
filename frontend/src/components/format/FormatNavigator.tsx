import { useEffect, useRef, useState } from "react";
import { useHexStore } from "@/stores/hex-store";
import { detectFormat, importKsy } from "@/api/client";

interface NavNode {
  label: string;
  offset: number;
  size: number;
  node_type: string;
  children: NavNode[];
}

interface FieldOverlay {
  field_name: string;
  offset: number;
  length: number;
  display: string;
  description: string;
  path: string;
  valid: boolean;
}

interface OverlaysInfo {
  structure_name: string;
  base_offset: number;
  fields: FieldOverlay[];
}

interface FormatInfo {
  format: string | null;
  nav_tree: NavNode | null;
  overlays: OverlaysInfo | null;
}

interface Props {
  dumpPath: string;
}

const TYPE_ICONS: Record<string, string> = {
  header: "\u{1F4CB}",
  section: "\u{1F4C2}",
  segment: "\u{1F9E9}",
};

function NodeRow({ node, depth }: { node: NavNode; depth: number }) {
  const [expanded, setExpanded] = useState(depth < 1);
  const hasChildren = node.children.length > 0;
  const handleNodeClick = (clickedNode: NavNode) => {
    const store = useHexStore.getState();
    store.scrollToOffset(clickedNode.offset);
    const overlay = store.activeStructureOverlay;
    const matchesField =
      overlay?.fields.some((f) => f.offset === clickedNode.offset) ?? false;
    if (matchesField) {
      store.setActiveFieldOffset(clickedNode.offset);
    } else {
      store.setHighlightedRegions([
        ...store.highlightedRegions.filter((r) => r.type !== "structure"),
        {
          offset: clickedNode.offset,
          length: clickedNode.size,
          type: "structure",
          label: clickedNode.label,
        },
      ]);
      store.setActiveFieldOffset(null);
    }
  };

  return (
    <div>
      <button
        className="flex items-center gap-1 w-full text-left py-0.5 hover:bg-[var(--md-bg-hover)] rounded px-1"
        style={{ paddingLeft: `${depth * 16 + 4}px` }}
        onClick={() => {
          if (hasChildren) setExpanded((p) => !p);
          handleNodeClick(node);
        }}
      >
        {hasChildren ? (
          <span className="md-text-secondary text-[10px] w-3 text-center">
            {expanded ? "\u25BC" : "\u25B6"}
          </span>
        ) : (
          <span className="w-3" />
        )}
        <span>{TYPE_ICONS[node.node_type] ?? "\u2022"}</span>
        <span className="truncate font-medium">{node.label}</span>
        <span className="ml-auto font-mono text-[10px] md-text-muted shrink-0">
          0x{node.offset.toString(16)}
        </span>
      </button>
      {expanded &&
        hasChildren &&
        node.children.map((child, i) => (
          <NodeRow key={i} node={child} depth={depth + 1} />
        ))}
    </div>
  );
}

export function FormatNavigator({ dumpPath }: Props) {
  const [info, setInfo] = useState<FormatInfo | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    setInfo(null);
    setError(null);
    let cancelled = false;
    detectFormat(dumpPath)
      .then((data) => {
        if (cancelled) return;
        setInfo(data as unknown as FormatInfo);
        if (data.overlays && data.overlays.fields.length > 0) {
          useHexStore.getState().setActiveStructureOverlay({
            structureName: data.overlays.structure_name,
            baseOffset: data.overlays.base_offset,
            totalSize: Math.max(...data.overlays.fields.map((f) => f.offset + f.length)),
            fields: data.overlays.fields.map((f) => ({
              name: f.field_name,
              offset: f.offset,
              length: f.length,
              display: `${f.path || f.field_name}: ${f.display}`,
              valid: f.valid,
            })),
          });
        }
      })
      .catch((e) => {
        if (!cancelled) setError(e instanceof Error ? e.message : String(e));
      });
    return () => { cancelled = true; };
  }, [dumpPath]);

  if (error) {
    return (
      <div className="p-3 text-xs md-text-muted">
        Format detection failed: {error}
      </div>
    );
  }

  if (!info) {
    return <div className="p-3 text-xs md-text-muted">Detecting format...</div>;
  }

  if (!info.format) {
    return (
      <div className="p-3 text-xs space-y-2">
        <p className="md-text-muted">No format detected</p>
        <KsyImportButton />
      </div>
    );
  }

  return (
    <div className="p-3 text-xs space-y-2">
      <div className="flex items-center gap-2">
        <h3 className="text-sm font-semibold md-text-accent">Format</h3>
        <span className="px-1.5 py-0.5 rounded bg-[var(--md-bg-hover)] font-mono text-[10px] md-text-secondary">
          {info.format}
        </span>
      </div>
      {info.nav_tree ? (
        <div className="space-y-0">
          <NodeRow node={info.nav_tree} depth={0} />
        </div>
      ) : (
        <p className="md-text-muted">
          Header structures reference data beyond the loaded window.
        </p>
      )}
      {info.overlays && (
        <p className="md-text-muted text-[10px]">
          {info.overlays.fields.length} fields parsed via Kaitai Struct
        </p>
      )}
      <KsyImportButton />
    </div>
  );
}

function KsyImportButton() {
  const fileRef = useRef<HTMLInputElement>(null);
  const [msg, setMsg] = useState<string | null>(null);

  const handleUpload = async (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;
    setMsg("Importing...");
    try {
      const data = await importKsy(file);
      setMsg(`Imported: ${data.name}`);
    } catch (err) {
      setMsg(err instanceof Error ? err.message : "Import failed");
    }
    if (fileRef.current) fileRef.current.value = "";
  };

  return (
    <div className="pt-1 border-t border-[var(--md-border)]">
      <input ref={fileRef} type="file" accept=".ksy,.yaml,.yml" onChange={handleUpload} className="hidden" />
      <button
        onClick={() => fileRef.current?.click()}
        className="text-[10px] px-2 py-0.5 rounded border border-[var(--md-border)] hover:bg-[var(--md-bg-hover)] transition-colors"
      >
        Import .ksy Template
      </button>
      {msg && <p className="mt-1 text-[10px] md-text-muted">{msg}</p>}
    </div>
  );
}

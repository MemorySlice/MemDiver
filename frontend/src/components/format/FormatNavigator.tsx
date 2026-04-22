import { useEffect, useRef, useState } from "react";
import { useHexStore } from "@/stores/hex-store";
import { detectFormat, importKsy } from "@/api/client";
import type { FormatSuggestion } from "@/api/types";
import { splitSuggested } from "./FormatNavigator.helpers";

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
  detected_format?: string | null;
  forced?: boolean;
  suggested_formats?: FormatSuggestion[];
  available_formats?: string[];
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
        aria-expanded={hasChildren ? expanded : undefined}
        onClick={() => {
          if (hasChildren) setExpanded((p) => !p);
          handleNodeClick(node);
        }}
      >
        {hasChildren ? (
          <span className="md-text-secondary text-[10px] w-3 text-center">
            {expanded ? "▼" : "▶"}
          </span>
        ) : (
          <span className="w-3" />
        )}
        <span>{TYPE_ICONS[node.node_type] ?? "•"}</span>
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

function applyOverlayToStore(overlays: OverlaysInfo | null): void {
  const store = useHexStore.getState();
  if (!overlays || overlays.fields.length === 0) {
    store.setActiveStructureOverlay(null);
    return;
  }
  store.setActiveStructureOverlay({
    structureName: overlays.structure_name,
    baseOffset: overlays.base_offset,
    totalSize: Math.max(...overlays.fields.map((f) => f.offset + f.length)),
    fields: overlays.fields.map((f) => ({
      name: f.field_name,
      offset: f.offset,
      length: f.length,
      display: `${f.path || f.field_name}: ${f.display}`,
      valid: f.valid,
    })),
  });
}

interface PickerProps {
  info: FormatInfo;
  onSelect: (format: string | null) => void;
}

function ParserPicker({ info, onSelect }: PickerProps) {
  const [open, setOpen] = useState(false);
  const [showOthers, setShowOthers] = useState(false);
  const ref = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (!open) return;
    const handler = (e: MouseEvent) => {
      if (ref.current && !ref.current.contains(e.target as Node)) setOpen(false);
    };
    document.addEventListener("mousedown", handler);
    return () => document.removeEventListener("mousedown", handler);
  }, [open]);

  const { suggested, others } = splitSuggested(
    info.available_formats,
    info.suggested_formats,
  );

  const handlePick = (fmt: string | null) => {
    setOpen(false);
    onSelect(fmt);
  };

  const activeFormat = info.format ?? "";

  return (
    <div ref={ref} className="relative inline-block">
      <button
        onClick={() => setOpen((p) => !p)}
        data-testid="format-pill"
        className="px-1.5 py-0.5 rounded bg-[var(--md-bg-hover)] font-mono text-[10px] md-text-secondary hover:bg-[var(--md-bg-active)] transition-colors cursor-pointer"
        aria-haspopup="menu"
        aria-expanded={open}
        title="Change parser"
      >
        {activeFormat}
        {info.forced && (
          <span className="ml-1 md-text-muted">(forced)</span>
        )}
        <span className="ml-1 md-text-muted">{"▾"}</span>
      </button>
      {open && (
        <div
          role="menu"
          className="absolute left-0 top-full mt-1 w-56 max-h-[60vh] overflow-auto rounded border border-[var(--md-border)] bg-[var(--md-bg-primary)] shadow-lg z-50 text-xs"
        >
          <div className="px-3 py-1.5 border-b border-[var(--md-border)] text-[10px] uppercase tracking-wider font-semibold md-text-muted">
            Parser
          </div>

          {suggested.length > 0 && (
            <div className="py-1 border-b border-[var(--md-border)]">
              <div className="px-3 py-0.5 text-[10px] md-text-muted">
                Suggested
              </div>
              {suggested.map((s) => (
                <SuggestedRow
                  key={s.format}
                  suggestion={s}
                  active={s.format === activeFormat}
                  onSelect={handlePick}
                />
              ))}
            </div>
          )}

          <div className="py-1 border-b border-[var(--md-border)]">
            <button
              onClick={() => setShowOthers((p) => !p)}
              aria-expanded={showOthers}
              className="w-full flex items-center gap-1 px-3 py-0.5 text-[10px] md-text-muted hover:bg-[var(--md-bg-hover)]"
            >
              <span className="w-3 text-center">
                {showOthers ? "▼" : "▶"}
              </span>
              <span>Other parsers ({others.length})</span>
            </button>
            {showOthers &&
              others.map((fmt) => (
                <OtherRow
                  key={fmt}
                  format={fmt}
                  active={fmt === activeFormat}
                  onSelect={handlePick}
                />
              ))}
          </div>

          <button
            onClick={() => handlePick(null)}
            disabled={!info.forced}
            role="menuitem"
            className="w-full text-left px-3 py-1 md-text-secondary hover:bg-[var(--md-bg-hover)] disabled:opacity-40 disabled:cursor-not-allowed"
          >
            Reset to auto
          </button>
        </div>
      )}
    </div>
  );
}

interface SuggestedRowProps {
  suggestion: FormatSuggestion;
  active: boolean;
  onSelect: (fmt: string) => void;
}

function SuggestedRow({ suggestion, active, onSelect }: SuggestedRowProps) {
  return (
    <button
      onClick={() => onSelect(suggestion.format)}
      role="menuitem"
      className="w-full flex items-center gap-2 px-3 py-1 text-left hover:bg-[var(--md-bg-hover)] md-text-secondary"
      title={suggestion.reason}
    >
      <span className="w-3 text-center md-text-accent">
        {active ? "✓" : "★"}
      </span>
      <span className="font-mono">{suggestion.format}</span>
      <span className="ml-auto text-[10px] md-text-muted">recommended</span>
    </button>
  );
}

interface OtherRowProps {
  format: string;
  active: boolean;
  onSelect: (fmt: string) => void;
}

function OtherRow({ format, active, onSelect }: OtherRowProps) {
  return (
    <button
      onClick={() => onSelect(format)}
      role="menuitem"
      className="w-full flex items-center gap-2 px-3 py-1 text-left hover:bg-[var(--md-bg-hover)] md-text-secondary"
      title="Magic doesn't match — may misparse"
    >
      <span className="w-3 text-center">{active ? "✓" : ""}</span>
      <span className="font-mono">{format}</span>
      <span
        className="ml-auto text-[10px] md-text-muted"
        aria-label="Warning: magic doesn't match"
      >
        {"⚠"}
      </span>
    </button>
  );
}

export function FormatNavigator({ dumpPath }: Props) {
  const [info, setInfo] = useState<FormatInfo | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [forcedFormat, setForcedFormat] = useState<string | null>(null);
  // Reset the user's parser override when the viewed dump changes by
  // comparing against the previous prop during render — idiomatic React
  // "adjusting state while rendering" pattern.
  const [lastDumpPath, setLastDumpPath] = useState<string>(dumpPath);
  if (lastDumpPath !== dumpPath) {
    setLastDumpPath(dumpPath);
    setForcedFormat(null);
  }

  useEffect(() => {
    setInfo(null);
    setError(null);
    // Clear any stale structure overlay from the previous dump/parser
    // immediately — otherwise e.g. ELF field boxes linger across a dump
    // switch until the new detect call lands.
    useHexStore.getState().setActiveStructureOverlay(null);

    let cancelled = false;
    detectFormat(dumpPath, 0, forcedFormat ?? undefined)
      .then((data) => {
        if (cancelled) return;
        const next = data as unknown as FormatInfo;
        setInfo(next);
        applyOverlayToStore(next.overlays);
      })
      .catch((e) => {
        if (!cancelled) setError(e instanceof Error ? e.message : String(e));
      });
    return () => {
      cancelled = true;
    };
  }, [dumpPath, forcedFormat]);

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
        <ParserPicker info={info} onSelect={setForcedFormat} />
        {info.forced && (
          <button
            onClick={() => setForcedFormat(null)}
            className="text-[10px] md-text-muted hover:md-text-secondary underline"
            title="Reset to auto-detected parser"
          >
            Reset
          </button>
        )}
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

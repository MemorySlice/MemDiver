import { useState } from "react";

const FIELD_TYPES = [
  "uint8", "uint16_le", "uint16_be", "uint32_le", "uint32_be",
  "uint64_le", "uint64_be", "bytes", "pointer", "utf8_string",
] as const;

interface FieldRow {
  name: string;
  field_type: string;
  offset: number;
  size: number;
  description: string;
}

const emptyField = (): FieldRow => ({
  name: "", field_type: "uint8", offset: 0, size: 1, description: "",
});

interface Props {
  onSave: () => void;
  onCancel: () => void;
}

export function StructureEditor({ onSave, onCancel }: Props) {
  const [name, setName] = useState("");
  const [description, setDescription] = useState("");
  const [protocol, setProtocol] = useState("");
  const [tags, setTags] = useState("");
  const [totalSize, setTotalSize] = useState(0);
  const [fields, setFields] = useState<FieldRow[]>([emptyField()]);
  const [errors, setErrors] = useState<string[]>([]);
  const [saving, setSaving] = useState(false);

  const updateField = (i: number, patch: Partial<FieldRow>) => {
    setFields((prev) => prev.map((f, idx) => (idx === i ? { ...f, ...patch } : f)));
  };

  const removeField = (i: number) => setFields((prev) => prev.filter((_, idx) => idx !== i));

  const handleSave = async () => {
    setSaving(true);
    setErrors([]);
    try {
      const body = {
        name,
        description,
        protocol,
        total_size: totalSize,
        tags: tags.split(",").map((t) => t.trim()).filter(Boolean),
        fields: fields.map((f) => ({
          name: f.name, field_type: f.field_type, offset: f.offset,
          size: f.size, description: f.description,
        })),
      };
      const res = await fetch("/api/structures/create", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(body),
      });
      if (!res.ok) {
        const data = await res.json();
        const detail = data.detail;
        setErrors(Array.isArray(detail) ? detail : [String(detail)]);
        return;
      }
      onSave();
    } catch (e) {
      setErrors([String(e)]);
    } finally {
      setSaving(false);
    }
  };

  const inputCls = "w-full px-2 py-1 rounded border border-[var(--md-border)] bg-[var(--md-bg-secondary)] text-xs";

  return (
    <div className="p-3 rounded border border-[var(--md-accent)] bg-[var(--md-bg-secondary)] space-y-3 text-xs">
      <h4 className="text-sm font-semibold md-text-accent">New Structure</h4>

      <div className="grid grid-cols-2 gap-2">
        <label>
          <span className="md-text-muted">Name</span>
          <input className={inputCls} value={name} onChange={(e) => setName(e.target.value)} placeholder="my_struct" />
        </label>
        <label>
          <span className="md-text-muted">Total Size (bytes)</span>
          <input className={inputCls} type="number" min={1} value={totalSize} onChange={(e) => setTotalSize(+e.target.value)} />
        </label>
        <label>
          <span className="md-text-muted">Protocol</span>
          <input className={inputCls} value={protocol} onChange={(e) => setProtocol(e.target.value)} placeholder="TLS, SSH, ..." />
        </label>
        <label>
          <span className="md-text-muted">Tags (comma-separated)</span>
          <input className={inputCls} value={tags} onChange={(e) => setTags(e.target.value)} placeholder="crypto, header" />
        </label>
      </div>

      <label>
        <span className="md-text-muted">Description</span>
        <input className={inputCls} value={description} onChange={(e) => setDescription(e.target.value)} />
      </label>

      <div>
        <div className="flex items-center justify-between mb-1">
          <span className="font-medium md-text-secondary">Fields</span>
          <button onClick={() => setFields((p) => [...p, emptyField()])} className="px-2 py-0.5 rounded border border-[var(--md-border)] hover:bg-[var(--md-bg-hover)]">
            + Add Field
          </button>
        </div>
        <table className="w-full text-xs">
          <thead>
            <tr className="md-text-muted text-left">
              <th className="pr-1">Name</th><th className="pr-1">Type</th><th className="pr-1 w-16">Offset</th>
              <th className="pr-1 w-16">Size</th><th className="pr-1">Desc</th><th className="w-8" />
            </tr>
          </thead>
          <tbody>
            {fields.map((f, i) => (
              <tr key={i} className="border-t border-[var(--md-border)]">
                <td className="pr-1 py-0.5"><input className={inputCls} value={f.name} onChange={(e) => updateField(i, { name: e.target.value })} /></td>
                <td className="pr-1 py-0.5">
                  <select className={inputCls} value={f.field_type} onChange={(e) => updateField(i, { field_type: e.target.value })}>
                    {FIELD_TYPES.map((t) => <option key={t} value={t}>{t}</option>)}
                  </select>
                </td>
                <td className="pr-1 py-0.5"><input className={inputCls} type="number" min={0} value={f.offset} onChange={(e) => updateField(i, { offset: +e.target.value })} /></td>
                <td className="pr-1 py-0.5"><input className={inputCls} type="number" min={1} value={f.size} onChange={(e) => updateField(i, { size: +e.target.value })} /></td>
                <td className="pr-1 py-0.5"><input className={inputCls} value={f.description} onChange={(e) => updateField(i, { description: e.target.value })} /></td>
                <td><button onClick={() => removeField(i)} className="px-1 hover:text-[var(--md-accent-red)]" title="Remove">x</button></td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      {errors.length > 0 && (
        <div className="p-2 rounded border border-[var(--md-accent-red)] bg-[var(--md-bg-primary)] text-[var(--md-accent-red)]">
          {errors.map((e, i) => <div key={i}>{e}</div>)}
        </div>
      )}

      <div className="flex gap-2 justify-end">
        <button onClick={onCancel} className="px-3 py-1 rounded border border-[var(--md-border)] hover:bg-[var(--md-bg-hover)]">
          Cancel
        </button>
        <button onClick={handleSave} disabled={saving} className="px-3 py-1 rounded border border-[var(--md-accent)] bg-[var(--md-accent)] text-[var(--md-bg-primary)] font-medium disabled:opacity-40">
          {saving ? "Saving..." : "Save"}
        </button>
      </div>
    </div>
  );
}

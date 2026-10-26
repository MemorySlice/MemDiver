import type {
  IsfBaseType, IsfEnum, IsfItem, IsfSection, IsfStruct, IsfSymbol, TypeDescriptor,
} from "@/api/isf";

export function formatType(d: TypeDescriptor | undefined): string {
  if (!d) return "?";
  if (d.kind === "pointer") return `${formatType(d.subtype)}*`;
  if (d.kind === "array") return `${formatType(d.subtype)}[${d.count ?? "?"}]`;
  return d.kind === "base" ? (d.name ?? "?") : `${d.kind} ${d.name ?? "?"}`;
}

/** One-line description of an entry, by section. */
export function summarize(section: IsfSection, item: IsfItem): string {
  if (section === "symbols") {
    const s = item as IsfSymbol;
    return s.type ? `${s.address} : ${formatType(s.type)}` : s.address;
  }
  if (section === "user_types") {
    const s = item as IsfStruct;
    return `${s.kind ?? "struct"} size ${s.size}, ${Object.keys(s.fields ?? {}).length} fields`;
  }
  if (section === "base_types") {
    const b = item as IsfBaseType;
    return `${b.kind} size ${b.size} ${b.signed ? "signed" : "unsigned"} ${b.endian}`;
  }
  const e = item as IsfEnum;
  return `${e.base} size ${e.size}, ${Object.keys(e.constants ?? {}).length} constants`;
}

export interface EntryRef { section: IsfSection; name: string; field?: string }

/**
 * An implicated item from a try (`task_struct.tasks`, `symbol:init_task`, `type:cred`)
 * as the tree entry it names.
 */
export function entryOfImplicated(item: string): EntryRef | null {
  const sym = /^symbol:(.+)$/.exec(item);
  if (sym) return { section: "symbols", name: sym[1] };
  const type = /^type:(.+)$/.exec(item);
  if (type) return { section: "user_types", name: type[1] };
  const dot = item.indexOf(".");
  if (dot > 0) return { section: "user_types", name: item.slice(0, dot), field: item.slice(dot + 1) };
  return item.trim() === "" ? null : { section: "user_types", name: item };
}

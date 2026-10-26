import type { TypeDescriptor } from "@/api/isf";

export const defaultDescriptor = (kind: string): TypeDescriptor => {
  if (kind === "pointer") return { kind, subtype: { kind: "base", name: "void" } };
  if (kind === "array") return { kind, count: 1, subtype: { kind: "base", name: "unsigned char" } };
  return { kind, name: kind === "base" ? "unsigned long" : "" };
};

/** A descriptor is submittable when every leaf is named and every array has a count. */
export function descriptorComplete(d: TypeDescriptor): boolean {
  if (d.kind === "pointer") return d.subtype !== undefined && descriptorComplete(d.subtype);
  if (d.kind === "array") {
    return Number.isInteger(d.count) && (d.count ?? 0) >= 0 && d.subtype !== undefined
      && descriptorComplete(d.subtype);
  }
  return (d.name ?? "").trim() !== "";
}

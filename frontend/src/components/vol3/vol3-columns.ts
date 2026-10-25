/** Spaces the user may reinterpret a column as (`null` on the wire = not an address). */
export const SPACE_CHOICES = ["physical", "kernel_va", "process_va"] as const;

/** Column name -> chosen space; `null` = "not an address", absent = the plugin's own. */
export type ColumnOverrides = Record<string, string | null>;

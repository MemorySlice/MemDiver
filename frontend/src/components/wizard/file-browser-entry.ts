import type { MouseEvent } from "react";

// Shared by the FileBrowser* components; kept out of the .tsx component files
// so those export only components (react-refresh/only-export-components).

export const ENTRY_ROW_ATTR = "data-entry-row";

export const preventMouseDownFocus = (e: MouseEvent) => e.preventDefault();

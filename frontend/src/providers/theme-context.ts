import { createContext } from "react";

// Lives apart from ThemeProvider.tsx so that file exports only a component
// (react-refresh/only-export-components keeps Fast Refresh working).

export type Theme = "light" | "dark";

export interface ThemeContextValue {
  theme: Theme;
  resolvedTheme: Theme;
  setTheme: (t: Theme) => void;
  highContrast: boolean;
  toggleHighContrast: () => void;
}

export const ThemeContext = createContext<ThemeContextValue | null>(null);

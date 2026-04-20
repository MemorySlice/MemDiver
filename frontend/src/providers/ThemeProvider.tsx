import { createContext, useContext, useEffect, useState } from "react";
import type { ReactNode } from "react";

type Theme = "light" | "dark";

interface ThemeContextValue {
  theme: Theme;
  resolvedTheme: Theme;
  setTheme: (t: Theme) => void;
  highContrast: boolean;
  toggleHighContrast: () => void;
}

const ThemeContext = createContext<ThemeContextValue | null>(null);

export function ThemeProvider({ children }: { children: ReactNode }) {
  const [theme, setThemeState] = useState<Theme>(() => {
    const stored = localStorage.getItem("memdiver-theme");
    if (stored === "light" || stored === "dark") return stored;
    return "dark";
  });

  const [highContrast, setHighContrast] = useState<boolean>(() => {
    return localStorage.getItem("memdiver-high-contrast") === "true";
  });

  useEffect(() => {
    document.documentElement.classList.toggle("dark", theme === "dark");
    localStorage.setItem("memdiver-theme", theme);
  }, [theme]);

  useEffect(() => {
    document.documentElement.classList.toggle("high-contrast", highContrast);
    localStorage.setItem("memdiver-high-contrast", String(highContrast));
  }, [highContrast]);

  const setTheme = (t: Theme) => setThemeState(t);
  const toggleHighContrast = () => setHighContrast((prev) => !prev);

  return (
    <ThemeContext value={{ theme, resolvedTheme: theme, setTheme, highContrast, toggleHighContrast }}>
      {children}
    </ThemeContext>
  );
}

export function useTheme(): ThemeContextValue {
  const ctx = useContext(ThemeContext);
  if (!ctx) throw new Error("useTheme must be used within ThemeProvider");
  return ctx;
}

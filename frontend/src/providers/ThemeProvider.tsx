import { createContext, useContext, useEffect, useState } from "react";
import type { ReactNode } from "react";
import { useSettingsStore } from "@/stores/settings-store";

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

  // Theme/high-contrast historically lived in two unsynchronized places:
  // ThemeProvider's own localStorage keys and settings-store's
  // display.theme/display.highContrast. Writing through to the settings
  // store here keeps the two copies in sync regardless of whether the user
  // toggled via ThemeToggle or the settings menu, avoiding drift.
  const setTheme = (t: Theme) => {
    setThemeState(t);
    useSettingsStore.getState().updateDisplay({ theme: t });
  };
  const toggleHighContrast = () => {
    // Compute the next value from the current state in the event handler and
    // write through to the settings store here — NOT inside the setState
    // updater. A store write inside the updater runs during React's render
    // phase and synchronously notifies subscribers (e.g. SettingsMenu),
    // triggering "Cannot update a component while rendering a different
    // component". This mirrors setTheme's event-time write above.
    const next = !highContrast;
    setHighContrast(next);
    useSettingsStore.getState().updateDisplay({ highContrast: next });
  };

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

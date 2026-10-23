import type { AppMode } from "@/stores/app-store";

/** The accent token each mode's selected button and toolbar badge wears. */
export const MODE_ACCENT: Readonly<Record<AppMode, string>> = {
  verification: "var(--md-accent-blue)",
  exploration: "var(--md-accent-purple)",
  heap: "var(--md-accent-cyan)",
};

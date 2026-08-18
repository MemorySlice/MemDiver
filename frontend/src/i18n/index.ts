import i18n from "i18next";
import { initReactI18next } from "react-i18next";

/**
 * Auto-discovering i18n bootstrap.
 *
 * Every English namespace lives in its own JSON file under
 * `./locales/en/<namespace>.json`. Vite's `import.meta.glob` eager-loads them
 * all at build time, and we derive the namespace name from each file's
 * basename (e.g. `hex.json` -> namespace `"hex"`).
 *
 * KEY DESIGN POINT: adding a new `locales/en/<ns>.json` later auto-registers
 * that namespace with ZERO edits to this file. Parallel migration agents can
 * each add their own namespace file without ever touching a shared module.
 */
type LocaleModule = { default: Record<string, unknown> };

const enModules = import.meta.glob<LocaleModule>("./locales/en/*.json", {
  eager: true,
});

const enNamespaces: Record<string, Record<string, unknown>> = {};

for (const [filePath, mod] of Object.entries(enModules)) {
  // "./locales/en/hex.json" -> "hex"
  const namespace = filePath.split("/").pop()!.replace(/\.json$/, "");
  enNamespaces[namespace] = mod.default;
}

const namespaceList = Object.keys(enNamespaces);

const resources = {
  en: enNamespaces,
};

void i18n.use(initReactI18next).init({
  resources,
  // Single-locale (en-only) is an intentional current choice, not a bug —
  // there is no locale switcher and no other `locales/<lng>/` directory yet.
  lng: "en",
  fallbackLng: "en",
  defaultNS: "common",
  ns: namespaceList,
  interpolation: {
    // React already escapes values, so disable i18next's own escaping.
    escapeValue: false,
  },
  react: {
    // The instance is initialized at import time, so we do not need Suspense
    // to gate rendering on async resource loading.
    useSuspense: false,
  },
});

export default i18n;

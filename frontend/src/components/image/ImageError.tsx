import { useTranslation } from "react-i18next";

import type { ImplicatedItem } from "./failure-details";

const NEEDS_EXTRA = /volatility|pakunoda|vol3|pip install/i;

/** A readable backend failure (already unwrapped from the JSON envelope). */
export function ImageError({ message, implicated = [] }: { message: string; implicated?: ImplicatedItem[] }) {
  const { t } = useTranslation("image");
  const hint = NEEDS_EXTRA.test(message) && !message.includes("memdiver[image]");
  return (
    <div role="alert" data-testid="image-error" className="text-xs space-y-0.5"
      style={{ color: "var(--md-accent-red)" }}>
      <p>{message}</p>
      {implicated.length > 0 && (
        <div data-testid="image-error-implicated" className="space-y-0.5">
          <span className="md-text-secondary">{t("error.implicated")}</span>
          <ul className="list-disc pl-4">
            {implicated.map((i) => (
              <li key={i.item} className="font-mono" title={i.reason}>
                {i.item}{i.reason ? <span className="md-text-muted font-sans"> - {i.reason}</span> : null}</li>
            ))}
          </ul>
        </div>
      )}
      {hint && <p className="md-text-muted">{t("error.installHint")}</p>}
    </div>
  );
}

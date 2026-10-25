import { useTranslation } from "react-i18next";

const NEEDS_EXTRA = /volatility|pakunoda|vol3|pip install/i;

/** A readable backend failure (already unwrapped from the JSON envelope). */
export function ImageError({ message }: { message: string }) {
  const { t } = useTranslation("image");
  const hint = NEEDS_EXTRA.test(message) && !message.includes("memdiver[image]");
  return (
    <div role="alert" data-testid="image-error" className="text-xs space-y-0.5"
      style={{ color: "var(--md-accent-red)" }}>
      <p>{message}</p>
      {hint && <p className="md-text-muted">{t("error.installHint")}</p>}
    </div>
  );
}

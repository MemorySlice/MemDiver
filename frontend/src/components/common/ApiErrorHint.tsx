import { useTranslation } from "react-i18next";

import { errorCodeHint } from "@/i18n/error-code-hint";

/**
 * A one-line, localized "what to do about it" for a coded API error, shown
 * beside the server's own message. Renders nothing for a missing or unknown
 * `code` (get it with `apiErrorCode(err)` from `@/api/client`).
 */
export function ApiErrorHint({ code, className }: { code?: string | null; className?: string }) {
  const { i18n } = useTranslation("common");
  const hint = errorCodeHint(code, i18n);
  if (!hint) return null;
  return (
    <p role="note" className={className ?? "md-text-secondary"} data-testid="api-error-hint"
      data-error-code={code ?? undefined}>
      {hint}
    </p>
  );
}

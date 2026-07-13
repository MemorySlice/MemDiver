import { useTranslation } from "react-i18next";
import type { TagStatus } from "@/api/types";

const STYLES: Record<TagStatus, { bg: string; labelKey: string; titleKey: string } | null> = {
  not_encrypted: null,
  valid: {
    bg: "var(--md-accent-green)",
    labelKey: "tagStatus.valid.label",
    titleKey: "tagStatus.valid.title",
  },
  corrupted: {
    bg: "var(--md-accent-red)",
    labelKey: "tagStatus.corrupt.label",
    titleKey: "tagStatus.corrupt.title",
  },
  missing_key: {
    bg: "var(--md-accent-orange)",
    labelKey: "tagStatus.noKey.label",
    titleKey: "tagStatus.noKey.title",
  },
};

export function TagStatusBadge({ status }: { status?: TagStatus }) {
  const { t } = useTranslation("dumps");
  const style = status ? STYLES[status] : null;
  if (!style) return null;
  return (
    <span
      className="px-1.5 py-0.5 rounded text-[10px] font-semibold uppercase"
      style={{ background: style.bg, color: "var(--md-bg-primary)" }}
      title={t(style.titleKey)}
    >
      {t(style.labelKey)}
    </span>
  );
}

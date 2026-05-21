import type { TagStatus } from "@/api/types";

const STYLES: Record<TagStatus, { bg: string; label: string; title: string } | null> = {
  not_encrypted: null,
  valid: {
    bg: "var(--md-accent-green)",
    label: "VALID",
    title: "AEAD tag verified — encrypted dump decrypted successfully",
  },
  corrupted: {
    bg: "var(--md-accent-red)",
    label: "CORRUPT",
    title: "AEAD verification failed — wrong key or tampered file",
  },
  missing_key: {
    bg: "var(--md-accent-orange)",
    label: "NO KEY",
    title: "Encrypted dump opened without a key",
  },
};

export function TagStatusBadge({ status }: { status?: TagStatus }) {
  const style = status ? STYLES[status] : null;
  if (!style) return null;
  return (
    <span
      className="px-1.5 py-0.5 rounded text-[10px] font-semibold uppercase"
      style={{ background: style.bg, color: "var(--md-bg-primary)" }}
      title={style.title}
    >
      {style.label}
    </span>
  );
}

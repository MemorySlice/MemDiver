import { useTranslation } from "react-i18next";

import type { ImageProbe } from "@/api/image";

const formatBytes = (n: number): string => {
  if (n < 1024) return `${n} B`;
  const units = ["KiB", "MiB", "GiB", "TiB"];
  let value = n / 1024;
  let i = 0;
  while (value >= 1024 && i < units.length - 1) { value /= 1024; i += 1; }
  return `${value.toFixed(1)} ${units[i]}`;
};

function Row({ label, value, testId }: { label: string; value: string; testId: string }) {
  return (
    <div className="flex gap-2">
      <dt className="md-text-muted w-24 shrink-0">{label}</dt>
      <dd data-testid={testId} className="break-all font-mono">{value}</dd>
    </div>
  );
}

/** Facts from the cheap probe: format, size, hash, banner, profile status. */
export function ProbeCard({ probe, onScanBanners }: {
  probe: ImageProbe;
  onScanBanners: () => void;
}) {
  const { t } = useTranslation("image");
  const profile = probe.profile;
  const profileText = t(`profile.${profile.status}`, { origin: profile.origin ?? "" });
  const banner = probe.banners?.[0] ?? profile.banner ?? "";
  const tools = Object.entries(probe.versions)
    .map(([name, v]) => `${name} ${v ?? t("probe.toolMissing")}`).join(", ");
  return (
    <div data-testid="image-probe-card" className="md-panel p-2 text-xs">
      <dl className="space-y-1">
        <Row label={t("probe.format")} testId="probe-format"
          value={probe.physical_layer_chain.join(" > ")} />
        <Row label={t("probe.size")} testId="probe-size" value={formatBytes(probe.size)} />
        <Row label={t("probe.sha256")} testId="probe-sha"
          value={probe.image_sha256 ?? t("probe.sha256Unknown")} />
        <Row label={t("probe.banner")} testId="probe-banner"
          value={banner || t("probe.bannerNone")} />
        <Row label={t("probe.profile")} testId="probe-profile" value={profileText} />
        <Row label={t("probe.tools")} testId="probe-tools" value={tools} />
      </dl>
      {!banner && (
        <button onClick={onScanBanners} className="mt-2 underline md-text-secondary">
          {t("probe.scanBanners")}
        </button>
      )}
    </div>
  );
}

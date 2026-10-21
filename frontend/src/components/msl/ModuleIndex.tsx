import { useTranslation } from "react-i18next";
import { mslInspectUrl, useFetchJson } from "@/hooks/useFetchJson";

interface ModuleIndexEntry {
  module_uuid: string;
  base_addr: number;
  size: number;
  path: string;
}

interface Props {
  mslPath: string;
}

function shortUuid(u: string): string {
  return u.split("-")[0] || u.slice(0, 8);
}

function shortPath(p: string): string {
  if (p.length <= 36) return p;
  return "..." + p.slice(-33);
}

export function ModuleIndex({ mslPath }: Props) {
  const { t } = useTranslation("msl");
  const { data, error } = useFetchJson<ModuleIndexEntry[]>(mslInspectUrl("module-index", mslPath));
  const entries = data ?? [];

  if (error) return <p className="p-3 text-xs md-text-error">{error}</p>;
  if (!entries.length) return <p className="p-3 text-xs md-text-muted">{t("moduleIndex.empty")}</p>;

  return (
    <div className="p-3 text-xs space-y-1">
      <h3 className="text-sm font-semibold md-text-accent">{t("moduleIndex.title", { count: entries.length })}</h3>
      <p className="md-text-muted text-[10px]">
        {t("moduleIndex.description")}
      </p>
      <div className="md-panel p-2 space-y-0.5 max-h-40 overflow-auto">
        {entries.map((e, i) => (
          <div key={i} className="font-mono md-text-secondary" title={`${e.path}\n${e.module_uuid}`}>
            <span className="md-text-muted text-[10px] mr-2">{shortUuid(e.module_uuid)}</span>
            <span>{shortPath(e.path)}</span>
            <span className="md-text-muted text-[10px] ml-2">
              0x{e.base_addr.toString(16)}
            </span>
          </div>
        ))}
      </div>
    </div>
  );
}

const STORAGE_PREFIX = "memdiver.isf.caseDir.";

/** `<case>` of a view stored at `<case>/views/<name>.mdview`; "" for any other layout. */
export function caseDirOfView(viewPath: string): string {
  const match = /^(.+)\/views\/[^/]+$/.exec(viewPath);
  return match ? match[1] : "";
}

export function rememberedCaseDir(captureId: string): string {
  try { return localStorage.getItem(STORAGE_PREFIX + captureId) ?? ""; } catch { return ""; }
}

export function rememberCaseDir(captureId: string, caseDir: string): void {
  if (!captureId) return;
  try { localStorage.setItem(STORAGE_PREFIX + captureId, caseDir); } catch { /* storage unavailable */ }
}

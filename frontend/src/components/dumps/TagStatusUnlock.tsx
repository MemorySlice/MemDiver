import { useState } from "react";
import { useDumpStore } from "../../stores/dump-store";

export function TagStatusUnlock({ dumpId }: { dumpId: string }) {
  const unlockTagStatus = useDumpStore((s) => s.unlockTagStatus);
  const [passphrase, setPassphrase] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const handleUnlock = async () => {
    if (!passphrase || busy) return;
    setBusy(true);
    setError(null);
    try {
      const status = await unlockTagStatus(dumpId, { passphrase });
      if (status === "corrupted") setError("Wrong key or tampered file");
      else setPassphrase("");
    } catch {
      setError("Unlock failed");
    } finally {
      setBusy(false);
    }
  };

  return (
    <div
      className="mt-1 flex flex-col gap-1"
      onClick={(e) => e.stopPropagation()}
    >
      <div className="flex gap-1">
        <input
          type="password"
          value={passphrase}
          onChange={(e) => setPassphrase(e.target.value)}
          onKeyDown={(e) => e.key === "Enter" && handleUnlock()}
          placeholder="Passphrase"
          className="flex-1 px-2 py-0.5 text-[10px] rounded border border-[var(--md-border)] bg-[var(--md-bg-secondary)]"
        />
        <button
          onClick={handleUnlock}
          disabled={!passphrase || busy}
          className="px-2 py-0.5 text-[10px] rounded border border-[var(--md-border)] hover:bg-[var(--md-bg-hover)] disabled:opacity-40"
        >
          {busy ? "..." : "Unlock"}
        </button>
      </div>
      {error && (
        <p className="text-[10px] text-[var(--md-accent-red)]">{error}</p>
      )}
    </div>
  );
}

/** What a human states about an edit; `author` is always `human` on this surface. */
export interface ProvenanceDraft { source: string; tier: string; evidence: string }

export const emptyProvenance = (): ProvenanceDraft => ({ source: "manual", tier: "manual", evidence: "" });

export const provenanceBody = (p: ProvenanceDraft) => ({
  source: p.source.trim() || "manual",
  tier: p.tier,
  evidence: p.evidence.split("\n").map((e) => e.trim()).filter(Boolean),
  author: "human",
});

/** Append one evidence line (used by "from selection" so the claim stays replayable). */
export const withEvidence = (p: ProvenanceDraft, line: string): ProvenanceDraft =>
  p.evidence.split("\n").includes(line) ? p
    : { ...p, evidence: p.evidence.trim() === "" ? line : `${p.evidence.trim()}\n${line}` };


/**
 * "What's an oracle?" + Shape 1 vs Shape 2 explainer.
 *
 * Collapsible help card for the Oracle wizard stage. Designed to
 * unblock a first-time user who has no idea how the BYO-oracle
 * contract works, without forcing them to context-switch to
 * ``docs/oracle_interface.md``. The snippets match the bundled
 * example oracles so a reader can go straight from here to
 * "Examples" tab and see real code.
 */

import { useState } from "react";
import { useTranslation } from "react-i18next";

const SHAPE_1_SNIPPET = `# Shape 1 — stateless function
# One call per candidate; memdiver doesn't cache anything.

def verify(candidate: bytes) -> bool:
    # your decrypt + tag-check here
    return try_decrypt(candidate, CIPHERTEXT, NONCE, TAG)
`;

const SHAPE_2_SNIPPET = `# Shape 2 — stateful factory
# Use when verify() needs cached state (HKDF output, open socket, etc).

class MyOracle:
    def __init__(self, cfg: dict):
        self.ct = Path(cfg["sample_ciphertext"]).read_bytes()

    def verify(self, candidate: bytes) -> bool:
        return try_decrypt(candidate, self.ct)

def build_oracle(cfg: dict) -> MyOracle:
    return MyOracle(cfg)
`;

export function OracleShapeExplainer() {
  const { t } = useTranslation("pipeline");
  const [open, setOpen] = useState(false);
  return (
    <div className="md-panel">
      <button
        type="button"
        onClick={() => setOpen((prev) => !prev)}
        className="w-full p-3 flex items-center justify-between text-left text-xs"
      >
        <span className="md-text-accent font-semibold">
          {t("oracle.shape.newToOracles")}
        </span>
        <span className="md-text-muted">{open ? t("oracle.shape.hide") : t("oracle.shape.show")}</span>
      </button>
      {open && (
        <div className="px-3 pb-3 space-y-3 text-xs md-text-secondary border-t border-[var(--md-border)]">
          <p>
            {t("oracle.shape.introPrefix")}{" "}
            <em>{t("oracle.shape.introOracle")}</em>{" "}
            {t("oracle.shape.introMid")}{" "}
            <code>{t("oracle.shape.introTrue")}</code>{" "}
            {t("oracle.shape.introForReal")}{" "}
            <code>{t("oracle.shape.introFalse")}</code>{" "}
            {t("oracle.shape.introTail")}
          </p>

          <p>
            {t("oracle.shape.twoShapesPrefix")}{" "}
            <code>verify()</code>{" "}
            {t("oracle.shape.twoShapesTail")}
          </p>

          <div>
            <div className="md-text-accent font-semibold mb-1">
              {t("oracle.shape.shape1Heading")}
            </div>
            <pre className="text-[10px] font-mono bg-[var(--md-bg-primary)] p-2 rounded border border-[var(--md-border)] overflow-x-auto">
              {SHAPE_1_SNIPPET}
            </pre>
          </div>

          <div>
            <div className="md-text-accent font-semibold mb-1">
              {t("oracle.shape.shape2Heading")}
            </div>
            <pre className="text-[10px] font-mono bg-[var(--md-bg-primary)] p-2 rounded border border-[var(--md-border)] overflow-x-auto">
              {SHAPE_2_SNIPPET}
            </pre>
          </div>

          <p className="md-text-muted">
            {t("oracle.shape.securityNotePrefix")}{" "}
            <code>__pycache__/</code>{" "}
            {t("oracle.shape.securityNoteMid")}
            <code> docs/oracle_interface.md</code>{" "}
            {t("oracle.shape.securityNoteTail")}
          </p>
        </div>
      )}
    </div>
  );
}

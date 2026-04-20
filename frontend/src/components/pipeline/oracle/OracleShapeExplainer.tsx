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
  const [open, setOpen] = useState(false);
  return (
    <div className="md-panel">
      <button
        type="button"
        onClick={() => setOpen((prev) => !prev)}
        className="w-full p-3 flex items-center justify-between text-left text-xs"
      >
        <span className="md-text-accent font-semibold">
          New to BYO oracles?
        </span>
        <span className="md-text-muted">{open ? "Hide" : "Show"}</span>
      </button>
      {open && (
        <div className="px-3 pb-3 space-y-3 text-xs md-text-secondary border-t border-[var(--md-border)]">
          <p>
            An <em>oracle</em> is a short Python file you write that returns{" "}
            <code>True</code> for the real key and <code>False</code> for
            everything else. Memdiver's pipeline hands it each surviving
            candidate from the search-reduce chain and reports the ones that
            pass. The server never sees the plaintext; you decide what
            "verified" means for your protocol.
          </p>

          <p>
            Two shapes are supported; pick Shape 1 for simple cases and
            Shape 2 when <code>verify()</code> needs to cache work (like a
            KDF output or an open socket) between calls.
          </p>

          <div>
            <div className="md-text-accent font-semibold mb-1">
              Shape 1 — stateless
            </div>
            <pre className="text-[10px] font-mono bg-[var(--md-bg-primary)] p-2 rounded border border-[var(--md-border)] overflow-x-auto">
              {SHAPE_1_SNIPPET}
            </pre>
          </div>

          <div>
            <div className="md-text-accent font-semibold mb-1">
              Shape 2 — stateful factory
            </div>
            <pre className="text-[10px] font-mono bg-[var(--md-bg-primary)] p-2 rounded border border-[var(--md-border)] overflow-x-auto">
              {SHAPE_2_SNIPPET}
            </pre>
          </div>

          <p className="md-text-muted">
            Memdiver refuses to load oracles from world-writable files,
            purges any stale <code>__pycache__/</code> next to the source,
            and requires an explicit "Arm oracle" step that re-hashes the
            file on disk before the pipeline will run it. See
            <code> docs/oracle_interface.md</code> for the full contract.
          </p>
        </div>
      )}
    </div>
  );
}

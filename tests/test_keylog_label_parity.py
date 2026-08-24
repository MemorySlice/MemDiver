"""Frontend<->backend parity for the canonical NSS key-log secret labels.

The composer UI keeps a hand-maintained mirror of the secret-type labels the
exporter understands in ``frontend/src/api/keylog-labels.ts`` (there is no build
step wiring the TS enum to Python). This test ties that mirror to the backend
truth so a label added/renamed/removed on one side but not the other fails CI
loudly instead of silently offering the composer a label the exporter rejects
(or hiding a label it accepts).

Backend truth for the TLS protocol's secret-type keys lives in two places that
must themselves agree:
  * ``core/protocols.py``          — ``TLS_DESCRIPTOR.secret_types`` (the registry)
  * ``core/keylog_templates.py``   — ``TLS12_TEMPLATE`` + ``TLS13_TEMPLATE``
"""

from __future__ import annotations

import re
from pathlib import Path

from memdiver.core.keylog_templates import TLS12_TEMPLATE, TLS13_TEMPLATE
from memdiver.core.protocols import TLS_DESCRIPTOR

# frontend/src/api/keylog-labels.ts, relative to this test file (repo_root/tests).
FRONTEND_LABELS_TS = (
    Path(__file__).resolve().parents[1] / "frontend" / "src" / "api" / "keylog-labels.ts"
)


def _extract_frontend_labels() -> set[str]:
    """Parse the string entries of the ``NSS_KEYLOG_LABELS`` array from the TS."""
    source = FRONTEND_LABELS_TS.read_text()
    match = re.search(
        r"NSS_KEYLOG_LABELS\s*=\s*\[(.*?)\]", source, re.DOTALL
    )
    assert match, "could not locate NSS_KEYLOG_LABELS array in keylog-labels.ts"
    return set(re.findall(r'"([A-Z0-9_]+)"', match.group(1)))


def test_backend_tls_label_sources_agree():
    """The registry and the keylog templates expose the same TLS label set."""
    registry_labels = TLS_DESCRIPTOR.all_secret_types()
    template_labels = TLS12_TEMPLATE.secret_types | TLS13_TEMPLATE.secret_types
    assert registry_labels == template_labels


def test_frontend_labels_mirror_backend_canonical_set():
    """The FE NSS-label mirror equals the backend canonical TLS label set."""
    backend_labels = TLS_DESCRIPTOR.all_secret_types()
    frontend_labels = _extract_frontend_labels()
    assert frontend_labels == backend_labels, (
        "frontend/src/api/keylog-labels.ts NSS_KEYLOG_LABELS drifted from the "
        "backend TLS secret-type set. "
        f"only in frontend: {sorted(frontend_labels - backend_labels)}; "
        f"only in backend: {sorted(backend_labels - frontend_labels)}"
    )

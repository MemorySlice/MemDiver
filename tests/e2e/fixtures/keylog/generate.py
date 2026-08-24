#!/usr/bin/env python3
"""Generate the committed keylog e2e fixture (``expected.json``).

Captures the real TLS 1.3 ``client_random`` + the five NSS-labeled secrets from
the ground-truth run

    .../TLS13/100_iterations_Abort_KeyUpdate/openssl/openssl_run_13_1/keylog.csv

in a shape a JS test can consume directly: build one keylog entry per secret and
assert the exact NSS keylog output line

    "<LABEL> <client_random> <secret>\\n"

The ``expected_lines`` array pins the REAL production emitter output: each line
is produced by ``memdiver.core.keylog.format_keylog_lines`` (the single
source-of-truth NSS renderer) rather than a re-implemented format string, so the
fixture can never drift from what the tool emits. All five secrets are included
(handshake + traffic + exporter); ``CLIENT_TRAFFIC_SECRET_0`` and
``SERVER_TRAFFIC_SECRET_0`` are both present as required.

Deterministic + re-runnable. Run from anywhere:

    /path/to/python tests/e2e/fixtures/keylog/generate.py
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
OUT = HERE / "expected.json"

# Shared TLS ground-truth lives in tests/fixtures; make it importable by bare
# name regardless of cwd (mirrors the pcap fixture generator's sys.path idiom).
sys.path.insert(0, str(HERE.parents[2] / "fixtures"))

from memdiver.core.keylog import format_keylog_lines  # noqa: E402
from memdiver.core.models import CryptoSecret  # noqa: E402
from tls_ground_truth import CLIENT_RANDOM, SECRETS, SOURCE_RUN  # noqa: E402


def main() -> None:
    entries = [
        {"label": label, "client_random": CLIENT_RANDOM, "secret": secret}
        for label, secret in SECRETS.items()
    ]
    # One NSS keylog line per secret, rendered by the production emitter so the
    # fixture pins the tool's real output byte-for-byte (each ends in a "\n").
    client_random_bytes = bytes.fromhex(CLIENT_RANDOM)
    expected_lines = [
        format_keylog_lines(
            [CryptoSecret(
                secret_type=label,
                identifier=client_random_bytes,
                secret_value=bytes.fromhex(secret),
            )]
        )
        for label, secret in SECRETS.items()
    ]
    fixture = {
        "protocol": "TLS1.3",
        "client_random": CLIENT_RANDOM,
        "source_run": SOURCE_RUN,
        "entries": entries,
        "expected_lines": expected_lines,
    }
    OUT.write_text(json.dumps(fixture, indent=2) + "\n")
    print(f"wrote {OUT}  ({OUT.stat().st_size} bytes; {len(SECRETS)} secrets)")


if __name__ == "__main__":
    main()

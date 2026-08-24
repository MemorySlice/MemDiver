#!/usr/bin/env python3
"""Generate the committed tshark fixture: real ``traffic.pcap`` + ``secrets.json``.

For the Python tshark test that decrypts a real TLS 1.3 capture using its NSS
key material. Both files come from the ground-truth run

    .../TLS13/100_iterations_Abort_KeyUpdate/openssl/openssl_run_13_1/

``traffic.pcap`` is a byte-for-byte copy of that run's capture; ``secrets.json``
carries the run's ``client_random`` + the five NSS-labeled secrets (from its
``keylog.csv``) so the test can materialise an NSS keylog file and hand it to
tshark's ``tls.keylog_file`` decryption.

Deterministic + re-runnable. Run from anywhere:

    /path/to/python tests/fixtures/tshark/generate.py
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent

# Shared TLS ground-truth lives one level up in tests/fixtures; make it
# importable by bare name regardless of cwd.
sys.path.insert(0, str(HERE.parent))

from tls_ground_truth import (  # noqa: E402
    CLIENT_RANDOM,
    SECRETS,
    SOURCE_RUN,
    copy_real_pcap,
)

OUT_PCAP = HERE / "traffic.pcap"
OUT_SECRETS = HERE / "secrets.json"


def main() -> None:
    copy_real_pcap(OUT_PCAP)
    fixture = {
        "protocol": "TLS1.3",
        "client_random": CLIENT_RANDOM,
        "source_run": SOURCE_RUN,
        "secrets": SECRETS,
    }
    OUT_SECRETS.write_text(json.dumps(fixture, indent=2) + "\n")

    for p in (OUT_PCAP, OUT_SECRETS):
        print(f"wrote {p}  ({p.stat().st_size} bytes)")


if __name__ == "__main__":
    main()

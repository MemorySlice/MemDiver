"""Shared TLS ground-truth for the committed pcap / keylog / tshark fixtures.

Single source of truth for the one real OpenSSL TLS 1.3 run every TLS fixture is
anchored to::

    .../TLS13/100_iterations_Abort_KeyUpdate/openssl/openssl_run_13_1/

The ``client_random`` + the five NSS-labeled secrets below come from that run's
``keylog.csv``; ``run_data/traffic.pcap`` is its captured session. The corpus is
machine-local and NOT committed, so its root is overridable via
``MEMDIVER_TLS_DUMPS_DIR``. Consuming the COMMITTED fixtures never reads it —
these values are used only when *regenerating* a fixture (the fixture generators)
or by the corpus-gated real-dump oracle test.

Both the standalone fixture generators (run as scripts, importing this by bare
name after adding ``tests/fixtures`` to ``sys.path``) and the pytest modules
(importing ``tests.fixtures.tls_ground_truth``) resolve this module.
"""

from __future__ import annotations

import os
import shutil
from pathlib import Path
from typing import Union

# Home-relative rather than an absolute developer path, so the one hardcoded
# spelling of the corpus location works on any machine that keeps it in the
# conventional place. Overridable via ``MEMDIVER_TLS_DUMPS_DIR``.
_DEFAULT_TLS_DUMPS_DIR = str(Path.home() / "Desktop" / "tls_dumps")


def tls_dumps_dir() -> Path:
    """Root of the local TLS-dump corpus (``MEMDIVER_TLS_DUMPS_DIR`` or default).

    This is the SINGLE spelling of "where the corpus lives". It is also the
    last resort of :func:`tests._paths.dataset_root`, which gates the
    ``requires_dataset`` marker -- so a test may be gated by ``dataset_root()``
    and resolve its own paths through here without the two disagreeing.
    """
    return Path(os.environ.get("MEMDIVER_TLS_DUMPS_DIR", _DEFAULT_TLS_DUMPS_DIR))


# The ground-truth run directory, as a string, for provenance in manifests +
# ``RUN_DIR`` gating. Resolved from the corpus root at import time (matching the
# generators' historical ``SOURCE_RUN`` module constant).
SOURCE_RUN = str(
    tls_dumps_dir()
    / "TLS13"
    / "100_iterations_Abort_KeyUpdate"
    / "openssl"
    / "openssl_run_13_1"
)


def real_pcap_path() -> Path:
    """The run's captured TLS 1.3 ``traffic.pcap`` (``run_data/traffic.pcap``)."""
    return Path(SOURCE_RUN) / "run_data" / "traffic.pcap"


def copy_real_pcap(dest: Union[str, Path]) -> Path:
    """Copy the real capture to ``dest``; ``SystemExit`` if the corpus is absent."""
    real = real_pcap_path()
    if not real.is_file():
        raise SystemExit(f"real capture not found: {real}")
    shutil.copyfile(real, dest)
    return Path(dest)


# The session's real TLS 1.3 client random.
CLIENT_RANDOM = "3923d14c059e6e60c3ddd950208a97c1eb878feeb83e614e0c3d5f7e26bdd823"

# The five NSS keylog secrets in the order they appear in the source keylog.csv
# (handshake + traffic + exporter). Dict insertion order IS this order, so
# consumers that need the keylog line order can iterate ``SECRETS.items()``.
SECRETS = {
    "CLIENT_HANDSHAKE_TRAFFIC_SECRET":
        "bcb398c70d56306a61d7e769c18ceeef5c6cc94080b5319034028b372af22876",
    "SERVER_HANDSHAKE_TRAFFIC_SECRET":
        "644197f0264ee3662c4ba96388f64fcf03353e6d218ad12ca4eadb07222e484c",
    "EXPORTER_SECRET":
        "01e748fec9e67f6be14ee586f52d6016755b361e45796a548de9d3d8aa05a2d3",
    "CLIENT_TRAFFIC_SECRET_0":
        "a05312cbc2ba85f6b5413fa97eb3627642e6049c98722c0d326b48dd3382c2c5",
    "SERVER_TRAFFIC_SECRET_0":
        "34733aa526c1213555d78f7ca9da1b9c0e03b7d7ef203441ea5913a51521a43e",
}

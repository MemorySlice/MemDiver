"""Heavy proof: recover a TLS key from a GENUINE process core and prove it
decrypts a REAL captured pcap — no synthetic material, no browser 60s budget.

Unlike ``tests/test_pcap_oracle_e2e.py`` (which builds synthetic captures under
known keys), this drives the *real* corpus:

    real openssl ELF/process core .dump  --open_dump-->  bytes
        -> locate the recovered SERVER_TRAFFIC_SECRET_0 (the dump genuinely
           contains it)
        -> app.tools_pipeline.brute_force(pcap_path=<real traffic.pcap>)
        -> the first-party pcap oracle proves the recovered 32-byte key
           decrypts the real captured TLS 1.3 records (confirmed_by == "pcap")

The corpus is machine-local and NOT committed, so the whole module is gated on
the run directory existing (see ``RUN_DIR``). Marked ``slow``.

Approach note (honesty): the full-dump exhaustive brute-force over 11 MB is
minutes-scale AND the "preferred" ``search_reduce`` front-end needs a
multi-dump consensus variance array this single run/file doesn't provide. So we
run the REAL ``brute_force`` engine + REAL pcap oracle over a bounded candidate
window around the offset the dump's own read/find API reports — exercising the
genuine recover->confirm vertical against the real dump and real pcap, in well
under a second. A direct ``build_oracle(...).verify()`` assertion backs it up.
"""

import json
import sys
from pathlib import Path

import pytest

pytest.importorskip("dpkt")

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from memdiver.app.composition import open_dump  # noqa: E402
from memdiver.app.tools_pipeline import brute_force  # noqa: E402
from memdiver.engine.resources.builtin_oracle import build_oracle  # noqa: E402
from memdiver.engine.verification import HAS_CRYPTO  # noqa: E402
from tests.fixtures.tls_ground_truth import SECRETS, SOURCE_RUN  # noqa: E402

# --------------------------------------------------------------------------- #
# Machine-local corpus (NOT committed) — gate the whole module on its presence.
# The corpus root is overridable via ``MEMDIVER_TLS_DUMPS_DIR`` (shared
# tls_ground_truth), so this no longer hardcodes the run directory.
# --------------------------------------------------------------------------- #
RUN_DIR = Path(SOURCE_RUN)
DUMP = RUN_DIR / "20251020_171845_606711_pre_server_key_update.dump"
PCAP = RUN_DIR / "run_data" / "traffic.pcap"
# Ground truth for this run: the server application-data traffic secret.
SERVER_TRAFFIC_SECRET_0 = SECRETS["SERVER_TRAFFIC_SECRET_0"]

pytestmark = [
    pytest.mark.slow,
    pytest.mark.skipif(
        not DUMP.exists() or not PCAP.exists(),
        reason=f"machine-local corpus not present: {RUN_DIR}",
    ),
    pytest.mark.skipif(not HAS_CRYPTO, reason="cryptography not installed"),
]


def _find_secret_offset() -> int:
    """Locate the ground-truth secret in the real dump via the app open path."""
    secret = bytes.fromhex(SERVER_TRAFFIC_SECRET_0)
    with open_dump(DUMP) as source:
        # ``__enter__`` already calls ``open()``; a second explicit open() would
        # re-initialize the reader and orphan the first handle (match generate.py).
        offset = source.read_all().find(secret)
    assert offset >= 0, "SERVER_TRAFFIC_SECRET_0 not present in the real dump"
    return offset


def test_real_dump_key_decrypts_real_pcap_via_oracle():
    """The key recovered from the real core decrypts the real capture."""
    offset = _find_secret_offset()
    assert offset > 0

    oracle = build_oracle({"resource_type": "tls-pcap", "pcap": str(PCAP)})
    assert len(oracle) >= 1, "real pcap yielded no verification challenges"
    # The exact 32 bytes at the found offset decrypt genuine captured records.
    assert oracle.verify(bytes.fromhex(SERVER_TRAFFIC_SECRET_0)) is True
    # A wrong key of the same size must not.
    assert oracle.verify(bytes(32)) is False


def test_real_brute_force_confirms_hit_against_real_pcap(tmp_path):
    """The REAL brute_force engine recovers the key and confirms it via pcap."""
    offset = _find_secret_offset()

    # Bounded window around the true offset: exercises the genuine brute_force
    # engine + pcap oracle over the real dump without a minutes-scale full sweep.
    # region.offset == offset-64 with stride 1 deterministically includes the
    # true offset among the candidates.
    candidates = tmp_path / "candidates.json"
    candidates.write_text(
        json.dumps({"regions": [{"offset": offset - 64, "length": 160}]})
    )

    result = brute_force(
        candidates_path=str(candidates),
        reference_path=str(DUMP),   # opened through the same app open_dump path
        output_dir=str(tmp_path / "out"),
        pcap_path=str(PCAP),
        key_sizes=(32,),
        stride=1,
    )

    assert result["verified_count"] == 1
    assert len(result["hits"]) == 1
    hit = result["hits"][0]
    assert hit["offset"] == offset
    assert hit["key_hex"] == SERVER_TRAFFIC_SECRET_0
    assert hit["confirmed_by"] == "pcap"

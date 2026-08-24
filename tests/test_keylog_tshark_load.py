"""Gap-4 proof: the NSS key log MemDiver *exports* actually decrypts a real
capture in real Wireshark/tshark — not a hand-rolled line, but the exact
artifact produced by the product's ``keylog_result`` export path.

Vertical under test::

    tests/fixtures/tshark/secrets.json          (real TLS 1.3 openssl secrets)
        -> app.tools_pipeline.keylog_result(...) (the REAL export producer)
        -> session.keylog (SSLKEYLOGFILE / NSS format)
        -> tshark -o tls.keylog_file:...         (real Wireshark decryption)
        -> decrypted inner records appear that DON'T without the key log

The capture (``tests/fixtures/tshark/traffic.pcap``) is a genuine TLS 1.3
openssl session (cipher ``TLS_CHACHA20_POLY1305_SHA256``): one client and eight
server application-data records. Raw TLS, no HTTP — so the decrypt signal is
tshark exposing the *decrypted inner record content type* (``tls.record.
content_type == 23``, application_data), which is only knowable once the
records are decrypted with the key log. Without the key log tshark sees only the
opaque outer type and reports zero content-type-23 records.

Only skips when ``tshark`` is absent (or the optional dpkt/cryptography deps);
it FAILS loudly if the exported key log does not decrypt the capture.
"""

import json
import shutil
import subprocess
from pathlib import Path

import pytest

# Decryption is done by tshark, and the export goes through the keylog_result
# product path (cryptography), not dpkt — so this test is gated only on tshark +
# HAS_CRYPTO below, NOT on the dpkt pcap-parser extra it never touches.
from memdiver.app.tools_pipeline import keylog_result
from memdiver.engine.verification import HAS_CRYPTO

TSHARK = shutil.which("tshark")

pytestmark = [
    pytest.mark.e2e,
    pytest.mark.skipif(TSHARK is None, reason="tshark not installed; skipping real-Wireshark decrypt proof"),
    pytest.mark.skipif(not HAS_CRYPTO, reason="cryptography not installed"),
]

FIXTURES = Path(__file__).resolve().parent / "fixtures" / "tshark"
PCAP = FIXTURES / "traffic.pcap"
SECRETS_JSON = FIXTURES / "secrets.json"

# tshark display filter that only matches once records are DECRYPTED: the
# inner (application_data == 23) content type is invisible on the opaque wire
# record and becomes readable only after the key log decrypts it.
DECRYPTED_APPDATA_FILTER = "tls.record.content_type == 23"
# Encrypted app-data records exist on the wire regardless of decryption; used to
# assert the capture genuinely carries TLS application data to decrypt.
OPAQUE_APPDATA_FILTER = "tls.record.opaque_type == 23"


def _export_keylog(tmp_path: Path) -> Path:
    """Build the NSS key log through the REAL product export path."""
    data = json.loads(SECRETS_JSON.read_text())
    client_random = data["client_random"]
    secrets = [
        {"secret_type": label, "client_random": client_random, "secret": secret}
        for label, secret in data["secrets"].items()
    ]
    out = tmp_path / "session.keylog"
    result = keylog_result(secrets=secrets, output_path=str(out))
    # Five NSS labels in, five lines out — the exported artifact is well-formed.
    assert result["count"] == len(secrets) == 5
    assert out.exists()
    return out


def _tshark_frames(display_filter: str, keylog: Path | None) -> list[str]:
    """Return frame numbers matching *display_filter*, optionally with a key log."""
    cmd = [TSHARK, "-r", str(PCAP)]
    if keylog is not None:
        cmd += ["-o", f"tls.keylog_file:{keylog}"]
    cmd += ["-Y", display_filter, "-T", "fields", "-e", "frame.number"]
    proc = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
    assert proc.returncode == 0, f"tshark failed: {proc.stderr}"
    return [line for line in proc.stdout.splitlines() if line.strip()]


def test_exported_keylog_decrypts_real_capture_in_tshark(tmp_path):
    """The exported NSS key log makes tshark decrypt records it otherwise can't."""
    keylog = _export_keylog(tmp_path)

    # The capture genuinely carries encrypted TLS application data (opaque
    # outer type 23), independent of whether we can decrypt it.
    opaque = _tshark_frames(OPAQUE_APPDATA_FILTER, keylog=None)
    assert len(opaque) >= 1, "fixture pcap has no TLS application-data records"

    # Without the key log tshark cannot see any decrypted inner content type.
    without = _tshark_frames(DECRYPTED_APPDATA_FILTER, keylog=None)
    assert without == [], (
        f"expected zero decrypted application-data records without the key log, "
        f"got frames {without}"
    )

    # With the EXPORTED key log tshark decrypts real records: the inner
    # application_data content type becomes visible. This is the decryption
    # proof — it must be strictly more than the no-key-log baseline.
    with_keylog = _tshark_frames(DECRYPTED_APPDATA_FILTER, keylog=keylog)
    assert len(with_keylog) >= 1, (
        "the exported key log did not decrypt any records in tshark"
    )
    assert len(with_keylog) > len(without)

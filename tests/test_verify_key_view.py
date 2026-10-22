"""verify-key reads the candidate in the byte view its offset addresses.

The Verify-Key panel pre-fills the hex cursor, an offset in the viewer's
CURRENT view. On the gcore fixture the planted ``secret=ABCDEF01`` is at raw
(container) offset 432 and VAS offset 4352, so the same number names a
different candidate in each view. ``view=None`` keeps the historical read.
"""

import json
from pathlib import Path

import pytest

from memdiver.app.tools_pipeline import verify_key_result
from memdiver.core.service_errors import CapabilityError
from memdiver.engine.verification import (
    VERIFICATION_IV,
    VERIFICATION_PLAINTEXT,
    VERIFIER_REGISTRY,
)

FIXTURE = Path(__file__).parent / "e2e" / "fixtures" / "gcore_planted"
CORE = FIXTURE / "planted.core"
PLANTED = json.loads((FIXTURE / "planted.json").read_text())
CIPHER = "AES-128-CBC"
KEY = CORE.read_bytes()[PLANTED["raw_offset"]:PLANTED["raw_offset"] + 16]
CIPHERTEXT_HEX = VERIFIER_REGISTRY[CIPHER].create_ciphertext(
    KEY, VERIFICATION_PLAINTEXT, VERIFICATION_IV).hex()


def _verify(offset, view=None):
    return verify_key_result(
        dump_path=str(CORE), offset=offset, length=16,
        ciphertext_hex=CIPHERTEXT_HEX, cipher=CIPHER, view=view)


def test_fixture_key_is_the_planted_secret():
    assert KEY.startswith(PLANTED["secret"].encode())


@pytest.mark.parametrize("offset,view", [
    (PLANTED["vas_offset"], "vas"),
    (PLANTED["raw_offset"], "raw"),
])
def test_verifies_in_the_view_the_offset_addresses(offset, view):
    result = _verify(offset, view)
    assert result["verified"] is True
    assert result["key_hex"] == KEY.hex()


def test_the_vas_number_in_the_raw_view_is_another_candidate():
    assert _verify(PLANTED["vas_offset"], "raw")["verified"] is False


def test_default_view_is_unchanged():
    # None = the historical read; it must equal one explicit view's answer
    # at every offset (i.e. the parameter did not change the default path).
    for offset in (PLANTED["raw_offset"], PLANTED["vas_offset"]):
        default = _verify(offset)
        assert default in (_verify(offset, "raw"), _verify(offset, "vas"))


def test_unsupported_view_is_a_capability_error():
    with pytest.raises(CapabilityError):
        _verify(0, "va")  # gcore has raw + vas only


def test_route_forwards_the_view():
    from fastapi.testclient import TestClient
    from memdiver.api.main import create_app

    client = TestClient(create_app())
    body = {"dump_path": str(CORE), "offset": PLANTED["vas_offset"], "length": 16,
            "ciphertext_hex": CIPHERTEXT_HEX, "cipher": CIPHER}
    vas = client.post("/api/analysis/verify-key", json={**body, "view": "vas"})
    raw = client.post("/api/analysis/verify-key", json={**body, "view": "raw"})
    assert vas.status_code == 200 and vas.json()["verified"] is True
    assert raw.status_code == 200 and raw.json()["verified"] is False
    bad = client.post("/api/analysis/verify-key", json={**body, "view": "vsa"})
    assert bad.status_code == 422


def test_cli_forwards_the_view(tmp_path):
    from memdiver.cli.main import build_parser
    from memdiver.cli.pipeline import _cmd_verify

    out = tmp_path / "v.json"
    rc = _cmd_verify(build_parser().parse_args(["verify", str(CORE), "--offset", hex(PLANTED["vas_offset"]),
               "--length", "16", "--ciphertext-hex", CIPHERTEXT_HEX,
               "--cipher", CIPHER, "--view", "vas", "-o", str(out)]))
    assert rc == 0
    assert json.loads(out.read_text())["verified"] is True

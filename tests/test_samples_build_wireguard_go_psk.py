"""``samples/build_wireguard_go_psk_sample.keylog_psk``: the PSK ground truth parser."""

import importlib.util
from pathlib import Path

import pytest

SCRIPT = Path(__file__).resolve().parents[1] / "samples" / "build_wireguard_go_psk_sample.py"


@pytest.fixture(scope="module")
def build():
    spec = importlib.util.spec_from_file_location("build_wireguard_go_psk_sample", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _run(tmp_path: Path, lines) -> Path:
    keylogs = tmp_path / "responder" / "keylogs"
    keylogs.mkdir(parents=True)
    (keylogs / "keylog_wireguard-go-responder.txt").write_text("\n".join(lines) + "\n")
    return tmp_path


def test_keylog_psk_reads_the_rig_line(build, tmp_path):
    psk = bytes(range(32))
    run = _run(tmp_path, ["2026-11-12 12:47:08.870  WG_STATIC_PRIV_LOCAL: " + "11" * 32,
                          "2026-11-12 12:47:08.872  WG_PRESHARED_KEY: " + psk.hex(),
                          "2026-11-12 12:47:09.000  WG_PRESHARED_KEY: " + psk.hex()])
    assert build.keylog_psk(run, "responder") == psk


@pytest.mark.parametrize("lines", [[], ["2026-11-12 12:47:08.872  WG_PRESHARED_KEY: " + "aa" * 32,
                                        "2026-11-12 12:47:08.872  WG_PRESHARED_KEY: " + "bb" * 32]],
                         ids=["missing", "two-different"])
def test_keylog_psk_refuses_missing_or_ambiguous(build, tmp_path, lines):
    with pytest.raises(ValueError):
        build.keylog_psk(_run(tmp_path, lines), "responder")

"""P2 closing proof (plan T2.6): a finding in an EXTRACTED ``.msl`` is found again by
an emitted Volatility 3 plugin run with ``--pid`` by stock ``vol`` on the FULL image.

Chain: alma-9 LiME → process view (sshd 22176) → ``image extract`` → ``.msl`` → pick a
high-entropy heap window in the ``.msl`` → ``emit_plugin_for_hit`` → ``vol3_write_config``
for that plugin (alma-9 runs LA57: stock ``vol`` automagic stacks 4-level and finds
nothing, so the config carries MemDiver's ``LinuxIntel5Level`` stack) → out-of-process
``vol -c config.json … --pid 22176`` → the reported key VA equals the ``.msl`` VA.

Gated on ``MEMDIVER_IMAGE_CORPUS`` (pakunoda ``dumps/acquired``) and a ``vol``
launcher; ~30 s with the corpus.
"""

import os
import shutil
from pathlib import Path

import pytest

from memdiver.app.tools_image import image_extract_process_result
from memdiver.app.tools_vol3_dev import SHIM_FILE, vol3_write_config_result
from memdiver.core.dump_source import open_dump
from memdiver.core.image.view_descriptor import ProfileRef, ViewDescriptor, ViewKind
from memdiver.engine import vol3_subproc
from memdiver.engine.vol3_emit import emit_plugin_for_hit

ALMA9 = "alma-9_5.14.0-427.el9"
SHA = "c9" * 32
PID = 22176
#: brk heap of sshd 22176 (mm.start_brk .. mm.brk), measured in P0.
HEAP = (0x56056696B000, 0x560566A91000)
WINDOW, KEY_OFFSET, KEY_LENGTH = 96, 32, 32
_ROOT = os.environ.get("MEMDIVER_IMAGE_CORPUS", "")
CORPUS = Path(_ROOT) if _ROOT else None


def _has_corpus():
    return CORPUS is not None and all(
        (CORPUS / f"{ALMA9}{ext}").is_file() for ext in (".lime", ".gt.isf.json"))


pytestmark = [
    pytest.mark.skipif(not _has_corpus(), reason="set MEMDIVER_IMAGE_CORPUS"),
    pytest.mark.skipif(vol3_subproc.resolve_launcher() is None, reason="no vol launcher"),
]


@pytest.fixture(autouse=True)
def _isolated_home(tmp_path, monkeypatch):
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "home"))


def _view(tmp_path, kind, pid=None):
    profile = ProfileRef(str(CORPUS / f"{ALMA9}.gt.isf.json"), sha256=SHA, origin="explicit")
    desc = ViewDescriptor(str(CORPUS / f"{ALMA9}.lime"), SHA, kind, pid=pid, profile=profile)
    path = tmp_path / f"{kind.value}.mdview"
    desc.write(path)
    return path


def _heap_finding(msl_path):
    """A fully captured, high-entropy heap window of the ``.msl``: (window VA, bytes)."""
    with open_dump(msl_path) as source:
        base = source.va_span_start()
        for va, length, _ in source.captured_runs():
            lo, hi = max(va, HEAP[0]), min(va + length, HEAP[1])
            for address in range(lo, hi - WINDOW, 16):
                data, runs = source.read_range_valid(address - base, WINDOW, view="va")
                if runs == [(0, WINDOW)] and len(set(data)) >= 70:
                    return address, data
    raise AssertionError("no high-entropy captured heap window in the extracted .msl")


def _emit(window, out_dir):
    variance = [0.0] * WINDOW
    for i in range(KEY_OFFSET, KEY_OFFSET + KEY_LENGTH):
        variance[i] = 5000.0
    hit = {"offset": KEY_OFFSET, "length": KEY_LENGTH, "neighborhood_start": 0,
           "neighborhood_variance": variance}
    out_dir.mkdir()
    return emit_plugin_for_hit(hit, window, "ProofKey", out_dir / "proof_key.py")


def test_emitted_plugin_with_pid_finds_the_msl_finding_on_the_full_image(tmp_path):
    msl = tmp_path / "sshd.msl"
    image_extract_process_result(str(_view(tmp_path, ViewKind.PROCESS, PID)), str(msl))
    window_va, window = _heap_finding(msl)
    plugin = _emit(window, tmp_path / "plugin")

    config = vol3_write_config_result(str(_view(tmp_path, ViewKind.KERNEL)),
                                      str(tmp_path / "cfg" / "config.json"),
                                      source=plugin.read_text()).payload
    assert config["kernel_layer_class"].endswith("LinuxIntel5Level")
    # run_plugin passes the plugin's own directory with -p: the layer shim goes there.
    shutil.copy(Path(config["shim_dir"]) / SHIM_FILE, plugin.parent / SHIM_FILE)

    rows = vol3_subproc.run_plugin(
        vol3_subproc.resolve_launcher(), plugin, Path(config["image"]),
        extra_args=["-c", config["config_path"]], plugin_args=["--pid", str(PID)],
        timeout=900)

    key_vas = [int(row["KeyOffset"]) for row in rows]
    expected = window_va + KEY_OFFSET
    assert expected in key_vas, f"{expected:#x} not in {[hex(v) for v in key_vas]}"
    # Every other hit is the same bytes seen through the kernel's direct map (the
    # process page tables map the kernel half too): never a second user-space hit.
    user_space = [v for v in key_vas if v < 1 << 47]
    assert user_space == [expected]

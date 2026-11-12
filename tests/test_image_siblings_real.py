"""Real-data gate of the image.siblings capability (plan S2) on capture v2b.

``MEMDIVER_SECRETS_CORPUS`` = absolute path of the acquired-secrets capture dir (unset ->
skipped). Stem ``ubuntu-24.04-secrets-x86-4level-v2b_6.8.0-136-generic``. Ground truth is
the sidecar's ``siblings[]`` (group, pid, ppid, role, build_id, smaps_rollup), taken in the
guest at the sibling snapshot.

Measured 2026-11-12: every sidecar member is found with the sidecar's build-id; dropbear is
one ``forked`` family (listener 11623 + 4 sessions); gocryptfs is the pooled ``independent``
group (the 3 planted mounts + an older mount, pid 9945, that the sidecar does not list);
OpenSSH 9.6 is ``mixed`` (each monitor->session pair is forked, pairs are independent
re-execs). Private_Dirty equals smaps_rollup exactly for all 17 members; Rss is 4 kB above
it (the PFNMAP ``[vvar]`` page, which smaps skips).
"""

import json
import os
from pathlib import Path

import pytest

from memdiver.app.tools_image import image_siblings_result

_CORPUS = os.environ.get("MEMDIVER_SECRETS_CORPUS", "")
CAPTURE_DIR = Path(_CORPUS) if _CORPUS else Path("/nonexistent")
STEM = "ubuntu-24.04-secrets-x86-4level-v2b_6.8.0-136-generic"
IMAGE = CAPTURE_DIR / f"{STEM}.lime"
ISF = CAPTURE_DIR / f"{STEM}.isf.json"
#: smaps skips the PFNMAP [vvar] page our walk counts in rss.
RSS_SLACK_KB = 4
#: Sidecar role -> our role hint.
ROLES = {"listener": "listener", "monitor": "intermediate", "session": "child",
         "daemon": "standalone"}

pytestmark = pytest.mark.skipif(
    not all((CAPTURE_DIR / f"{STEM}{ext}").is_file()
            for ext in (".lime", ".isf.json", ".secrets.json")),
    reason="set MEMDIVER_SECRETS_CORPUS to the capture v2b directory")


@pytest.fixture(scope="module")
def truth():
    rows = json.loads((CAPTURE_DIR / f"{STEM}.secrets.json").read_text())["siblings"]
    return {r["pid"]: r for r in rows}


@pytest.fixture(scope="module")
def default_run():
    """Defaults (listener not analysed), grouping only."""
    return image_siblings_result(str(IMAGE), str(ISF), accounting=False).payload


@pytest.fixture(scope="module")
def accounted_run():
    """Every member analysed (the sidecar has smaps for the listeners too)."""
    return image_siblings_result(str(IMAGE), str(ISF), include_parent=True).payload


def _group_of(payload, pid):
    return next(g for g in payload["groups"] if pid in {m["pid"] for m in g["members"]})


def _members(group):
    return {m["pid"]: m for m in group["members"]}


def test_every_sidecar_member_is_found_with_its_build_id_and_role(default_run, truth):
    for pid, record in truth.items():
        member = _members(_group_of(default_run, pid))[pid]
        assert member["build_id"] == record["build_id"], pid
        assert member["ppid"] == record["ppid"]
        assert member["role"] == ROLES[record["role"]], (pid, member["role"], record["role"])
        assert member["analysed"] is (record["role"] != "listener")


def test_dropbear_is_one_forked_family(default_run, truth):
    group = _group_of(default_run, 11623)
    print("dropbear", group["family_root"], group["shape"], group["pair_shapes"])
    assert set(_members(group)) == {p for p, r in truth.items() if r["group"] == "dropbear"}
    assert (group["family_root"], group["shape"]) == (11623, "forked")
    assert group["analysis_pids"] == [11642, 11653, 11664, 11675]


def test_gocryptfs_daemons_are_independent(default_run, truth):
    group = _group_of(default_run, 11970)
    planted = {p for p, r in truth.items() if r["group"] == "gocryptfs"}
    print("gocryptfs", sorted(_members(group)), group["shape"], group["layout_clusters"])
    assert planted <= set(_members(group)) and group["family_root"] is None
    assert group["shape"] == "independent"
    assert all(len(cluster) == 1 for cluster in group["layout_clusters"])


def test_openssh_reexec_is_mixed_with_forked_monitor_session_pairs(default_run, truth):
    group = _group_of(default_run, 11681)
    print("openssh", group["family_root"], group["shape"], group["pair_shapes"],
          group["layout_clusters"])
    assert set(_members(group)) == {p for p, r in truth.items() if r["group"] == "openssh"}
    assert (group["family_root"], group["shape"]) == (11681, "mixed")
    pairs = sorted(sorted([p, r["ppid"]]) for p, r in truth.items()
                   if r["group"] == "openssh" and r["role"] == "session")
    assert sorted(sorted(c) for c in group["layout_clusters"]) == pairs
    assert group["pair_shapes"] == {"forked": 4, "independent": 24}


def test_private_dirty_equals_smaps_rollup(accounted_run, truth):
    for pid, record in sorted(truth.items()):
        acc = _members(_group_of(accounted_run, pid))[pid]["accounting"]
        kernel = record["smaps_rollup"]
        print("%-9s %5d rss %6d/%6d private_dirty %6d/%6d private %.1f%% walk %.2fs" % (
            record["group"], pid, acc["rss"] // 1024, kernel["Rss"],
            acc["private_dirty"] // 1024, kernel["Private_Dirty"], acc["private_pct"],
            acc["walk_seconds"]))
        assert acc["private_dirty"] // 1024 == kernel["Private_Dirty"], pid
        assert 0 <= acc["rss"] // 1024 - kernel["Rss"] <= RSS_SLACK_KB, pid
        assert acc["smear"] == 0
    print("timings", accounted_run["timings"])


def test_cli_and_rest_once_on_the_real_image(capsys, monkeypatch, tmp_path):
    from fastapi.testclient import TestClient

    from memdiver.api.config import get_settings
    from memdiver.api.main import create_app
    from memdiver.cli import _build_parser, _cmd_image
    rc = _cmd_image(_build_parser().parse_args(
        ["image", "siblings", str(IMAGE), "--isf", str(ISF), "--comm", "dropbear"]))
    cli = json.loads(capsys.readouterr().out)
    assert rc == 0
    assert [(g["family_root"], g["shape"]) for g in cli["groups"]] == [(11623, "forked")]

    monkeypatch.delenv("MEMDIVER_ALLOWED_ROOTS", raising=False)
    monkeypatch.setenv("MEMDIVER_UPLOAD_DIR", str(tmp_path / "uploads"))
    get_settings.cache_clear()
    try:
        r = TestClient(create_app()).get("/api/image/siblings", params={
            "image_path": str(IMAGE), "isf": str(ISF), "comm": "gocryptfs"})
    finally:
        get_settings.cache_clear()
    assert r.status_code == 200
    (group,) = r.json()["groups"]
    assert group["shape"] == "independent" and {11970, 12011, 12056} <= set(
        group["analysis_pids"])

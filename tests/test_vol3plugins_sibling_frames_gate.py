"""C-SIB1 real-data recall gate of the in-image differential (plan S1) on capture v2b.

``MEMDIVER_SECRETS_CORPUS`` = absolute path of the acquired-secrets capture dir (unset ->
skipped). Stem ``ubuntu-24.04-secrets-x86-4level-v2b_6.8.0-136-generic``. The sidecar's
``siblings[]`` holds three sibling groups (dropbear forked: listener + 4 sessions; OpenSSH
re-exec: listener + 4 monitor->session pairs; gocryptfs: 3 independent daemons) and, per
member, the kernel's own view of every page holding a per-session secret (``frames[]``:
pagemap pfn, exclusive bit, kpagecount; 38 in total) plus ``smaps_rollup``. Both were taken
in the guest at the sibling snapshot (12:31:09 UTC); the dump's meta timestamp is 12:40:59.

Claim C-SIB1 (S1 half):
  * translation: our walked PFN for (pid, va) equals the kernel's pagemap PFN, 38/38;
  * recall: every per-session secret lies in a ``private_*`` frame, 38/38, whether the
    group is classified with or without its listener;
  * accounting: Rss / Private_Dirty / Shared per member agree with the kernel's
    smaps_rollup (loose bound; exact numbers are printed with ``-s``);
  * reduction: private bytes / rss per member, and in the forked dropbear group the
    listener's anonymous frames are ``shared_lineage`` with every session (the free filter).
"""

import collections
import json
import os
from pathlib import Path

import pytest

from memdiver.core.image.context import ImageContext
from memdiver.core.image.page_sharing import classify_processes, pages_at
from memdiver.vol3plugins.memdiver import frames as F

_CORPUS = os.environ.get("MEMDIVER_SECRETS_CORPUS", "")
CAPTURE_DIR = Path(_CORPUS) if _CORPUS else Path("/nonexistent")
STEM = "ubuntu-24.04-secrets-x86-4level-v2b_6.8.0-136-generic"
EXPECTED_FRAMES = 38
#: Slack for the smaps comparison: drift over the acquisition window plus pages smaps
#: skips (e.g. the PFNMAP ``[vvar]`` page, which our walk counts in rss).
SMAPS_SLACK_KB = 64
SMAPS_SLACK_RATIO = 0.05

pytestmark = pytest.mark.skipif(
    not all((CAPTURE_DIR / f"{STEM}{ext}").is_file()
            for ext in (".lime", ".isf.json", ".secrets.json")),
    reason="set MEMDIVER_SECRETS_CORPUS to the capture v2b directory")


@pytest.fixture(scope="module")
def siblings():
    return json.loads((CAPTURE_DIR / f"{STEM}.secrets.json").read_text())["siblings"]


@pytest.fixture(scope="module")
def groups(siblings):
    by_group = collections.OrderedDict()
    for record in siblings:
        by_group.setdefault(record["group"], []).append(record)
    return by_group


@pytest.fixture(scope="module")
def image_ctx():
    return ImageContext.build(CAPTURE_DIR / f"{STEM}.lime", CAPTURE_DIR / f"{STEM}.isf.json")


def _variants(records):
    """(label, pids): the whole group, and the group without its listener when it has one."""
    everyone = [r["pid"] for r in records]
    yield "all", everyone
    without = [r["pid"] for r in records if r["role"] != "listener"]
    if without != everyone:
        yield "no-listener", without


@pytest.fixture(scope="module")
def classified(image_ctx, groups):
    """{(group, variant): SiblingFrames} for every group and variant."""
    return {(name, label): classify_processes(image_ctx, pids)
            for name, records in groups.items() for label, pids in _variants(records)}


def _smaps_kb(record):
    lines = record["smaps_rollup_text"].splitlines()[1:]
    return {k: int(v.split()[0]) for k, v in (line.split(":", 1) for line in lines)}


def _secret_rows(groups, classified):
    """One row per (variant, ground-truth frame): kernel facts next to ours."""
    rows = []
    for (name, label), result in classified.items():
        for record in groups[name]:
            if record["pid"] not in result.accounting:
                continue
            for truth in record["frames"]:
                (page,) = pages_at(result.classification, record["pid"], [int(truth["va"], 16)])
                rows.append((name, label, record, truth, page))
    return rows


def test_sidecar_has_the_expected_ground_truth(siblings):
    frames = [f for r in siblings for f in r["frames"]]
    assert len(siblings) == 17 and len(frames) == EXPECTED_FRAMES
    assert all(f["pagemap_flags"]["present"] == 1 and f["pagemap_flags"]["exclusive"] == 1
               and f["kpagecount"] == 1 for f in frames)


def test_c_sib1_translation_and_recall_on_every_secret_frame(groups, classified):
    rows = _secret_rows(groups, classified)
    misses = []
    for name, label, record, truth, page in rows:
        print("%-9s %-11s pid %5d %-8s va %s kernel %#x ours %s %s/%s smear=%s" % (
            name, label, record["pid"], truth["secret"], truth["va"], truth["pfn"],
            None if page is None else hex(page.pfn), None if page is None else page.share_class,
            None if page is None else page.decided_by, None if page is None else page.smear_conflict))
        if page is None or page.pfn != truth["pfn"] or page.share_class not in F.PRIVATE_CLASSES:
            misses.append((name, label, record["pid"], truth["secret"], truth["va"],
                           truth["pfn"], page))
    per_variant = collections.Counter((name, label) for name, label, *_ in rows)
    classes = collections.Counter(page.share_class for *_, page in rows if page is not None)
    print("rows per variant:", dict(per_variant), "classes:", dict(classes))
    assert not misses, "C-SIB1 counterexamples: %r" % (misses,)
    # Every ground-truth frame is checked in each variant that contains its pid.
    for (name, label), count in per_variant.items():
        expected = sum(len(r["frames"]) for r in groups[name]
                       if r["pid"] in classified[(name, label)].accounting)
        assert count == expected
    assert sum(per_variant[(n, "all")] for n in groups) == EXPECTED_FRAMES


def test_accounting_agrees_with_kernel_smaps_rollup(groups, classified):
    for name, records in groups.items():
        result = classified[(name, "all")]
        for record in records:
            ours = {k: v // 1024 for k, v in result.accounting[record["pid"]].items()}
            kernel = _smaps_kb(record)
            kernel_shared = kernel["Shared_Clean"] + kernel["Shared_Dirty"]
            print("%-9s pid %5d %-8s rss %6d/%6d  private_dirty %6d/%6d  shared %6d/%6d "
                  "(ours/kernel kB)" % (
                      name, record["pid"], record["role"], ours["rss"], kernel["Rss"],
                      ours["private_dirty"], kernel["Private_Dirty"], ours["shared"],
                      kernel_shared))
            for mine, theirs in ((ours["rss"], kernel["Rss"]),
                                 (ours["private_dirty"], kernel["Private_Dirty"]),
                                 (ours["shared"] + ours["private_clean"],
                                  kernel_shared + kernel["Private_Clean"])):
                assert abs(mine - theirs) <= max(SMAPS_SLACK_KB, SMAPS_SLACK_RATIO * theirs)


def test_reduction_and_the_free_filter_in_the_forked_group(groups, classified):
    for name, records in groups.items():
        result = classified[(name, "all")]
        private = sum(result.accounting[r["pid"]]["private_dirty"]
                      + result.accounting[r["pid"]]["private_clean"] for r in records)
        rss = sum(result.accounting[r["pid"]]["rss"] for r in records)
        for record in records:
            print("%-9s pid %5d %-8s private/rss %.2f%%" % (
                name, record["pid"], record["role"], 100 * result.reduction(record["pid"])))
            assert 0 < result.reduction(record["pid"]) < 0.6
        print("%-9s group private/rss %.2f%% (%d/%d kB)" % (
            name, 100 * private / rss, private // 1024, rss // 1024))

    dropbear = classified[("dropbear", "all")]
    listener = next(r["pid"] for r in groups["dropbear"] if r["role"] == "listener")
    lineage = collections.defaultdict(set)
    for page in dropbear.classification.pages:
        if page.share_class == F.SHARED_LINEAGE:
            lineage[page.member].add(page.pfn)
    for record in groups["dropbear"]:
        if record["pid"] != listener:
            common = lineage[listener] & lineage[record["pid"]]
            print("dropbear listener shared_lineage frames %d, shared with %d: %d" % (
                len(lineage[listener]), record["pid"], len(common)))
            assert common and common == lineage[listener]


def test_walk_time_per_process(classified):
    for (name, label), result in classified.items():
        assert result.same_address_space == {}
        for pid, seconds in sorted(result.walk_seconds.items()):
            print("%-9s %-11s pid %5d walk %.3fs" % (name, label, pid, seconds))
            assert seconds < 30

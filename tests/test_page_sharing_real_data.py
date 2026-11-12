"""S1 real-data gate (MemDiver dev data ONLY): frame classification of the Cumulus nginx group.

``MEMDIVER_IMAGE_CORPUS`` = the acquired full-image dev corpus. nginx master 2414 and workers
2415/2417 hold the same 4096-bit RSA primes at the same heap VAs (found by ``rsa_factor``,
see tests/test_p3_keys_real_data.py). Measured (kernel 6.1, avml): all three map the primes'
heap page to ONE physical frame (W=0, dirty): nginx loads the key in the master before
``fork()`` and no worker writes that page afterwards. The primes are therefore a GROUP
secret (``shared_lineage``), not a per-worker one: the free filter labels them, it must not
drop them. Run with ``-s`` to see the accounting and walk times.
"""

import os
from pathlib import Path

import pytest

from memdiver.core.image.context import ImageContext
from memdiver.core.image.page_sharing import classify_processes, pages_at
from memdiver.vol3plugins.memdiver import frames as F

_IMG = os.environ.get("MEMDIVER_IMAGE_CORPUS", "")
IMAGE_ROOT = Path(_IMG) if _IMG else None
CUMULUS = "cumulus-5.10.0_6.1.0-cl-1-amd64_avml"
MASTER, WORKERS = 2414, (2415, 2417)
#: Little-endian 2048-bit RSA primes p, q (rsa_factor on each pid's extracted .msl).
PRIME_VAS = (0x564165991770, 0x564165991960)
PRIME_BYTES = 256

pytestmark = pytest.mark.skipif(
    IMAGE_ROOT is None or not all(
        (IMAGE_ROOT / f"{CUMULUS}{ext}").is_file() for ext in (".lime", ".gt.isf.json")),
    reason="set MEMDIVER_IMAGE_CORPUS")


@pytest.fixture(scope="module")
def image_ctx():
    return ImageContext.build(IMAGE_ROOT / f"{CUMULUS}.lime", IMAGE_ROOT / f"{CUMULUS}.gt.isf.json")


@pytest.fixture(scope="module")
def group(image_ctx):
    return classify_processes(image_ctx, (MASTER,) + WORKERS)


def _probable_prime(n):
    return n % 2 == 1 and all(pow(a, n - 1, n) == 1 for a in (2, 3, 5, 7, 11))


def _read(image_ctx, pid, va):
    from memdiver.core.image.adapters import ProcessAdapter
    return bytes(ProcessAdapter(image_ctx, pid).read(va, PRIME_BYTES))


def test_every_member_holds_the_same_rsa_primes(image_ctx):
    for va in PRIME_VAS:
        values = {_read(image_ctx, pid, va) for pid in (MASTER,) + WORKERS}
        assert len(values) == 1
        assert _probable_prime(int.from_bytes(values.pop(), "little"))


def test_primes_are_one_shared_lineage_frame_in_every_member(group):
    for va in PRIME_VAS:
        pages = {pid: pages_at(group.classification, pid, [va])[0] for pid in group.accounting}
        for pid, page in sorted(pages.items()):
            print("prime %#x pid %d: %s decided_by=%s pfn=%#x dirty=%s W=%s smear=%s" % (
                va, pid, page.share_class, page.decided_by, page.pfn, page.dirty,
                page.writable, page.smear_conflict))
        assert {p.share_class for p in pages.values()} == {F.SHARED_LINEAGE}
        assert len({p.pfn for p in pages.values()}) == 1
        assert not any(p.smear_conflict or p.writable for p in pages.values())


def test_workers_only_group_still_shares_the_prime_frame(image_ctx):
    workers = classify_processes(image_ctx, WORKERS)
    for pid in WORKERS:
        (page,) = pages_at(workers.classification, pid, [PRIME_VAS[0]])
        assert (page.share_class, page.decided_by) == (F.SHARED_LINEAGE, "T1")


def test_a_lone_worker_gets_only_possibly_shared_never_proof(image_ctx):
    lone = classify_processes(image_ctx, WORKERS[:1])
    (page,) = pages_at(lone.classification, WORKERS[0], [PRIME_VAS[0]])
    assert page.share_class == F.PRIVATE_DIRTY and page.possibly_shared
    assert page.decided_by == "T1"


def test_accounting_reduction_and_walk_time(group):
    for pid in sorted(group.accounting):
        acc = group.accounting[pid]
        print("pid %d walk %.3fs %s private/rss=%.2f%%" % (
            pid, group.walk_seconds[pid], acc, 100 * group.reduction(pid)))
        assert acc["rss"] > 0 and acc["rss"] == (
            acc["private_dirty"] + acc["private_clean"] + acc["shared"])
        assert 0 < group.reduction(pid) < 0.5
        assert group.walk_seconds[pid] < 30
    assert group.same_address_space == {}

"""Real-data aarch64 proof for T5.5 code evidence (gated on MEMDIVER_IMAGE_CORPUS).

Each image's shipped ISF is joined against the accesses the arm64 decoder reads
out of the real kernel function body. The expected members are the measured
ones: ``current`` lands on ``task_struct.<member>`` exactly and the decoder
follows one deref (``cred.uid.val`` after ``task_struct.cred``).
"""
from __future__ import annotations

import os
from pathlib import Path

import pytest

pytest.importorskip("pakunoda")

from memdiver.app.tools_code_evidence import code_evidence_result  # noqa: E402
from memdiver.core.service_errors import CapabilityError  # noqa: E402

_ROOT = os.environ.get("MEMDIVER_IMAGE_CORPUS", "")
# label -> (image file, isf file)
_IMAGES = {
    "fedora-40": ("fedora-40_6.8.5-301.fc40.aarch64.lime",
                  "fedora-40_6.8.5-301.fc40.aarch64.isf.json"),
    "ubuntu-24.04": ("ubuntu-24.04-arm64_6.8.0-106-generic_lime.lime",
                     "ubuntu-24.04-arm64_6.8.0-106-generic.isf.json"),
    "sonic": ("sonic-master_6.1.0-29-2-arm64.elf", "sonic-master_6.1.0-29-2-arm64.isf.json"),
}
_DEBIAN = ("debian-12_6.1.0-28-arm64.lime", "debian-12_6.1.0-28-arm64.isf.json")


def _have(*pairs) -> bool:
    return bool(_ROOT) and all((Path(_ROOT) / f).is_file() for p in pairs for f in p)


_SKIP = "set MEMDIVER_IMAGE_CORPUS to pakunoda dumps/acquired (arm64 images + ISFs)"
needs_corpus = pytest.mark.skipif(not _have(*_IMAGES.values()), reason=_SKIP)

# function -> exact (base, member) joins that must be present (current-based, all exact)
_EXPECT = {
    "__arm64_sys_getuid": {("current", "cred"), ("deref(current+0x{cred:x})", "uid.val"),
                           ("deref(current+0x{cred:x})", "user_ns")},
    "__arm64_sys_getppid": {("current", "real_parent")},
    "__task_pid_nr_ns": {("current", "thread_pid"), ("deref(current+0x{thread_pid:x})", "level")},
}
_DEREF_PARENT = {"__arm64_sys_getuid": "cred", "__task_pid_nr_ns": "thread_pid"}
_JOIN = {  # function -> (checked, exact, unresolved)
    "__arm64_sys_getuid": (3, 3, 0), "__arm64_sys_getppid": (1, 1, 0),
    "__task_pid_nr_ns": (2, 2, 0),
}
_DO_EXIT = {"fedora-40": (32, 32, 0), "ubuntu-24.04": (33, 33, 0), "sonic": (81, 75, 6)}


# debian-12 measured: function -> (access count, expected isf_join)
_EXPECT_DEBIAN = {
    "__arm64_sys_getuid": (3, {"checked": 3, "exact": 3, "unresolved": 0}),
    "__arm64_sys_getppid": (1, {"checked": 1, "exact": 1, "unresolved": 0}),
}


def _debian_keys(function, members):
    if function == "__arm64_sys_getppid":
        return {("current", "real_parent")}
    cred = members[("current", "cred")]["offset"]
    base = f"deref(current+0x{cred:x})"
    return {("current", "cred"), (base, "uid.val"), (base, "user_ns")}


@pytest.fixture(scope="module", params=sorted(_IMAGES))
def arm_image(request):
    if not _have(*_IMAGES.values()):
        pytest.skip(_SKIP)
    from memdiver.app.tools_isf import _Session
    image, isf = (Path(_ROOT) / f for f in _IMAGES[request.param])
    session = _Session(image, "auto", {})
    try:
        yield request.param, session, image, str(isf)
    finally:
        session.close()


def _run(arm_image, function):
    _, session, image, isf = arm_image
    return code_evidence_result(session, image_path=str(image), function=function,
                                params={"isf": isf}).payload


def _members(payload):
    return {(a["base"], a["isf_member"]["member"]): a["isf_member"]
            for a in payload["accesses"] if a.get("isf_member")}


@needs_corpus
@pytest.mark.parametrize("function", sorted(_EXPECT))
def test_arm64_exact_joins(arm_image, function):
    payload = _run(arm_image, function)
    assert payload["coverage"]["truncated"] is False and payload["coverage"]["complete"] is True
    assert payload["coverage"]["bytes_decoded"] == payload["coverage"]["function_size"]
    checked, exact, unresolved = _JOIN[function]
    join = payload["isf_join"]
    assert (join["checked"], join["exact"], join["unresolved"]) == (checked, exact, unresolved)
    members = _members(payload)
    parent = _DEREF_PARENT.get(function)
    for base, member in _EXPECT[function]:
        if parent:
            off = members[("current", parent)]["offset"]
            base = base.format(cred=off, thread_pid=off)
        assert (base, member) in members, (function, base, member, sorted(members))
        assert members[(base, member)]["exact"] is True
    assert all(a["location"]["space"] == "kernel_va" for a in payload["accesses"])


@needs_corpus
def test_arm64_do_exit_richer_join(arm_image):
    label = arm_image[0]
    payload = _run(arm_image, "do_exit")
    checked, exact, unresolved = _DO_EXIT[label]
    join = payload["isf_join"]
    assert (join["checked"], join["exact"], join["unresolved"]) == (checked, exact, unresolved)
    assert join["contained"] == 0
    members = _members(payload)
    for key in (("current", "signal"), ("current", "mm"), ("current", "tgid"),
                ("current", "exit_code")):
        assert key in members and members[key]["struct"] == "task_struct"
    writes = {a["isf_member"]["member"] for a in payload["accesses"]
              if a["base"] == "current" and a["kind"] == "write" and a.get("isf_member")}
    assert "exit_code" in writes
    assert any(b.startswith("deref(current+") for b, _ in members)  # chain followed


@pytest.mark.skipif(not _have(_DEBIAN), reason=_SKIP)
@pytest.mark.parametrize("function", sorted(_EXPECT_DEBIAN))
def test_arm64_debian12_verified_init_task_delta_places_reads(function):
    """debian-12 arm64: kallsyms has no init_task, so the VERIFIED self_reference anchor's
    va->pa delta places the reads (delta_source 'explicit'); the pakunoda self-tests are
    SKIPPED there and must be reported as skipped, never as passed."""
    image, isf = (Path(_ROOT) / f for f in _DEBIAN)
    payload = code_evidence_result(image_path=str(image), function=function,
                                   params={"isf": str(isf)}).payload
    reads = payload["image_reads"]
    assert reads["delta_source"] == "explicit"
    assert reads["init_task_anchor_source"] == "self_reference"
    assert reads["self_tests"] == {"banner": "skipped", "kimage_voffset": "skipped"}
    assert any("SKIPPED" in w and "not passed" in w for w in payload["warnings"])
    assert payload["coverage"]["complete"] is True and payload["coverage"]["truncated"] is False
    accesses, join = _EXPECT_DEBIAN[function]
    assert len(payload["accesses"]) == accesses
    got = payload["isf_join"]
    assert {k: got[k] for k in join} == join and got["contained"] == 0
    members = {(a["base"], a["isf_member"]["member"]): a["isf_member"]
               for a in payload["accesses"] if a.get("isf_member")}
    assert set(members) == _debian_keys(function, members)
    assert all(m["exact"] for m in members.values())

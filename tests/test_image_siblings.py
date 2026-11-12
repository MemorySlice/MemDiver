"""Sibling groups of one image (plan S2): core/image/siblings.py + the image.siblings producer
on all four surfaces.

The grouping is pure and tested on hand-made ``TaskFacts``; the vol3 walk runs over fake
task/mm/VMA objects; the frame accounting runs the REAL classifier over synthetic x86_64
page tables (tests/_synthetic_pagetables.py). The real-image gate is
tests/test_image_siblings_real.py.
"""

import json
import struct
from types import SimpleNamespace

import pytest

from memdiver.app import tools_image as ti
from memdiver.core.image import siblings as S
from memdiver.core.image.view_descriptor import ProfileRef
from memdiver.core.service_errors import CapabilityError

# --- synthetic ELF ----------------------------------------------------------------------------

BUILD_ID = bytes(range(20))


def _note(name=b"GNU\x00", kind=S.NT_GNU_BUILD_ID, desc=BUILD_ID, endian="<"):
    pad = lambda b: b + b"\x00" * (-len(b) % 4)  # noqa: E731
    return struct.pack(endian + "III", len(name), len(desc), kind) + pad(name) + pad(desc)


def elf64(notes, note_offset=0x200, endian="<", phnum_extra=1):
    """An ELF64 header + phdrs (one PT_LOAD, one PT_NOTE) + ``notes`` at ``note_offset``."""
    image = bytearray(0x1000)
    image[:6] = b"\x7fELF" + bytes([2, 1 if endian == "<" else 2])
    struct.pack_into(endian + "Q", image, 0x20, 0x40)            # e_phoff
    struct.pack_into(endian + "HH", image, 0x36, 56, 1 + phnum_extra)  # e_phentsize, e_phnum
    struct.pack_into(endian + "I", image, 0x40, 1)                # PT_LOAD
    note_phdr = 0x40 + 56
    struct.pack_into(endian + "I", image, note_phdr, S.PT_NOTE)
    struct.pack_into(endian + "Q", image, note_phdr + 8, note_offset)
    struct.pack_into(endian + "Q", image, note_phdr + 32, len(notes))
    image[note_offset:note_offset + len(notes)] = notes
    return bytes(image)


def elf32(notes, note_offset=0x100):
    image = bytearray(0x1000)
    image[:6] = b"\x7fELF\x01\x01"
    struct.pack_into("<I", image, 0x1C, 0x34)
    struct.pack_into("<HH", image, 0x2A, 32, 1)
    struct.pack_into("<III", image, 0x34, S.PT_NOTE, note_offset, 0)
    struct.pack_into("<I", image, 0x34 + 16, len(notes))
    image[note_offset:note_offset + len(notes)] = notes
    return bytes(image)


def reader(blob, base):
    def read(va, length):
        if not base <= va or va + length > base + len(blob):
            raise ValueError("unmapped")
        return blob[va - base:va - base + length]
    return read


BASE = 0x555500000000


def test_parse_build_id_gnu_note_after_another_note():
    notes = _note(b"GNU\x00", kind=1, desc=b"\x00" * 16) + _note()
    assert S.parse_build_id(reader(elf64(notes), BASE), BASE, 0x1000) == BUILD_ID.hex()


def test_parse_build_id_big_endian_and_elf32():
    assert S.parse_build_id(reader(elf64(_note(endian=">"), endian=">"), BASE), BASE,
                            0x1000) == BUILD_ID.hex()
    assert S.parse_build_id(reader(elf32(_note()), BASE), BASE, 0x1000) == BUILD_ID.hex()


@pytest.mark.parametrize("blob,mapped", [
    (b"\x00" * 0x1000, 0x1000),                            # not ELF
    (elf64(_note(name=b"XYZ\x00")), 0x1000),               # wrong owner
    (elf64(_note(), note_offset=0xF00), 0xF00),            # note outside the mapped page
    (elf64(b"\xff" * 12), 0x1000),                         # truncated / garbage note
])
def test_parse_build_id_none_cases(blob, mapped):
    assert S.parse_build_id(reader(blob, BASE), BASE, mapped) is None


def test_parse_build_id_unreadable_page_raises():
    with pytest.raises(ValueError):
        S.parse_build_id(reader(b"", BASE), BASE, 0x1000)


# --- pure grouping -----------------------------------------------------------------------------

LAYOUT_A = (0x5000, 0x7F00, 0x7FFE)
DROPBEAR = "d0de"


def facts(pid, ppid, aslr=LAYOUT_A, build_id=DROPBEAR, exe="/usr/sbin/dropbear", comm="dropbear"):
    return S.TaskFacts(pid, ppid, comm, mm=pid * 0x100, aslr=aslr, exe_path=exe,
                       build_id=build_id, build_id_source="elf_note" if build_id else None)


def _parents(items):
    return {f.pid: f.ppid for f in items}


def _layout(n):
    return (0x5000 + n, 0x7F00 + n, 0x7FFE + n)


def test_forked_group_with_listener_excluded_by_default():
    items = [facts(100, 1)] + [facts(p, 100) for p in (101, 102, 103)]
    (group,) = S.group_siblings(items, _parents(items))
    roles = {m.facts.pid: (m.role, m.analysed) for m in group.members}
    assert roles == {100: ("listener", False), 101: ("child", True),
                     102: ("child", True), 103: ("child", True)}
    assert (group.shape, group.pair_shapes, group.family_root) == ("forked", {"forked": 3}, 100)
    assert group.analysis_pids == [101, 102, 103]
    assert group.layout_clusters == [[101, 102, 103]]
    (with_parent,) = S.group_siblings(items, _parents(items), include_parent=True)
    assert with_parent.analysis_pids == [100, 101, 102, 103] and with_parent.shape == "forked"


def test_reexec_monitor_session_pairs_are_mixed_with_intermediate_roles():
    sshd = dict(build_id="5181", exe="/usr/sbin/sshd", comm="sshd")
    items = [facts(200, 1, _layout(0), **sshd)]
    for i, (mon, ses) in enumerate(((210, 211), (220, 221)), start=1):
        items += [facts(mon, 200, _layout(i), **sshd), facts(ses, mon, _layout(i), **sshd)]
    (group,) = S.group_siblings(items, _parents(items))
    assert {m.facts.pid: m.role for m in group.members} == {
        200: "listener", 210: "intermediate", 211: "child", 220: "intermediate", 221: "child"}
    assert group.shape == "mixed"
    assert group.pair_shapes == {"forked": 2, "independent": 4}
    assert sorted(group.layout_clusters) == [[210, 211], [220, 221]]


def test_standalone_daemons_pool_into_one_independent_group():
    items = [facts(p, 1, _layout(p), build_id="7bf1", exe="/usr/bin/gocryptfs",
                   comm="gocryptfs") for p in (300, 301, 302)]
    (group,) = S.group_siblings(items, _parents(items))
    assert (group.family_root, group.shape) == (None, "independent")
    assert {m.role for m in group.members} == {"standalone"}


def test_two_families_of_one_binary_split_unless_asked():
    items = [facts(100, 1), facts(101, 100), facts(102, 100),
             facts(400, 1, _layout(4)), facts(401, 400, _layout(4)), facts(402, 400, _layout(4))]
    groups = S.group_siblings(items, _parents(items))
    assert [(g.family_root, g.shape) for g in groups] == [(100, "forked"), (400, "forked")]
    (merged,) = S.group_siblings(items, _parents(items), split_families=False)
    assert merged.family_root is None and merged.shape == "mixed"
    assert merged.analysis_pids == [101, 102, 401, 402]


def test_min_members_counts_analysed_members():
    items = [facts(100, 1), facts(101, 100)]
    assert S.group_siblings(items, _parents(items)) == []
    assert len(S.group_siblings(items, _parents(items), min_members=1)) == 1
    assert len(S.group_siblings(items, _parents(items), include_parent=True)) == 1


def test_unreadable_build_id_is_inferred_from_the_exe_path_once_unambiguous():
    items = [facts(100, 1), facts(101, 100, build_id=None), facts(102, 100, build_id=None)]
    (group,) = S.group_siblings(items, _parents(items))
    assert group.identity == DROPBEAR
    assert [m.facts.build_id_source for m in group.members] == [
        "elf_note", "inferred_from_exe", "inferred_from_exe"]
    two_builds = items + [facts(103, 1, build_id="other")]
    filled = S.fill_build_ids_from_exe(two_builds)
    assert [f.build_id for f in filled][1:3] == [None, None]


def test_identity_falls_back_to_exe_then_comm():
    assert facts(1, 0, build_id=None).identity == ("exe_path", "/usr/sbin/dropbear")
    assert facts(1, 0, build_id=None, exe=None).identity == ("comm", "dropbear")


def test_pair_shapes():
    parents = {1: 0, 2: 1, 3: 2, 4: 0}
    assert S.pair_shape(facts(1, 0), facts(3, 2), parents) == "forked"   # grand-ancestor
    assert S.pair_shape(facts(2, 1), facts(4, 0), parents) == "same_layout_unrelated"
    assert S.pair_shape(facts(2, 1), facts(4, 0, _layout(9)), parents) == "independent"
    assert S.group_shape([facts(1, 0)], parents) == ("single", {})
    shape, _ = S.group_shape([facts(2, 1), facts(4, 0)], parents)
    assert shape == "mixed"


# --- the vol3 walk over fake tasks -------------------------------------------------------------

EXE_FILE, LIB_FILE = 0xF11E, 0x11B


class FakeVma(SimpleNamespace):
    def get_name(self, context, task):
        return self.name


class FakeMm(SimpleNamespace):
    def __int__(self):
        return self.address

    def get_vma_iter(self):
        return iter(self.vmas)


class FakeLayer:
    def __init__(self, pages):
        self.pages = pages

    def read(self, va, length, pad=False):
        for base, blob in self.pages.items():
            if base <= va and va + length <= base + len(blob):
                return blob[va - base:va - base + length]
        raise ValueError("page not resident")


class FakeTask:
    def __init__(self, ctx, pid, ppid, comm, mm, header=None, aslr=LAYOUT_A):
        self.tgid, self._ppid, self.mm = pid, ppid, mm
        self.comm = SimpleNamespace(cast=lambda *a, **k: comm)
        self._ctx, self._header = ctx, header

    def get_parent_pid(self):
        return self._ppid

    def add_process_layer(self):
        name = f"proc{self.tgid}"
        pages = {} if self._header is None else {int(self.mm.start_code) - 0x1000: self._header}
        self._ctx.context.layers[name] = FakeLayer(pages)
        return name


def fake_mm(address, start=BASE, name="/usr/sbin/dropbear"):
    vmas = [FakeVma(vm_start=start, vm_end=start + 0x1000, vm_file=EXE_FILE, vm_pgoff=0,
                    name=name),
            FakeVma(vm_start=start + 0x1000, vm_end=start + 0x3000, vm_file=EXE_FILE,
                    vm_pgoff=1, name=name),
            FakeVma(vm_start=0x7F0000000000, vm_end=0x7F0000001000, vm_file=LIB_FILE,
                    vm_pgoff=0, name="/lib/libc.so.6")]
    return FakeMm(address=address, start_code=start + 0x1000, mmap_base=0x7F00,
                  start_stack=0x7FFE, vmas=vmas)


@pytest.fixture
def fake_image(monkeypatch):
    pytest.importorskip("volatility3")
    from volatility3.plugins.linux import pslist
    import threading
    ctx = SimpleNamespace(lock=threading.RLock(), context=SimpleNamespace(layers={}),
                          kernel=SimpleNamespace(name="kernel"))
    tasks = []
    monkeypatch.setattr(pslist.PsList, "list_tasks",
                        classmethod(lambda cls, context, name, *a, **k: iter(tasks)))
    return ctx, tasks


def test_collect_dedups_mm_skips_kernel_threads_and_reads_build_ids(fake_image):
    ctx, tasks = fake_image
    header = elf64(_note())
    listener_mm = fake_mm(0xA000)
    tasks += [FakeTask(ctx, 2, 0, "kthreadd", 0),
              FakeTask(ctx, 100, 1, "dropbear", listener_mm, header),
              FakeTask(ctx, 105, 1, "dropbear", listener_mm, header),     # same mm (vfork)
              FakeTask(ctx, 101, 100, "dropbear", fake_mm(0xB000)),      # header not resident
              FakeTask(ctx, 102, 100, "dropbear", fake_mm(0xC000)),
              FakeTask(ctx, 300, 1, "bash", fake_mm(0xD000, name="/usr/bin/bash"), header)]
    items, parents, duplicates = S.collect_task_facts(ctx)
    assert [f.pid for f in items] == [100, 101, 102, 300]
    assert duplicates == {105: 100} and parents[101] == 100 and parents[2] == 0
    first = items[0]
    assert (first.build_id, first.build_id_source, first.exe_path) == (
        BUILD_ID.hex(), "elf_note", "/usr/sbin/dropbear")
    assert items[1].build_id is None and "unreadable" in items[1].build_id_error
    assert [f.pid for f in S.collect_task_facts(ctx, comm="dropbear")[0]] == [100, 101, 102]
    found = S.discover_siblings(ctx)
    assert found.tasks_examined == 5 and found.same_address_space == {105: 100}
    (group,) = found.groups
    assert (group.identity, group.shape, group.analysis_pids) == (
        BUILD_ID.hex(), "forked", [101, 102])


# --- the producer -----------------------------------------------------------------------------

HEAP = 0x555500000000


def _synthetic_classify(pids):
    """SiblingFrames of a forked group over synthetic page tables: per member one page shared
    (fork CoW, same frame) and one private dirty page."""
    pytest.importorskip("volatility3")
    from memdiver.core.image.page_sharing import SiblingFrames
    from memdiver.vol3plugins.memdiver import frames as F
    from tests._synthetic_pagetables import (
        ACCESSED, DIRTY, P, RW, USER, PageTables, PhysMemory, layers)
    mem = PhysMemory()
    vmas = [F.VmaInfo(HEAP, HEAP + 0x2000, F.VM_WRITE, False)]
    tables = []
    for index, _ in enumerate(pids):
        t = PageTables(mem)
        t.map4k(HEAP, 0x400000, P | USER | ACCESSED | DIRTY)
        t.map4k(HEAP + 0x1000, 0x500000 + index * 0x1000, P | RW | USER | ACCESSED | DIRTY)
        tables.append(t)
    members = {pid: list(F.member_frames(lay, vmas))
               for pid, lay in zip(pids, layers(mem, tables))}
    return SiblingFrames(F.classify_frames(members, ()), {pid: 0.01 for pid in pids})


@pytest.fixture
def producer_fakes(monkeypatch, tmp_path):
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "xdg"))
    image = tmp_path / "img" / "box.lime"
    image.parent.mkdir()
    image.write_bytes(b"\x00" * 8192)
    profile = ProfileRef(str(tmp_path / "img" / "box.isf.json"), "ab" * 32, "explicit")
    monkeypatch.setattr(ti, "_profiled_context", lambda img, isf: (SimpleNamespace(), profile))
    items = [facts(100, 1), facts(101, 100), facts(102, 100),
             facts(300, 1, _layout(3), build_id="7bf1", exe="/usr/bin/gocryptfs")]
    calls = {"classify": [], "open": []}
    monkeypatch.setattr(S, "collect_task_facts",
                        lambda ctx, comm=None: ([f for f in items if not comm or f.comm == comm],
                                                _parents(items), {}))

    def classify(ctx, pids):
        calls["classify"].append(list(pids))
        return _synthetic_classify(list(pids))
    monkeypatch.setattr("memdiver.core.image.page_sharing.classify_processes", classify)

    def open_view(image_path, view, pid, isf, case_dir):
        calls["open"].append((view, pid, case_dir))
        return SimpleNamespace(payload={"view_path": f"/views/pid{pid}.mdview"})
    monkeypatch.setattr(ti, "image_open_view_result", open_view)
    return image, calls


def test_producer_groups_accounting_and_views(producer_fakes):
    image, calls = producer_fakes
    out = ti.image_siblings_result(str(image), open_views=True, case_dir="demo").payload
    assert out["count"] == 1 and out["profile_origin"] == "explicit"
    (group,) = out["groups"]
    assert (group["shape"], group["family_root"], group["analysis_pids"]) == (
        "forked", 100, [101, 102])
    assert calls["classify"] == [[101, 102]]
    rows = {m["pid"]: m for m in group["members"]}
    assert rows[100]["accounting"] is None and rows[100]["view_path"] is None
    acc = rows[101]["accounting"]
    assert (acc["rss"], acc["private_dirty"], acc["shared_lineage"], acc["private_pct"]) == (
        8192, 4096, 4096, 50.0)
    assert acc["shared_file"] == acc["shmem"] == acc["smear"] == 0
    assert rows[101]["view_path"] == "/views/pid101.mdview"
    assert calls["open"] == [("process", 101, "demo"), ("process", 102, "demo")]
    assert rows[101]["aslr"]["start_code"] == LAYOUT_A[0]
    json.dumps(out)  # plain JSON


def test_producer_without_accounting_and_with_parent(producer_fakes):
    image, calls = producer_fakes
    out = ti.image_siblings_result(str(image), accounting=False, include_parent=True,
                                   min_members=1).payload
    assert calls["classify"] == [] and out["timings"]["accounting_seconds"] == 0
    assert [g["analysis_pids"] for g in out["groups"]] == [[100, 101, 102], [300]]
    assert all(m["accounting"] is None for g in out["groups"] for m in g["members"])


def test_producer_bad_input(producer_fakes, tmp_path):
    image, _ = producer_fakes
    with pytest.raises(CapabilityError) as err:
        ti.image_siblings_result(str(image), min_members=0)
    assert err.value.code == "invalid_min_members"
    with pytest.raises(CapabilityError):
        ti.image_siblings_result(str(tmp_path / "missing.lime"))


# --- surfaces ---------------------------------------------------------------------------------

def test_cli_siblings(producer_fakes, capsys):
    from memdiver.cli import _build_parser, _cmd_image
    image, calls = producer_fakes
    rc = _cmd_image(_build_parser().parse_args(
        ["image", "siblings", str(image), "--comm", "dropbear", "--no-accounting"]))
    out = json.loads(capsys.readouterr().out)
    assert rc == 0 and out["comm"] == "dropbear" and out["count"] == 1
    assert calls["classify"] == []


@pytest.fixture
def client(monkeypatch, tmp_path):
    from fastapi.testclient import TestClient

    from memdiver.api.config import get_settings
    from memdiver.api.main import create_app
    monkeypatch.delenv("MEMDIVER_ALLOWED_ROOTS", raising=False)
    monkeypatch.setenv("MEMDIVER_UPLOAD_DIR", str(tmp_path / "uploads"))
    get_settings.cache_clear()
    yield TestClient(create_app())
    get_settings.cache_clear()


def test_rest_get_is_inline_and_post_submits_a_contained_job(client, producer_fakes,
                                                             monkeypatch, tmp_path):
    image, _ = producer_fakes
    r = client.get("/api/image/siblings", params={"image_path": str(image),
                                                  "accounting": "false"})
    assert r.status_code == 200 and r.json()["groups"][0]["family_root"] == 100
    submitted = []
    monkeypatch.setattr("memdiver.api.routers.image._submit",
                        lambda job, args: submitted.append((job, args)) or {"task_id": "t"})
    r = client.post("/api/image/siblings", json={"image_path": str(image),
                                                 "open_views": True, "case_dir": "demo"})
    assert r.status_code == 200 and submitted[0][0] == "siblings"
    assert submitted[0][1]["open_views"] is True and submitted[0][1]["case_dir"] == "demo"
    r = client.post("/api/image/siblings", json={"image_path": str(image),
                                                 "case_dir": str(tmp_path / "elsewhere")})
    assert r.status_code == 403 and len(submitted) == 1


def test_job_runner_knows_the_siblings_job():
    from memdiver.app.pipeline import image_task_runner
    assert "siblings" in image_task_runner.JOBS


def test_mcp_tool(producer_fakes):
    pytest.importorskip("mcp")
    from memdiver.mcp_server.server import create_server
    from memdiver.mcp_server.tool_policy import classify_tools
    server = create_server()
    tool = {t.name: t for t in server._tool_manager.list_tools()}["image_siblings"]
    image, _ = producer_fakes
    out = json.loads(tool.fn(image_path=str(image), accounting=False))
    assert out["groups"][0]["analysis_pids"] == [101, 102]
    assert classify_tools(server)["image_siblings"].access == "write"

"""``msl.threads`` (``vol3plugins/msl/threads.py``): THREAD_CONTEXT rows, spec 5.7."""

import pytest

pytest.importorskip("volatility3")

from memdiver.vol3plugins import msl_layer  # noqa: E402
from memdiver.vol3plugins.msl import threads  # noqa: E402
from tests.test_vol3plugins_msl_layer import _file_context, plain_slice  # noqa: E402,F401
from tests.test_vol3plugins_msl_slim import (  # noqa: E402
    plain_rows, rich_slice, run_plugin, run_with_both_readers, sample_msls)  # noqa: F401


@pytest.fixture(autouse=True)
def _fresh_layer_cache():
    yield
    msl_layer.close_slices()


def test_rows_pick_pc_sp_fp_by_role(rich_slice):
    rows = plain_rows(run_plugin(threads.Threads, rich_slice[0])[0])
    assert len(rows) == 2
    main, sleeper = rows
    assert main[:9] == (1001, "main", "RUNNING", "X86_64", "current", 0x401000, 0x7FFF0000,
                        0x7FFF0008, 5)
    assert sleeper[:9] == (1002, "N/A", "SLEEPING", "X86_64", "suspended", 0x402000,
                           0x7FFE0000, 0x7FFE0008, 5)
    assert main[9] == "not recorded" and len(main) == 10  # no Registers column


def test_verbose_adds_every_register(rich_slice):
    rows = plain_rows(run_plugin(threads.Threads, rich_slice[0], verbose=True)[0])
    registers = rows[0][10]
    assert "rax=0xaa" in registers and "rip=0x401000" in registers
    assert "xmm0=" + bytes(range(16)).hex() in registers  # wide register: raw bytes


def test_slim_reader_gives_the_same_rows(rich_slice, monkeypatch):
    full, slim, _, _ = run_with_both_readers(threads.Threads, rich_slice[0], monkeypatch,
                                             verbose=True)
    assert full == slim and len(full) == 2


def test_real_sample_has_one_thread(sample_msls):
    rows = plain_rows(run_plugin(threads.Threads, sample_msls["ssh_libssh_client.msl"],
                                 verbose=True)[0])
    assert len(rows) == 1 and rows[0][8] == len(rows[0][10].split())
    assert rows[0][5] != "N/A"  # a program counter is recorded


def test_capture_without_threads_has_no_rows(plain_slice):
    assert run_plugin(threads.Threads, plain_slice[0])[0] == []


def test_role_register_falls_back_to_conventional_names():
    from types import SimpleNamespace

    def reg(name, value, flags=0, width=8):
        return SimpleNamespace(name=name, width=width, flags=flags,
                               value=value.to_bytes(width, "little"))

    thread = SimpleNamespace(registers=[reg("rip", 0x10), reg("sp", 0x20)],
                             register=lambda n: next((r for r in thread.registers
                                                      if r.name == n), None))
    assert threads.role_register(thread, threads.ROLE_PC) == 0x10
    assert threads.role_register(thread, threads.ROLE_SP) == 0x20
    assert threads.role_register(thread, threads.ROLE_FP) is None


def test_flags_text():
    assert threads.flags_text(0) == "-"
    assert threads.flags_text(0x0B) == "current,crashed,partial"


def test_non_msl_primary_refuses_cleanly(plain_slice, caplog):
    ctx = _file_context(plain_slice[0])
    ctx.config["plugins.P.primary"] = "FileLayer"
    rows = []
    threads.Threads(ctx, "plugins.P").run().populate(
        lambda node, acc: rows.append(node.values) or acc, None)
    assert rows == [] and "not an MSL capture layer" in caplog.text

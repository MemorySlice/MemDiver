"""Cross-repo Thread Context interop: blocks written by memslicer's
``MSLWriter.write_thread_context`` (spec Tables 19a/19b, type 0x0011) must
decode field-for-field through MemDiver's reader, and both sides must agree
on the ``ThreadState`` / ``TC_FLAG_*`` / ``REG_ROLE_*`` vocabularies.

Skipped when the sibling ``memslicer`` package is not importable or too old.
"""

from uuid import UUID

import pytest

pytest.importorskip("blake3")
pytest.importorskip("memslicer.msl.writer")

try:
    from memslicer.msl import constants as ms_constants  # noqa: E402
    from memslicer.msl.constants import (  # noqa: E402
        REG_ROLE_FLAGS,
        REG_ROLE_FP,
        REG_ROLE_PC,
        REG_ROLE_SP,
        TC_FLAG_CURRENT,
        TC_FLAG_SUSPENDED,
        PageState,
        ThreadState,
    )
    from memslicer.msl.types import (  # noqa: E402
        FileHeader,
        MemoryRegion,
        ProcessIdentity,
        ThreadContext,
        ThreadRegister,
    )
    from memslicer.msl.writer import _TC_HEAD, MSLWriter, _pack_thread_register  # noqa: E402
except ImportError as exc:
    pytest.skip(f"installed memslicer predates Thread Context (needs >= 0.5): {exc}",
                allow_module_level=True)

from memdiver.msl import enums as md_enums  # noqa: E402
from memdiver.msl.decoders_ext import decode_thread_context  # noqa: E402
from memdiver.msl.integrity import verify_chain  # noqa: E402
from memdiver.msl.reader import MslReader  # noqa: E402
from memdiver.msl.types import MslBlockHeader, MslThreadContext  # noqa: E402

BO = "<"
_PC_VALUE = (0x00007FFF_DEAD_BEEF).to_bytes(8, "little")
_SP_VALUE = (0x00007FFF_0000_1000).to_bytes(8, "little")
_FP_VALUE = (0x00007FFF_0000_1080).to_bytes(8, "little")
_FLAGS_VALUE = (0x0000_0000_0000_0246).to_bytes(8, "little")
_XMM0_VALUE = bytes(range(16))


def _main_thread() -> ThreadContext:
    return ThreadContext(
        thread_id=0x1001,
        start_time_ns=1_700_000_000_123_456_789,
        flags=TC_FLAG_CURRENT,
        state=ThreadState.RUNNING,
        arch=0,
        name="main",
        registers=[
            ThreadRegister("pc", 8, REG_ROLE_PC, _PC_VALUE),
            ThreadRegister("sp", 8, REG_ROLE_SP, _SP_VALUE),
            ThreadRegister("fp", 8, REG_ROLE_FP, _FP_VALUE),
            ThreadRegister("flags", 8, REG_ROLE_FLAGS, _FLAGS_VALUE),
            ThreadRegister("xmm0", 16, 0, _XMM0_VALUE),
        ],
    )


def _worker_thread() -> ThreadContext:
    return ThreadContext(
        thread_id=0x1002,
        start_time_ns=1_700_000_000_987_654_321,
        flags=TC_FLAG_SUSPENDED,
        state=ThreadState.SLEEPING,
        arch=0,
        name="",
        registers=[ThreadRegister("pc", 8, REG_ROLE_PC, _PC_VALUE)],
    )


def _write_memslicer(path, threads):
    with path.open("wb") as f:
        w = MSLWriter(f, FileHeader(pid=4242))
        w.write_process_identity(ProcessIdentity(ppid=1, exe_path="/bin/x", cmd_line="x"))
        for tc in threads:
            w.write_thread_context(tc)
        w.write_memory_region(MemoryRegion(
            base_addr=0x10000, region_size=4096, protection=3,
            page_states=[PageState.CAPTURED],
            page_data_chunks=[b"\x41" * 4096],
        ))
        w.finalize()
    return path


def _hdr(block_length: int) -> MslBlockHeader:
    return MslBlockHeader(
        block_type=0x0011, flags=0, block_length=block_length,
        payload_version=1,
        block_uuid=UUID(int=1), parent_uuid=UUID(int=0),
        prev_hash=b"\x00" * 32,
        file_offset=0, payload_offset=80,
    )


def _pad8(data: bytes) -> bytes:
    return data.ljust((len(data) + 7) & ~7, b"\x00")


def _assert_matches(decoded: MslThreadContext, written: ThreadContext) -> None:
    assert decoded.thread_id == written.thread_id
    assert decoded.start_time_ns == written.start_time_ns
    assert decoded.flags == written.flags
    assert int(decoded.state) == int(written.state)
    assert decoded.arch == written.arch
    assert decoded.name == written.name
    assert len(decoded.registers) == len(written.registers)
    for got, want in zip(decoded.registers, written.registers):
        assert got.name == want.name.lower()
        assert got.width == want.width
        assert got.flags == want.flags
        assert got.value == want.value


def test_memslicer_thread_contexts_roundtrip(tmp_path):
    main, worker = _main_thread(), _worker_thread()
    path = _write_memslicer(tmp_path / "threads.msl", [main, worker])

    with MslReader(path) as reader:
        contexts = reader.collect_thread_contexts()
        report = verify_chain(reader)

    assert report.valid, report.errors
    assert len(contexts) == 2
    assert all(isinstance(tc, MslThreadContext) for tc in contexts)
    first, second = contexts
    _assert_matches(first, main)
    _assert_matches(second, worker)

    assert first.current is True
    assert first.suspended is False
    assert second.current is False
    assert second.suspended is True
    assert first.register("pc").is_pc
    assert first.register("sp").is_sp
    assert first.register("xmm0").width == 16
    assert first.register("xmm0").value == _XMM0_VALUE
    assert second.register("pc").is_pc


def test_payload_level_roundtrip():
    registers = [
        ThreadRegister("PC", 8, REG_ROLE_PC, _PC_VALUE),
        ThreadRegister("xmm0", 16, 0, _XMM0_VALUE),
    ]
    name_raw = b"main\x00"
    payload = _TC_HEAD.pack(
        0x1001, 1_700_000_000_123_456_789, TC_FLAG_CURRENT,
        int(ThreadState.RUNNING), 0, len(registers), len(name_raw),
    )
    payload += _pad8(name_raw)
    payload += b"".join(_pack_thread_register(r) for r in registers)

    tc = decode_thread_context(_hdr(len(payload)), payload, BO)
    assert isinstance(tc, MslThreadContext)
    assert tc.thread_id == 0x1001
    assert tc.start_time_ns == 1_700_000_000_123_456_789
    assert tc.flags == TC_FLAG_CURRENT
    assert tc.state == ThreadState.RUNNING
    assert tc.arch == 0
    assert tc.name == "main"
    assert len(tc.registers) == 2
    assert (tc.registers[0].name, tc.registers[0].width, tc.registers[0].flags,
            tc.registers[0].value) == ("pc", 8, REG_ROLE_PC, _PC_VALUE)
    assert (tc.registers[1].name, tc.registers[1].width, tc.registers[1].flags,
            tc.registers[1].value) == ("xmm0", 16, 0, _XMM0_VALUE)
    assert tc.register("pc").is_pc

    unnamed = _TC_HEAD.pack(
        0x1002, 0, TC_FLAG_SUSPENDED, int(ThreadState.SLEEPING), 0, 1, 0,
    ) + _pack_thread_register(registers[0])
    tc2 = decode_thread_context(_hdr(len(unnamed)), unnamed, BO)
    assert isinstance(tc2, MslThreadContext)
    assert tc2.thread_id == 0x1002
    assert tc2.name == ""
    assert tc2.suspended
    assert tc2.state == ThreadState.SLEEPING
    assert len(tc2.registers) == 1
    assert tc2.registers[0].name == "pc"
    assert tc2.registers[0].value == _PC_VALUE


_TC_FLAG_NAMES = ("CURRENT", "CRASHED", "SUSPENDED", "PARTIAL")
_REG_ROLE_NAMES = ("PC", "SP", "FP", "FLAGS", "TLS", "LR")


def test_thread_state_enums_agree():
    ms_names = {m.name for m in ThreadState}
    md_names = {m.name for m in md_enums.ThreadState}
    assert ms_names == md_names
    assert all(n.isupper() for n in ms_names)
    for member in ThreadState:
        assert md_enums.ThreadState[member.name].value == member.value, member.name

    for name in _TC_FLAG_NAMES:
        attr = f"TC_FLAG_{name}"
        assert getattr(ms_constants, attr) == getattr(md_enums, attr), attr
    for name in _REG_ROLE_NAMES:
        attr = f"REG_ROLE_{name}"
        assert getattr(ms_constants, attr) == getattr(md_enums, attr), attr

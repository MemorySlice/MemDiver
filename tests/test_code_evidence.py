"""Tests for engine.code_evidence and app.tools_code_evidence (plan T5.5)."""

import pytest

pytest.importorskip("pakunoda")

from pakunoda.arch.data_refs import DataRefKind
from pakunoda.arch.field_access import FieldAccess as PkAccess
from pakunoda.arch.field_access import SymbolicBase

from memdiver.app import tools_code_evidence as tce
from memdiver.core.service_errors import CapabilityError
from memdiver.engine import code_evidence as ce

# mov rax,[rdi+0x4d0]; ret
CODE = bytes.fromhex("488b87d0040000c3")
TARGET = ce.CodeTarget("f", 0xFFFFFFFF81000000, 8, "x86_64")


def test_map_real_pakunoda_records_faithfully():
    raw = PkAccess(0x10, SymbolicBase.deref(SymbolicBase.current(), 0x678), 4, 4,
                   DataRefKind.STORE, "eax")
    mapped = ce.PakunodaFieldAccessProvider._map(raw)
    assert (mapped.base, mapped.offset, mapped.width, mapped.kind) == (
        "deref(current+0x678)", 4, 4, "write")
    assert "dest_reg=eax" in mapped.detail
    addr = PkAccess(0x20, SymbolicBase.static("init_task"), 8, None, DataRefKind.ADDRESS_OF, "rax")
    assert ce.PakunodaFieldAccessProvider._map(addr).kind == "address"


def test_real_decode_via_registry():
    ev = ce.evidence_for(CODE, TARGET, current_task_vas=[0x1000])
    assert [(a.base, a.offset, a.width, a.kind) for a in ev.accesses] == [("arg0", 0x4D0, 8, "read")]
    assert ev.coverage["complete"] and ev.coverage["declined"] is None
    assert ev.to_dict()["accesses"][0]["insn_va"] == TARGET.va


def test_x86_without_current_vas_warns():
    assert ce.evidence_for(CODE, TARGET).warnings


@pytest.mark.parametrize("arch", ["i386", "arm", "mips", "riscv64"])
def test_declined_arch_is_explicit_not_empty_success(arch):
    ev = ce.evidence_for(CODE, ce.CodeTarget("f", 0, 8, arch))
    assert ev.accesses == () and ev.coverage["declined"]


def test_unknown_provider_declines():
    ev = ce.evidence_for(CODE, TARGET, provider="nope")
    assert ev.coverage["declined"] and ev.provider == "nope"


def test_support_for_fields_join():
    acc = lambda base, off: ce.FieldAccess(1, base, off, 8, "read")  # noqa: E731
    ev = ce.CodeEvidence("p", TARGET, (acc("current", 0x4D0), acc("current", 0x4D4),
                                       acc("arg0", 0x10)))
    out = ce.support_for_fields(ev, "current", {0x4D0: 8, 0x600: 8})
    assert len(out[0x4D0]) == 2 and out[0x600] == []   # 0x4d4 falls inside the 8-byte field
    assert ce.support_for_fields(ev, "arg0", [(0x10, None)])[0x10]


TYPES = {"task_struct": {"fields": {
    "cred": {"offset": 0x678, "type": {"kind": "pointer", "subtype": {"kind": "struct", "name": "cred"}}}}},
    "cred": {"fields": {"uid": {"offset": 4, "type": {"kind": "base", "name": "int"}}}}}


def test_isf_member_join():
    cur = ce.FieldAccess(1, "current", 0x678, 8, "read")
    deref = ce.FieldAccess(2, "deref(current+0x678)", 4, 4, "read")
    assert tce._isf_member_for(cur, TYPES)["member"] == "cred"
    assert tce._isf_member_for(deref, TYPES)["struct"] == "cred"
    assert tce._isf_member_for(ce.FieldAccess(3, "arg0", 0x678, 8, "read"), TYPES) is None


class FakeSession:
    arch_name, arch_source, capture = "x86_64", "explicit", "c" * 64

    def __init__(self, symbols):
        self._symbols = symbols

    def symbols(self):
        return self._symbols


def _code(exc_code, **kw):
    with pytest.raises(CapabilityError) as info:
        tce.code_evidence_result(FakeSession(kw.pop("symbols")), image_path="x", **kw)
    assert info.value.code == exc_code


def test_producer_error_paths():
    _code("code_evidence.no_kallsyms", symbols={}, function="f")
    _code("code_evidence.unknown_function", symbols={"a": 0x1000}, function="zzz")
    _code("code_evidence.function_required", symbols={"a": 0x1000}, function=" ")
    _code("code_evidence.invalid_max_bytes", symbols={"a": 1}, function="a", max_bytes=0)
    _code("code_evidence.isf_not_found", symbols={"a": 1}, function="a",
          params={"isf": "/nonexistent.json"})


def test_producer_unsupported_arch():
    session = FakeSession({"a": 0x1000})
    session.arch_name = "riscv64"
    with pytest.raises(CapabilityError) as info:
        tce.code_evidence_result(session, image_path="x", function="a")
    assert info.value.code == "code_evidence.unsupported_arch"


def test_producer_happy_path_with_stubbed_read(monkeypatch):
    symbols = {"f": TARGET.va, "g": TARGET.va + 8, "current_task": 0x1000}
    monkeypatch.setattr(tce, "_read_body", lambda *a: CODE)
    payload = tce.code_evidence_result(FakeSession(symbols), image_path="x",
                                       function="f").payload
    assert payload["target"]["size"] == 8
    assert payload["coverage"]["bytes_decoded"] == 8 and payload["coverage"]["truncated"] is False
    assert payload["accesses"][0]["location"]["space"] == "kernel_va"
    capped = tce.code_evidence_result(FakeSession(symbols), image_path="x", function="f",
                                      max_bytes=4).payload
    assert capped["coverage"]["truncated"] is True


def test_function_size_from_next_symbol():
    assert tce._function_size(0x10, {"a": 0x10, "b": 0x30}) == 0x20
    assert tce._function_size(0x30, {"a": 0x10, "b": 0x30}) is None


NESTED = {
    "__base_types__": {"pointer": {"size": 8}, "unsigned int": {"size": 4}, "char": {"size": 1},
                       "long": {"size": 8}},
    "task_struct": {"size": 64, "fields": {
        "flags": {"offset": 36, "type": {"kind": "base", "name": "unsigned int"}},
        "ptrace": {"offset": 40, "type": {"kind": "base", "name": "unsigned int"}},
        "se": {"offset": 8, "type": {"kind": "struct", "name": "se_t"}},
        "comm": {"offset": 48, "type": {"kind": "array", "count": 16,
                                        "subtype": {"kind": "base", "name": "char"}}}}},
    "se_t": {"size": 16, "fields": {"load": {"offset": 0, "type": {"kind": "base", "name": "long"}},
                                    "vruntime": {"offset": 8, "type": {"kind": "base", "name": "long"}}}},
}


def _cur(off):
    return tce._isf_member_for(ce.FieldAccess(1, "current", off, 4, "read"), NESTED)


def test_isf_join_resolves_containing_member():
    inside = _cur(0x29)
    assert inside["member"] == "ptrace" and inside["inner_offset"] == 1 and not inside["exact"]
    assert _cur(0x25)["member"] == "flags" and _cur(0x25)["isf_member_offset"] == 36
    assert _cur(0x24)["exact"] is True
    leaf = _cur(16)
    assert leaf["member"] == "se.vruntime" and leaf["exact"] and leaf["isf_member_offset"] == 16
    assert _cur(51)["member"] == "comm[3]" and _cur(51)["exact"]
    assert _cur(0x3F + 100) is None


def test_isf_summary_counts_exact_contained_unresolved():
    evidence = ce.CodeEvidence("pakunoda", TARGET, (
        ce.FieldAccess(1, "current", 36, 4, "read"), ce.FieldAccess(2, "current", 0x29, 1, "read"),
        ce.FieldAccess(3, "current", 900, 4, "read")))
    s = tce._isf_summary(evidence, NESTED)
    assert (s["exact"], s["contained"], s["unresolved"], s["matched"]) == (1, 1, 1, 2)


def test_truncated_when_size_unknown_or_short_read(monkeypatch):
    monkeypatch.setattr(tce, "_read_body", lambda *a: CODE)
    unknown = tce.code_evidence_result(FakeSession({"f": TARGET.va}), image_path="x",
                                       function="f").payload["coverage"]
    assert unknown["truncated"] is True and unknown["size_known"] is False
    symbols = {"f": TARGET.va, "g": TARGET.va + 64}
    short = tce.code_evidence_result(FakeSession(symbols), image_path="x",
                                     function="f").payload["coverage"]
    assert short["truncated"] is True and short["bytes_requested"] == 64 and short["bytes_read"] == 8

"""``locate_context`` (plan T1.9, D12): range containment over case tables."""
from __future__ import annotations

import pyarrow as pa
import pytest

from memdiver.analysis.case import Case
from memdiver.analysis.context import locate_context
from memdiver.analysis.record import AnalysisEntry, retraction_of
from memdiver.analysis.record_store import AnalysisRecord
from memdiver.core.location import AddressSpace, Coverage, Location
from memdiver.core.service_errors import CapabilityError, ErrorCategory

CAP = "c" * 64
TOP = 0xFFFFFFFFFFFFF000


@pytest.fixture
def case(tmp_path):
    return Case.init(tmp_path / "case")


def _register(case, name, addrs, sizes, *, space="kernel_va", pids=None,
              capture=CAP, **extra):
    n = len(addrs)
    cols = {"addr": pa.array(addrs, pa.uint64()), "size": pa.array(sizes, pa.uint64()),
            "space": [space] * n, "pid": pa.array(pids or [None] * n, pa.int64()), **extra}
    return case.register_table(name, pa.table(cols), capture_id=capture, producer="test")


def _loc(value, space=AddressSpace.KERNEL_VA, pid=None, capture=CAP):
    return Location(space, value, capture_id=capture, pid=pid)


def _names(stack):
    return [(layer.source, layer.name) for layer in stack.layers]


def test_nested_layers_are_ordered_outermost_first(case):
    _register(case, "vmas", [0x1000], [0x10000], label=["[heap]"])
    _register(case, "heap_chunks", [0x2000], [0x100], state=["inuse"])
    AnalysisRecord(case.dir).append(AnalysisEntry(
        capture_id=CAP, kind="key_hit", author="human", length=32,
        locations=(_loc(0x2010),)))
    stack = locate_context(case, _loc(0x2018))
    assert _names(stack) == [("table", "vmas"), ("table", "heap_chunks"),
                             ("annotation", "key_hit")]
    assert [layer.size for layer in stack.layers] == [0x10000, 0x100, 32]
    assert stack.layers[0].row["label"] == "[heap]"
    assert stack.layers[0].ref and not stack.truncated and stack.coverage is None


def test_pid_filter_and_null_pid_matches_any(case):
    _register(case, "vmas", [0x1000, 0x1000, 0x1000], [0x100] * 3, pids=[1, 2, None])
    hit = locate_context(case, _loc(0x1010, pid=1))
    assert sorted(layer.row["pid"] for layer in hit.layers if layer.row["pid"]) == [1]
    assert len(hit.layers) == 2  # pid 1 + the NULL-pid row
    assert len(locate_context(case, _loc(0x1010, pid=9)).layers) == 1  # NULL only
    assert len(locate_context(case, _loc(0x1010)).layers) == 3  # no pid: all


def test_space_filter(case):
    _register(case, "a", [0x1000], [0x100], space="kernel_va")
    _register(case, "b", [0x1000], [0x100], space="physical")
    stack = locate_context(case, _loc(0x1010, AddressSpace.PHYSICAL))
    assert _names(stack) == [("table", "b")]


def test_capture_filter(case):
    _register(case, "a", [0x1000], [0x100], capture="other")
    assert locate_context(case, _loc(0x1010)).layers == ()
    assert len(locate_context(case, _loc(0x1010, capture="other")).layers) == 1


def test_row_ending_at_2_64_contains_last_address(case):
    _register(case, "vmas", [TOP], [0x1000])
    assert len(locate_context(case, _loc(0xFFFFFFFFFFFFFFFF)).layers) == 1
    assert len(locate_context(case, _loc(TOP)).layers) == 1


def test_address_at_end_is_not_contained(case):
    _register(case, "vmas", [0x1000], [0x100])
    assert locate_context(case, _loc(0x1100)).layers == ()
    assert len(locate_context(case, _loc(0x10FF)).layers) == 1
    assert locate_context(case, _loc(0xFFF)).layers == ()


def test_superseded_and_retracted_annotations_are_not_reported(case):
    record = AnalysisRecord(case.dir)
    old = record.append(AnalysisEntry(capture_id=CAP, kind="note", author="human",
                                      locations=(_loc(0x10),), label="old"))
    new = record.append(AnalysisEntry(capture_id=CAP, kind="note", author="human",
                                      locations=(_loc(0x10),), label="new",
                                      supersedes=old.id))
    gone = record.append(AnalysisEntry(capture_id=CAP, kind="gone", author="human",
                                       locations=(_loc(0x10),)))
    record.append(retraction_of(gone, "human", "oops"))
    layers = locate_context(case, _loc(0x10)).layers
    assert [(layer.name, layer.ref) for layer in layers] == [("note", new.id)]


def test_location_without_capture_id_is_rejected(case):
    with pytest.raises(CapabilityError) as err:
        locate_context(case, Location(AddressSpace.PHYSICAL, 1))
    assert err.value.category is ErrorCategory.INVALID_INPUT


class _Source:
    def read_location(self, value, length):
        cov = Coverage(start=value, requested=length, captured=length)
        return type("R", (), {"coverage": cov})()


def test_source_with_read_location_adds_coverage(case):
    stack = locate_context(case, _loc(0x1000), source=_Source(), length=16)
    assert stack.coverage is not None and stack.coverage.requested == 16
    assert stack.to_dict()["coverage"]["captured"] == 16
    assert locate_context(case, _loc(0x1000), source=object()).coverage is None


def test_tables_subset(case):
    _register(case, "a", [0x1000], [0x100])
    _register(case, "b", [0x1000], [0x100])
    assert _names(locate_context(case, _loc(0x1010), tables=["b"])) == [("table", "b")]
    assert locate_context(case, _loc(0x1010), tables=[]).layers == ()


def test_truncation_flag_with_tiny_limit(case):
    _register(case, "a", [0x1000] * 5, [0x100] * 5)
    stack = locate_context(case, _loc(0x1010), limit=2)
    assert stack.truncated and len(stack.layers) == 2
    assert not locate_context(case, _loc(0x1010), limit=5).truncated


def test_empty_case_has_no_layers(case):
    stack = locate_context(case, _loc(0x1))
    assert stack.layers == () and not stack.truncated

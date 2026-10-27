"""core.vas_runs: the shared captured-run table normalization."""

from memdiver.app import tools_consensus
from memdiver.core.vas_runs import vas_run_table, vas_runs
from memdiver.engine.xref_pointers import _captured_runs


class _Ranges:
    def __init__(self, fmt, ranges):
        self.format_name, self._ranges = fmt, ranges

    def iter_ranges(self):
        return iter(self._ranges)


class _Tabulated:
    format_name = "gcore"

    def captured_runs(self):
        return [(0x2000, 16, 0), (0x1000, 8, 16)]


def test_msl_ranges_carry_lengths_and_cumulative_offsets():
    src = _Ranges("msl", [(0x1000, 16, 0), (0x5000, 0, 1), (0x8000, 4, 2)])
    assert list(vas_runs(src)) == [(0x1000, 16, 0), (0x8000, 4, 16)]


def test_start_end_ranges_skip_empty_runs():
    src = _Ranges("gcore", [(0x1000, 0x1010, 99), (0x2000, 0x2000, 7), (0x3000, 0x3008, 5)])
    assert vas_run_table(src) == ((0x1000, 16, 0), (0x3000, 8, 16))


def test_captured_runs_table_is_used_verbatim():
    assert list(vas_runs(_Tabulated())) == [(0x2000, 16, 0), (0x1000, 8, 16)]


def test_xref_captured_runs_sorts_the_shared_table():
    assert _captured_runs(_Tabulated()) == [(0x1000, 8, 16), (0x2000, 16, 0)]


def test_tools_consensus_keeps_its_names():
    assert tools_consensus._vas_runs is vas_runs
    assert tools_consensus._vas_run_table is vas_run_table

"""Stride-coverage instrumentation for the brute-force stage.

The candidate grid is *absolute*: at ``--stride N`` only offsets that are
multiples of N are ever handed to the oracle, so a secret at an unaligned
offset is never tested and the run still ends "succeeded" with zero hits.
The default is therefore ``--stride 1`` (full coverage); raising it is an
opt-in speed tradeoff. These tests pin that default, the numbers that make
partial coverage visible (``candidates_tested`` / ``candidates_possible`` /
``stride`` / ``coverage_fraction``) and the ``brute_force.partial_coverage``
warning that explains a zero-hit partial run.
"""

from __future__ import annotations

import inspect
import json
import os
import re
from unittest.mock import patch

import pytest

from memdiver.app.tools_pipeline import (
    PARTIAL_COVERAGE_CODE,
    _smaller_stride_hint,
    brute_force,
)
from memdiver.engine.brute_force import (
    brute_force_with_oracle,
    count_candidate_slices,
    count_possible_candidates,
    iter_candidate_slices,
)
from memdiver.engine.candidate_grid import count_region_grid, iter_region_grid

# --------------------------------------------------------------------------- #
# Correctness anchor: the closed-form count must equal the real iteration
# --------------------------------------------------------------------------- #

_SHAPES = [
    # (r_start, r_end, key_sizes, dump_len)
    (0, 128, (32,), 1024),
    (1, 128, (32,), 1024),
    (7, 100, (32,), 1024),
    (256, 288, (32,), 1024),
    (585140, 585200, (32,), 700000),
    (0, 16, (32,), 1024),          # region too short for any window
    (64, 200, (16, 32, 48), 1024),  # several key sizes
    (900, 1100, (32,), 1024),       # window clipped by dump_len
    (1024, 2048, (32,), 1024),      # region entirely past dump_len
    (0, 1, (1,), 1024),             # degenerate 1-byte region
    (64, 200, (32, 32), 1024),      # duplicate key sizes: counted twice, not deduped
    (64, 200, (), 1024),            # no key sizes at all
    (100, 90, (32,), 1024),         # malformed region: r_end < r_start
    (0, 4096, (4096,), 1024),       # key size larger than the whole dump
    (1020, 1030, (8,), 1024),       # window straddles dump_len
]


@pytest.mark.parametrize("r_start,r_end,key_sizes,dump_len", _SHAPES)
@pytest.mark.parametrize("stride", [1, 2, 3, 4, 8, 16, 64])
def test_count_region_grid_matches_iter_region_grid(
    r_start, r_end, key_sizes, stride, dump_len
):
    expected = len(list(iter_region_grid(r_start, r_end, key_sizes, stride, dump_len)))
    assert count_region_grid(r_start, r_end, key_sizes, stride, dump_len) == expected


@pytest.mark.parametrize("r_start,r_end,key_sizes,dump_len", _SHAPES)
def test_candidates_possible_matches_stride_one_iteration(
    r_start, r_end, key_sizes, dump_len
):
    """``candidates_possible`` is exactly the stride-1 candidate count."""
    regions = [{"offset": r_start, "length": r_end - r_start}]
    reference = b"\x00" * dump_len
    expected = len(list(iter_region_grid(r_start, r_end, key_sizes, 1, dump_len)))
    assert count_possible_candidates(regions, reference, key_sizes) == expected


def test_candidates_possible_over_many_regions():
    reference = b"\x00" * 4096
    regions = [
        {"offset": 3, "length": 200},
        {"offset": 512, "length": 64},
        {"offset": 1000, "length": 31},   # too short for a 32-byte window
        {"offset": 4000, "length": 200},  # clipped by dump_len
    ]
    key_sizes = (32, 48)
    expected = count_candidate_slices(regions, reference, key_sizes, stride=1)
    assert count_possible_candidates(regions, reference, key_sizes) == expected


_MULTI_REGION = [
    {"offset": 0, "length": 128},
    {"offset": 3, "length": 200},      # unaligned start, snapped up by the grid
    {"offset": 512, "length": 64},
    {"offset": 1000, "length": 31},    # too short for the smallest key size
    {"offset": 2000, "length": 100},
    {"offset": 4000, "length": 200},   # clipped by dump_len
    {"offset": 5000, "length": 64},    # entirely past dump_len
]


@pytest.mark.parametrize("stride", [1, 2, 3, 8, 64])
def test_count_candidate_slices_matches_real_iteration(stride):
    """Guards the numerator/denominator drift the closed-form count could cause.

    ``count_candidate_slices`` no longer walks the grid — it sums a closed form
    — while the run itself still walks ``iter_candidate_slices``. If the two
    ever disagree, every progress bar and every ``coverage_fraction`` in the
    product silently reports a total the run will not reach (or overshoot).
    Only an exhaustive same-input comparison catches that.
    """
    reference = b"\x00" * 4096
    key_sizes = (16, 32, 48)
    expected = len(list(iter_candidate_slices(
        _MULTI_REGION, reference, key_sizes, stride
    )))
    assert count_candidate_slices(
        _MULTI_REGION, reference, key_sizes, stride
    ) == expected


@pytest.mark.parametrize("stride", [0, -1, -8])
def test_non_positive_stride_is_rejected_by_both_count_and_iteration(stride):
    """Guards the one input where the closed form and the real grid disagree.

    ``count_region_grid`` and ``iter_region_grid`` are equivalent for every
    valid input but diverge for a negative stride (``range`` yields nothing;
    the closed form does not know that). The counting path is only safe to
    delegate while this guard holds, and it must stay symmetric with the
    iterating path — a stride the counter rejects but the iterator accepts (or
    the reverse) would mean a run whose progress total was never computed.
    """
    reference = b"\x00" * 1024
    regions = [{"offset": 0, "length": 256}]

    with pytest.raises(ValueError, match="stride must be positive"):
        count_candidate_slices(regions, reference, (32,), stride)

    with pytest.raises(ValueError, match="stride must be positive"):
        # The generator body only runs on first advance, so drain it.
        list(iter_candidate_slices(regions, reference, (32,), stride))


# --------------------------------------------------------------------------- #
# Engine: the result carries the coverage numbers
# --------------------------------------------------------------------------- #


def _unaligned_setup():
    """A 1024-byte reference whose planted 32-byte secret starts at offset 260.

    ``260 % 8 == 4`` — a stride-8 grid tests 256 and 264 but never 260.
    """
    reference = bytearray(b"\xAA" * 1024)
    secret = bytes(range(100, 132))
    reference[260:292] = secret
    regions = [{"offset": 256, "length": 64, "mean_variance": 9.0, "mean_entropy": 7.0}]
    return bytes(reference), secret, regions


def test_engine_reports_coverage_on_a_partial_run():
    reference, secret, regions = _unaligned_setup()
    result = brute_force_with_oracle(regions, reference, lambda c: c == secret, stride=8)

    assert result.verified_count == 0  # the secret is not 8-aligned
    assert result.stride == 8
    assert result.candidates_tested == result.total_candidates
    assert result.candidates_possible == count_possible_candidates(
        regions, reference, (32,)
    )
    assert 0.0 < result.coverage_fraction < 1.0


def test_engine_reports_full_coverage_at_stride_one():
    reference, secret, regions = _unaligned_setup()
    result = brute_force_with_oracle(regions, reference, lambda c: c == secret, stride=1)

    assert result.verified_count == 1
    assert result.hits[0].offset == 260
    assert result.stride == 1
    assert result.coverage_fraction == 1.0
    assert result.candidates_tested == result.candidates_possible


def test_to_dict_exposes_coverage_fields():
    reference, secret, regions = _unaligned_setup()
    payload = brute_force_with_oracle(
        regions, reference, lambda c: c == secret, stride=8
    ).to_dict()

    for key in ("candidates_tested", "candidates_possible", "stride",
                "coverage_fraction"):
        assert key in payload
    # The pre-existing keys are untouched.
    assert payload["total_candidates"] == payload["candidates_tested"]


def test_coverage_fraction_defaults_to_full_when_uncounted():
    from memdiver.engine.brute_force import BruteForceResult

    assert BruteForceResult().coverage_fraction == 1.0


# --------------------------------------------------------------------------- #
# Producer: the warning, and the numbers on every run
# --------------------------------------------------------------------------- #


def _producer_fixture(tmp_path, secret_offset: int):
    reference = bytearray(b"\xAA" * 1024)
    secret = bytes(range(100, 132))
    reference[secret_offset:secret_offset + 32] = secret

    ref_path = tmp_path / "reference.bin"
    ref_path.write_bytes(bytes(reference))

    cand_path = tmp_path / "candidates.json"
    cand_path.write_text(json.dumps({
        "regions": [
            {"offset": 256, "length": 64, "mean_variance": 9.0, "mean_entropy": 7.0},
        ]
    }))

    oracle_path = tmp_path / "oracle.py"
    oracle_path.write_text(
        f"TARGET = bytes(range(100, 132))\n"
        f"def verify(candidate): return candidate == TARGET\n"
    )
    os.chmod(oracle_path, 0o644)
    return str(cand_path), str(ref_path), str(oracle_path)


def _run_producer(tmp_path, secret_offset: int, stride: int):
    cand_path, ref_path, oracle_path = _producer_fixture(tmp_path, secret_offset)
    return brute_force(
        candidates_path=cand_path,
        reference_path=ref_path,
        oracle_path=oracle_path,
        output_dir=str(tmp_path / "out"),
        stride=stride,
    )


def test_producer_warns_on_zero_hit_partial_run(tmp_path):
    """Offset 260 is not 8-aligned: 0 hits, and the silence must be broken."""
    result = _run_producer(tmp_path, secret_offset=260, stride=8)

    assert result["verified_count"] == 0
    assert result["stride"] == 8
    assert result["candidates_tested"] < result["candidates_possible"]
    assert result["coverage_fraction"] < 1.0

    (warning,) = result["warnings"]
    assert warning["code"] == PARTIAL_COVERAGE_CODE
    assert warning["severity"] == "warning"
    assert warning["details"]["candidates_tested"] == result["candidates_tested"]
    assert warning["details"]["candidates_possible"] == result["candidates_possible"]
    assert warning["details"]["stride"] == 8
    # The message carries the real numbers and the remedy.
    assert f"{result['candidates_tested']:,}" in warning["message"]
    assert f"{result['candidates_possible']:,}" in warning["message"]
    assert "32-byte windows" in warning["message"]
    assert "stride=8 only tests offsets that are multiples of 8" in warning["message"]
    assert "--stride 4 or 1" in warning["message"]


def test_producer_same_secret_found_at_stride_one_without_warning(tmp_path):
    result = _run_producer(tmp_path, secret_offset=260, stride=1)

    assert result["verified_count"] == 1
    assert result["hits"][0]["offset"] == 260
    assert result["coverage_fraction"] == 1.0
    assert result["warnings"] == []


def test_producer_reports_coverage_on_a_successful_partial_run(tmp_path):
    """A hit does NOT suppress the numbers — 'one hit' is not 'one key present'."""
    result = _run_producer(tmp_path, secret_offset=264, stride=8)

    assert result["verified_count"] == 1
    assert result["warnings"] == []           # only the warning is hit-conditional
    assert result["candidates_possible"] > result["candidates_tested"]
    assert 0.0 < result["coverage_fraction"] < 1.0


def test_hits_json_carries_the_coverage_numbers(tmp_path):
    result = _run_producer(tmp_path, secret_offset=260, stride=8)
    payload = json.loads(open(result["hits_path"]).read())

    assert payload["stride"] == 8
    assert payload["candidates_possible"] == result["candidates_possible"]
    assert payload["coverage_fraction"] == result["coverage_fraction"]


def test_stage_end_extra_carries_coverage_and_warning(tmp_path):
    """Web surface: the numbers ride the existing brute_force ``stage_end`` extra."""
    events = []

    def on_progress(kind, **kwargs):
        events.append((kind, kwargs))

    cand_path, ref_path, oracle_path = _producer_fixture(tmp_path, 260)
    brute_force(
        candidates_path=cand_path,
        reference_path=ref_path,
        oracle_path=oracle_path,
        output_dir=str(tmp_path / "out"),
        stride=8,
        on_progress=on_progress,
    )

    ends = [kw for kind, kw in events
            if kind == "stage_end" and kw.get("stage") == "brute_force"]
    assert len(ends) == 1
    extra = ends[0]["extra"]
    assert extra["stride"] == 8
    assert extra["candidates_possible"] > extra["candidates_tested"]
    assert extra["coverage_fraction"] < 1.0
    assert extra["warnings"][0]["code"] == PARTIAL_COVERAGE_CODE
    # The pre-existing keys the frontend already reads are untouched.
    assert "verified_count" in extra and "total_candidates" in extra
    assert "hits" in extra and "variance_threshold" in extra


# --------------------------------------------------------------------------- #
# CLI surface: the warning reaches stderr
# --------------------------------------------------------------------------- #


def _bf_args(**overrides):
    from memdiver.cli.main import build_parser

    argv = [
        "brute-force",
        "--candidates", overrides["candidates"],
        "--dump", overrides["dump"],
        "--oracle", overrides["oracle"],
        "--stride", str(overrides.get("stride", 8)),
        "--output", overrides["output"],
    ]
    return build_parser().parse_args(argv)


def test_cli_prints_partial_coverage_warning_to_stderr(tmp_path, capsys):
    from memdiver.cli import pipeline as cli_pipeline

    cand_path, ref_path, oracle_path = _producer_fixture(tmp_path, 260)
    out_path = tmp_path / "hits.json"
    code = cli_pipeline._cmd_brute_force(_bf_args(
        candidates=cand_path, dump=ref_path, oracle=oracle_path,
        output=str(out_path), stride=8,
    ))

    assert code != 0  # no hit
    err = capsys.readouterr().err
    assert "memdiver: warning:" in err
    assert "stride=8 only tests offsets that are multiples of 8" in err
    assert "--stride 4 or 1" in err
    # The JSON output carries the numbers too.
    payload = json.loads(out_path.read_text())
    assert payload["stride"] == 8
    assert payload["coverage_fraction"] < 1.0


def test_cli_prints_no_warning_on_full_coverage(tmp_path, capsys):
    from memdiver.cli import pipeline as cli_pipeline

    cand_path, ref_path, oracle_path = _producer_fixture(tmp_path, 260)
    out_path = tmp_path / "hits.json"
    cli_pipeline._cmd_brute_force(_bf_args(
        candidates=cand_path, dump=ref_path, oracle=oracle_path,
        output=str(out_path), stride=1,
    ))

    err = capsys.readouterr().err
    assert "memdiver: warning:" not in err


def test_cli_tolerates_a_producer_result_without_warnings(tmp_path):
    """Backward compatibility: the relay must not require the new key."""
    from memdiver.cli import pipeline as cli_pipeline

    def _legacy_result(**kwargs):
        return {
            "hits_path": "/c/scratch/hits.json",
            "verified_count": 1,
            "total_candidates": 1,
            "exit_code": 0,
            "hits": [{"offset": 0, "length": 32}],
        }

    args = _bf_args(candidates="/c/c.json", dump="/c/r.bin",
                    oracle="/c/o.py", output="/c/hits.json")
    with patch("memdiver.app.tools_pipeline.brute_force", _legacy_result), \
            patch("shutil.copyfile"), patch("pathlib.Path.mkdir"):
        assert cli_pipeline._cmd_brute_force(args) == 0


# --------------------------------------------------------------------------- #
# MCP / library surfaces get the fields for free (they return the producer dict)
# --------------------------------------------------------------------------- #


def test_mcp_tool_relays_the_producer_dict_verbatim(tmp_path):
    """The MCP wrapper returns the producer dict unchanged, coverage included."""
    from memdiver.mcp_server import tools_pipeline as mcp_pipeline

    cand_path, ref_path, oracle_path = _producer_fixture(tmp_path, 260)
    result = mcp_pipeline.brute_force(
        candidates_path=cand_path,
        reference_path=ref_path,
        oracle_path=oracle_path,
        output_dir=str(tmp_path / "out"),
        stride=8,
    )
    assert result["warnings"][0]["code"] == PARTIAL_COVERAGE_CODE
    assert result["coverage_fraction"] < 1.0


class TestSmallerStrideHint:
    """The remedy must never suggest a *coarser* grid than the one that failed.

    The example used to be hardcoded as "--stride 4 or 1", which is wrong the
    moment the user picked something unusual: at ``stride=3`` a suggestion of 4
    widens the gaps instead of closing them.
    """

    @pytest.mark.parametrize(
        ("stride", "expected"),
        [
            (2, "--stride 1"),
            (3, "--stride 1"),
            (4, "--stride 2 or 1"),
            (8, "--stride 4 or 1"),
            (16, "--stride 8 or 1"),
        ],
    )
    def test_hint_matches_the_stride(self, stride: int, expected: str) -> None:
        assert _smaller_stride_hint(stride) == expected

    @pytest.mark.parametrize("stride", [2, 3, 4, 5, 8, 9, 16, 64])
    def test_every_suggested_stride_is_strictly_smaller(self, stride: int) -> None:
        # Every integer named in the hint must be a finer grid than the one used.
        values = [int(v) for v in re.findall(r"\d+", _smaller_stride_hint(stride))]
        assert values, "hint must name at least one stride"
        assert all(1 <= v < stride for v in values), (stride, values)

    def test_the_unaligned_run_hint_is_actionable(self) -> None:
        """A stride-3 run must be told to go finer, not to try 4."""
        assert "4" not in _smaller_stride_hint(3)
        assert _smaller_stride_hint(3) == "--stride 1"


class TestDefaultStrideIsFullCoverage:
    """Every surface must default to ``stride=1``.

    The grid is absolute, so any default > 1 silently makes unaligned secrets
    unreachable while the run still reports "succeeded". A real corpus dump
    holds its TLS traffic secret at offset 585148 (``585148 % 8 == 4``), which
    the old default of 8 could never test. These assertions pin the corrected
    default so a surface cannot drift back on its own.
    """

    @staticmethod
    def _default_stride(func) -> int:
        return inspect.signature(func).parameters["stride"].default

    def test_producers_default_to_stride_one(self) -> None:
        from memdiver.app import tools_pipeline

        for producer in (tools_pipeline.brute_force, tools_pipeline.n_sweep,
                         tools_pipeline.auto_floor):
            assert self._default_stride(producer) == 1, producer.__name__

    def test_engines_default_to_stride_one(self) -> None:
        from memdiver.engine import auto_floor as af_engine
        from memdiver.engine import brute_force as bf_engine
        from memdiver.engine import nsweep as ns_engine

        for engine_fn in (bf_engine.brute_force_with_oracle, bf_engine.run_brute_force,
                          ns_engine.run_nsweep, af_engine.run_auto_floor):
            assert self._default_stride(engine_fn) == 1, engine_fn.__name__

    def test_cli_defaults_to_stride_one(self) -> None:
        from memdiver.cli.main import build_parser

        args = build_parser().parse_args(
            ["brute-force", "--candidates", "c.json", "--dump", "d.bin",
             "--oracle", "o.py", "-o", "hits.json"]
        )
        assert args.stride == 1

    def test_api_request_models_default_to_stride_one(self) -> None:
        from memdiver.api.routers.pipeline import (
            AutoFloorRunRequest,
            BruteForceParams,
            NSweepParams,
        )

        for model in (BruteForceParams, NSweepParams, AutoFloorRunRequest):
            assert model.model_fields["stride"].default == 1, model.__name__

    def test_default_run_has_full_coverage_and_no_partial_warning(
        self, tmp_path
    ) -> None:
        """At the default the coverage fraction is 1.0, so the warning is silent."""
        reference, secret, regions = _unaligned_setup()
        result = brute_force_with_oracle(regions, reference, lambda c: c == secret)

        assert result.stride == 1
        assert result.coverage_fraction == 1.0
        assert result.hits, "the unaligned secret must be reachable at the default"


class TestResolveJobs:
    """``jobs=0`` (auto) must pick a safe worker count, never a surprising one.

    Auto is deliberately conservative: it only reaches for a pool when the
    sweep is both large enough to amortise process spawn and exhaustive, so
    the emitted ``hits.json`` stays reproducible.
    """

    def test_explicit_positive_is_honoured_verbatim(self) -> None:
        """A user who names a worker count gets exactly that count."""
        from memdiver.engine.brute_force import resolve_jobs

        for explicit in (1, 2, 3, 8, 64):
            assert resolve_jobs(explicit, 10_000_000, exhaustive=True) == explicit
            assert resolve_jobs(explicit, 1, exhaustive=True) == explicit
            # even where auto would have refused to parallelise
            assert resolve_jobs(explicit, 10_000_000, exhaustive=False) == explicit

    def test_auto_is_serial_below_the_candidate_threshold(self) -> None:
        from memdiver.engine.brute_force import (
            PARALLEL_MIN_CANDIDATES,
            resolve_jobs,
        )

        for total in (0, 1, 100, PARALLEL_MIN_CANDIDATES - 1):
            assert resolve_jobs(0, total, exhaustive=True) == 1, total

    def test_auto_is_parallel_above_the_candidate_threshold(self) -> None:
        from memdiver.engine.brute_force import (
            PARALLEL_MAX_JOBS,
            PARALLEL_MIN_CANDIDATES,
            resolve_jobs,
        )

        with patch("memdiver.engine.brute_force.os.cpu_count", return_value=10):
            assert resolve_jobs(0, PARALLEL_MIN_CANDIDATES, exhaustive=True) == 4
            assert resolve_jobs(0, 701_084, exhaustive=True) == 4
        # Never more than the cap, never less than 1, whatever the machine says.
        for cpus in (None, 1, 2, 3, 5, 128):
            with patch("memdiver.engine.brute_force.os.cpu_count", return_value=cpus):
                got = resolve_jobs(0, 701_084, exhaustive=True)
            assert 1 <= got <= PARALLEL_MAX_JOBS, (cpus, got)

    def test_auto_never_parallelises_a_first_hit_run(self) -> None:
        """The load-bearing one: ``exhaustive=False`` must stay serial.

        ``_run_parallel`` drains its in-flight window after the first hit, so
        the number of candidates consumed is timing-dependent — and that number
        is published in hits.json as total_candidates / candidates_tested /
        coverage_fraction. Auto must never make a first-hit artifact
        irreproducible on the user's behalf.
        """
        from memdiver.engine.brute_force import resolve_jobs

        with patch("memdiver.engine.brute_force.os.cpu_count", return_value=64):
            for total in (0, 1, 20_000, 701_084, 10_000_000):
                assert resolve_jobs(0, total, exhaustive=False) == 1, total

    def test_non_positive_jobs_are_all_treated_as_auto(self) -> None:
        """Negative values are nonsense input; auto is the safe reading."""
        from memdiver.engine.brute_force import resolve_jobs

        assert resolve_jobs(-1, 10, exhaustive=True) == 1
        assert resolve_jobs(0, 10, exhaustive=True) == 1


class TestDefaultJobsIsAuto:
    """Every surface must default ``jobs`` to ``0`` (auto).

    Measured on a ~700k-candidate exhaustive sweep with an oracle priced like
    the first-party pcap oracle, the chunked pool runs 3.5x faster than the
    serial loop (``tools/bench_brute_force_parallel.py``). A surface left at 1
    silently opts its users out of that, so these assertions pin the default.
    ``StageRecipe`` is exempt: it is a pinned paper-reproduction recipe.
    """

    @staticmethod
    def _default_jobs(func) -> int:
        return inspect.signature(func).parameters["jobs"].default

    def test_producer_defaults_to_auto(self) -> None:
        from memdiver.app import tools_pipeline

        assert self._default_jobs(tools_pipeline.brute_force) == 0

    def test_engine_defaults_to_auto(self) -> None:
        from memdiver.engine import brute_force as bf_engine

        assert self._default_jobs(bf_engine.run_brute_force) == 0

    def test_cli_defaults_to_auto(self) -> None:
        from memdiver.cli.main import build_parser

        args = build_parser().parse_args(
            ["brute-force", "--candidates", "c.json", "--dump", "d.bin",
             "--oracle", "o.py", "-o", "hits.json"]
        )
        assert args.jobs == 0

    def test_api_request_model_defaults_to_auto(self) -> None:
        from memdiver.api.routers.pipeline import BruteForceParams

        assert BruteForceParams.model_fields["jobs"].default == 0

    def test_mcp_tool_defaults_to_auto(self) -> None:
        import memdiver.mcp_server.server as server

        src = inspect.getsource(server)
        assert "jobs: int = 0" in src
        assert "jobs: int = 1" not in src

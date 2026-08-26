"""Benchmark the brute-force parallel path: does ``jobs > 1`` actually pay?

Answers one question with numbers: at the stride-1 default (~700k candidates on
a real corpus dump) is a chunked process pool faster than the serial loop, and
by how much? That ratio is the gate for whether ``jobs`` should default to
auto-parallel instead of 1.

Everything is synthetic — a generated reference buffer, a generated
candidates.json, and a generated oracle script — so this runs on any clone with
no private dataset.

CAVEAT, read before trusting the ratio: the default oracle here is a cheap
byte-prefix comparison, far cheaper than the first-party pcap oracle (HKDF
expand + AEAD open per candidate). A cheap oracle makes the pool's fixed
IPC/spawn overhead look as large as possible relative to useful work, so it
UNDERSTATES the parallel win. If serial still wins under this harness the
conclusion is conservative in the right direction; if parallel wins here it
will win by more in production. Use ``--oracle-work N`` to add N SHA-256 rounds
per candidate and watch the crossover move.

Calibration (2026-08-25, macOS arm64, 10 cores): the first-party tls-pcap
oracle costs ~173 us per candidate on
``tests/e2e/fixtures/pcap/session_tls13.pcap`` (HKDF expand + AEAD open), which
is equivalent to roughly ``--oracle-work 500`` here. The free-oracle default
(``--oracle-work 0``) is ~0.34 us per candidate — 500x cheaper than anything
real. Judge the gate at a realistic oracle cost; ``--oracle-work 0`` measures
the pool's fixed overhead, not the decision.

Usage:
    python tools/bench_brute_force_parallel.py --candidates 700000
    python tools/bench_brute_force_parallel.py --candidates 700000 \\
        --oracle-work 500 --chunks 1 256 1024 --json-out bench.json
    python tools/bench_brute_force_parallel.py --self-test
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import statistics
import sys
import tempfile
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import List, Optional, Sequence, Tuple

logger = logging.getLogger("bench_brute_force_parallel")

# Make the memdiver package importable regardless of cwd.
_THIS = Path(__file__).resolve()
_PKG_ROOT = _THIS.parent.parent
if str(_PKG_ROOT) not in sys.path:
    sys.path.insert(0, str(_PKG_ROOT))

from memdiver.engine.brute_force import run_brute_force  # noqa: E402

KEY_SIZE = 32
MARKER = b"\xde\xad\xbe\xef"


# ---------------------------------------------------------------------------
# Data containers
# ---------------------------------------------------------------------------


@dataclass
class CaseResult:
    """One (jobs, chunk) configuration, timed over ``repeats`` runs."""

    label: str
    jobs: int
    chunk: int
    wall_s: List[float] = field(default_factory=list)
    total_candidates: int = 0
    hit_offsets: List[int] = field(default_factory=list)

    @property
    def best_s(self) -> float:
        return min(self.wall_s) if self.wall_s else float("nan")

    @property
    def median_s(self) -> float:
        return statistics.median(self.wall_s) if self.wall_s else float("nan")

    def candidates_per_s(self) -> float:
        return self.total_candidates / self.best_s if self.best_s else 0.0


@dataclass
class BenchReport:
    candidates_requested: int
    candidates_actual: int
    key_size: int
    oracle_work: int
    repeats: int
    cpu_count: int
    auto_jobs: int
    cases: List[CaseResult] = field(default_factory=list)

    def baseline(self) -> Optional[CaseResult]:
        for case in self.cases:
            if case.jobs == 1:
                return case
        return None

    def best_parallel(self) -> Optional[CaseResult]:
        parallel = [c for c in self.cases if c.jobs > 1]
        return min(parallel, key=lambda c: c.best_s) if parallel else None

    def speedup(self) -> Optional[float]:
        base, best = self.baseline(), self.best_parallel()
        if base is None or best is None or not best.best_s:
            return None
        return base.best_s / best.best_s


# ---------------------------------------------------------------------------
# Synthetic fixture
# ---------------------------------------------------------------------------


def auto_job_count() -> int:
    """The job count ``resolve_jobs``-style auto would pick: 2..4 cores."""
    return max(1, min(4, (os.cpu_count() or 2) - 1))


def build_fixture(work_dir: Path, candidates: int, plants: int,
                  oracle_work: int) -> Tuple[bytes, Path, Path]:
    """Generate a reference buffer, a candidates.json, and an oracle script.

    Returns ``(reference_data, candidates_path, oracle_path)``. The region is
    sized so a stride-1 sweep over it yields ~``candidates`` slices.
    """
    length = candidates + KEY_SIZE - 1
    # Deterministic, cheap to build, and not compressible into a trivial memcmp:
    # a repeating byte ramp with planted markers.
    buf = bytearray(bytes(range(256)) * (length // 256 + 1))[:length]
    step = max(1, length // (plants + 1))
    planted: List[int] = []
    for i in range(plants):
        off = min(step * (i + 1), length - KEY_SIZE)
        buf[off:off + len(MARKER)] = MARKER
        planted.append(off)
    reference = bytes(buf)

    cand_path = work_dir / "candidates.json"
    cand_path.write_text(json.dumps({
        "regions": [{"offset": 0, "length": length,
                     "mean_variance": 1.0, "mean_entropy": 7.0}]
    }))

    oracle_path = work_dir / "bench_oracle.py"
    oracle_path.write_text(
        "import hashlib\n"
        f"MARKER = {MARKER!r}\n"
        f"WORK = {int(oracle_work)}\n"
        "\n"
        "def verify(candidate: bytes) -> bool:\n"
        "    for _ in range(WORK):\n"
        "        candidate = hashlib.sha256(candidate).digest()\n"
        "    return candidate[:4] == MARKER\n"
    )
    logger.info("fixture: %d bytes, ~%d candidates, %d planted at %s",
                length, candidates, plants, planted)
    return reference, cand_path, oracle_path


# ---------------------------------------------------------------------------
# Measurement
# ---------------------------------------------------------------------------


def time_case(label: str, jobs: int, chunk: int, reference: bytes,
              cand_path: Path, oracle_path: Path, repeats: int) -> CaseResult:
    """Time one configuration with wall-clock ``perf_counter``.

    Includes pool spawn and worker oracle import — that startup cost is real
    for a user running one sweep, so excluding it would flatter the pool.
    """
    import memdiver.engine.brute_force as bf

    case = CaseResult(label=label, jobs=jobs, chunk=chunk)

    # ``chunk`` is a keyword-only knob on ``_run_parallel`` and is not plumbed
    # through the public ``run_brute_force`` signature (it is a tuning detail,
    # not a user-facing option). Wrap the module-global here so the benchmark
    # exercises the real dispatch path with the chunk size under test.
    original_run_parallel = bf._run_parallel

    def _with_chunk(*a, **kw):
        kw["chunk"] = chunk
        return original_run_parallel(*a, **kw)

    for _ in range(repeats):
        bf._run_parallel = _with_chunk
        try:
            start = time.perf_counter()
            result = run_brute_force(
                candidates_path=cand_path,
                reference_data=reference,
                oracle_path=oracle_path,
                jobs=jobs,
                stride=1,
                exhaustive=True,
                oracle_trusted=True,
            )
            elapsed = time.perf_counter() - start
        finally:
            bf._run_parallel = original_run_parallel
        case.wall_s.append(elapsed)
        case.total_candidates = result.total_candidates
        case.hit_offsets = [h.offset for h in result.hits]
    return case


def run_bench(candidates: int, chunks: Sequence[int], repeats: int,
              plants: int, oracle_work: int,
              jobs_override: Optional[int] = None) -> BenchReport:
    jobs = jobs_override or auto_job_count()
    report = BenchReport(
        candidates_requested=candidates,
        candidates_actual=0,
        key_size=KEY_SIZE,
        oracle_work=oracle_work,
        repeats=repeats,
        cpu_count=os.cpu_count() or 0,
        auto_jobs=jobs,
    )
    with tempfile.TemporaryDirectory(prefix="bench_bf_") as td:
        work_dir = Path(td)
        reference, cand_path, oracle_path = build_fixture(
            work_dir, candidates, plants, oracle_work
        )

        plan: List[Tuple[str, int, int]] = [("serial (jobs=1)", 1, 1)]
        for chunk in chunks:
            plan.append((f"jobs={jobs} chunk={chunk}", jobs, chunk))

        for label, case_jobs, case_chunk in plan:
            print(f"  measuring {label} ...", file=sys.stderr, flush=True)
            case = time_case(label, case_jobs, case_chunk, reference,
                             cand_path, oracle_path, repeats)
            report.candidates_actual = case.total_candidates
            report.cases.append(case)
    return report


# ---------------------------------------------------------------------------
# Reporting
# ---------------------------------------------------------------------------


def render_terminal(report: BenchReport) -> str:
    base = report.baseline()
    lines = [
        "",
        f"brute-force parallel benchmark  "
        f"({report.candidates_actual} candidates, key_size={report.key_size}, "
        f"oracle_work={report.oracle_work}, repeats={report.repeats}, "
        f"cpus={report.cpu_count})",
        "",
        f"{'configuration':<28} {'best (s)':>10} {'median (s)':>11} "
        f"{'cand/s':>12} {'vs serial':>10}",
        "-" * 76,
    ]
    for case in report.cases:
        ratio = (base.best_s / case.best_s) if base and case.best_s else float("nan")
        lines.append(
            f"{case.label:<28} {case.best_s:>10.3f} {case.median_s:>11.3f} "
            f"{case.candidates_per_s():>12,.0f} {ratio:>9.2f}x"
        )
    lines.append("-" * 76)

    offsets = {tuple(c.hit_offsets) for c in report.cases}
    totals = {c.total_candidates for c in report.cases}
    lines.append(
        f"result invariance: hit sets identical={len(offsets) == 1}, "
        f"totals identical={len(totals) == 1}"
    )
    speedup = report.speedup()
    if speedup is not None:
        verdict = "PASS (>=1.5x)" if speedup >= 1.5 else "FAIL (<1.5x)"
        lines.append(f"best parallel speedup: {speedup:.2f}x  ->  gate {verdict}")
    lines.append(
        "note: the default oracle is cheap, which understates the parallel "
        "win vs the real pcap oracle."
    )
    lines.append("")
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Self-test
# ---------------------------------------------------------------------------


def run_self_test() -> int:
    """Tiny end-to-end run: fixture sanity + result invariance across configs."""
    with tempfile.TemporaryDirectory(prefix="bench_bf_st_") as td:
        work_dir = Path(td)
        reference, cand_path, oracle_path = build_fixture(work_dir, 2000, 3, 0)
        assert len(reference) == 2000 + KEY_SIZE - 1, len(reference)
        payload = json.loads(cand_path.read_text())
        assert payload["regions"][0]["length"] == len(reference)
        assert "def verify" in oracle_path.read_text()

        serial = time_case("serial", 1, 1, reference, cand_path,
                           oracle_path, repeats=1)
        chunked = time_case("parallel", 2, 64, reference, cand_path,
                            oracle_path, repeats=1)
        assert serial.total_candidates == 2000, serial.total_candidates
        assert serial.hit_offsets, "no planted marker was found"
        assert serial.hit_offsets == chunked.hit_offsets, (
            serial.hit_offsets, chunked.hit_offsets)
        assert serial.total_candidates == chunked.total_candidates

    report = BenchReport(candidates_requested=10, candidates_actual=10,
                         key_size=KEY_SIZE, oracle_work=0, repeats=1,
                         cpu_count=4, auto_jobs=3)
    report.cases = [
        CaseResult("serial", 1, 1, wall_s=[2.0], total_candidates=10),
        CaseResult("parallel", 3, 256, wall_s=[1.0], total_candidates=10),
    ]
    assert abs(report.speedup() - 2.0) < 1e-9, report.speedup()
    assert "2.00x" in render_terminal(report)
    assert auto_job_count() >= 1
    print("self-test: OK")
    return 0


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--candidates", type=int, default=700_000,
                   help="Approximate candidate-space size (default: 700000)")
    p.add_argument("--chunks", nargs="*", type=int, default=[1, 256, 1024],
                   help="Chunk sizes to measure for the parallel case")
    p.add_argument("--jobs", type=int, default=None,
                   help="Worker count (default: auto, 2..4)")
    p.add_argument("--repeats", type=int, default=3,
                   help="Timed runs per configuration; the best is reported")
    p.add_argument("--plants", type=int, default=3,
                   help="How many planted keys the oracle should find")
    p.add_argument("--oracle-work", type=int, default=0,
                   help="SHA-256 rounds per candidate; raises oracle cost so "
                        "the pool has real work to amortise")
    p.add_argument("--json-out", type=Path, default=None)
    p.add_argument("--self-test", action="store_true")
    p.add_argument("--verbose", action="store_true")
    return p


def main(argv: Optional[List[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    logging.basicConfig(level=logging.INFO if args.verbose else logging.WARNING)

    if args.self_test:
        return run_self_test()

    print(f"Benchmarking ~{args.candidates} candidates "
          f"(repeats={args.repeats}) ...", file=sys.stderr)
    report = run_bench(
        candidates=args.candidates,
        chunks=args.chunks,
        repeats=args.repeats,
        plants=args.plants,
        oracle_work=args.oracle_work,
        jobs_override=args.jobs,
    )
    print(render_terminal(report))

    if args.json_out:
        args.json_out.parent.mkdir(parents=True, exist_ok=True)
        payload = asdict(report)
        payload["speedup_best_parallel_vs_serial"] = report.speedup()
        args.json_out.write_text(json.dumps(payload, indent=2))
        print(f"Wrote JSON: {args.json_out}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

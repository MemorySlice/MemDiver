"""The N-sweep harness on a pcap-oracle run (P2.2).

Until now ``app.tools_pipeline.n_sweep`` demanded an ``oracle_path`` *file* and
loaded it itself, so a pcap run -- which deliberately carries
``oracle_path=None`` -- could not reach the stage at all; the web UI hard-gated
the checkbox off rather than let the worker fail mid-run. The producer now
accepts the same two mutually-exclusive oracle sources ``brute_force`` accepts.

What this module pins, in order:

* the exactly-one guard (both sources / neither source),
* the cap validation shared with ``brute_force`` / ``inspect_pcap``,
* that a pcap run really reaches the FIRST-PARTY oracle with the right spec,
* that the oracle-FILE route is untouched -- same load call, same sandbox, same
  report -- which is the regression that matters most here,
* the ``pipeline_runner`` wrapper + stage gate that carry the pcap fields, and
* the real-corpus acceptance run (``requires_dataset``): nsweep on a pcap run
  reaches the same confirmed key, at the same offset, as the oracle-file route.
"""

from __future__ import annotations

import json
import shutil
from pathlib import Path
from unittest.mock import patch

import pytest

from memdiver.app import tools_pipeline as tp
from memdiver.core.service_errors import CapabilityError, ErrorCategory

# The committed pcap fixture pair: a small ``.msl`` holding a real
# SERVER_TRAFFIC_SECRET_0 at offset 512 and the capture that secret decrypts.
# Generated from the real corpus (see ``generate.py`` beside them), so this is
# genuine TLS 1.3 material -- it just does not need the corpus on disk.
_PCAP_FIXTURES = Path(__file__).resolve().parent / "e2e" / "fixtures" / "pcap"
_MANIFEST = _PCAP_FIXTURES / "manifest.json"
_MATCHED_MSL = _PCAP_FIXTURES / "matched.msl"
_SESSION_PCAP = _PCAP_FIXTURES / "session_tls13.pcap"

# The sweep's reduction has to keep the fixture's key offset in play; these are
# the same knobs the web UI posts, loosened only in ``min_region`` because the
# fixture dump is 4 KB rather than 11 MB.
_FIXTURE_REDUCE = dict(
    alignment=8, block_size=32, density_threshold=0.5, min_variance=3000.0,
    entropy_window=32, entropy_threshold=4.5, min_region=16,
)


def _manifest() -> dict:
    return json.loads(_MANIFEST.read_text())


requires_pcap_fixture = pytest.mark.skipif(
    not (_MATCHED_MSL.is_file() and _SESSION_PCAP.is_file()),
    reason="committed pcap fixture pair not present",
)


@pytest.fixture
def oracle_file(tmp_path: Path) -> Path:
    """A BYO oracle that confirms the pcap fixture's ground-truth secret.

    Deliberately NOT a pcap verifier: the point of the oracle-file route in
    these tests is that it is a different mechanism reaching the same answer.
    """
    secret = _manifest()["secret_hex"]
    path = tmp_path / "gt_oracle.py"
    path.write_text(
        f'KEY = bytes.fromhex("{secret}")\n'
        "def verify(candidate):\n"
        "    return candidate == KEY\n"
    )
    # load_oracle refuses group/world-writable oracles.
    path.chmod(0o700)
    return path


# --------------------------------------------------------------------------- #
# the exactly-one guard
# --------------------------------------------------------------------------- #


def test_n_sweep_rejects_both_oracle_sources(tmp_path):
    """Both sources at once is ambiguous, so it is refused before any I/O."""
    with pytest.raises(CapabilityError) as excinfo:
        tp.n_sweep(
            source_paths=[str(tmp_path / "dump.bin")],
            output_dir=str(tmp_path / "out"),
            n_values=[1],
            oracle_path=str(tmp_path / "oracle.py"),
            pcap_path=str(tmp_path / "session.pcap"),
        )

    assert excinfo.value.category is ErrorCategory.INVALID_INPUT
    assert "exactly one" in str(excinfo.value)
    # Nothing was opened: the guard runs before the sources and before the
    # output dir is created.
    assert not (tmp_path / "out").exists()


def test_n_sweep_rejects_neither_oracle_source(tmp_path):
    """No source at all is an error, not a silently unverified sweep.

    This is the branch the old signature made unreachable (``oracle_path`` was
    required) and the one a mis-wired surface would hit first.
    """
    with pytest.raises(CapabilityError) as excinfo:
        tp.n_sweep(
            source_paths=[str(tmp_path / "dump.bin")],
            output_dir=str(tmp_path / "out"),
            n_values=[1],
        )

    assert excinfo.value.category is ErrorCategory.INVALID_INPUT
    assert "exactly one" in str(excinfo.value)


@pytest.mark.parametrize("cap", ["pcap_max_records", "pcap_max_challenges"])
@pytest.mark.parametrize("value", [0, -1])
def test_n_sweep_rejects_a_cap_below_one(tmp_path, cap, value):
    """The sweep refuses a sub-1 cap exactly as ``brute_force`` does.

    A cap of 0 yields zero decryption challenges, so a genuine key reports as
    unconfirmed from a run that otherwise looks successful -- the silent false
    negative ``_validate_pcap_caps`` exists to prevent. Validation happens
    before any dump is opened, so nothing is stubbed here.
    """
    with pytest.raises(CapabilityError) as excinfo:
        tp.n_sweep(
            source_paths=[str(tmp_path / "dump.bin")],
            output_dir=str(tmp_path / "out"),
            n_values=[1],
            pcap_path=str(tmp_path / "session.pcap"),
            **{cap: value},
        )

    assert excinfo.value.category is ErrorCategory.INVALID_INPUT
    assert excinfo.value.status == 400
    assert cap in str(excinfo.value)
    assert "must be >= 1" in str(excinfo.value)


# --------------------------------------------------------------------------- #
# which oracle each route actually loads
# --------------------------------------------------------------------------- #


class _StopAfterLoad(RuntimeError):
    """Raised from the patched loader once its arguments are captured."""


def _capture_load_oracle(tmp_path, **kwargs) -> dict:
    """Run ``n_sweep`` far enough to record how it loaded its oracle."""
    source = tmp_path / "dump.bin"
    source.write_bytes(bytes(1024))
    captured: dict = {}

    def _fake_load(path, config=None, **kw):
        captured["path"] = Path(path)
        captured["config"] = config
        captured["kwargs"] = dict(kw)
        raise _StopAfterLoad("captured")

    with patch("memdiver.engine.oracle.load_oracle", _fake_load):
        with pytest.raises(_StopAfterLoad):
            tp.n_sweep(
                source_paths=[str(source)],
                output_dir=str(tmp_path / "out"),
                n_values=[1],
                **kwargs,
            )
    return captured


@requires_pcap_fixture
def test_pcap_run_loads_the_first_party_oracle_with_the_capture_spec(tmp_path):
    """A pcap run reaches the builtin oracle carrying the whole capture spec."""
    from memdiver.engine.resources.builtin_oracle import BUILTIN_ORACLE_PATH

    captured = _capture_load_oracle(
        tmp_path,
        pcap_path=str(_SESSION_PCAP),
        tls_client_random=_manifest()["client_random"],
        pcap_max_records=4,
        pcap_max_challenges=32,
    )

    assert captured["path"] == Path(BUILTIN_ORACLE_PATH)
    assert captured["config"] == {
        "resource_type": "tls-pcap",
        "pcap": str(_SESSION_PCAP),
        "client_random": _manifest()["client_random"],
        "max_records_per_direction": 4,
        "max_challenges": 32,
    }
    # Trusted first-party code reading data, so the untrusted-code load sandbox
    # is skipped -- the same contract ``run_brute_force`` applies via
    # ``oracle_trusted``. Sandboxing it would also misread a slow parse of a
    # large capture as a hang.
    assert captured["kwargs"]["sandbox"] is False


def test_pcap_run_omits_caps_the_caller_never_asked_for(tmp_path):
    """An unset cap leaves the resource default alone rather than restating it."""
    captured = _capture_load_oracle(tmp_path, pcap_path="/c/session.pcap")

    assert captured["config"] == {
        "resource_type": "tls-pcap",
        "pcap": "/c/session.pcap",
    }


def test_oracle_file_run_still_loads_the_user_script_under_the_sandbox(
    tmp_path, oracle_file
):
    """REGRESSION: the BYO route is unchanged by the pcap branch.

    Same path, same TOML-derived config, and crucially no ``sandbox=False`` --
    a user-supplied script must still be replayed in the resource-capped
    subprocess before it runs in-process.
    """
    captured = _capture_load_oracle(tmp_path, oracle_path=str(oracle_file))

    assert captured["path"] == oracle_file
    assert captured["config"] == {}
    assert "sandbox" not in captured["kwargs"]


# --------------------------------------------------------------------------- #
# green runs on the committed fixture: both routes, same answer
# --------------------------------------------------------------------------- #


@pytest.fixture
def fixture_sources(tmp_path: Path) -> list:
    """Two copies of the fixture dump -- the sweep's consensus needs N >= 2."""
    pytest.importorskip("dpkt")
    first = tmp_path / "dump_a.msl"
    second = tmp_path / "dump_b.msl"
    shutil.copyfile(_MATCHED_MSL, first)
    shutil.copyfile(_MATCHED_MSL, second)
    return [str(first), str(second)]


def _sweep(output_dir: Path, sources: list, **kwargs) -> dict:
    manifest = _manifest()
    return tp.n_sweep(
        source_paths=sources,
        output_dir=str(output_dir),
        n_values=[2],
        reduce_kwargs=dict(_FIXTURE_REDUCE),
        key_sizes=(manifest["key_size"],),
        stride=1,
        exhaustive=False,
        **kwargs,
    )


@requires_pcap_fixture
def test_pcap_sweep_finds_the_key_and_writes_the_three_reports(
    tmp_path, fixture_sources
):
    """The whole point: a pcap run completes the sweep and confirms the key."""
    manifest = _manifest()
    result = _sweep(tmp_path / "pcap", fixture_sources, pcap_path=str(_SESSION_PCAP))

    assert result["first_hit_n"] == 2
    assert result["first_hit_offset"] == manifest["offset"]
    assert result["total_dumps"] == 2
    for key in ("report_json", "report_md", "report_html"):
        assert Path(result[key]).is_file()


@requires_pcap_fixture
def test_pcap_and_oracle_file_routes_agree_on_the_fixture(
    tmp_path, fixture_sources, oracle_file
):
    """Both oracle sources reach the same offset at the same N.

    The two verify by entirely different means -- a byte comparison against the
    known secret vs. a real AEAD decryption of captured records -- so agreement
    is evidence the pcap route reaches the genuine key rather than a candidate
    that merely happens to be first.
    """
    via_pcap = _sweep(tmp_path / "pcap", fixture_sources, pcap_path=str(_SESSION_PCAP))
    via_file = _sweep(tmp_path / "file", fixture_sources, oracle_path=str(oracle_file))

    assert via_pcap["first_hit_offset"] == via_file["first_hit_offset"]
    assert via_pcap["first_hit_n"] == via_file["first_hit_n"]

    # The sweep points carry the reduction and the candidate budget; those are
    # oracle-independent, so they must match exactly.
    points_pcap = json.loads(Path(via_pcap["report_json"]).read_text())["points"]
    points_file = json.loads(Path(via_file["report_json"]).read_text())["points"]
    assert [p["stages"] for p in points_pcap] == [p["stages"] for p in points_file]
    assert [p["candidates_tried"] for p in points_pcap] == [
        p["candidates_tried"] for p in points_file
    ]
    assert [p["hit_offset"] for p in points_pcap] == [
        p["hit_offset"] for p in points_file
    ]


@requires_pcap_fixture
def test_oracle_file_sweep_is_byte_identical_across_repeat_runs(
    tmp_path, fixture_sources, oracle_file
):
    """REGRESSION pin for the default route: same inputs, same report bytes.

    ``headline`` and ``timing_ms`` are wall-clock, so they are compared
    structurally rather than byte-wise; everything the analyst reasons about --
    the reduction stages, the candidate budget, the hit -- must be identical.
    """
    a = _sweep(tmp_path / "a", fixture_sources, oracle_path=str(oracle_file))
    b = _sweep(tmp_path / "b", fixture_sources, oracle_path=str(oracle_file))

    assert a["first_hit_n"] == b["first_hit_n"]
    assert a["first_hit_offset"] == b["first_hit_offset"]
    assert a["total_dumps"] == b["total_dumps"]

    def _stable(report_json: str) -> dict:
        payload = json.loads(Path(report_json).read_text())
        payload.pop("headline", None)
        for point in payload["points"]:
            point.pop("timing_ms", None)
        return payload

    assert _stable(a["report_json"]) == _stable(b["report_json"])


# --------------------------------------------------------------------------- #
# the pipeline runner: wrapper forwarding + stage gate
# --------------------------------------------------------------------------- #


class _Ctx:
    def is_cancelled(self) -> bool:
        return False


def _capture_stage_kwargs(tmp_path: Path, **wrapper_kwargs) -> dict:
    """Call ``_run_nsweep`` with the producer stubbed; return its kwargs."""
    from memdiver.app.pipeline import pipeline_runner

    out_dir = tmp_path / "nsweep"
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "report.json").write_text(json.dumps({"points": []}))
    captured: dict = {}

    def _fake_run_producer(_producer, **kwargs):
        captured.update(kwargs)

    with patch.object(pipeline_runner, "_run_producer", _fake_run_producer), \
            patch.object(pipeline_runner, "register_artifact"), \
            patch.object(pipeline_runner, "_producer_sink", return_value=None):
        pipeline_runner._run_nsweep(
            ["/c/dump1.msl", "/c/dump2.msl"],
            wrapper_kwargs.pop("oracle_path", None),
            {"n_values": [1, 2]},
            ctx=_Ctx(),
            artifact_dir=tmp_path,
            artifacts=[],
            **wrapper_kwargs,
        )
    return captured


def test_pipeline_runner_nsweep_stage_forwards_the_pcap_fields(tmp_path):
    """The web pipeline's wrapper hands the producer the whole pcap source."""
    captured = _capture_stage_kwargs(
        tmp_path,
        oracle_path=None,
        pcap_path="/c/session.pcap",
        tls_client_random="ab" * 32,
        pcap_max_records=4,
        pcap_max_challenges=32,
    )

    assert captured["oracle_path"] is None
    assert captured["pcap_path"] == "/c/session.pcap"
    assert captured["tls_client_random"] == "ab" * 32
    assert captured["pcap_max_records"] == 4
    assert captured["pcap_max_challenges"] == 32


def test_pipeline_runner_nsweep_stage_still_stringifies_an_oracle_file(tmp_path):
    """REGRESSION: the oracle-file run posts exactly what it always did."""
    captured = _capture_stage_kwargs(tmp_path, oracle_path=Path("/c/oracle.py"))

    assert captured["oracle_path"] == "/c/oracle.py"
    assert captured["pcap_path"] is None
    assert captured["tls_client_random"] is None
    assert captured["pcap_max_records"] is None
    assert captured["pcap_max_challenges"] is None


def _state(**kwargs):
    from memdiver.app.pipeline.pipeline_runner import PipelineState

    defaults = dict(
        ctx=_Ctx(), artifact_dir=Path("/c/artifacts"), reduce_kwargs={},
        oracle_path=None, bf_kwargs={}, nsweep_params=None, emit_params=None,
    )
    defaults.update(kwargs)
    return PipelineState(**defaults)


def test_nsweep_stage_is_enabled_on_a_pcap_run():
    """The gate reads the opt-in, not which oracle source is armed."""
    from memdiver.app.pipeline.pipeline_runner import _nsweep_enabled

    assert _nsweep_enabled(
        _state(nsweep_params={"n_values": [1, 2]}, pcap_path="/c/session.pcap")
    )
    # ... and stays off when the opt-in is absent, pcap or not.
    assert not _nsweep_enabled(_state(pcap_path="/c/session.pcap"))


def test_nsweep_stage_is_still_enabled_on_an_oracle_file_run():
    """REGRESSION: the BYO-oracle gate is unchanged."""
    from memdiver.app.pipeline.pipeline_runner import _nsweep_enabled

    assert _nsweep_enabled(
        _state(nsweep_params={"n_values": [1, 2]}, oracle_path=Path("/c/oracle.py"))
    )
    assert not _nsweep_enabled(_state(oracle_path=Path("/c/oracle.py")))


def test_escalate_stage_remains_oracle_file_only_on_a_pcap_run(tmp_path):
    """Scope guard: P2.2 moved nsweep, NOT escalate.

    ``escalate`` still calls ``auto_floor`` with ``str(state.oracle_path)``, so
    it must keep declining a pcap run rather than stringify ``None``.
    """
    from memdiver.app.pipeline.pipeline_runner import _escalate_enabled

    hits = tmp_path / "hits.json"
    hits.write_text(json.dumps({"verified_count": 0}))
    state = _state(
        escalate=True, pcap_path="/c/session.pcap", consensus={}, hits_path=hits,
    )

    assert not _escalate_enabled(state)


# --------------------------------------------------------------------------- #
# the other two surfaces reach the same producer arguments
# --------------------------------------------------------------------------- #


def test_mcp_n_sweep_tool_forwards_the_pcap_params():
    """The MCP tool exposes the pcap source and relays it verbatim.

    ``test_architecture_invariants`` ratchets the *presence* of these params;
    this pins that they actually arrive at the producer.
    """
    pytest.importorskip("mcp")
    from memdiver.mcp_server.server import create_server

    server = create_server()
    tool = {t.name: t for t in server._tool_manager.list_tools()}["n_sweep"]
    captured: dict = {}

    def _fake_n_sweep(**kwargs):
        captured.update(kwargs)
        return {
            "report_json": "/c/report.json", "report_md": "/c/report.md",
            "report_html": "/c/report.html", "first_hit_n": None,
            "first_hit_offset": None, "total_dumps": 0, "headline": "",
        }

    with patch("memdiver.mcp_server.tools_pipeline.n_sweep", _fake_n_sweep):
        tool.fn(
            source_paths=["/c/dump1.msl"],
            output_dir="/c/out",
            n_values=[1, 2],
            pcap_path="/c/session.pcap",
            tls_client_random="ab" * 32,
            pcap_max_records=4,
            pcap_max_challenges=32,
        )

    assert captured["oracle_path"] is None
    assert captured["pcap_path"] == "/c/session.pcap"
    assert captured["tls_client_random"] == "ab" * 32
    assert captured["pcap_max_records"] == 4
    assert captured["pcap_max_challenges"] == 32


def test_cli_n_sweep_accepts_the_pcap_flags(tmp_path):
    """``n-sweep --pcap`` parses and forwards; ``--oracle`` is now optional."""
    from memdiver.cli import pipeline as cli_pipeline
    from memdiver.cli.main import build_parser

    runs_dir = tmp_path / "runs" / "run_1"
    runs_dir.mkdir(parents=True)
    (runs_dir / "dump.msl").write_bytes(b"")

    args = build_parser().parse_args([
        "n-sweep",
        "--runs-dir", str(tmp_path / "runs"),
        "--pcap", "/c/session.pcap",
        "--tls-client-random", "ab" * 32,
        "--pcap-max-records", "4",
        "--pcap-max-challenges", "32",
        "--output-dir", str(tmp_path / "out"),
    ])
    assert args.oracle is None

    captured: dict = {}

    def _fake_n_sweep(**kwargs):
        captured.update(kwargs)
        return {
            "report_json": "/c/report.json", "report_md": "/c/report.md",
            "report_html": "/c/report.html", "first_hit_n": 2,
            "first_hit_offset": 512, "total_dumps": 2, "headline": "ok",
        }

    with patch("memdiver.app.tools_pipeline.n_sweep", _fake_n_sweep):
        assert cli_pipeline._cmd_n_sweep(args) == 0

    assert captured["oracle_path"] is None
    assert captured["pcap_path"] == "/c/session.pcap"
    assert captured["tls_client_random"] == "ab" * 32
    assert captured["pcap_max_records"] == 4
    assert captured["pcap_max_challenges"] == 32


# --------------------------------------------------------------------------- #
# the real corpus -- the load-bearing acceptance assertion
# --------------------------------------------------------------------------- #

#: Eight 11,223,040-byte dumps of one real OpenSSL TLS 1.2 session. Its
#: ``keylog.csv`` CLIENT_RANDOM line carries a 48-byte master secret that lives
#: at offset 370,672 in the two ``*_abort`` dumps and in NONE of the six
#: ``*_cleanup`` ones -- so the pair below is exactly the pair that holds it.
_TLS12_RUN = "TLS12/100_iterations_Abort/openssl/openssl_run_12_1"
_TLS12_KEY_OFFSET = 370_672
_TLS12_KEY_LENGTH = 48
#: The pre-abort dump goes FIRST: it is the reference the sweep slices
#: candidates out of, and it is the phase that still holds the secret.
_TLS12_DUMPS = (
    "20251025_104527_944938_pre_abort.dump",
    "20251025_104529_939883_post_abort.dump",
)


def _tls12_run_dir() -> Path:
    from tests.fixtures.tls_ground_truth import tls_dumps_dir

    return Path(tls_dumps_dir()) / _TLS12_RUN


def _tls12_master_secret(run_dir: Path) -> bytes:
    """The run's own ground truth, read for the ASSERTION only."""
    import csv

    with open(run_dir / "keylog.csv", newline="") as handle:
        return next(
            bytes.fromhex(row["line"].split()[2])
            for row in csv.DictReader(handle)
            if row["line"].split()[:1] == ["CLIENT_RANDOM"]
        )


@pytest.mark.requires_dataset
def test_real_corpus_pcap_sweep_reaches_the_same_key_as_the_oracle_file(tmp_path):
    """The acceptance run: nsweep on a REAL pcap run finds the REAL key.

    Two dumps of a genuine OpenSSL TLS 1.2 session go in, plus the session's
    own captured ``traffic.pcap``. Nothing else -- no keylog, no oracle script.
    The sweep must land on offset 370,672, and the oracle-FILE route (a BYO
    script that simply compares against the keylog secret) must land there too:
    same N, same offset, same reduction, same candidate budget.

    Measured facts this is anchored to, which are NOT free parameters:
    ``stride`` must be 1 (370,672 is not 4-aligned in the general TLS 1.2 case,
    and stride 4 silently misses such offsets), N must be 2, and the pre-abort
    dump goes first.
    """
    pytest.importorskip("dpkt")
    from memdiver.engine.verification import HAS_CRYPTO

    if not HAS_CRYPTO:
        pytest.skip("cryptography not installed")

    run_dir = _tls12_run_dir()
    sources = [str(run_dir / name) for name in _TLS12_DUMPS]
    pcap = run_dir / "run_data" / "traffic.pcap"
    if not all(Path(p).is_file() for p in sources) or not pcap.is_file():
        pytest.skip(f"TLS 1.2 reference run not present under {run_dir}")

    secret = _tls12_master_secret(run_dir)
    assert len(secret) == _TLS12_KEY_LENGTH

    oracle = tmp_path / "gt_oracle.py"
    oracle.write_text(
        f'KEY = bytes.fromhex("{secret.hex()}")\n'
        "def verify(candidate):\n"
        "    return candidate == KEY\n"
    )
    oracle.chmod(0o700)

    def _run(label: str, **kwargs) -> dict:
        return tp.n_sweep(
            source_paths=sources,
            output_dir=str(tmp_path / label),
            n_values=[2],
            reduce_kwargs=dict(
                alignment=8, block_size=32, density_threshold=0.5,
                min_variance=3000.0, entropy_window=32, entropy_threshold=4.5,
                min_region=16,
            ),
            key_sizes=(_TLS12_KEY_LENGTH,),
            stride=1,
            exhaustive=False,
            **kwargs,
        )

    via_pcap = _run("pcap", pcap_path=str(pcap))
    via_file = _run("file", oracle_path=str(oracle))

    # The load-bearing assertion.
    assert via_pcap["first_hit_offset"] == _TLS12_KEY_OFFSET
    assert via_pcap["first_hit_n"] == 2
    assert via_pcap["total_dumps"] == 2

    assert via_file["first_hit_offset"] == _TLS12_KEY_OFFSET
    assert via_file["first_hit_n"] == via_pcap["first_hit_n"]

    point_pcap = json.loads(Path(via_pcap["report_json"]).read_text())["points"][0]
    point_file = json.loads(Path(via_file["report_json"]).read_text())["points"][0]
    assert point_pcap["stages"] == point_file["stages"]
    assert point_pcap["candidates_tried"] == point_file["candidates_tried"]
    assert point_pcap["hit_offset"] == point_file["hit_offset"] == _TLS12_KEY_OFFSET
    # N=2 is below the variance floor, so the reduction is entropy-only. Recorded
    # rather than glossed over: the sweep still reaches the key, but it does so
    # without the cross-dump variance signal.
    assert point_pcap["fallback_entropy_only"] is True

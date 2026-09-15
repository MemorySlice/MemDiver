"""Capture discovery: a corpus run owns its own packet capture.

The corpus layout is
``<lib>_run_<ver>_<n>/{<dumps>, keylog.csv, run_data/traffic.pcap}``.
``RunDiscovery.load_run_directory`` only iterates *files*, so ``run_data/``
is invisible to dump discovery and the capture is probed explicitly.

Every test here is fully synthetic (tmp_path) and byte-cheap: the probe is
stat-only, so a placeholder file exercises exactly the same code path a real
multi-megabyte capture would.
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from memdiver.core.discovery import (
    CAPTURE_FILENAMES,
    CAPTURE_SUBDIR,
    DatasetScanner,
    RunDiscovery,
)


def _make_run(tmp_path, name="openssl_run_13_1", capture=None, capture_bytes=b"\xd4\xc3\xb2\xa1"):
    """Create a minimal run dir with one dump, optionally plus a capture."""
    run_dir = tmp_path / name
    run_dir.mkdir(parents=True)
    (run_dir / "20240101_120000_000001_pre_handshake.dump").write_bytes(b"\x00" * 256)
    if capture is not None:
        capture_dir = run_dir / CAPTURE_SUBDIR
        capture_dir.mkdir()
        (capture_dir / capture).write_bytes(capture_bytes)
    return run_dir


# -- _find_capture: the three states -----------------------------------------


def test_capture_present(tmp_path):
    """A non-empty run_data/traffic.pcap is reported present with its path."""
    run_dir = _make_run(tmp_path, capture="traffic.pcap")
    run = RunDiscovery.load_run_directory(run_dir, extract_secrets=False)
    assert run is not None
    assert run.capture_status == "present"
    assert run.capture_path == run_dir / CAPTURE_SUBDIR / "traffic.pcap"


def test_capture_absent_without_run_data_dir(tmp_path):
    """No run_data/ at all -> absent, and capture_path stays None."""
    run_dir = _make_run(tmp_path)
    run = RunDiscovery.load_run_directory(run_dir, extract_secrets=False)
    assert run is not None
    assert run.capture_status == "absent"
    assert run.capture_path is None


def test_capture_absent_with_empty_run_data_dir(tmp_path):
    """run_data/ exists but holds no recognised capture -> absent."""
    run_dir = _make_run(tmp_path)
    (run_dir / CAPTURE_SUBDIR).mkdir()
    (run_dir / CAPTURE_SUBDIR / "notes.txt").write_text("not a capture")
    run = RunDiscovery.load_run_directory(run_dir, extract_secrets=False)
    assert run is not None
    assert run.capture_status == "absent"
    assert run.capture_path is None


def test_capture_zero_byte_is_unreadable_not_absent(tmp_path):
    """A zero-byte capture must NOT deflate a corpus denominator silently."""
    run_dir = _make_run(tmp_path, capture="traffic.pcap", capture_bytes=b"")
    run = RunDiscovery.load_run_directory(run_dir, extract_secrets=False)
    assert run is not None
    assert run.capture_status == "unreadable"
    # The path is still reported so the caller can name the offending file.
    assert run.capture_path == run_dir / CAPTURE_SUBDIR / "traffic.pcap"


def test_capture_subdir_replaced_by_file_is_absent(tmp_path):
    """A regular file named run_data cannot hold a capture; never raises."""
    run_dir = _make_run(tmp_path)
    (run_dir / CAPTURE_SUBDIR).write_bytes(b"not a directory")
    run = RunDiscovery.load_run_directory(run_dir, extract_secrets=False)
    assert run is not None
    assert run.capture_status == "absent"


def test_capture_candidate_that_is_a_directory_is_skipped(tmp_path):
    """A directory named traffic.pcap is not a capture; the next name wins."""
    run_dir = _make_run(tmp_path, capture="traffic.pcapng")
    (run_dir / CAPTURE_SUBDIR / "traffic.pcap").mkdir()
    path, status = RunDiscovery._find_capture(run_dir)
    assert status == "present"
    assert path.name == "traffic.pcapng"


# -- a usable capture always beats an earlier unusable one -------------------
#
# The candidate loop must not stop at the first non-absent verdict: a zero-byte
# traffic.pcap would then discard a perfectly good traffic.pcapng AND disagree
# with DatasetScanner._has_capture (which skips the empty file and counts the
# run), inflating DatasetInfo.runs_with_capture above the number of runs that
# can actually be proven against their own traffic.


def test_zero_byte_pcap_does_not_mask_a_good_pcapng(tmp_path):
    """An empty first candidate must not hide a readable later candidate."""
    run_dir = _make_run(tmp_path, capture="traffic.pcap", capture_bytes=b"")
    (run_dir / CAPTURE_SUBDIR / "traffic.pcapng").write_bytes(b"\x0a\x0d\x0d\x0a")

    path, status = RunDiscovery._find_capture(run_dir)
    assert status == "present"
    assert path.name == "traffic.pcapng"


def test_find_capture_and_has_capture_agree_on_zero_byte_plus_good(tmp_path):
    """The per-run load and the fast-scan probe must reach the same verdict.

    ``runs_with_capture`` is documented as "how many runs own a capture"; it
    would be dishonest for the counter to include a run whose own
    ``capture_status`` says the capture is unusable, or to exclude one that has
    a readable capture under a non-default name.
    """
    run_dir = _make_run(tmp_path, capture="traffic.pcap", capture_bytes=b"")
    (run_dir / CAPTURE_SUBDIR / "traffic.pcapng").write_bytes(b"\x0a\x0d\x0d\x0a")

    _, status = RunDiscovery._find_capture(run_dir)
    assert (status == "present") is DatasetScanner._has_capture(run_dir)


def test_all_candidates_unusable_still_reports_the_first(tmp_path):
    """With nothing readable anywhere, the first unusable file is named."""
    run_dir = _make_run(tmp_path, capture="traffic.pcap", capture_bytes=b"")
    for name in CAPTURE_FILENAMES[1:]:
        (run_dir / CAPTURE_SUBDIR / name).write_bytes(b"")

    path, status = RunDiscovery._find_capture(run_dir)
    assert status == "unreadable"
    assert path.name == CAPTURE_FILENAMES[0]


def test_zero_byte_declared_capture_does_not_mask_the_probe(tmp_path):
    """"present wins" applies to the meta-declared candidate too."""
    run_dir = _make_run(tmp_path, capture="traffic.pcap")
    (run_dir / "declared.pcap").write_bytes(b"")
    _write_meta(run_dir, capture="declared.pcap")

    run = RunDiscovery.load_run_directory(run_dir, extract_secrets=False)
    assert run.capture_status == "present"
    assert run.capture_path == run_dir / CAPTURE_SUBDIR / "traffic.pcap"


def test_fast_scan_counter_matches_per_run_status_across_a_corpus(tmp_path):
    """End-to-end: the counter equals the number of "present" runs.

    Mixes every case -- good, absent, zero-byte-only, and zero-byte-shadowing-
    a-good-pcapng -- so a regression in either probe desynchronises the two.
    """
    lib_dir = tmp_path / "TLS13" / "scenario_a" / "openssl"
    good = _make_run(lib_dir, name="openssl_run_13_1", capture="traffic.pcap")
    none_ = _make_run(lib_dir, name="openssl_run_13_2")
    empty = _make_run(lib_dir, name="openssl_run_13_3",
                      capture="traffic.pcap", capture_bytes=b"")
    shadowed = _make_run(lib_dir, name="openssl_run_13_4",
                         capture="traffic.pcap", capture_bytes=b"")
    (shadowed / CAPTURE_SUBDIR / "traffic.pcapng").write_bytes(b"\x0a\x0d\x0d\x0a")

    statuses = {
        d.name: RunDiscovery._find_capture(d)[1]
        for d in (good, none_, empty, shadowed)
    }
    assert statuses == {
        "openssl_run_13_1": "present",
        "openssl_run_13_2": "absent",
        "openssl_run_13_3": "unreadable",
        "openssl_run_13_4": "present",
    }

    info = DatasetScanner(tmp_path).fast_scan()
    assert info.total_runs == 4
    assert info.runs_with_capture == sum(
        1 for s in statuses.values() if s == "present"
    ) == 2


def test_load_run_directory_survives_an_unreadable_meta_json(tmp_path, monkeypatch):
    """An EACCES from load_run_meta skips the run's meta, not the whole sweep."""
    run_dir = _make_run(tmp_path, capture="traffic.pcap")

    def _boom(_run_dir):
        raise PermissionError(13, "Permission denied")

    monkeypatch.setattr("memdiver.core.discovery.load_run_meta", _boom)
    run = RunDiscovery.load_run_directory(run_dir, extract_secrets=False)
    assert run is not None
    assert run.meta is None
    # The capture probe still runs, falling back to the hardcoded names.
    assert run.capture_status == "present"


# -- meta.json-declared capture path -----------------------------------------
#
# ``DatasetMeta.capture`` names the capture relative to the run dir. It wins
# over the hardcoded probe so a corpus can carry a capture this module has
# never heard of; the three states are preserved either way.


def _write_meta(run_dir, capture=None):
    """Write a minimal valid meta.json, optionally declaring a capture."""
    import json

    payload = {
        "run_id": run_dir.name,
        "cipher": "AES-256-GCM",
        "password": "pw",
        "master_key_hex": "ab" * 32,
        "aslr_base": 0,
        "pid": 1,
        "dumps": {},
    }
    if capture is not None:
        payload["capture"] = capture
    (run_dir / "meta.json").write_text(json.dumps(payload))


def test_meta_declared_capture_is_honoured(tmp_path):
    """A capture named by meta.json is found even outside CAPTURE_SUBDIR."""
    run_dir = _make_run(tmp_path)
    (run_dir / "pcaps").mkdir()
    (run_dir / "pcaps" / "session.pcapng").write_bytes(b"\x0a\x0d\x0d\x0a")
    _write_meta(run_dir, capture="pcaps/session.pcapng")

    run = RunDiscovery.load_run_directory(run_dir, extract_secrets=False)
    assert run is not None
    assert run.capture_status == "present"
    assert run.capture_path == run_dir / "pcaps" / "session.pcapng"


def test_meta_declared_capture_wins_over_probe(tmp_path):
    """When both exist the declaration is preferred, not the hardcoded name."""
    run_dir = _make_run(tmp_path, capture="traffic.pcap")
    (run_dir / "declared.pcap").write_bytes(b"\xd4\xc3\xb2\xa1")
    _write_meta(run_dir, capture="declared.pcap")

    run = RunDiscovery.load_run_directory(run_dir, extract_secrets=False)
    assert run.capture_status == "present"
    assert run.capture_path == run_dir / "declared.pcap"


def test_meta_declared_zero_byte_capture_is_unreadable(tmp_path):
    """The three-state semantics hold for a declared path too."""
    run_dir = _make_run(tmp_path)
    (run_dir / "declared.pcap").write_bytes(b"")
    _write_meta(run_dir, capture="declared.pcap")

    run = RunDiscovery.load_run_directory(run_dir, extract_secrets=False)
    assert run.capture_status == "unreadable"
    assert run.capture_path == run_dir / "declared.pcap"


def test_meta_declared_missing_capture_falls_back_to_probe(tmp_path):
    """A declaration pointing at nothing must not mask a real capture."""
    run_dir = _make_run(tmp_path, capture="traffic.pcap")
    _write_meta(run_dir, capture="pcaps/does_not_exist.pcap")

    run = RunDiscovery.load_run_directory(run_dir, extract_secrets=False)
    assert run.capture_status == "present"
    assert run.capture_path == run_dir / CAPTURE_SUBDIR / "traffic.pcap"


def test_meta_declared_missing_and_no_probe_hit_is_absent(tmp_path):
    """Nothing anywhere -> absent, and no path is invented."""
    run_dir = _make_run(tmp_path)
    _write_meta(run_dir, capture="pcaps/does_not_exist.pcap")

    run = RunDiscovery.load_run_directory(run_dir, extract_secrets=False)
    assert run.capture_status == "absent"
    assert run.capture_path is None


def test_meta_declared_directory_falls_back_to_probe(tmp_path):
    """A declaration naming a directory is not a capture; the probe still runs."""
    run_dir = _make_run(tmp_path, capture="traffic.pcap")
    (run_dir / "declared.pcap").mkdir()
    _write_meta(run_dir, capture="declared.pcap")

    run = RunDiscovery.load_run_directory(run_dir, extract_secrets=False)
    assert run.capture_status == "present"
    assert run.capture_path == run_dir / CAPTURE_SUBDIR / "traffic.pcap"


def test_meta_without_capture_key_uses_probe(tmp_path):
    """The key is optional: a meta.json lacking it behaves exactly as before."""
    run_dir = _make_run(tmp_path, capture="traffic.pcap")
    _write_meta(run_dir)

    run = RunDiscovery.load_run_directory(run_dir, extract_secrets=False)
    assert run.capture_status == "present"
    assert run.capture_path == run_dir / CAPTURE_SUBDIR / "traffic.pcap"


def test_meta_declared_absolute_path_is_rejected(tmp_path):
    """Corpus-authored data may not point the scanner outside the run dir."""
    outside = tmp_path / "outside.pcap"
    outside.write_bytes(b"\xd4\xc3\xb2\xa1")
    run_dir = _make_run(tmp_path)
    _write_meta(run_dir, capture=str(outside))

    run = RunDiscovery.load_run_directory(run_dir, extract_secrets=False)
    assert run.capture_status == "absent"
    assert run.capture_path is None


def test_meta_declared_parent_traversal_is_rejected(tmp_path):
    """``..`` components are rejected rather than escaping the run dir."""
    outside = tmp_path / "outside.pcap"
    outside.write_bytes(b"\xd4\xc3\xb2\xa1")
    run_dir = _make_run(tmp_path)
    _write_meta(run_dir, capture="../outside.pcap")

    run = RunDiscovery.load_run_directory(run_dir, extract_secrets=False)
    assert run.capture_status == "absent"
    assert run.capture_path is None


def test_meta_loads_before_capture_probe(tmp_path):
    """Regression guard for the ordering bug: meta must precede the probe.

    If ``load_run_meta`` ran after ``_find_capture`` the declaration could
    never be consulted, so assert the probe actually received the meta.
    """
    run_dir = _make_run(tmp_path)
    (run_dir / "declared.pcap").write_bytes(b"\xd4\xc3\xb2\xa1")
    _write_meta(run_dir, capture="declared.pcap")

    seen = {}
    original = RunDiscovery._find_capture

    def _spy(run_path, meta=None):
        seen["meta"] = meta
        return original(run_path, meta)

    RunDiscovery._find_capture = staticmethod(_spy)
    try:
        run = RunDiscovery.load_run_directory(run_dir, extract_secrets=False)
    finally:
        RunDiscovery._find_capture = staticmethod(original)

    assert seen["meta"] is not None
    assert seen["meta"].capture == "declared.pcap"
    assert run.capture_path == run_dir / "declared.pcap"


def test_find_capture_meta_arg_is_optional(tmp_path):
    """Existing single-argument callers keep working (probe-only behaviour)."""
    run_dir = _make_run(tmp_path, capture="traffic.pcap")
    path, status = RunDiscovery._find_capture(run_dir)
    assert status == "present"
    assert path == run_dir / CAPTURE_SUBDIR / "traffic.pcap"


# -- alternate capture flavours ----------------------------------------------


def test_capture_pcapng_found(tmp_path):
    run_dir = _make_run(tmp_path, capture="traffic.pcapng")
    path, status = RunDiscovery._find_capture(run_dir)
    assert status == "present"
    assert path.name == "traffic.pcapng"


def test_capture_cap_found(tmp_path):
    run_dir = _make_run(tmp_path, capture="traffic.cap")
    path, status = RunDiscovery._find_capture(run_dir)
    assert status == "present"
    assert path.name == "traffic.cap"


def test_capture_filenames_is_an_ordered_tuple():
    """A tuple (not a set) so first-match order is deterministic."""
    assert isinstance(CAPTURE_FILENAMES, tuple)
    assert CAPTURE_FILENAMES[0] == "traffic.pcap"


def test_capture_first_match_wins_when_several_exist(tmp_path):
    """All three flavours present -> the first CAPTURE_FILENAMES entry wins."""
    run_dir = _make_run(tmp_path, capture="traffic.pcap")
    capture_dir = run_dir / CAPTURE_SUBDIR
    for name in CAPTURE_FILENAMES[1:]:
        (capture_dir / name).write_bytes(b"\x0a\x0d\x0d\x0a")
    for _ in range(3):  # order must not depend on directory iteration order
        path, status = RunDiscovery._find_capture(run_dir)
        assert status == "present"
        assert path.name == CAPTURE_FILENAMES[0]


# -- nothing regresses -------------------------------------------------------


def test_run_without_capture_still_loads_dumps_and_secrets(tmp_path):
    """A capture-less run keeps its dump inventory and keylog secrets."""
    run_dir = _make_run(tmp_path)
    (run_dir / "keylog.csv").write_text(
        "line\nCLIENT_RANDOM " + "aa" * 32 + " " + "ff" * 32 + "\n"
    )
    run = RunDiscovery.load_run_directory(run_dir)
    assert run is not None
    assert len(run.dumps) == 1
    assert run.secret_source == "keylog"
    assert run.secrets
    assert run.capture_status == "absent"


def test_capture_does_not_become_a_dump(tmp_path):
    """The capture must never be mistaken for a dump file."""
    run_dir = _make_run(tmp_path, capture="traffic.pcap")
    run = RunDiscovery.load_run_directory(run_dir, extract_secrets=False)
    assert [d.path.name for d in run.dumps] == [
        "20240101_120000_000001_pre_handshake.dump"
    ]


def test_run_directory_capture_defaults():
    """The dataclass defaults mirror the secrets/secret_source pairing."""
    from memdiver.core.models import RunDirectory

    run = RunDirectory(path=Path("/nope"), library="x", protocol_version="13", run_number=1)
    assert run.capture_path is None
    assert run.capture_status == "absent"


# -- DatasetScanner counters -------------------------------------------------


def _make_dataset(tmp_path, captured_runs, total_runs=3):
    """TLS13/scenario_a/openssl with `total_runs` runs; some own a capture."""
    lib_dir = tmp_path / "TLS13" / "scenario_a" / "openssl"
    for n in range(1, total_runs + 1):
        _make_run(
            lib_dir,
            name=f"openssl_run_13_{n}",
            capture="traffic.pcap" if n in captured_runs else None,
        )
    return tmp_path


def test_fast_scan_counts_runs_with_capture(tmp_path):
    root = _make_dataset(tmp_path, captured_runs={1, 3})
    info = DatasetScanner(root).fast_scan()
    assert info.total_runs == 3
    assert info.runs_with_capture == 2
    assert info.captures == {"13/scenario_a/openssl": 2}


def test_fast_scan_capture_counters_zero_when_no_captures(tmp_path):
    root = _make_dataset(tmp_path, captured_runs=set())
    info = DatasetScanner(root).fast_scan()
    assert info.total_runs == 3
    assert info.runs_with_capture == 0
    assert info.captures == {}


def test_fast_scan_captures_keyed_per_library(tmp_path):
    """captures uses the same "ver/scenario/library" key as info.phases."""
    root = tmp_path
    _make_run(root / "TLS13" / "scenario_a" / "openssl",
              name="openssl_run_13_1", capture="traffic.pcap")
    _make_run(root / "TLS12" / "scenario_a" / "boringssl",
              name="boringssl_run_12_1", capture="traffic.pcapng")
    _make_run(root / "TLS12" / "scenario_a" / "boringssl", name="boringssl_run_12_2")
    info = DatasetScanner(root).fast_scan()
    assert info.total_runs == 3
    assert info.runs_with_capture == 2
    assert info.captures == {
        "13/scenario_a/openssl": 1,
        "12/scenario_a/boringssl": 1,
    }
    assert set(info.captures) <= set(info.phases)


def test_fast_scan_probe_does_not_load_runs(tmp_path, monkeypatch):
    """The scan probe must stay stat-only across thousands of runs."""
    root = _make_dataset(tmp_path, captured_runs={1})

    def _boom(*args, **kwargs):
        raise AssertionError("fast_scan must not call load_run_directory")

    monkeypatch.setattr(RunDiscovery, "load_run_directory", staticmethod(_boom))
    info = DatasetScanner(root).fast_scan()
    assert info.runs_with_capture == 1


def test_serialize_dataset_info_carries_capture_counters(tmp_path):
    """The two new fields reach every surface via the existing payload."""
    from memdiver.engine.serializer import serialize_dataset_info

    root = _make_dataset(tmp_path, captured_runs={2})
    info = DatasetScanner(root).fast_scan()
    payload = serialize_dataset_info(info)
    assert payload["runs_with_capture"] == 1
    assert payload["captures"] == {"13/scenario_a/openssl": 1}


def test_scan_dataset_tool_surfaces_capture_counters(tmp_path):
    """app.tools.scan_dataset exposes the counters without a new capability."""
    from memdiver.app.session import ToolSession
    from memdiver.app.tools import scan_dataset

    root = _make_dataset(tmp_path, captured_runs={1, 2})
    payload = scan_dataset(ToolSession(), str(root))
    assert payload["total_runs"] == 3
    assert payload["runs_with_capture"] == 2
    assert payload["captures"] == {"13/scenario_a/openssl": 2}


# -- meta_for_dump: the normalisation, extracted --------------------------------
#
# ``find_capture_for`` used to own the "dump path -> run dir -> load_run_meta"
# walk privately and then discard the meta. It is now ``meta_for_dump``, so a
# caller that wants the run's OWN metadata (its vault, its library version)
# asks the same question the capture probe does, the same way.


def test_meta_for_dump_given_a_dump_file(tmp_path):
    """A dump path normalises to its parent, where the meta.json lives."""
    run_dir = _make_run(tmp_path)
    _write_meta(run_dir)

    meta = RunDiscovery.meta_for_dump(run_dir / "20240101_120000_000001_pre_handshake.dump")
    assert meta is not None
    assert meta.run_id == run_dir.name


def test_meta_for_dump_given_the_run_directory(tmp_path):
    """A directory is used as-is, so both call shapes agree on one answer."""
    run_dir = _make_run(tmp_path)
    _write_meta(run_dir)

    assert RunDiscovery.meta_for_dump(run_dir) == RunDiscovery.meta_for_dump(
        run_dir / "20240101_120000_000001_pre_handshake.dump"
    )


def test_meta_for_dump_accepts_a_string_path(tmp_path):
    """The ``Union[str, Path]`` signature its siblings use, honoured."""
    run_dir = _make_run(tmp_path)
    _write_meta(run_dir)

    meta = RunDiscovery.meta_for_dump(str(run_dir))
    assert meta is not None


def test_meta_for_dump_without_meta_json_is_none(tmp_path):
    """A legacy-style run has no meta.json; that is None, not an exception."""
    run_dir = _make_run(tmp_path)
    assert RunDiscovery.meta_for_dump(run_dir / "20240101_120000_000001_pre_handshake.dump") is None


def test_meta_for_dump_never_raises_on_a_missing_directory(tmp_path):
    """Same tolerance ``find_capture_for`` has: no run there is simply None."""
    assert RunDiscovery.meta_for_dump("/nonexistent/deep/a.dump") is None


def test_meta_for_dump_carries_the_vault_declaration(tmp_path):
    """The reason the meta stopped being thrown away: callers want its fields."""
    import json

    run_dir = _make_run(tmp_path)
    (run_dir / "cipher").mkdir()
    payload = {"run_id": run_dir.name, "dumps": {}, "vault_cipher_dir": "cipher"}
    (run_dir / "meta.json").write_text(json.dumps(payload))

    meta = RunDiscovery.meta_for_dump(run_dir / "20240101_120000_000001_pre_handshake.dump")
    assert meta is not None
    assert meta.vault_dir() == run_dir / "cipher"


def test_find_capture_for_still_honours_a_declared_capture(tmp_path):
    """The refactor kept ``find_capture_for`` reading the meta it now shares."""
    run_dir = _make_run(tmp_path)
    (run_dir / "declared.pcap").write_bytes(b"\xd4\xc3\xb2\xa1")
    _write_meta(run_dir, capture="declared.pcap")

    assert RunDiscovery.find_capture_for(
        run_dir / "20240101_120000_000001_pre_handshake.dump"
    ) == (run_dir / "declared.pcap", "present")

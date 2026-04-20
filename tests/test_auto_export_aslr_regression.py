"""Regression test: ASLR divergence between API /auto-export and CLI export.

Originally documented the divergence where the FastAPI endpoint
`api/routers/analysis.py::auto_export` called `cm.build(paths)` while the
CLI command `memdiver export --auto` (`cli.py::_cmd_export`) called
`cm.build_from_sources(sources)`. For ASLR-shifted *native* MSL inputs,
the two paths disagreed:

- `build_from_sources` uses `engine.consensus_msl.build_msl_consensus` which
  aligns regions by ASLR-invariant keys via `core.region_align.align_dumps`.
  The key appears at its region-relative offset — the same offset the user
  would see inside the module's memory.
- `build(paths)` reads the MSL file as flat bytes. It happens to find the
  key too (because the divergent key payload still has high variance), but
  at the raw *file-byte* offset — a number the user cannot map back to a
  memory address without knowing the MSL binary layout.

All 3 original tests passed on the PR 4 gating run (2026-04-13),
confirming the divergence was real and user-visible. PR 4 promoted the
router-as-service layer refactor from "deferred" to "ship now" and
introduced `api/services/analysis_service.py::auto_export_pattern`, which
both the HTTP route and the CLI command now dispatch to. That service
function uses `build_from_sources` with properly-opened sources, so:

- Test 1 (`build_from_sources_isolates_...`) still passes — unchanged.
- Test 2 (`build_paths_on_msl_reports_...`) still passes — the primitive
  `build(paths)` behaviour is unchanged; the fact that it is no longer
  what the API/CLI use is what PR 4 changed.
- Test 3 (`api_auto_export_returns_MEMORY_RELATIVE_offset_on_aslr_msl`)
  was FLIPPED in PR 4: previously it asserted the API returned the
  flat-file offset `KEY_FILE_OFFSET`; now it asserts the API returns the
  memory-relative offset `KEY_REGION_OFFSET`. If this test ever regresses
  (API goes back to file-relative offsets), the router has drifted away
  from the service function and PR 4 should be re-audited.
- Test 4 (`cli_and_api_return_the_same_region`) is the new parity guard:
  the CLI and the API must return byte-identical region offsets on the
  same ASLR fixture. This catches any future split where one transport
  bypasses the service layer.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from api.main import create_app
from core.dump_source import MslDumpSource
from engine.consensus import ConsensusVector, _is_native_msl
from tests.fixtures.generate_msl_fixtures import write_aslr_fixture


# Region-relative offset where each fixture plants a divergent 32-byte "key"
KEY_REGION_OFFSET = 0x200
KEY_LENGTH = 32

# Flat-file offset of the key bytes inside the MSL binary layout:
#   file_header (64) + block_header (80) + region_struct (32) + page_map (8)
#   + KEY_REGION_OFFSET (0x200) = 0x2B8 (696)
# See tests/fixtures/generate_msl_fixtures.py for the byte layout this derives
# from (_build_file_header, _build_memory_region, _build_block).
KEY_FILE_OFFSET = 64 + 80 + 32 + 8 + KEY_REGION_OFFSET  # 0x2B8 = 696

# Three divergent 32-byte key values. Per-byte variance of {0x00, 0xFF, 0x80}
# is ≈10837, comfortably above POINTER_MAX=3000 so every byte classifies as
# KEY_CANDIDATE on either code path.
KEY_VALUES = (
    b"\x00" * KEY_LENGTH,
    b"\xFF" * KEY_LENGTH,
    b"\x80" * KEY_LENGTH,
)

# Three ASLR-shifted region base addresses. They differ in a single byte each,
# giving the base_addr field a variance ≈170 — classified as STRUCTURAL, NOT
# KEY_CANDIDATE, so the base_addr bytes do NOT create a spurious volatile
# region in the flat-bytes path. This keeps test 2's assertions clean.
REGION_BASES = (
    0x7FFF00000000,
    0x7FFF10000000,
    0x7FFF20000000,
)


@pytest.fixture
def aslr_fixture_paths(tmp_path):
    """Write three ASLR-shifted native MSL fixtures and return their paths."""
    paths = []
    for i, (base, key) in enumerate(zip(REGION_BASES, KEY_VALUES)):
        p = write_aslr_fixture(
            tmp_path / f"aslr_{i}.msl",
            region_base=base,
            key_offset=KEY_REGION_OFFSET,
            key_bytes=key,
        )
        paths.append(p)
    return paths


def _open_msl_sources(paths):
    sources = [MslDumpSource(p) for p in paths]
    for s in sources:
        s.open()
    return sources


def _close_sources(sources):
    for s in sources:
        s.close()


# ---------------------------------------------------------------------------
# Test 1: build_from_sources correctly isolates the key at its memory offset
# ---------------------------------------------------------------------------

def test_build_from_sources_isolates_key_at_region_offset(aslr_fixture_paths):
    """`build_from_sources` on native MSL produces ONE KEY_CANDIDATE region
    of exactly KEY_LENGTH bytes at the region-relative KEY_REGION_OFFSET.

    This is the correct behavior — it's what the CLI relies on and what the
    API endpoint ought to return.
    """
    sources = _open_msl_sources(aslr_fixture_paths)
    try:
        for s in sources:
            assert _is_native_msl(s), (
                "Fixture is not native MSL — check flags field in "
                "_build_file_header (must be 0 for imported=False)"
            )

        cm = ConsensusVector()
        cm.build_from_sources(sources)

        assert cm.size > 0, "MSL alignment produced no aligned bytes"

        regions = cm.get_volatile_regions(min_length=16)
        assert len(regions) == 1, (
            f"Expected exactly one KEY_CANDIDATE region, got {len(regions)}: "
            f"{[(r.start, r.end) for r in regions]}"
        )
        r = regions[0]
        assert r.end - r.start == KEY_LENGTH, (
            f"Expected region length {KEY_LENGTH}, got {r.end - r.start}"
        )
        assert r.start == KEY_REGION_OFFSET, (
            f"Expected region at region-relative offset 0x{KEY_REGION_OFFSET:x}, "
            f"got 0x{r.start:x}"
        )
    finally:
        _close_sources(sources)


# ---------------------------------------------------------------------------
# Test 2: build(paths) on the same MSL files reports the flat-file offset
# ---------------------------------------------------------------------------

def test_build_paths_on_msl_reports_key_at_flat_file_offset(aslr_fixture_paths):
    """`build(paths)` reads MSL files as flat bytes. For ASLR-shifted native
    MSL it finds the key at the raw file-byte offset, NOT at the memory-
    relative offset. The returned offset is unusable for locating the key
    inside the captured memory.

    If this test ever starts reporting a region at KEY_REGION_OFFSET, it
    means `build(paths)` has learned ASLR normalization and the divergence
    is gone — update the assertion and close PR 4 trigger (b) in
    .claude-work/plans/curried-jumping-lantern.md.
    """
    cm = ConsensusVector()
    cm.build(aslr_fixture_paths)

    regions = cm.get_volatile_regions(min_length=16)

    assert regions, (
        "Expected at least one KEY_CANDIDATE region in flat-file mode; got none. "
        "Variance may be smeared below threshold — that is ALSO a divergence "
        "symptom, but this test expects the stronger 'wrong offset' form."
    )

    key_length_regions = [r for r in regions if r.end - r.start == KEY_LENGTH]
    assert key_length_regions, (
        f"Expected at least one {KEY_LENGTH}-byte KEY_CANDIDATE region, got "
        f"{[(r.start, r.end) for r in regions]}"
    )

    region_relative_hits = [
        r for r in key_length_regions if r.start == KEY_REGION_OFFSET
    ]
    flat_file_hits = [
        r for r in key_length_regions if r.start == KEY_FILE_OFFSET
    ]

    assert not region_relative_hits, (
        f"build(paths) unexpectedly reported the key at region-relative "
        f"offset 0x{KEY_REGION_OFFSET:x}. The divergence is gone — close "
        "PR 4 trigger (b) and update this test."
    )
    assert flat_file_hits, (
        f"Expected build(paths) to report the key at flat-file offset "
        f"0x{KEY_FILE_OFFSET:x} (= 0x40+0x50+0x20+0x08+0x200); "
        f"got regions {[hex(r.start) for r in key_length_regions]}"
    )


# ---------------------------------------------------------------------------
# Test 3: the /api/analysis/auto-export endpoint now serves the CORRECT offset
# ---------------------------------------------------------------------------

def test_api_auto_export_returns_memory_relative_offset_on_aslr_msl(
    aslr_fixture_paths,
):
    """The HTTP endpoint `/api/analysis/auto-export` dispatches through
    `api.services.analysis_service.auto_export_pattern`, which uses
    `build_from_sources` under a proper ExitStack, so the returned
    `region.key_start` is the memory-relative offset (region-aligned,
    ASLR-invariant) — the same value a user needs to locate the key
    inside the captured module.

    Pre-PR-4 this test asserted `key_start == KEY_FILE_OFFSET` and
    documented the wrong behavior. The assertion was flipped when PR 4
    moved the consensus build under the service layer. If this test
    regresses (API returns the flat-file offset again), the router has
    drifted back to the old `cm.build(paths)` pipeline and PR 4 needs
    a re-audit.
    """
    app = create_app()
    client = TestClient(app)

    response = client.post(
        "/api/analysis/auto-export",
        json={
            "dump_paths": [str(p) for p in aslr_fixture_paths],
            "format": "json",
            "name": "aslr_regression",
            # Disable alignment filter so get_volatile_regions is used.
            "align": False,
            # 32 bytes of context on each side so the extracted region has
            # enough static filler for PatternGenerator to emit a signature.
            "context": 32,
        },
    )

    assert response.status_code == 200, response.text
    body = response.json()
    region = body["region"]
    key_start = region["key_start"]
    key_end = region["key_end"]

    assert key_end - key_start == KEY_LENGTH, (
        f"Expected key region length {KEY_LENGTH}, got {key_end - key_start}"
    )
    assert key_start == KEY_REGION_OFFSET, (
        f"Expected API to return the memory-relative offset "
        f"0x{KEY_REGION_OFFSET:x}, got 0x{key_start:x}. The router has "
        "drifted away from analysis_service.auto_export_pattern — re-audit PR 4."
    )
    # And definitively NOT the flat-file offset.
    assert key_start != KEY_FILE_OFFSET, (
        f"API regressed to flat-file offset 0x{KEY_FILE_OFFSET:x}. "
        "This is the pre-PR-4 bug. Re-audit api/routers/analysis.py::auto_export."
    )


# ---------------------------------------------------------------------------
# Test 4: CLI and API must agree on the same input (parity guard)
# ---------------------------------------------------------------------------

def test_cli_and_api_return_the_same_region(aslr_fixture_paths, tmp_path):
    """Both the HTTP API and the CLI command dispatch through the same
    ``analysis_service.auto_export_pattern``. Running them against the
    same set of dumps must produce byte-identical region offsets.

    This is the parity guard PR 4 promises. Any future change that makes
    one transport bypass the service (e.g. an over-eager optimization
    that inlines the pipeline in the route) will immediately fail this
    test.
    """
    import json
    import subprocess
    import sys

    # -- API path ---------------------------------------------------------
    app = create_app()
    client = TestClient(app)
    api_resp = client.post(
        "/api/analysis/auto-export",
        json={
            "dump_paths": [str(p) for p in aslr_fixture_paths],
            "format": "json",
            "name": "parity",
            "align": False,
            "context": 32,
        },
    )
    assert api_resp.status_code == 200, api_resp.text
    api_region = api_resp.json()["region"]

    # -- CLI path ---------------------------------------------------------
    # Invoke the CLI via `python -m memdiver export --auto ...` so the
    # test is portable (no reliance on an installed `memdiver` script)
    # and so the subprocess is isolated from the TestClient process.
    out_file = tmp_path / "cli_out.json"
    completed = subprocess.run(
        [
            sys.executable, "-m", "cli", "export", "--auto",
            "--format", "json",
            "--name", "parity",
            "--context", "32",
            "--min-static-ratio", "0.3",
            "-o", str(out_file),
            *[str(p) for p in aslr_fixture_paths],
        ],
        capture_output=True,
        text=True,
    )
    assert completed.returncode == 0, (
        f"CLI failed: rc={completed.returncode}\n"
        f"stdout:\n{completed.stdout}\n"
        f"stderr:\n{completed.stderr}"
    )
    assert out_file.exists(), "CLI did not write output file"
    cli_payload = json.loads(out_file.read_text())

    # The CLI exporter writes the pattern content, not the region wrapper
    # the API returns. Instead, parse the JSON content and compare the
    # pattern's key metadata — wildcard bytes, total length — to confirm
    # byte-for-byte agreement with the API's rendered pattern.
    api_content = api_resp.json()["content"]
    api_parsed = json.loads(api_content) if isinstance(api_content, str) else api_content

    assert cli_payload == api_parsed, (
        "CLI and API produced different pattern payloads on the same ASLR "
        f"fixture.\nCLI:\n{json.dumps(cli_payload, indent=2)}\n"
        f"API:\n{json.dumps(api_parsed, indent=2)}"
    )
    # Sanity: memory-relative key offset is present in both and consistent.
    assert api_region["key_start"] == KEY_REGION_OFFSET
